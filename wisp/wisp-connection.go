package wisp

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

type writeReq struct {
	data []byte
	pool bool
}

var connIDCounter uint64

type wispConnection struct {
	netConn        net.Conn
	writeCh        chan writeReq
	streams        sync.Map
	cachedStreamId uint32
	cachedStream   unsafe.Pointer
	isClosed       atomic.Bool
	shutdownOnce   sync.Once
	config         *Config
	twispStreams   *twispRegistry
	remoteIP       string

	isV2          bool
	handshakeDone chan struct{}
	streamConfirm bool
	v2Challenge   []byte
	authenticated atomic.Bool

	dialSem     chan struct{}
	closeCh     chan struct{}
	createdAt   time.Time
	streamCount atomic.Int32

	globals    *Globals
	connID     uint64
	violations atomic.Int32
}

func (c *wispConnection) close() {
	if !c.isClosed.CompareAndSwap(false, true) {
		return
	}
	c.netConn.Close()
}

func (c *wispConnection) writeLoop() {
	for req := range c.writeCh {
		bufs := net.Buffers{req.data}
		n := len(c.writeCh)
		for i := 0; i < n; i++ {
			r := <-c.writeCh
			bufs = append(bufs, r.data)
		}
		if _, err := bufs.WriteTo(c.netConn); err != nil {
			c.isClosed.Store(true)
			c.netConn.Close()
			return
		}
	}
}

func (c *wispConnection) queueWrite(data []byte) {
	if c.isClosed.Load() {
		return
	}
	defer func() {
		recover()
	}()
	select {
	case c.writeCh <- writeReq{data: data}:
	case <-c.closeCh:
		return
	}
}

func (c *wispConnection) queueWritePooled(data []byte) {
	if c.isClosed.Load() {
		c.releaseFrame(data)
		return
	}
	defer func() {
		if recover() != nil {
			c.releaseFrame(data)
		}
	}()
	select {
	case c.writeCh <- writeReq{data: data, pool: true}:
	case <-c.closeCh:
		c.releaseFrame(data)
		return
	}
}

func (c *wispConnection) releaseFrame(data []byte) {
	if c.config == nil || len(data) == 0 {
		return
	}
	if cap(data) < 64*1024 {
		return
	}
	buf := data
	if len(buf) != cap(buf) {
		buf = data[:cap(data)]
	}
	// cfg.config.FramePool.Put(buf)
}

func (c *wispConnection) handlePacket(packetType uint8, streamId uint32, payload []byte) {
	switch packetType {
	case packetTypeInfo:
		if c.isV2 {
			c.handleInfo(streamId, payload)
		}
	case packetTypeConnect:
		c.handleConnectPacket(streamId, payload)
	case packetTypeClose:
		c.handleClosePacket(streamId, payload)
	case twispExtensionID:
		if c.config.EnableTwisp && c.twispStreams != nil && len(payload) >= 4 {
			rows := binary.LittleEndian.Uint16(payload[0:2])
			cols := binary.LittleEndian.Uint16(payload[2:4])
			ts := c.twispStreams.get(streamId)
			if ts != nil {
				ts.resize(rows, cols)
			}
		}
	}
}

func (c *wispConnection) handleConnectPacket(streamId uint32, payload []byte) {
	if len(payload) < 3 {
		return
	}
	streamType := payload[0]
	port := strconv.FormatUint(uint64(binary.LittleEndian.Uint16(payload[1:3])), 10)
	hostname := string(payload[3:])

	c.config.Logger.Debug("creating stream", "ip", c.remoteIP, "streamId", streamId, "hostname", hostname, "port", port, "type", streamType)

	// Per-connection concurrent-stream cap.
	if c.config.FloodProtection != nil && c.config.FloodProtection.MaxConcurrentStreamsPerConnection > 0 {
		if c.streamCount.Load() >= int32(c.config.FloodProtection.MaxConcurrentStreamsPerConnection) {
			c.violation("per_ws_streams")
			c.sendClosePacket(streamId, closeReasonThrottled)
			return
		}
	}

	// Per-source-IP rate.
	if c.globals != nil && c.globals.PerSource != nil && !c.globals.PerSource.Allow(c.remoteIP) {
		c.violation("per_source_rate")
		c.repAddSource("burstRate")
		c.config.Logger.Warn("flood block", "reason", "per_source_rate", "ip", c.remoteIP, "host", hostname, "port", port)
		c.sendClosePacket(streamId, closeReasonThrottled)
		return
	}

	if streamType == streamTypeTerm {
		c.handleTwispConnect(streamId, hostname)
		return
	}

	portNum, _ := strconv.Atoi(port)
	stream := &wispStream{
		wispConn:  c,
		streamId:  streamId,
		connReady: make(chan struct{}),
		hostname:  strings.ToLower(strings.TrimSpace(hostname)),
		portNum:   portNum,
	}
	stream.isOpen.Store(true)

	if _, loaded := c.streams.LoadOrStore(streamId, stream); loaded {
		close(stream.connReady)
		return
	}

	c.streamCount.Add(1)
	go stream.handleConnect(streamType, port, hostname)
}

// handleTwispConnect gates terminal-stream requests. Twisp requires v2,
// auth configured, and the client to have completed auth.
func (c *wispConnection) handleTwispConnect(streamId uint32, command string) {
	if !c.config.EnableTwisp {
		c.sendClosePacket(streamId, closeReasonBlocked)
		return
	}
	if !c.isV2 {
		c.repAddSource("twispNoAuth")
		c.config.Logger.Warn("twisp blocked", "reason", "v1_no_auth", "ip", c.remoteIP)
		c.sendClosePacket(streamId, closeReasonBlocked)
		return
	}
	if !c.config.PasswordAuth {
		c.repAddSource("twispNoAuth")
		c.config.Logger.Warn("twisp blocked", "reason", "no_auth_configured", "ip", c.remoteIP)
		c.sendClosePacket(streamId, closeReasonBlocked)
		return
	}
	if !c.twispAuthorized() {
		c.repAddSource("twispNoAuth")
		c.config.Logger.Warn("twisp blocked", "reason", "not_authenticated", "ip", c.remoteIP)
		c.sendClosePacket(streamId, closeReasonBlocked)
		return
	}
	go handleTwisp(c, streamId, command)
}

func (c *wispConnection) violation(reason string) {
	if c.config.FloodProtection == nil || c.config.FloodProtection.WsCloseAfterViolations <= 0 {
		return
	}
	n := c.violations.Add(1)
	if n >= int32(c.config.FloodProtection.WsCloseAfterViolations) {
		c.config.Logger.Warn("ws closed for violations", "ip", c.remoteIP, "violations", n, "lastReason", reason)
		c.close()
	}
}

func (c *wispConnection) repAddSource(reason string) {
	if c.globals != nil && c.globals.Reputation != nil {
		c.globals.Reputation.AddSource(c.remoteIP, reason)
	}
}

func (c *wispConnection) repAddDest(ip string, port int, reason string) {
	if c.globals != nil && c.globals.Reputation != nil {
		c.globals.Reputation.AddDest(ip, port, reason, net.ParseIP(c.remoteIP))
	}
}

func (c *wispConnection) handleDataPacket(streamId uint32, payload []byte) {
	var stream *wispStream
	if c.cachedStreamId == streamId {
		stream = (*wispStream)(atomic.LoadPointer(&c.cachedStream))
	}
	if stream == nil {
		v, ok := c.streams.Load(streamId)
		if !ok {
			if c.twispStreams != nil {
				ts := c.twispStreams.get(streamId)
				if ts != nil && ts.isOpen.Load() {
					if err := ts.writePty(payload); err != nil {
						ts.close(closeReasonNetworkError)
					}
					return
				}
			}
			c.sendClosePacket(streamId, closeReasonInvalidInfo)
			return
		}
		stream = v.(*wispStream)
		atomic.StorePointer(&c.cachedStream, unsafe.Pointer(stream))
		c.cachedStreamId = streamId
	}

	if !stream.isOpen.Load() {
		return
	}

	stream.pendingMutex.Lock()
	if !stream.connReadyDone.Load() {
		if stream.pendingBytes+len(payload) > 16*1024*1024 {
			stream.pendingMutex.Unlock()
			stream.close(closeReasonThrottled)
			return
		}
		dataCopy := make([]byte, len(payload))
		copy(dataCopy, payload)
		stream.pendingData = append(stream.pendingData, dataCopy)
		stream.pendingBytes += len(dataCopy)
		stream.pendingMutex.Unlock()
		return
	}
	stream.pendingMutex.Unlock()

	_, err := stream.conn.Write(payload)
	if err != nil {
		stream.close(closeReasonNetworkError)
		return
	}

	if stream.streamType == streamTypeTCP {
		stream.bufferRemaining--
		if stream.bufferRemaining == 0 {
			stream.bufferRemaining = c.config.BufferRemainingLength
			c.sendPacket(streamId, stream.bufferRemaining)
		}
	}
}

func (c *wispConnection) twispAuthorized() bool {
	return c.isV2 && c.authenticated.Load()
}

func (c *wispConnection) handleClosePacket(streamId uint32, payload []byte) {
	if len(payload) < 1 {
		return
	}

	v, ok := c.streams.Load(streamId)
	if !ok {
		if c.twispStreams != nil {
			ts := c.twispStreams.get(streamId)
			if ts != nil {
				go ts.close(closeReasonVoluntary)
			}
		}
		return
	}
	stream := v.(*wispStream)
	go stream.close(closeReasonVoluntary)
}

func (c *wispConnection) sendPacket(streamId uint32, bufferRemaining uint32) {
	if c.isClosed.Load() {
		return
	}
	buf := make([]byte, 11)
	buf[0] = 0x82
	buf[1] = 9
	buf[2] = packetTypeContinue
	buf[3] = byte(streamId)
	buf[4] = byte(streamId >> 8)
	buf[5] = byte(streamId >> 16)
	buf[6] = byte(streamId >> 24)
	binary.LittleEndian.PutUint32(buf[7:11], bufferRemaining)
	c.queueWrite(buf)
}

func (c *wispConnection) sendClosePacket(streamId uint32, reason uint8) {
	if c.isClosed.Load() {
		return
	}
	buf := make([]byte, 8)
	buf[0] = 0x82
	buf[1] = 6
	buf[2] = packetTypeClose
	buf[3] = byte(streamId)
	buf[4] = byte(streamId >> 8)
	buf[5] = byte(streamId >> 16)
	buf[6] = byte(streamId >> 24)
	buf[7] = reason
	c.queueWrite(buf)
}

func (c *wispConnection) writeRawPong(payload []byte) error {
	if c.isClosed.Load() {
		return nil
	}
	totalLen := len(payload)
	buf := make([]byte, 2+totalLen)
	buf[0] = 0x8A
	buf[1] = byte(totalLen)
	copy(buf[2:], payload)
	c.queueWrite(buf)
	return nil
}

func (c *wispConnection) deleteWispStream(streamId uint32) {
	c.streams.Delete(streamId)
	if c.cachedStreamId == streamId {
		atomic.StorePointer(&c.cachedStream, nil)
	}
	c.streamCount.Add(-1)
}

func (c *wispConnection) deleteAllWispStreams() {
	c.close()
	c.config.Logger.Info("connection closed", "ip", c.remoteIP)
	c.streams.Range(func(key, value any) bool {
		stream := value.(*wispStream)
		stream.close(closeReasonUnspecified)
		return true
	})
	if c.twispStreams != nil {
		c.twispStreams.mu.Lock()
		streams := make([]*twispStream, 0, len(c.twispStreams.streams))
		for _, ts := range c.twispStreams.streams {
			streams = append(streams, ts)
		}
		c.twispStreams.mu.Unlock()
		for _, ts := range streams {
			ts.close(closeReasonUnspecified)
		}
	}
	if c.globals != nil {
		if c.globals.Connections != nil {
			c.globals.Connections.Release()
		}
		if c.globals.Signature != nil {
			c.globals.Signature.Forget(c.connID)
		}
	}
	defer func() { recover() }()
	close(c.writeCh)
}
