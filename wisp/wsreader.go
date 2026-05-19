package wisp

import (
	"bufio"
	"encoding/binary"
	"io"
)

func (c *wispConnection) readLoop() {
	defer c.deleteAllWispStreams()
	reader := bufio.NewReaderSize(c.netConn, 64*1024)

	const PayloadBufferSize = 256 * 1024
	PayloadBuffer := make([]byte, PayloadBufferSize)
	var headerBuffer [14]byte

	for {
		if _, err := io.ReadFull(reader, headerBuffer[:2]); err != nil {
			return
		}

		data := headerBuffer[0] & 0x0F
		masked := headerBuffer[1]&0x80 != 0
		lengthCode := headerBuffer[1] & 0x7F

		var payloadLen uint64
		switch {
		case lengthCode <= 125:
			payloadLen = uint64(lengthCode)
		case lengthCode == 126:
			if _, err := io.ReadFull(reader, headerBuffer[2:4]); err != nil {
				return
			}
			payloadLen = uint64(binary.BigEndian.Uint16(headerBuffer[2:4]))
		case lengthCode == 127:
			if _, err := io.ReadFull(reader, headerBuffer[2:10]); err != nil {
				return
			}
			payloadLen = binary.BigEndian.Uint64(headerBuffer[2:10])
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(reader, maskKey[:]); err != nil {
				return
			}
		}

		maxPayload := uint64(c.config.MaxPayloadBytes)
		if maxPayload > 0 && payloadLen > maxPayload {
			return
		}

		var payload []byte
		if payloadLen <= PayloadBufferSize {
			payload = PayloadBuffer[:payloadLen]
		} else {
			payload = make([]byte, payloadLen)
		}

		if payloadLen > 0 {
			if _, err := io.ReadFull(reader, payload); err != nil {
				return
			}
		}

		if masked && payloadLen > 0 {
			maskXOR(payload, maskKey)
		}

		switch data {
		case 0x2:
			c.handleWispFrame(payload)

		case 0x9:
			_ = c.writeRawPong(payload)

		case 0x8:
			if len(payload) >= 2 {
				code := binary.BigEndian.Uint16(payload[:2])
				c.sendWSClose(code)
			} else {
				c.sendWSClose(1000)
			}
			return

		case 0xA:
			continue

		case 0x1:
			c.handleWispFrame(payload)

		default:
			continue
		}
	}
}

func (c *wispConnection) handleWispFrame(packet []byte) {
	if len(packet) < 5 {
		return
	}

	packetType := packet[0]
	streamId := binary.LittleEndian.Uint32(packet[1:5])
	payload := packet[5:]

	if c.isV2 && c.handshakeDone != nil {
		select {
		case <-c.handshakeDone:
		default:
			if packetType == packetTypeInfo {
				c.handlePacket(packetType, streamId, payload)
				return
			}
			if packetType == packetTypeClose && streamId == 0 {
				c.handlePacket(packetType, streamId, payload)
				return
			}
			return
		}
	}

	if packetType == packetTypeData {
		c.handleDataPacket(streamId, payload)
	} else {
		c.handlePacket(packetType, streamId, payload)
	}
}

func maskXOR(b []byte, key [4]byte) {
	maskKey := binary.LittleEndian.Uint32(key[:])
	key64 := uint64(maskKey)<<32 | uint64(maskKey)
	i := 0
	for ; i+8 <= len(b); i += 8 {
		v := binary.LittleEndian.Uint64(b[i:])
		v ^= key64
		binary.LittleEndian.PutUint64(b[i:], v)
	}
	for j := i; j < len(b); j++ {
		b[j] ^= key[j&3]
	}
}

func (c *wispConnection) sendWSClose(code uint16) {
	buf := make([]byte, 4)
	buf[0] = 0x88
	buf[1] = 2
	binary.BigEndian.PutUint16(buf[2:4], code)
	c.queueWrite(buf)
}
