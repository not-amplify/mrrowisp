![night chan](https://raw.githubusercontent.com/starlightdevgroup/mrrowisp/main/night%20chan.png)

it has the zoomies

so quick story abt how this was made, this was the initial project, then amplify made me write a whole new wisp library, then i scrapped that and wrote this in rust. this has still been faster than all of them. every single time.

> [!WARNING]
> Twisp, and by extension mrrowisp, does NOT work on windows! linux and macos supported tho

## Features

- Wisp v1 and v2 protocol support
- TCP and UDP stream multiplexing over WebSocket
- Twisp (terminal over wisp) support for remote shell access
- Password and Ed25519 certificate authentication (v2)
- Hostname blacklist/whitelist filtering
- SOCKS5 proxy support for upstream connections
- Custom DNS server with caching
- WebSocket permessage-deflate compression
- Configurable TCP buffer sizes and flow control

## Installation

### Go Binary

```bash
go build -o mrrowisp
```

### Node / Bun

```bash
bun add mrrowisp
# or
npm install mrrowisp
```

## Usage

### TypeScript / JavaScript

```ts
import { createMrrowisp } from "mrrowisp";

// Basic start and stop
const server = await createMrrowisp()
	.port(6001)
	.v2(true)
	.start();

// later
await server.stop();
```

#### Configuration

```ts
const server = await createMrrowisp()
	.port(6001)
	.v2(true)
	.udp(true)
	.twisp(true)
	.motd("mrrow merp purr :3")
	.blacklist(["truthsocial.com"]) // idk i'd block this
	.dns(["8.8.8.8","1.1.1.1"])
	.start();
```

#### Event Handlers

```ts
const server = await createMrrowisp()
	.port(6001)
	.onReady(() => {
		console.log("Server is ready!");
	})
	.onError((err) => {
		console.error("Server error:", err);
	})
	.onExit((code, signal) => {
		console.log(`Server exited (code: ${code}, signal: ${signal})`);
	})
	.onStdout((data) => {
		console.log(`[mrrowisp] ${data}`);
	})
	.onStderr((data) => {
		console.error(`[mrrowisp] ${data}`);
	})
	.start();

server.on("error", (err) => console.error(err));
server.on("exit", (code) => console.log(`Exit: ${code}`));
```

#### Loading Config

```ts
// Load from a config file
const server = await createMrrowisp()
	.fromFile("./config.json")
	.start();

// Merge multiple sources
const server = await createMrrowisp()
	.fromFile("./config.json")
	.withConfig({ port: 8080 })	// Override specific values
	.start();

// Or from a JSON config
const server = await createMrrowisp()
	.fromJSON('{"port": 6001, "enableV2": true}')
	.start();
```

#### Server Control

```ts
const server = await createMrrowisp().port(6001).start();

// Check if server is running
console.log(server.running);

// Access the config
console.log(server.config);

// Access the child process
console.log(server.process.pid);

// Graceful shutdown
await server.stop();

// Force kill
server.kill();
server.kill("SIGTERM");
```

#### Builder Methods

| Method                 | Description                        |
| ---------------------- | ---------------------------------- |
| `fromFile(path)`       | Load config from a JSON file       |
| `fromJSON(json)`       | Load config from a JSON string     |
| `withConfig(config)`   | Merge a partial config object      |
| `port(port)`           | Set the server port                |
| `udp(enabled)`         | Enable/disable UDP support         |
| `v2(enabled)`          | Enable/disable Wisp v2 protocol    |
| `twisp(enabled)`       | Enable/disable terminal over wisp  |
| `motd(message)`        | Set message of the day             |
| `blacklist(hostnames)` | Set blocked hostnames              |
| `whitelist(hostnames)` | Set whitelisted hostnames          |
| `proxy(url)`           | Set SOCKS5 proxy address           |
| `dns(server)`          | Set custom DNS server              |
| `onReady(cb)`          | Callback when server starts        |
| `onError(cb)`          | Callback on errors                 |
| `onExit(cb)`           | Callback when server exits         |
| `onStdout(cb)`         | Callback for stdout data           |
| `onStderr(cb)`         | Callback for stderr data           |
| `getConfig()`          | Get the current config object      |
| `start()`              | Start the server (returns Promise) |

#### Server Methods

| Method           | Description                         |
| ---------------- | ----------------------------------- |
| `stop()`         | Graceful shutdown (returns Promise) |
| `kill(signal?)`  | Force kill with optional signal     |
| `on(event, cb)`  | Add event listener                  |
| `off(event, cb)` | Remove event listener               |
| `running`        | Whether the server is running       |
| `config`         | The resolved configuration          |
| `process`        | The underlying ChildProcess         |

### CLI

```bash
./mrrowisp
```

## Configuration

Copy `example.config.json` to `config.json` and edit as needed:

```json
{
	"port": "6001",
	"disableUDP": false,
	"tcpBufferSize": 65535,
	"bufferRemainingLength": 1024,
	"tcpNoDelay": true,
	"websocketTcpNoDelay": true,
	"blacklist": {
		"hostnames": []
	},
	"whitelist": {
		"hostnames": []
	},
	"proxy": "",
	"websocketPermessageDeflate": false,
	"dnsServer": "",
	"enableTwisp": false,
	"enableV2": true,
	"motd": "",
	"passwordAuth": false,
	"passwordAuthRequired": false,
	"passwordUsers": {},
	"certAuth": false,
	"certAuthRequired": false,
	"certAuthPublicKeys": [],
	"enableStreamConfirm": false
}
```

### Configuration Options

| Option                       | Type     | Description                                   |
| ---------------------------- | -------- | --------------------------------------------- |
| `port`                       | string   | Port to listen on                             |
| `disableUDP`                 | bool     | Disable UDP stream support                    |
| `tcpBufferSize`              | int      | TCP read buffer size                          |
| `bufferRemainingLength`      | uint32   | Flow control buffer threshold                 |
| `tcpNoDelay`                 | bool     | Enable TCP_NODELAY on outbound connections    |
| `websocketTcpNoDelay`        | bool     | Enable TCP_NODELAY on WebSocket connections   |
| `blacklist.hostnames`        | []string | Hostnames to block                            |
| `whitelist.hostnames`        | []string | Hostnames to bypass DNS resolution            |
| `proxy`                      | string   | SOCKS5 proxy address (e.g., `127.0.0.1:1080`) |
| `websocketPermessageDeflate` | bool     | Enable WebSocket compression                  |
| `dnsServer`                  | string   | Custom DNS server (e.g., `8.8.8.8:53`)        |
| `enableTwisp`                | bool     | Enable terminal streams (Unix only)           |
| `enableV2`                   | bool     | Enable Wisp v2 protocol                       |
| `motd`                       | string   | Message of the day sent to v2 clients         |
| `passwordAuth`               | bool     | Enable password authentication                |
| `passwordAuthRequired`       | bool     | Require password authentication               |
| `passwordUsers`              | object   | Username/password map                         |
| `certAuth`                   | bool     | Enable Ed25519 certificate authentication     |
| `certAuthRequired`           | bool     | Require certificate authentication            |
| `certAuthPublicKeys`         | []string | Allowed Ed25519 public keys (hex-encoded)     |
| `enableStreamConfirm`        | bool     | Send confirmation when streams connect        |

### Flood protection & egress

To prevent the server from being abused as a TCP SYN flood relay (see OVH abuse reports the maintainers received), this build adds:

- **SSRF defense:** `allowDirectIP` now refuses CONNECTs to IP-literal hostnames; `allowPrivateIPs` and `allowLoopbackIPs` reject CONNECTs whose resolved IP is in private/loopback/link-local/multicast ranges. The DNS resolution loop walks all returned addresses and picks the first allowed one, so DNS responses can't bypass the policy by interleaving private and public IPs.
- **Per-source / per-destination rate limits:** sliding-window limiters on source IP, destination IP:port (sec + min). Defaults: 50/sec/source, 8/sec/dest, 60/min/dest. Tune via `floodProtection`.
- **In-flight SYN cap:** counting semaphore around outbound TCP dials.
- **SYN-flood signature detector:** per-(WS, dst) ring buffer of dial outcomes. When ≥`minSamples` attempts in `windowMs` exceed `failedHandshakeRatio` failed-handshake fraction, the WS is closed.
- **Reputation store:** persists 0–100 scores per source IP and per destination IP:port to `reputation.storePath` via atomic-rename. Bad behavior (egress violations, SYN signatures, twisp-without-auth, repeated burst-rate hits) raises the score; long-lived successful streams lower it. When a destination's score reaches the strict threshold (default 81) — which happens when many distinct sources hit it — new CONNECTs to that destination are refused. This is the defense against the popular-website-script attack pattern where many residential IPs each look innocent on their own but collectively target one victim.
- **Trusted proxy support:** `parseRealIP: true` plus `trustedProxies` (CIDRs) plus `trustedHeaders` (default: CF-Connecting-IP, X-Forwarded-For). Headers are honored only when the immediate peer is in `trustedProxies`.
- **Twisp now requires auth:** with `enableTwisp: true`, you must also enable `passwordAuth` and the client must pass the v2 auth handshake. Anonymous twisp on v1 is refused. `passwordUsers` may contain bcrypt hashes (prefix `$2a$`/`$2b$`/`$2y$`); plaintext is deprecated and logs a warning on first use.
- **Structured logging:** every block emits a Logger.Warn line — fail2ban-friendly. Example regex: `"flood block".*"ip", "<HOST>"`.

## Credits
 - [soap phia](https://github.com/soap-phia/) - writing most of this
 - [rebecca](https://github.com/rebeccaheartz69/) - greatly helping with implementing wisp v2 and extensions
 - [ObjectAscended](https://github.com/ObjectAscended/) - writing [go-wisp](https://github.com/ObjectAscended/go-wisp/), which this was initially based off of
