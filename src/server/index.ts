import { spawn, type ChildProcess } from "child_process";
import * as fs from "fs";
import * as net from "net";
import * as os from "os";
import * as path from "path";
import { WebSocketServer, WebSocket } from "ws";
import { wispConfigPath, wispPath } from "../path.js";
import type {
	Config,
	WispBuilder,
	WispEvents,
	WispServer,
	FloodProtectionConfig,
	ReputationConfig,
	EgressConfig,
} from "../types.js";
import type { IncomingMessage } from "http";

type EventListeners = {
	[E in keyof WispEvents]: Array<WispEvents[E]>;
};

class WispServerImpl implements WispServer {
	readonly process: ChildProcess;
	readonly config: Config;
	private _running: boolean = true;
	private listeners: EventListeners;

	constructor(process: ChildProcess, config: Config, listeners: EventListeners) {
		this.process = process;
		this.config = config;
		this.listeners = listeners;

		this.process.on("exit", (code, signal) => {
			this._running = false;
			this.listeners.exit.forEach((cb) => cb(code, signal));
		});

		this.process.on("error", (err) => {
			this._running = false;
			this.listeners.error.forEach((cb) => cb(err));
		});
	}

	get running(): boolean {
		return this._running;
	}

	stop(): Promise<void> {
		return new Promise((resolve, reject) => {
			if (!this._running) {
				resolve();
				return;
			}

			const timeout = setTimeout(() => {
				this.process.kill("SIGKILL");
			}, 5000);

			this.process.once("exit", () => {
				clearTimeout(timeout);
				resolve();
			});

			this.process.once("error", (err) => {
				clearTimeout(timeout);
				reject(err);
			});

			this.process.kill("SIGTERM");
		});
	}

	kill(signal: NodeJS.Signals = "SIGKILL"): void {
		if (this._running) {
			this.process.kill(signal);
		}
	}

	on<K extends keyof WispEvents>(event: K, listener: WispEvents[K]): WispServer {
		(this.listeners[event] as Array<WispEvents[K]>).push(listener);
		return this;
	}

	off<K extends keyof WispEvents>(event: K, listener: WispEvents[K]): WispServer {
		const arr = this.listeners[event] as Array<WispEvents[K]>;
		const idx = arr.indexOf(listener);
		if (idx !== -1) {
			arr.splice(idx, 1);
		}
		return this;
	}
}

class WispBuilderImpl implements WispBuilder {
	private config: Config;
	private listeners: EventListeners = {
		ready: [],
		error: [],
		exit: [],
		stdout: [],
		stderr: [],
	};
	private wss?: WebSocketServer;

	constructor() {
		this.config = JSON.parse(fs.readFileSync(wispConfigPath, "utf-8"));
	}

	fromFile(filePath: string): WispBuilder {
		const fileConfig = JSON.parse(fs.readFileSync(filePath, "utf-8"));
		this.config = { ...this.config, ...fileConfig };
		return this;
	}

	fromJSON(json: string): WispBuilder {
		const parsed = JSON.parse(json);
		this.config = { ...this.config, ...parsed };
		return this;
	}

	withConfig(config: Partial<Config>): WispBuilder {
		this.config = { ...this.config, ...config };
		return this;
	}

	port(port: number): WispBuilder {
		this.config.port = port;
		return this;
	}

	udp(enabled: boolean): WispBuilder {
		this.config.disableUDP = !enabled;
		return this;
	}

	v2(enabled: boolean): WispBuilder {
		this.config.enableV2 = enabled;
		return this;
	}

	twisp(enabled: boolean): WispBuilder {
		this.config.enableTwisp = enabled;
		return this;
	}

	motd(message: string): WispBuilder {
		this.config.motd = message;
		return this;
	}

	blacklist(hostnames: string[]): WispBuilder {
		this.config.blacklist = { ...this.config.blacklist, hostnames };
		return this;
	}

	whitelist(hostnames: string[]): WispBuilder {
		this.config.whitelist = { ...this.config.whitelist, hostnames };
		return this;
	}

	blacklistPorts(ports: number[]): WispBuilder {
		this.config.blacklist = {
			hostnames: this.config.blacklist?.hostnames ?? [],
			...this.config.blacklist,
			ports,
		};
		return this;
	}

	whitelistPorts(ports: number[]): WispBuilder {
		this.config.whitelist = {
			hostnames: this.config.whitelist?.hostnames ?? [],
			...this.config.whitelist,
			ports,
		};
		return this;
	}

	proxy(url: string): WispBuilder {
		this.config.proxy = url;
		return this;
	}

	dns(servers: string | string[]): WispBuilder {
		this.config.dnsServers = Array.isArray(servers) ? servers : [servers];
		return this;
	}

	trustedProxies(cidrs: string[]): WispBuilder {
		this.config.trustedProxies = cidrs;
		return this;
	}

	trustedHeaders(headers: string[]): WispBuilder {
		this.config.trustedHeaders = headers;
		return this;
	}

	maxPayloadBytes(bytes: number): WispBuilder {
		this.config.maxPayloadBytes = bytes;
		return this;
	}

	floodProtection(cfg: FloodProtectionConfig): WispBuilder {
		this.config.floodProtection = { ...this.config.floodProtection, ...cfg };
		return this;
	}

	reputation(cfg: ReputationConfig): WispBuilder {
		this.config.reputation = { ...this.config.reputation, ...cfg };
		return this;
	}

	egress(cfg: EgressConfig): WispBuilder {
		this.config.egress = { ...this.config.egress, ...cfg };
		return this;
	}

	route(req: IncomingMessage, socket: net.Socket, head: Buffer): void {
		const port = this.config.port ?? 8080;
		if (!this.wss) {
			this.wss = new WebSocketServer({ noServer: true });
		}
		const wss = this.wss;

		wss.handleUpgrade(req, socket, head, (ws: WebSocket) => {
			const client = new WebSocket(`ws://localhost:${port}`);

			client.on("open", () => {
				ws.on("message", (data: Buffer) => {
					if (client.readyState === WebSocket.OPEN) {
						client.send(data);
					}
				});
				ws.on("close", () => client.close());
				ws.on("error", () => client.close());
			});

			client.on("message", (data: Buffer) => {
				if (ws.readyState === ws.OPEN) {
					ws.send(data);
				}
			});

			client.on("close", () => ws.close());
			client.on("error", (err) => ws.close(1011, err.message));
		});

		socket.on("error", () => {
			/* keep wss alive across requests */
		});
	}

	onReady(callback: () => void): WispBuilder {
		this.listeners.ready.push(callback);
		return this;
	}

	onError(callback: (error: Error) => void): WispBuilder {
		this.listeners.error.push(callback);
		return this;
	}

	onExit(callback: (code: number | null, signal: NodeJS.Signals | null) => void): WispBuilder {
		this.listeners.exit.push(callback);
		return this;
	}

	onStdout(callback: (data: string) => void): WispBuilder {
		this.listeners.stdout.push(callback);
		return this;
	}

	onStderr(callback: (data: string) => void): WispBuilder {
		this.listeners.stderr.push(callback);
		return this;
	}

	getConfig(): Config {
		return { ...this.config };
	}

	start(): Promise<WispServer> {
		return new Promise((resolve, reject) => {
			let resolved = false;

			// Write config to a private temp file rather than passing on argv.
			// Passing JSON on argv exposes secrets via /proc/*/cmdline.
			const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mrrowisp-"));
			const cfgPath = path.join(dir, "config.json");
			fs.writeFileSync(cfgPath, JSON.stringify(this.config), { mode: 0o600 });

			const cleanup = () => {
				try {
					fs.rmSync(dir, { recursive: true, force: true });
				} catch {
					/* ignore */
				}
			};

			const child = spawn(wispPath, ["--config", cfgPath]);
			const server = new WispServerImpl(child, this.config, this.listeners);

			child.stdout.on("data", (data: Buffer) => {
				const str = data.toString();
				this.listeners.stdout.forEach((cb) => cb(str));

				if (!resolved && str.includes("Starting Mrrowisp")) {
					resolved = true;
					this.listeners.ready.forEach((cb) => cb());
					resolve(server);
				}
			});

			child.stderr.on("data", (data: Buffer) => {
				const str = data.toString();
				this.listeners.stderr.forEach((cb) => cb(str));
			});

			child.on("error", (err) => {
				cleanup();
				if (!resolved) {
					resolved = true;
					this.listeners.error.forEach((cb) => cb(err));
					reject(err);
				}
			});

			child.on("exit", (code, signal) => {
				cleanup();
				if (!resolved) {
					resolved = true;
					const err = new Error(`Server exited before ready (code: ${code}, signal: ${signal})`);
					this.listeners.error.forEach((cb) => cb(err));
					reject(err);
				}
			});

			setTimeout(() => {
				if (!resolved) {
					resolved = true;
					const err = new Error("Server startup timed out after 10 seconds");
					this.listeners.error.forEach((cb) => cb(err));
					child.kill("SIGKILL");
					cleanup();
					reject(err);
				}
			}, 10000);
		});
	}
}

export function createMrrowisp(): WispBuilder {
	return new WispBuilderImpl();
}
