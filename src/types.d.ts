import type { ChildProcess } from "child_process";

export type FloodProtectionConfig = {
	enabled?: boolean;
	maxConnectsPerSourceIPPerSecond?: number;
	maxConnectsPerDestPerSecond?: number;
	maxConnectsPerDestPerMinute?: number;
	maxInFlightSyns?: number;
	maxConcurrentStreamsPerConnection?: number;
	maxConcurrentConnections?: number;
	synFloodSignature?: {
		enabled?: boolean;
		windowMs?: number;
		minSamples?: number;
		failedHandshakeRatio?: number;
	};
	wsCloseAfterViolations?: number;
	logBlockedDials?: boolean;
};

export type ReputationConfig = {
	enabled?: boolean;
	storePath?: string;
	saveIntervalSeconds?: number;
	scoreDecayPerHour?: number;
	evictAfterDays?: number;
	thresholds?: { warn?: number; throttle?: number; strict?: number };
	weights?: Record<string, number>;
	destinationWeights?: Record<string, number>;
};

export type EgressConfig = {
	allowPrivate?: boolean;
	allowIPs?: string[];
	allowCIDRs?: string[];
	denyIPs?: string[];
	denyCIDRs?: string[];
};

export type Config = {
	port?: number;
	disableUDP?: boolean;
	tcpBufferSize?: number;
	bufferRemainingLength?: number;
	tcpNoDelay?: boolean;
	websocketTcpNoDelay?: boolean;
	maxPayloadBytes?: number;
	blacklist?: {
		hostnames: string[];
		ports?: number[];
	};
	whitelist?: {
		hostnames: string[];
		ports?: number[];
	};
	proxy?: string;
	websocketPermessageDeflate?: boolean;
	dnsServers?: string[];
	/** @deprecated use dnsServers */
	dnsServer?: string[];
	enableTwisp?: boolean;
	enableV2: boolean;
	motd?: string;
	passwordAuth?: boolean;
	passwordAuthRequired?: boolean;
	passwordUsers?: {
		[username: string]: string;
	};
	certAuth?: boolean;
	certAuthRequired?: boolean;
	certAuthPublicKeys?: string[];
	enableStreamConfirm?: boolean;
	maxConnectsPerSecond?: number;
	trustedProxies?: string[];
	trustedHeaders?: string[];
	floodProtection?: FloodProtectionConfig;
	reputation?: ReputationConfig;
	egress?: EgressConfig;
};

export type WispEvents = {
	ready: () => void;
	error: (error: Error) => void;
	exit: (code: number | null, signal: NodeJS.Signals | null) => void;
	stdout: (data: string) => void;
	stderr: (data: string) => void;
};

export type WispServer = {
	readonly process: ChildProcess;
	readonly config: Config;
	readonly running: boolean;
	stop(): Promise<void>;
	kill(signal?: NodeJS.Signals): void;
	on<K extends keyof WispEvents>(event: K, listener: WispEvents[K]): WispServer;
	off<K extends keyof WispEvents>(event: K, listener: WispEvents[K]): WispServer;
};

export type WispBuilder = {
	fromFile(path: string): WispBuilder;
	fromJSON(json: string): WispBuilder;
	withConfig(config: Partial<Config>): WispBuilder;
	port(port: number): WispBuilder;
	udp(enabled: boolean): WispBuilder;
	v2(enabled: boolean): WispBuilder;
	twisp(enabled: boolean): WispBuilder;
	motd(message: string): WispBuilder;
	blacklist(hostnames: string[]): WispBuilder;
	whitelist(hostnames: string[]): WispBuilder;
	blacklistPorts(ports: number[]): WispBuilder;
	whitelistPorts(ports: number[]): WispBuilder;
	proxy(url: string): WispBuilder;
	dns(servers: string | string[]): WispBuilder;
	trustedProxies(cidrs: string[]): WispBuilder;
	trustedHeaders(headers: string[]): WispBuilder;
	maxPayloadBytes(bytes: number): WispBuilder;
	floodProtection(cfg: FloodProtectionConfig): WispBuilder;
	reputation(cfg: ReputationConfig): WispBuilder;
	egress(cfg: EgressConfig): WispBuilder;
	route(req: IncomingMessage, socket: Socket, head: Buffer): void;
	onReady(callback: () => void): WispBuilder;
	onError(callback: (error: Error) => void): WispBuilder;
	onExit(callback: (code: number | null, signal: NodeJS.Signals | null) => void): WispBuilder;
	onStdout(callback: (data: string) => void): WispBuilder;
	onStderr(callback: (data: string) => void): WispBuilder;
	getConfig(): Config;
	start(): Promise<WispServer>;
};

export type RouteRequest = {
	(req: IncomingMessage, socket: Socket, head: Buffer): void;
};
