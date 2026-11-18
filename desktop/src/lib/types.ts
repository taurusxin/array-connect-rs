export type TlsBackend = "rustls" | "openssl";
export type Profile = {
  id: string;
  name: string;
  server: string;
  username: string;
  authgroup: string;
  savePassword: boolean;
  passwordStored: boolean;
  twoFactor: boolean;
  otpMode: "manual" | "automatic";
  otpSecretStored: boolean;
  otpParameters: { period: number; time_offset_seconds: number | null } | null;
  otpPending: boolean;
  proxyEnabled: boolean;
  proxyScheme: string;
  proxyHost: string;
  proxyPort: number;
  proxyUsername: string;
  proxyPasswordStored: boolean;
  tlsBackend: TlsBackend;
  insecure: boolean;
  caFile: string;
  serverPins: string[];
  opensslCiphers: string;
  resolve: string;
  hostname: string;
  userAgent: string;
  interfaceName: string;
  mtu: number;
  routeMode: "server" | "full" | "none";
  includeRoutes: string[];
  excludeRoutes: string[];
  manageDns: boolean;
  connectTimeout: number;
  reconnectTimeout: number;
  dpd: number | null;
};
export type SecretUpdates = {
  password?: string;
  otpSecret?: string;
  proxyPassword?: string;
};
export type Preferences = {
  theme: "system" | "light" | "dark";
  logLevel: "error" | "warn" | "info" | "debug" | "trace";
  closeBehavior: "ask" | "tray" | "exit";
};
export type CloseChoice = "tray" | "exit";
export type ExitState = "idle" | "choose" | "checking" | "confirm" | "closing";
export type Stats = {
  bytes_sent: number;
  bytes_received: number;
  packets_sent: number;
  packets_received: number;
  reconnects: number;
};
export type NetworkSettings = {
  address: string;
  prefix_len: number;
  mtu: number;
  include_routes: string[];
  exclude_routes: string[];
  dns_servers: string[];
  search_domains: string[];
};
export type LiveSession = {
  profileId: string | null;
  profileName: string | null;
  state: string;
  connectedSeconds: number;
  stats: Stats;
  downloadRate: number;
  uploadRate: number;
  network: NetworkSettings | null;
  error: string | null;
};
export type CredentialRequest = {
  id: string;
  profileId: string;
  needsPassword: boolean;
  needsOtp: boolean;
};
export type LogRecord = {
  id: number;
  timestamp: number;
  level: string;
  target: string;
  message: string;
};
export type HistoryItem = {
  id: string;
  profileName: string;
  server: string;
  startedAt: number;
  endedAt: number | null;
  connectedSeconds: number;
  bytesSent: number;
  bytesReceived: number;
  state: string;
};
export type Usage = {
  bytesSent: number;
  bytesReceived: number;
  connectedSeconds: number;
  sessions: number;
  recent: HistoryItem[];
};
export type NetworkServiceStatus =
  | "unavailable"
  | "notInstalled"
  | "upgradeRequired"
  | "repairRequired"
  | "enabled";
export const networkServiceLabels: Record<NetworkServiceStatus, string> = {
  unavailable: "VPN 网络服务需要 macOS 13 或更新系统，请从应用程序包启动。",
  notInstalled: "首次连接前，请安装 VPN 网络服务。",
  upgradeRequired: "VPN 网络服务与当前客户端版本不匹配，请更新服务。",
  repairRequired: "VPN 网络服务无法连接，请检查后台运行权限或重新安装。",
  enabled: "VPN 网络服务已就绪。",
};
export type Bootstrap = {
  profiles: Profile[];
  preferences: Preferences;
  session: LiveSession;
  credentialRequest: CredentialRequest | null;
  logs: LogRecord[];
  usage: Usage;
  autostart: boolean;
  autostartError: string | null;
  administrator: boolean;
  networkService: NetworkServiceStatus | null;
  wintunAvailable: boolean;
  storagePath: string;
  platform: string;
  version: string;
  trayAvailable: boolean;
  exitState: ExitState;
};
export type RatePoint = { time: number; download: number; upload: number };

export function newProfile(): Profile {
  return {
    id: crypto.randomUUID(),
    name: "",
    server: "",
    username: "",
    authgroup: "",
    savePassword: true,
    passwordStored: false,
    twoFactor: false,
    otpMode: "manual",
    otpSecretStored: false,
    otpParameters: null,
    otpPending: false,
    proxyEnabled: false,
    proxyScheme: "http",
    proxyHost: "127.0.0.1",
    proxyPort: 8080,
    proxyUsername: "",
    proxyPasswordStored: false,
    tlsBackend: "rustls",
    insecure: false,
    caFile: "",
    serverPins: [],
    opensslCiphers: "",
    resolve: "",
    hostname: "",
    userAgent: "",
    interfaceName: "",
    mtu: 1400,
    routeMode: "server",
    includeRoutes: [],
    excludeRoutes: [],
    manageDns: true,
    connectTimeout: 30,
    reconnectTimeout: 300,
    dpd: null,
  };
}
export const emptySession: LiveSession = {
  profileId: null,
  profileName: null,
  state: "Disconnected",
  connectedSeconds: 0,
  stats: {
    bytes_received: 0,
    bytes_sent: 0,
    packets_received: 0,
    packets_sent: 0,
    reconnects: 0,
  },
  downloadRate: 0,
  uploadRate: 0,
  network: null,
  error: null,
};
export const stateLabels: Record<string, string> = {
  Disconnected: "未连接",
  Connecting: "建立连接",
  Authenticating: "正在认证",
  AwaitingPassword: "等待认证",
  Negotiating: "协商配置",
  ConfiguringNetwork: "配置网络",
  Connected: "已连接",
  Reconnecting: "重新连接",
  Disconnecting: "正在断开",
};
