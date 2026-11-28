export type CoreType = 'xray';
export type CoreState = 'uninstalled' | 'installing' | 'stopped' | 'running' | 'error';
export type ProtocolType = 'vless' | 'vmess' | 'trojan' | 'shadowsocks';

export interface User {
  id: number;
  username: string;
}

export interface NodeCore {
  id: number;
  nodeId: number;
  coreType: CoreType;
  installed: boolean;
  installedVersion: string;
  desiredVersion: string;
  state: CoreState;
  errorMsg: string;
  progressPct: number;
  configHash: string;
}

export interface NodeItem {
  id: number;
  name: string;
  publicHost: string;
  remark: string;
  enabled: boolean;
  configDirty: boolean;
  online: boolean;
  lastSeenAt: number;
  agentVersion: string;
  hostname: string;
  os: string;
  arch: string;
  publicIpv4: string;
  publicIpv6: string;
  cpuPercent: number;
  cpuCores: number;
  memUsed: number;
  memTotal: number;
  diskUsed: number;
  diskTotal: number;
  netUpRate: number;
  netDownRate: number;
  netUpTotal: number;
  netDownTotal: number;
  uptime: number;
  cores: NodeCore[];
}

export interface NodeWithEnroll {
  node: NodeItem;
  enrollToken: string;
}

export interface InboundItem {
  id: number;
  nodeId: number;
  nodeName?: string;
  coreType: CoreType;
  tag: string;
  remark: string;
  enable: boolean;
  listen: string;
  port: number;
  protocol: ProtocolType;
  settings: string;
  streamSettings: string;
  sniffing: string;
  up: number;
  down: number;
  clientCount?: number;
}

export interface ClientItem {
  id: number;
  email: string;
  subId: string;
  uuid: string;
  password: string;
  flow: string;
  totalBytes: number;
  up: number;
  down: number;
  expiryTime: number;
  enable: boolean;
  comment: string;
  inboundIds: number[];
}

export interface OverviewStats {
  totalNodes: number;
  onlineNodes: number;
  installedCores: number;
  runningCores: number;
  totalInbounds: number;
  totalClients: number;
  activeClients: number;
  netUpRate: number;
  netDownRate: number;
  totalTrafficUp: number;
  totalTrafficDn: number;
}

export interface SubscriptionBundle {
  client: ClientItem;
  links: string[];
  rawBase64: string;
}

interface APIEnvelope<T> {
  success: boolean;
  msg?: string;
  obj: T;
}

export async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  const body = (await res.json().catch(() => ({}))) as Partial<APIEnvelope<T>>;
  if (res.status === 401 && path !== '/api/auth/login' && path !== '/api/auth/me') {
    window.dispatchEvent(new CustomEvent('mcui:unauthorized'));
  }
  if (!res.ok || !body.success) {
    throw new Error(body.msg || `HTTP ${res.status}`);
  }
  return body.obj as T;
}

export function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let idx = 0;
  let val = bytes;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return `${val.toFixed(idx === 0 ? 0 : 2)} ${units[idx]}`;
}

export function formatSpeed(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

export function formatUptime(sec: number): string {
  if (!sec) return '-';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}
