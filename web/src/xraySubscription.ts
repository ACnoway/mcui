export type XrayProtocol = 'socks' | 'http' | 'vless' | 'vless-reality' | 'vmess' | 'shadowsocks' | 'trojan'

export const xrayProtocolName: Record<XrayProtocol, string> = {
  socks: 'SOCKS5', http: 'HTTP', vless: 'VLESS', vmess: 'VMess', shadowsocks: 'Shadowsocks 2022', trojan: 'Trojan / TLS',
  'vless-reality': 'VLESS / REALITY',
}

export type XrayPublicEndpoint = { address: string; port: number }
export type VLESSStream = { network: 'ws' | 'grpc' | 'httpupgrade' | 'xhttp'; path?: string; host?: string; service_name?: string; authority?: string; multi_mode?: boolean; mode?: 'auto' | 'packet-up' | 'stream-up' | 'stream-one' }

export type XraySubscription = {
  schema_version: 1 | 2 | 3 | 4 | 5
  username: string
  address: '127.0.0.1'
  ports: number[]
  http_ports?: number[]
  port_protocols?: Record<number, XrayProtocol>
  trojan_trust?: { certificate: string; sha256: string }
  reality_public_key?: string
  public_endpoints?: Record<number, XrayPublicEndpoint>
  vless_streams?: Record<number, VLESSStream>
  revision: number
  expires_at: number
}

function validPort(value: number) {
  return Number.isInteger(value) && value >= 1024 && value <= 65535
}

function validPublishedEndpoint(value: unknown): value is XrayPublicEndpoint {
  if (!value || typeof value !== 'object') return false
  const { address, port } = value as XrayPublicEndpoint
  if (!Number.isInteger(port) || port < 1 || port > 65535 || typeof address !== 'string' ||
    !/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(address)) return false
  const bytes = address.split('.').map(Number)
  const [a, b, c, d] = bytes
  return bytes.every(byte => byte <= 255) && a > 0 && a < 224 && a !== 10 && a !== 127 &&
    !(a === 100 && b >= 64 && b <= 127) && !(a === 168 && b === 63 && c === 129 && d === 16) &&
    !(a === 169 && b === 254) && !(a === 172 && b >= 16 && b <= 31) &&
    !(a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) &&
    !(a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) && !(a === 203 && b === 0 && c === 113)
}

export function validSubscription(value: unknown): value is XraySubscription {
  if (!value || typeof value !== 'object') return false
  const {
    schema_version, username, address, ports, http_ports, port_protocols, trojan_trust, reality_public_key, public_endpoints,
    revision, expires_at, vless_streams,
  } = value as XraySubscription
  if (typeof username !== 'string' || !/^[a-z][a-z0-9_-]{0,23}$/.test(username) || address !== '127.0.0.1' ||
    !Array.isArray(ports) || ports.length === 0 || ports.length > 4 ||
    !ports.every((port, index) => validPort(port) && (index === 0 || ports[index - 1] < port)) ||
    !Number.isSafeInteger(revision) || revision <= 0 || !Number.isSafeInteger(expires_at) || expires_at <= 0) return false
  const typed = schema_version === 3 || schema_version === 4 || schema_version === 5
  if (!typed && (trojan_trust !== undefined || reality_public_key !== undefined)) return false
  if (schema_version !== 4 && schema_version !== 5 && public_endpoints !== undefined) return false
  if (schema_version !== 5 && vless_streams !== undefined) return false
  if (schema_version === 1) return http_ports === undefined && port_protocols === undefined
  if (schema_version === 2) {
    return port_protocols === undefined && Array.isArray(http_ports) && http_ports.length > 0 && http_ports.length <= ports.length &&
      http_ports.every((port, index) => ports.includes(port) && (index === 0 || http_ports[index - 1] < port))
  }
  if (!typed || http_ports !== undefined || !port_protocols || typeof port_protocols !== 'object' || Array.isArray(port_protocols)) return false
  const entries = Object.entries(port_protocols)
  if (schema_version === 4 || (schema_version === 5 && public_endpoints !== undefined)) {
    if (!public_endpoints || typeof public_endpoints !== 'object' || Array.isArray(public_endpoints)) return false
    const published = Object.entries(public_endpoints)
    const seen = new Set<string>()
    if (!published.length || published.some(([key, endpoint]) => {
      const port = Number(key)
      const protocol = port_protocols[port]
      if (String(port) !== key || !ports.includes(port) || (protocol !== 'socks' && protocol !== 'trojan' && protocol !== 'vless-reality' && protocol !== 'vless') ||
        !validPublishedEndpoint(endpoint)) return true
      const address = `${endpoint.address}:${endpoint.port}`
      if (seen.has(address)) return true
      seen.add(address)
      return false
    })) return false
  }
  if (schema_version === 5) {
    if (!vless_streams || typeof vless_streams !== 'object' || Array.isArray(vless_streams)) return false
    const streams = Object.entries(vless_streams)
    if (!streams.length || streams.some(([key, stream]) => {
      const port = Number(key)
      if (String(port) !== key || !ports.includes(port) || port_protocols[port] !== 'vless' || !stream || typeof stream !== 'object') return true
      if (typeof stream.network !== 'string' || !['ws', 'grpc', 'httpupgrade', 'xhttp'].includes(stream.network)) return true
      if (stream.host !== undefined && (typeof stream.host !== 'string' || !/^[A-Za-z0-9.:-]{0,253}$/.test(stream.host))) return true
      if (stream.authority !== undefined && (typeof stream.authority !== 'string' || !/^[A-Za-z0-9.:-]{0,253}$/.test(stream.authority))) return true
      if (stream.multi_mode !== undefined && typeof stream.multi_mode !== 'boolean') return true
      if (stream.service_name !== undefined && (typeof stream.service_name !== 'string' || !/^[A-Za-z0-9_.-]{0,128}$/.test(stream.service_name))) return true
      if (stream.network === 'grpc') return !!stream.path || !!stream.host || !!stream.mode
      return typeof stream.path !== 'string' || !stream.path.startsWith('/') || stream.path.length > 256 || /[\r\n\0]/.test(stream.path) ||
        !!stream.service_name || !!stream.authority || !!stream.multi_mode || (stream.network === 'xhttp' ? !['auto', 'packet-up', 'stream-up', 'stream-one'].includes(stream.mode ?? '') : !!stream.mode)
    })) return false
  }
  if (entries.some(([, protocol]) => protocol === 'trojan')) {
    if (!trojan_trust || typeof trojan_trust.certificate !== 'string' || trojan_trust.certificate.length > 1024 ||
      !/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----$/.test(trojan_trust.certificate.trim()) ||
      typeof trojan_trust.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(trojan_trust.sha256)) return false
  } else if (trojan_trust !== undefined) return false
  if (entries.some(([, protocol]) => protocol === 'vless-reality')) {
    if (typeof reality_public_key !== 'string' || !passwordPattern.test(reality_public_key)) return false
  } else if (reality_public_key !== undefined) return false
  return entries.some(([, protocol]) => protocol !== 'http') && entries.every(([port, protocol]) =>
    String(Number(port)) === port && ports.includes(Number(port)) && ['socks', 'http', 'vless', 'vless-reality', 'vmess', 'shadowsocks', 'trojan'].includes(protocol),
  )
}

export function subscriptionProtocol(subscription: XraySubscription, port: number): XrayProtocol {
  return subscription.port_protocols?.[port] ?? (subscription.http_ports?.includes(port) ? 'http' : 'socks')
}

export function subscriptionEndpoint(subscription: XraySubscription, port: number): XrayPublicEndpoint {
  return subscription.public_endpoints?.[port] ?? { address: subscription.address, port }
}

const passwordPattern = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/
const uuidV4 = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/
const shadowsocksKey = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/

function outboundSettings(subscription: XraySubscription, port: number, protocol: XrayProtocol, credential: string) {
  const { address, port: endpointPort } = subscriptionEndpoint(subscription, port)
  const endpoint = { address, port: endpointPort }
  switch (protocol) {
    case 'vless':
    case 'vmess':
      if (!uuidV4.test(credential)) throw new Error('请输入节点提供的小写 UUIDv4。')
      return protocol === 'vless'
        ? { ...endpoint, id: credential, encryption: 'none' }
        : { ...endpoint, id: credential, security: 'aes-128-gcm' }
    case 'shadowsocks': {
      const keys = credential.split(':')
      if (keys.length !== 2 || !keys.every(key => shadowsocksKey.test(key))) throw new Error('请输入节点提供的服务端密钥和用户密钥，中间用冒号连接。')
      return { ...endpoint, method: '2022-blake3-aes-256-gcm', password: credential }
    }
    case 'trojan':
      if (!passwordPattern.test(credential)) throw new Error('请输入节点提供的 43 位 Trojan 密码。')
      return { ...endpoint, password: credential }
    case 'vless-reality': {
      const parts = credential.split(':')
      if (parts.length !== 2 || !uuidV4.test(parts[0]) || !/^[0-9a-f]{16}$/.test(parts[1]) || parts[1] === '0000000000000000') {
        throw new Error('请输入节点提供的 VLESS UUID 和 REALITY Short ID，中间用冒号连接。')
      }
      return { ...endpoint, id: parts[0], encryption: 'none' }
    }
    default:
      if (!passwordPattern.test(credential)) throw new Error('请输入节点提供的 43 位 Base64URL 密码。')
      return { ...endpoint, user: subscription.username, pass: credential }
  }
}

export function buildXrayClient(subscription: XraySubscription, proxyPort: number, localPort: number, credential: string) {
  if (!validSubscription(subscription) || !subscription.ports.includes(proxyPort)) throw new Error('此节点端口未获授权。')
  if (!validPort(localPort) || subscription.ports.includes(localPort)) throw new Error('请选择不同的本地非特权端口。')
  const protocol = subscriptionProtocol(subscription, proxyPort)
  const settings = outboundSettings(subscription, proxyPort, protocol, credential)
  const account = { user: subscription.username, pass: credential }
  const trust = subscription.trojan_trust
  const vlessStream = subscription.vless_streams?.[proxyPort]
  const streamSettings = vlessStream ? {
    network: vlessStream.network,
    [`${vlessStream.network}Settings`]: vlessStream.network === 'grpc'
      ? { serviceName: vlessStream.service_name ?? '', authority: vlessStream.authority ?? '', multiMode: vlessStream.multi_mode ?? false }
      : { path: vlessStream.path, host: vlessStream.host ?? '', ...(vlessStream.network === 'xhttp' ? { mode: vlessStream.mode } : {}) },
  } : protocol === 'vless-reality' ? {
    network: 'raw', security: 'reality',
    realitySettings: {
      serverName: 'localhost', fingerprint: 'chrome', password: subscription.reality_public_key,
      shortId: credential.split(':')[1],
    },
  } : protocol === 'trojan' && trust ? {
    network: 'raw', security: 'tls',
    tlsSettings: {
      // This fingerprint setting selects Xray's native Go TLS handshake.
      serverName: 'localhost', minVersion: '1.3', fingerprint: 'unsafe', disableSystemRoot: true,
      certificates: [{ usage: 'verify', certificate: [trust.certificate.trim()] }],
    },
  } : undefined
  return {
    log: { loglevel: 'none' },
    inbounds: [{
      listen: '127.0.0.1', port: localPort, protocol: 'socks',
      settings: { auth: 'password', udp: false, users: [account] },
    }],
    outbounds: [{ protocol: protocol === 'vless-reality' ? 'vless' : protocol, settings, ...(streamSettings ? { streamSettings } : {}) }],
  }
}

// Share only the VLESS variants represented by the current subscription schema.
export function buildVlessLink(subscription: XraySubscription, proxyPort: number, credential: string, remark: string) {
  if (!validSubscription(subscription) || !subscription.ports.includes(proxyPort)) throw new Error('此节点端口未获授权。')
  const protocol = subscriptionProtocol(subscription, proxyPort)
  if (protocol !== 'vless' && protocol !== 'vless-reality') throw new Error('此入站不是 VLESS。')
  outboundSettings(subscription, proxyPort, protocol, credential)
  const endpoint = subscriptionEndpoint(subscription, proxyPort)
  const stream = subscription.vless_streams?.[proxyPort]
  const params = new URLSearchParams({ type: stream?.network ?? 'tcp', encryption: 'none', security: protocol === 'vless-reality' ? 'reality' : 'none' })
  if (stream?.path) params.set('path', stream.path)
  if (stream?.host) params.set('host', stream.host)
  if (stream?.service_name) params.set('serviceName', stream.service_name)
  if (stream?.authority) params.set('authority', stream.authority)
  if (stream?.multi_mode) params.set('mode', 'multi')
  if (stream?.mode) params.set('mode', stream.mode)
  if (protocol === 'vless-reality') {
    params.set('sni', 'localhost')
    params.set('fp', 'chrome')
    params.set('pbk', subscription.reality_public_key!)
    params.set('sid', credential.split(':')[1])
  }
  return `vless://${credential.split(':')[0]}@${endpoint.address}:${endpoint.port}?${params.toString()}#${encodeURIComponent(remark)}`
}
