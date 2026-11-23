export type XrayProtocol = 'socks' | 'http' | 'vless' | 'vmess' | 'shadowsocks' | 'trojan'

export const xrayProtocolName: Record<XrayProtocol, string> = {
  socks: 'SOCKS5', http: 'HTTP', vless: 'VLESS', vmess: 'VMess', shadowsocks: 'Shadowsocks 2022', trojan: 'Trojan / TLS',
}

export type XraySubscription = {
  schema_version: 1 | 2 | 3
  username: string
  address: '127.0.0.1'
  ports: number[]
  http_ports?: number[]
  port_protocols?: Record<number, Exclude<XrayProtocol, 'socks'>>
  trojan_trust?: { certificate: string; sha256: string }
  revision: number
  expires_at: number
}

function validPort(value: number) {
  return Number.isInteger(value) && value >= 1024 && value <= 65535
}

export function validSubscription(value: unknown): value is XraySubscription {
  if (!value || typeof value !== 'object') return false
  const { schema_version, username, address, ports, http_ports, port_protocols, trojan_trust, revision, expires_at } = value as XraySubscription
  if (typeof username !== 'string' || !/^[a-z][a-z0-9_-]{0,23}$/.test(username) || address !== '127.0.0.1' ||
    !Array.isArray(ports) || ports.length === 0 || ports.length > 4 ||
    !ports.every((port, index) => validPort(port) && (index === 0 || ports[index - 1] < port)) ||
    !Number.isSafeInteger(revision) || revision <= 0 || !Number.isSafeInteger(expires_at) || expires_at <= 0) return false
  if (schema_version === 1) return http_ports === undefined && port_protocols === undefined && trojan_trust === undefined
  if (schema_version === 2) {
    return port_protocols === undefined && trojan_trust === undefined && Array.isArray(http_ports) && http_ports.length > 0 && http_ports.length <= ports.length &&
      http_ports.every((port, index) => ports.includes(port) && (index === 0 || http_ports[index - 1] < port))
  }
  if (schema_version !== 3 || http_ports !== undefined || !port_protocols || typeof port_protocols !== 'object' || Array.isArray(port_protocols)) return false
  const entries = Object.entries(port_protocols)
  if (entries.some(([, protocol]) => protocol === 'trojan')) {
    if (!trojan_trust || typeof trojan_trust.certificate !== 'string' || trojan_trust.certificate.length > 1024 ||
      !/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----$/.test(trojan_trust.certificate.trim()) ||
      typeof trojan_trust.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(trojan_trust.sha256)) return false
  } else if (trojan_trust !== undefined) return false
  return entries.some(([, protocol]) => protocol !== 'http') && entries.every(([port, protocol]) =>
    String(Number(port)) === port && ports.includes(Number(port)) && ['http', 'vless', 'vmess', 'shadowsocks', 'trojan'].includes(protocol),
  )
}

export function subscriptionProtocol(subscription: XraySubscription, port: number): XrayProtocol {
  return subscription.port_protocols?.[port] ?? (subscription.http_ports?.includes(port) ? 'http' : 'socks')
}

const passwordPattern = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/
const uuidV4 = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/
const shadowsocksKey = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/

function outboundSettings(subscription: XraySubscription, port: number, protocol: XrayProtocol, credential: string) {
  const endpoint = { address: subscription.address, port }
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
  const streamSettings = protocol === 'trojan' && trust ? {
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
    outbounds: [{ protocol, settings, ...(streamSettings ? { streamSettings } : {}) }],
  }
}
