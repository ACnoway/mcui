export type XraySubscription = {
  schema_version: 1 | 2
  username: string
  address: '127.0.0.1'
  ports: number[]
  http_ports?: number[]
  revision: number
  expires_at: number
}

function validPort(value: number) {
  return Number.isInteger(value) && value >= 1024 && value <= 65535
}

export function validSubscription(value: unknown): value is XraySubscription {
  if (!value || typeof value !== 'object') return false
  const { schema_version, username, address, ports, http_ports, revision, expires_at } = value as XraySubscription
  if (typeof username !== 'string' || !/^[a-z][a-z0-9_-]{0,23}$/.test(username) || address !== '127.0.0.1' ||
    !Array.isArray(ports) || ports.length === 0 || ports.length > 4 ||
    !ports.every((port, index) => validPort(port) && (index === 0 || ports[index - 1] < port)) ||
    !Number.isSafeInteger(revision) || revision <= 0 || !Number.isSafeInteger(expires_at) || expires_at <= 0) return false
  if (schema_version === 1) return http_ports === undefined
  return schema_version === 2 && Array.isArray(http_ports) && http_ports.length > 0 && http_ports.length <= ports.length &&
    http_ports.every((port, index) => ports.includes(port) && (index === 0 || http_ports[index - 1] < port))
}

export function buildXrayClient(subscription: XraySubscription, proxyPort: number, localPort: number, password: string) {
  if (!validSubscription(subscription) || !subscription.ports.includes(proxyPort)) throw new Error('此节点端口未获授权。')
  if (!validPort(localPort) || subscription.ports.includes(localPort)) throw new Error('请选择不同的本地非特权端口。')
  if (!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(password)) throw new Error('请输入节点提供的 43 位 Base64URL 密码。')
  const account = { user: subscription.username, pass: password }
  return {
    log: { loglevel: 'none' },
    inbounds: [{
      listen: '127.0.0.1', port: localPort, protocol: 'socks',
      settings: { auth: 'password', udp: false, users: [account] },
    }],
    outbounds: [{
      protocol: subscription.http_ports?.includes(proxyPort) ? 'http' : 'socks',
      settings: { address: subscription.address, port: proxyPort, ...account },
    }],
  }
}
