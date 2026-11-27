<script setup lang="ts">
import { computed, ref } from 'vue'
import PanelDialog from './PanelDialog.vue'
import { destinationLabel, type Destination, type Network } from './xrayManagement'
import { buildXrayClient, type VLESSStream, type XraySubscription } from './xraySubscription'

type Protocol = '' | 'http' | 'vless' | 'vmess' | 'trojan'
type Inbound = { port: number; protocol?: string; users: string[]; public_endpoint?: Destination; host_listen?: Destination; tls_cert_sha256?: string; vless_stream?: VLESSStream; vless_flows?: Record<string, 'xtls-rprx-vision'> }
type Client = { username: string; credential: string; flow?: 'xtls-rprx-vision' | '' }
type ClientEdit = Client & { originalUsername?: string }
type TabKey = 'basic' | 'transport' | 'security' | 'clients' | 'routing' | 'review'
const maxInboundClients = 8
const maxNodeClients = 16
export type PanelInboundChange = { remove: true } | {
  protocol: Protocol; clients: Client[]; destination?: Destination; copy_routes_from?: number
  public_endpoint?: Destination; host_listen?: Destination; rotate_tls?: boolean; vless_stream?: VLESSStream; reality_target?: string; reality_names?: string[]; rotate_reality?: boolean
}

const props = defineProps<{
  inbounds: Inbound[]; network: Network | null; busy: boolean
  managedBindings: { port: number; credential: string }[]
  save: (port: number, change: PanelInboundChange) => Promise<void>
  multiClient: boolean; trojan: boolean; publicVless: boolean; hostAvailable: boolean; appliedVerified: boolean
  addresses: string[]; trust?: XraySubscription['trojan_trust']; applied: Inbound[]; revision: number
}>()

const protocols: { value: Protocol; label: string }[] = [
  { value: '', label: 'SOCKS5' }, { value: 'http', label: 'HTTP' },
  { value: 'vless', label: 'VLESS' }, { value: 'vmess', label: 'VMess' },
  { value: 'trojan', label: 'Trojan/TLS' },
]
const activeTab = ref<TabKey>('basic')
const form = ref<{
  port: number; editing: boolean; copyFrom?: number; protocol: Protocol; clients: ClientEdit[]; address: string; targetPort: number
  published: boolean; publicAddress: string; publicPort: number; rotateTLS: boolean
  hostMode: boolean; listenAddress: string; listenPort: number
  transport: VLESSStream['network']; tls: boolean; reality: boolean; realityTarget: string; realityNames: string; rotateReality: boolean
  path: string; host: string; serviceName: string; authority: string; multiMode: boolean; mode: NonNullable<VLESSStream['mode']>
} | null>(null)
const error = ref('')
const validationError = ref('')
const credentialsCopied = ref(false)
const download = ref<{ inbound: Inbound; username: string; revision: number; localPort: number; password: string; error: string } | null>(null)
const duplicate = computed(() => !!form.value && !form.value.editing && props.inbounds.some(inbound => inbound.port === form.value?.port))
const duplicateClient = computed(() => {
  const names = (form.value?.clients ?? []).map(client => client.username).filter(Boolean)
  return new Set(names).size !== names.length
})
const tabs = computed(() => {
  const result: { key: TabKey; label: string }[] = [{ key: 'basic', label: '基本设置' }]
  if (form.value?.protocol === 'vless') result.push({ key: 'transport', label: '传输' }, { key: 'security', label: '安全' })
  else if (form.value?.protocol === 'trojan') result.push({ key: 'security', label: '安全' })
  result.push({ key: 'clients', label: '客户端' }, { key: 'routing', label: '路由' }, { key: 'review', label: '确认' })
  return result
})
const clientLimit = computed(() => {
  const draft = form.value
  if (!draft || !props.multiClient) return 1
  const otherClients = props.inbounds
    .filter(inbound => !draft.editing || inbound.port !== draft.port)
    .reduce((total, inbound) => total + inbound.users.length, 0)
  return Math.max(0, Math.min(maxInboundClients, maxNodeClients - otherClients))
})
const hasCredentials = computed(() => form.value?.clients.some(client => client.credential) ?? false)
function needsCredential(client: Client) {
  const draft = form.value
  const prior = draft && props.inbounds.find(inbound => inbound.port === draft.port)
  return !draft?.editing || !prior || (prior.protocol ?? '') !== draft.protocol || !prior.users.includes(client.username)
}

function protocolLabel(protocol?: string) {
  return protocols.find(option => option.value === (protocol ?? ''))?.label ?? protocol
}

function centrallyBound(port: number, username?: string) {
  return props.managedBindings.some(binding => binding.port === port && (username === undefined || binding.credential === username))
}

function boundClient(port: number, client: ClientEdit) {
  return client.originalUsername !== undefined && centrallyBound(port, client.originalUsername)
}

function targets(port: number) {
  const network = props.network
  return network?.routes.filter(route => route.inbound_port === port)
    .flatMap(route => network.outbounds.find(outbound => outbound.tag === route.outbound_tag)?.destination ?? []) ?? []
}

function open(inbound?: Inbound, copy = false) {
  const configured = inbound ? targets(inbound.port) : []
  const existing = configured.length === 1 ? configured[0] : undefined
  const protocol = protocols.find(option => option.value === inbound?.protocol)?.value ?? ''
  const firstFree = Array.from({ length: 5 }, (_, index) => 1080 + index)
    .find(port => !props.inbounds.some(entry => entry.port === port)) ?? 1080
  form.value = {
    editing: !!inbound && !copy, copyFrom: copy ? inbound?.port : undefined, port: copy ? firstFree : inbound?.port ?? firstFree,
    protocol,
    clients: inbound?.users.map(username => {
      const client: ClientEdit = { username, credential: '', flow: inbound.vless_flows?.[username] ?? '', originalUsername: copy ? undefined : username }
      if (copy) generateCredential(client, protocol)
      return client
    }) ??
      [newClient(protocol)],
    address: existing?.address ?? '', targetPort: existing?.port ?? 443,
    published: !copy && !!inbound?.public_endpoint, publicAddress: inbound?.public_endpoint?.address ?? props.addresses[0] ?? '',
    publicPort: inbound?.public_endpoint?.port ?? 443, rotateTLS: false,
    hostMode: !!props.network?.host || (!props.inbounds.length && props.hostAvailable),
    listenAddress: inbound?.host_listen?.address ?? '0.0.0.0', listenPort: copy ? firstFree : inbound?.host_listen?.port ?? inbound?.port ?? firstFree,
    transport: inbound?.vless_stream?.network ?? 'tcp', path: inbound?.vless_stream?.path ?? '',
    tls: inbound?.vless_stream?.security === 'tls',
    reality: inbound?.vless_stream?.security === 'reality', realityTarget: inbound?.vless_stream?.reality?.target ?? '',
    realityNames: inbound?.vless_stream?.reality?.server_names.join(',') ?? '', rotateReality: false,
    host: inbound?.vless_stream?.host ?? '', serviceName: inbound?.vless_stream?.service_name ?? '', mode: inbound?.vless_stream?.mode ?? 'auto',
    authority: inbound?.vless_stream?.authority ?? '', multiMode: inbound?.vless_stream?.multi_mode ?? false,
  }
  activeTab.value = 'basic'
  error.value = ''
  validationError.value = ''
  credentialsCopied.value = false
}

function randomUsername() {
  return 'u' + crypto.randomUUID().replaceAll('-', '').slice(0, 11)
}

function newClient(protocol: Protocol): ClientEdit {
  const client: ClientEdit = { username: randomUsername(), credential: '', flow: '' }
  generateCredential(client, protocol)
  return client
}

function generateCredential(client: Client, protocol = form.value?.protocol ?? '') {
  if (protocol === 'vless' || protocol === 'vmess') {
    client.credential = crypto.randomUUID()
  } else {
    const bytes = crypto.getRandomValues(new Uint8Array(32))
    client.credential = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
  }
  credentialsCopied.value = false
}

function changeProtocol(protocol: Protocol) {
  const draft = form.value
  if (!draft || draft.protocol === protocol) return
  draft.protocol = protocol
  draft.clients.forEach(client => {
    client.flow = ''
    client.credential = ''
    if (!boundClient(draft.port, client)) generateCredential(client, protocol)
  })
  if (protocol === 'vless') {
    draft.transport = 'tcp'
    draft.tls = false
    draft.reality = false
    draft.realityTarget = ''
    draft.realityNames = ''
    draft.path = ''
    draft.host = ''
    draft.serviceName = ''
    draft.authority = ''
    draft.multiMode = false
    draft.mode = 'auto'
  }
  if (!['', 'trojan', 'vless'].includes(protocol)) draft.published = false
  if (protocol !== 'vless' && protocol !== 'trojan') draft.rotateTLS = false
  if (protocol !== 'vless') draft.rotateReality = false
  activeTab.value = 'basic'
  validationError.value = ''
}

function selectProtocol(event: Event) {
  changeProtocol((event.target as HTMLSelectElement).value as Protocol)
}

function selectTransport(event: Event) {
  changeTransport((event.target as HTMLSelectElement).value as VLESSStream['network'])
}

function changeTransport(network: VLESSStream['network']) {
  const draft = form.value
  if (!draft) return
  draft.transport = network
  if (['ws', 'httpupgrade'].includes(network)) draft.reality = false
  if (network !== 'grpc') {
    draft.serviceName = ''
    draft.authority = ''
    draft.multiMode = false
  }
  if (['ws', 'httpupgrade', 'xhttp'].includes(network)) {
    if (!draft.path) draft.path = '/'
  } else {
    draft.path = ''
    draft.host = ''
  }
  if (network !== 'xhttp') draft.mode = 'auto'
  clearUnavailableFlows()
  validationError.value = ''
}

function clearUnavailableFlows() {
  const draft = form.value
  if (draft && (draft.protocol !== 'vless' || draft.transport !== 'tcp' || (!draft.tls && !draft.reality))) {
    draft.clients.forEach(client => { client.flow = '' })
  }
}

function isIPv4(value: string) {
  const parts = value.split('.')
  return parts.length === 4 && parts.every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)
}

function isPublicIPv4(value: string) {
  if (!isIPv4(value)) return false
  const [a, b, c, d] = value.split('.').map(Number)
  return a > 0 && a < 224 && a !== 10 && a !== 127 &&
    !(a === 100 && b >= 64 && b <= 127) && !(a === 168 && b === 63 && c === 129 && d === 16) &&
    !(a === 169 && b === 254) && !(a === 172 && b >= 16 && b <= 31) &&
    !(a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) &&
    !(a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) && !(a === 203 && b === 0 && c === 113)
}

function isHostAddress(value: string) {
  if (isIPv4(value)) return true
  try {
    return new URL(`http://[${value}]/`).hostname === `[${value}]`
  } catch {
    return false
  }
}

function isPort(value: number, minimum = 1) {
  return Number.isInteger(value) && value >= minimum && value <= 65535
}

function validateForm(): { tab: TabKey; message: string } | null {
  const draft = form.value
  if (!draft) return null
  if (!protocols.some(protocol => protocol.value === draft.protocol) || (draft.protocol === 'trojan' && !props.trojan)) {
    return { tab: 'basic', message: '当前节点不支持所选协议。' }
  }
  if (!isPort(draft.port, 1024)) return { tab: 'basic', message: '监听端口必须是 1024–65535 的整数。' }
  if (duplicate.value) return { tab: 'basic', message: '该监听端口已在草稿中使用。' }
  if (draft.hostMode && (!isHostAddress(draft.listenAddress) || !isPort(draft.listenPort))) {
    return { tab: 'basic', message: '请输入有效的宿主监听 IP 和 1–65535 端口。' }
  }
  if (draft.hostMode && props.inbounds.some(inbound => inbound.port !== (draft.editing ? draft.port : 0) && inbound.host_listen?.port === draft.listenPort)) {
    return { tab: 'basic', message: '宿主监听端口已被其他主控入站占用。' }
  }
  if (draft.published) {
    if (!isPublicIPv4(draft.publicAddress) || !isPort(draft.publicPort)) return { tab: 'basic', message: '公布地址须为公网 IPv4，端口须为 1–65535。' }
    if (!['', 'trojan', 'vless'].includes(draft.protocol)) return { tab: 'basic', message: '当前协议不支持公网发布。' }
    if (draft.protocol === 'vless' && !props.publicVless) return { tab: 'basic', message: '当前节点尚未报告 VLESS 公网入口能力。' }
    if (props.inbounds.some(inbound => inbound.port !== (draft.editing ? draft.port : 0) &&
      inbound.public_endpoint?.address === draft.publicAddress && inbound.public_endpoint?.port === draft.publicPort)) {
      return { tab: 'basic', message: '该公网地址和端口已被其他主控入站使用。' }
    }
  }
  if (draft.protocol === 'vless') {
    if (draft.tls && !props.trojan) return { tab: 'security', message: '当前节点尚未报告主控 TLS 入站能力。' }
    if (!['tcp', 'ws', 'grpc', 'httpupgrade', 'xhttp'].includes(draft.transport)) {
      return { tab: 'transport', message: '请选择支持的 VLESS 传输方式。' }
    }
    if (draft.host.length > 253 || !/^[A-Za-z0-9.:-]*$/.test(draft.host)) {
      return { tab: 'transport', message: 'Host 只能包含字母、数字、点、冒号和连字符，最多 253 个字符。' }
    }
    if (draft.serviceName.length > 128 || !/^[A-Za-z0-9_.-]*$/.test(draft.serviceName)) {
      return { tab: 'transport', message: 'gRPC serviceName 只能包含字母、数字、点、下划线和连字符，最多 128 个字符。' }
    }
    if (draft.authority.length > 253 || !/^[A-Za-z0-9.:-]*$/.test(draft.authority)) {
      return { tab: 'transport', message: 'gRPC authority 只能包含字母、数字、点、冒号和连字符，最多 253 个字符。' }
    }
    if (draft.path.length > 256 || /[\r\n\0]/.test(draft.path)) {
      return { tab: 'transport', message: '传输路径不能包含换行或空字符，最多 256 个字符。' }
    }
    if (draft.reality && (draft.tls || ['ws', 'httpupgrade'].includes(draft.transport))) {
      return { tab: 'security', message: '当前传输组合不支持 REALITY。' }
    }
    if (draft.transport === 'tcp' && (draft.path || draft.host || draft.serviceName || draft.authority || draft.multiMode)) {
      return { tab: 'transport', message: 'RAW TCP 不接受路径、Host 或 gRPC 参数。' }
    }
    if (['ws', 'httpupgrade', 'xhttp'].includes(draft.transport) && (!draft.path.startsWith('/') || draft.path.length > 256)) {
      return { tab: 'transport', message: '传输路径必须以 / 开头且不超过 256 个字符。' }
    }
    if (draft.transport === 'grpc' && (draft.path || draft.host || draft.mode !== 'auto')) {
      return { tab: 'transport', message: 'gRPC 不接受路径、Host 或 XHTTP 模式。' }
    }
    if (draft.transport !== 'grpc' && (draft.serviceName || draft.authority || draft.multiMode)) {
      return { tab: 'transport', message: 'serviceName、authority 和 multiMode 仅用于 gRPC。' }
    }
    if (draft.reality) {
      const names = draft.realityNames.split(',').map(name => name.trim()).filter(Boolean)
      if (!draft.realityTarget.trim() || names.length === 0 || names.length > 16 || new Set(names).size !== names.length) {
        return { tab: 'security', message: 'REALITY 需要握手目标和不重复的服务器名称（最多 16 个）。' }
      }
    }
  }
  if (!draft.clients.length || draft.clients.length > clientLimit.value || duplicateClient.value) {
    return { tab: 'clients', message: `客户端数量须为 1–${clientLimit.value}，且用户名不可重复。` }
  }
  const credentialSet = new Set<string>()
  for (const client of draft.clients) {
    if (!/^[a-z][a-z0-9_-]{0,23}$/.test(client.username)) {
      return { tab: 'clients', message: '用户名须以小写字母开头，最多 24 位，只能包含小写字母、数字、_ 和 -。' }
    }
    if (needsCredential(client)) {
      const valid = draft.protocol === 'vless' || draft.protocol === 'vmess'
        ? /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(client.credential)
        : /^[A-Za-z0-9_-]{43}$/.test(client.credential)
      if (!valid) return { tab: 'clients', message: `请为 ${client.username} 填写有效凭据，或使用安全随机生成。` }
    }
    if (client.flow && !(draft.protocol === 'vless' && draft.transport === 'tcp' && (draft.tls || draft.reality))) {
      return { tab: 'clients', message: 'xtls-rprx-vision 仅支持 RAW TCP + TLS 或 REALITY。' }
    }
    if (client.credential && credentialSet.has(client.credential)) return { tab: 'clients', message: '客户端凭据不能重复。' }
    if (client.credential) credentialSet.add(client.credential)
  }
  const routeEditable = !draft.editing || targets(draft.port).length <= 1
  if (!draft.copyFrom && routeEditable && draft.address && (!isPublicIPv4(draft.address) || !isPort(draft.targetPort))) {
    return { tab: 'routing', message: '目标须为公网 IPv4 地址和有效 TCP 端口。' }
  }
  return null
}

async function copyCredentials() {
  const draft = form.value
  if (!draft) return
  const clients = draft.clients.filter(client => client.credential)
  if (!clients.length) {
    error.value = '此入站未提供明文凭据；留空的客户端会保留节点中已有的凭据。'
    return
  }
  const rows = clients.map(client => [client.username, client.credential, client.flow ?? ''].join('\t'))
  try {
    await navigator.clipboard.writeText(['用户名\t凭据\tFlow', ...rows].join('\n'))
    credentialsCopied.value = true
    error.value = ''
  } catch {
    error.value = '无法访问剪贴板，请手动复制客户端凭据。'
  }
}

function moveTab(direction: -1 | 1) {
  const current = tabs.value.findIndex(tab => tab.key === activeTab.value)
  const next = Math.max(0, Math.min(tabs.value.length - 1, current + direction))
  if (direction > 0 && next === current) {
    void submit()
    return
  }
  activeTab.value = tabs.value[next].key
}

async function submit() {
  const draft = form.value
  if (!draft || props.busy) return
  error.value = ''
  const issue = validateForm()
  if (issue) {
    activeTab.value = issue.tab
    validationError.value = issue.message
    return
  }
  validationError.value = ''
  try {
    await props.save(draft.port, {
      protocol: draft.protocol, clients: draft.clients.map(({ username, credential, flow }) => ({ username, credential,
        flow: draft.protocol === 'vless' && draft.transport === 'tcp' && (draft.tls || draft.reality) && flow ? flow : undefined })),
      destination: !draft.copyFrom && draft.address && targets(draft.port).length <= 1 ? { address: draft.address, port: draft.targetPort } : undefined,
      copy_routes_from: draft.copyFrom,
      public_endpoint: (draft.protocol === '' || draft.protocol === 'trojan' || draft.protocol === 'vless') && draft.published ? { address: draft.publicAddress, port: draft.publicPort } : undefined,
      host_listen: draft.hostMode ? { address: draft.listenAddress, port: draft.listenPort } : undefined,
      rotate_tls: (draft.protocol === 'trojan' || (draft.protocol === 'vless' && draft.tls)) && draft.rotateTLS ? true : undefined,
      vless_stream: draft.protocol !== 'vless' || (draft.transport === 'tcp' && !draft.tls && !draft.reality) ? undefined : draft.transport === 'tcp'
        ? { network: 'tcp', security: draft.reality ? 'reality' : 'tls' }
        : draft.transport === 'grpc'
          ? { network: 'grpc', security: draft.reality ? 'reality' : draft.tls ? 'tls' : undefined, service_name: draft.serviceName || undefined, authority: draft.authority || undefined, multi_mode: draft.multiMode || undefined }
          : { network: draft.transport, security: draft.reality ? 'reality' : draft.tls ? 'tls' : undefined, path: draft.path, host: draft.host || undefined, ...(draft.transport === 'xhttp' ? { mode: draft.mode } : {}) },
      reality_target: draft.protocol === 'vless' && draft.reality ? draft.realityTarget : undefined,
      reality_names: draft.protocol === 'vless' && draft.reality ? draft.realityNames.split(',').map(name => name.trim()).filter(Boolean) : undefined,
      rotate_reality: draft.protocol === 'vless' && draft.reality && draft.rotateReality ? true : undefined,
    })
    form.value = null
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : '保存入站失败'
  }
}

function downloadFile(contents: string, type: string, filename: string) {
  const url = URL.createObjectURL(new Blob([contents], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function appliedPublic(port: number) {
  if (!props.appliedVerified) return undefined
  return props.applied.find(entry => entry.port === port && entry.public_endpoint &&
    (!entry.protocol || (entry.protocol === 'vless' && (entry.vless_stream?.security !== 'tls' || (props.trust && entry.tls_cert_sha256 === props.trust.sha256))) ||
      (entry.protocol === 'trojan' && props.trust && entry.tls_cert_sha256 === props.trust.sha256)))
}

function openDownload(port: number) {
  const inbound = appliedPublic(port)
  if (inbound) download.value = { inbound, username: inbound.users[0], revision: props.revision, localPort: port === 10808 ? 10809 : 10808, password: '', error: '' }
}

function downloadClient() {
  const dialog = download.value
  if (!dialog) return
  const { inbound, username, localPort, password } = dialog
  const active = appliedPublic(inbound.port)
  if (!active?.public_endpoint || dialog.revision !== props.revision || !active.users.includes(username) ||
      active.protocol !== inbound.protocol ||
      destinationLabel(active.public_endpoint) !== destinationLabel(inbound.public_endpoint!) ||
      active.tls_cert_sha256 !== inbound.tls_cert_sha256 || JSON.stringify(active.vless_stream) !== JSON.stringify(inbound.vless_stream) ||
      active.vless_flows?.[username] !== inbound.vless_flows?.[username]) {
    dialog.error = '生效入站已变化，请重新打开客户端配置。'
    return
  }
  try {
    const metadata: XraySubscription = {
      schema_version: active.vless_stream ? 5 : 4, username, address: '127.0.0.1', ports: [active.port],
      port_protocols: { [active.port]: active.protocol === '' ? 'socks' : active.protocol === 'trojan' ? 'trojan' : 'vless' },
      public_endpoints: { [active.port]: active.public_endpoint },
      ...(active.protocol === 'trojan' || active.vless_stream?.security === 'tls' ? { trojan_trust: props.trust } : {}),
      ...(active.vless_stream ? { vless_streams: { [active.port]: active.vless_stream } } : {}),
      ...(active.vless_flows?.[username] ? { vless_flows: { [active.port]: active.vless_flows[username] } } : {}),
      revision: props.revision, expires_at: Math.floor(Date.now() / 1000) + 60,
    }
    const config = buildXrayClient(metadata, active.port, localPort, password)
    downloadFile(JSON.stringify(config, null, 2), 'application/json', 'xray-client.json')
    download.value = null
  } catch (cause) {
    dialog.error = cause instanceof Error ? cause.message : '生成客户端配置失败'
  }
}

async function remove(port: number) {
  if (props.busy || !confirm(`从草稿删除入站 ${port}？`)) return
  error.value = ''
  try {
    await props.save(port, { remove: true })
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : '删除入站失败'
  }
}
</script>

<template>
  <div class="actions">
    <button type="button" :disabled="busy || inbounds.length >= 4" @click="open()">添加入站</button>
    <button v-if="trust" type="button" class="outline" @click="downloadFile(trust.certificate, 'application/x-pem-file', 'xray-trojan.crt')">下载生效的 TLS 证书</button>
  </div>
  <p v-if="error && !form" class="notice" role="alert">{{ error }}</p>
  <div v-if="inbounds.length" class="table-wrap">
    <table class="data-table" aria-label="主控入站草稿">
      <thead><tr><th scope="col">监听</th><th scope="col">协议</th><th scope="col">客户端</th><th scope="col">出站</th><th scope="col">操作</th></tr></thead>
      <tbody><tr v-for="inbound in inbounds" :key="inbound.port">
        <th scope="row">{{ inbound.host_listen ? destinationLabel(inbound.host_listen) : inbound.public_endpoint ? destinationLabel(inbound.public_endpoint) : `127.0.0.1:${inbound.port}` }}</th>
        <td>{{ protocolLabel(inbound.protocol) }}</td>
        <td>{{ inbound.users.join('、') }}<template v-if="centrallyBound(inbound.port)"> · 已在「客户端」绑定</template></td>
        <td>{{ !inbound.protocol || inbound.protocol === 'vless' ? `${targets(inbound.port).map(destinationLabel).join('、')}${targets(inbound.port).length ? '，其余' : ''}直连公网（内网目标拒绝）` : targets(inbound.port).map(destinationLabel).join('、') || '拒绝全部' }}</td>
        <td><div class="actions">
          <button type="button" class="outline" :disabled="busy" @click="open(inbound)">编辑</button>
          <button type="button" class="outline" :disabled="busy || inbounds.length >= 4" @click="open(inbound, true)">复制</button>
          <button v-if="!centrallyBound(inbound.port)" type="button" class="quiet" :disabled="busy" @click="remove(inbound.port)">删除</button>
          <button v-if="appliedPublic(inbound.port)" type="button" class="outline" @click="openDownload(inbound.port)">客户端配置</button>
        </div></td>
      </tr></tbody>
    </table>
  </div>
  <p v-else class="empty">暂无入站。</p>

  <PanelDialog v-if="form" :title="form.editing ? `编辑入站 · ${form.port}` : form.copyFrom ? `复制入站 · ${form.copyFrom}` : '添加入站'" @close="form = null">
    <form class="inbound-form" novalidate @input="validationError = ''" @change="validationError = ''" @submit.prevent="activeTab === 'review' ? submit() : moveTab(1)">
      <nav class="tabs inbound-tabs" role="tablist" aria-label="入站设置步骤">
        <button v-for="tab in tabs" :key="tab.key" type="button" role="tab" :aria-selected="activeTab === tab.key"
          :aria-pressed="activeTab === tab.key" @click="activeTab = tab.key">{{ tab.label }}</button>
      </nav>

      <section v-if="activeTab === 'basic'" role="tabpanel" aria-label="基本设置" class="inbound-tab-panel">
      <label>协议 <select :value="form.protocol" :disabled="form.editing && centrallyBound(form.port)" @change="selectProtocol">
        <option v-for="protocol in protocols.filter(option => trojan || option.value !== 'trojan')" :key="protocol.value" :value="protocol.value">{{ protocol.label }}</option>
      </select></label>
      <label>监听端口 <input v-model.number="form.port" type="number" min="1024" max="65535" :disabled="form.editing" /></label>
      <p v-if="form.editing">端口作为此入站的稳定标识，编辑时不能修改。若需更换端口，请复制入站并检查客户端绑定。</p>
      <template v-if="hostAvailable || form.hostMode">
        <label><input v-model="form.hostMode" type="checkbox" :disabled="inbounds.length > (form.editing ? 1 : 0)" /> 宿主网络直监听</label>
        <p v-if="form.hostMode" class="feedback">Xray 将直接监听宿主 IP。该节点所有主控入站必须使用相同网络模式。</p>
        <template v-if="form.hostMode">
          <label>监听 IP <input v-model.trim="form.listenAddress" placeholder="0.0.0.0、:: 或节点 IP" /></label>
          <label>监听端口 <input v-model.number="form.listenPort" type="number" min="1" max="65535" /></label>
        </template>
      </template>
      <template v-if="form.protocol === '' || form.protocol === 'trojan' || (form.protocol === 'vless' && (publicVless || form.published))">
        <label><input v-model="form.published" type="checkbox" :disabled="!form.hostMode && !addresses.length && !form.published" /> {{ form.hostMode ? '设置订阅公布地址' : '启用公网 TCP 接入' }}</label>
        <p v-if="form.protocol === 'vless' && form.published && !form.tls && !form.reality" class="feedback">此 VLESS 入口不提供传输加密，请在可信网络或受保护的传输通道中使用。</p>
        <p v-if="form.protocol === '' && form.published" class="feedback">公网 SOCKS5 使用明文 TCP，账号、密码和代理流量都可被链路观察。</p>
        <p v-if="!form.hostMode && !addresses.length" class="feedback">节点暂未上报可绑定的公网 IPv4。</p>
        <template v-if="form.published">
          <label v-if="form.hostMode">公布公网 IPv4 <input v-model.trim="form.publicAddress" inputmode="decimal" placeholder="填写实际公网 IPv4" /></label>
          <label v-else>宿主公网 IPv4 <select v-model="form.publicAddress">
            <option v-if="!addresses.includes(form.publicAddress)" value="" disabled>请选择节点上报的地址</option>
            <option v-for="address in addresses" :key="address" :value="address">{{ address }}</option>
          </select></label>
          <label>公网 TCP 端口 <input v-model.number="form.publicPort" type="number" min="1" max="65535" /></label>
        </template>
      </template>
      <p v-if="form.protocol === ''">SOCKS5 使用受保护的公网直连出站；节点策略会拒绝回环、私网、链路本地和元数据目标。</p>
      <p v-if="form.protocol === 'http' || form.protocol === 'vmess'" class="feedback">此协议当前使用节点隔离网络中的 RAW TCP 入站，不开放宿主直连和公网中继。</p>
      </section>

      <section v-else-if="activeTab === 'transport'" role="tabpanel" aria-label="传输设置" class="inbound-tab-panel">
        <template v-if="form.protocol === 'vless'">
          <label>传输方式 <select :value="form.transport" @change="selectTransport">
          <option value="tcp">RAW / TCP</option><option value="ws">WebSocket</option><option value="grpc">gRPC</option>
          <option value="httpupgrade">HTTPUpgrade</option><option value="xhttp">XHTTP</option>
        </select></label>
          <template v-if="form.transport === 'grpc'">
          <label>gRPC serviceName <input v-model="form.serviceName" maxlength="128" pattern="[A-Za-z0-9_.\-]*" /></label>
          <label>gRPC authority <input v-model="form.authority" maxlength="253" pattern="[A-Za-z0-9.\-:]*" /></label>
          <label><input v-model="form.multiMode" type="checkbox" /> gRPC multiMode</label>
        </template>
        <template v-else-if="form.transport !== 'tcp'">
          <label>路径 <input v-model="form.path" maxlength="256" pattern="/.*" /></label>
          <label>Host <input v-model="form.host" maxlength="253" pattern="[A-Za-z0-9.\-:]*" /></label>
          <label v-if="form.transport === 'xhttp'">XHTTP 模式 <select v-model="form.mode">
            <option value="auto">auto</option><option value="packet-up">packet-up</option><option value="stream-up">stream-up</option><option value="stream-one">stream-one</option>
          </select></label>
        </template>
          <p v-if="form.transport === 'tcp'" class="feedback">RAW TCP 不需要额外传输字段。安全选项可单独启用 TLS 或 REALITY。</p>
        </template>
        <p v-else>当前协议使用 Xray 默认 RAW TCP 传输。</p>
      </section>

      <section v-else-if="activeTab === 'security'" role="tabpanel" aria-label="安全设置" class="inbound-tab-panel">
        <template v-if="form.protocol === 'vless'">
          <label><input v-model="form.tls" type="checkbox" :disabled="(!trojan && !form.tls) || form.reality" @change="clearUnavailableFlows" /> 启用 TLS</label>
          <p v-if="form.tls" class="feedback">使用本节点共用的自动生成证书；客户端通过证书指纹验证。</p>
          <label><input v-model="form.reality" type="checkbox" :disabled="form.tls || ['ws', 'httpupgrade'].includes(form.transport)" @change="clearUnavailableFlows" /> 启用 REALITY</label>
          <template v-if="form.reality">
            <label>握手目标 <input v-model.trim="form.realityTarget" placeholder="www.example.com:443 或公网 IPv4:端口" /></label>
            <label>服务端名称（逗号分隔） <input v-model.trim="form.realityNames" placeholder="www.example.com" /></label>
            <label v-if="form.editing"><input v-model="form.rotateReality" type="checkbox" /> 重新生成 REALITY 密钥和 Short ID</label>
          </template>
          <label v-if="form.tls && inbounds.some(entry => entry.tls_cert_sha256)"><input v-model="form.rotateTLS" type="checkbox" /> 轮换节点共用 TLS 证书</label>
          <p v-if="!form.tls && !form.reality" class="feedback">此入站不启用传输加密。账号凭据仍在主控和节点间加密传递。</p>
        </template>
        <template v-else-if="form.protocol === 'trojan'">
          <p class="feedback">Trojan 始终使用本节点共用的自动生成 TLS 证书，客户端通过证书指纹验证。</p>
          <label v-if="inbounds.some(entry => entry.tls_cert_sha256)"><input v-model="form.rotateTLS" type="checkbox" /> 轮换节点共用 TLS 证书</label>
        </template>
        <p v-else>SOCKS5、HTTP 和 VMess 按当前受控配置使用 Xray 默认传输安全设置。</p>
      </section>

      <section v-else-if="activeTab === 'clients'" role="tabpanel" aria-label="客户端设置" class="inbound-tab-panel">
      <p>每个客户端使用独立用户名和凭据。新增时自动生成安全随机凭据；编辑时留空可保留原凭据。</p>
      <fieldset v-for="(client, index) in form.clients" :key="index">
        <legend>客户端 {{ index + 1 }}</legend>
        <label>用户名 <input v-model="client.username" pattern="[a-z][a-z0-9_\-]{0,23}" autocomplete="off"
          :disabled="boundClient(form.port, client)" /></label>
        <template v-if="!boundClient(form.port, client)">
          <label>{{ form.protocol === 'vless' || form.protocol === 'vmess' ? 'UUID' : '密码' }}
            <input v-model="client.credential" autocomplete="off" :placeholder="needsCredential(client) ? '安全随机生成，可手动替换' : '留空保留原凭据'" />
          </label>
          <div class="actions">
            <button type="button" class="outline" :disabled="busy" @click="generateCredential(client)">生成凭据</button>
            <button v-if="form.clients.length > 1" type="button" class="quiet" :disabled="busy" @click="form.clients.splice(index, 1); credentialsCopied = false">移除此客户端</button>
          </div>
        </template>
        <p v-else class="feedback">在「客户端」中解除绑定或轮换凭据。</p>
        <label v-if="form.protocol === 'vless' && form.transport === 'tcp' && (form.tls || form.reality)">Flow
          <select v-model="client.flow"><option value="">无</option><option value="xtls-rprx-vision">xtls-rprx-vision</option></select>
        </label>
      </fieldset>
      <p>此节点剩余授权容量：{{ clientLimit }} 个客户端（单入站最多 {{ maxInboundClients }} 个，单节点最多 {{ maxNodeClients }} 个）。</p>
      <div class="actions">
        <button type="button" class="outline" :disabled="busy || form.clients.length >= clientLimit" @click="form.clients.push(newClient(form.protocol))">添加客户端</button>
        <button type="button" class="quiet" :disabled="busy || !hasCredentials" @click="copyCredentials">{{ credentialsCopied ? '凭据已复制' : '复制全部客户端凭据' }}</button>
      </div>
      </section>

      <section v-else-if="activeTab === 'routing'" role="tabpanel" aria-label="路由设置" class="inbound-tab-panel">
        <p v-if="form.copyFrom">复制源入站的路由：{{ form.copyFrom }}。可稍后在「路由」页调整。</p>
        <p v-else-if="form.editing && targets(form.port).length > 1">此入站有多条放行规则。请在「路由」页编辑目标和顺序。</p>
        <template v-else>
          <label>允许的目标 IPv4 <input v-model.trim="form.address" inputmode="decimal" :placeholder="form.protocol === 'vless' ? '留空使用受保护的公网直连' : '留空拒绝全部'" /></label>
          <label>目标 TCP 端口 <input v-model.number="form.targetPort" type="number" min="1" max="65535" :disabled="!form.address" /></label>
          <p v-if="form.protocol === 'vless'" class="feedback">未匹配固定目标的连接走受保护的公网直连；节点策略会拒绝回环、私网、链路本地和元数据地址。</p>
          <p v-else class="feedback">留空时默认拒绝全部出站。固定目标仅接受公网 IPv4 和 TCP 端口。</p>
        </template>
      </section>

      <section v-else role="tabpanel" aria-label="确认入站设置" class="inbound-tab-panel">
        <h3>入站摘要</h3>
        <dl class="inbound-summary">
          <div><dt>协议和监听端口</dt><dd>{{ protocolLabel(form.protocol) }} · {{ form.port }}</dd></div>
          <div><dt>实际监听</dt><dd>{{ form.hostMode ? `${form.listenAddress}:${form.listenPort}` : `隔离网络回环 · ${form.port}` }}</dd></div>
          <div><dt>传输和安全</dt><dd>{{ form.protocol === 'vless' ? `${form.transport.toUpperCase()} · ${form.reality ? 'REALITY' : form.tls ? 'TLS' : '无传输加密'}` : form.protocol === 'trojan' ? 'RAW TCP · TLS' : 'Xray 默认 RAW TCP' }}</dd></div>
          <div><dt>公网公布地址</dt><dd>{{ form.published ? `${form.publicAddress}:${form.publicPort}` : '未启用' }}</dd></div>
          <div><dt>客户端</dt><dd>{{ form.clients.length }} 个：{{ form.clients.map(client => client.username).join('、') }}</dd></div>
          <div><dt>路由</dt><dd>{{ form.copyFrom ? `复制入站 ${form.copyFrom}` : form.address ? `${form.address}:${form.targetPort}` : form.protocol === 'vless' || form.protocol === '' ? '受保护的公网直连' : '默认拒绝全部' }}</dd></div>
        </dl>
        <p class="notice">凭据仅在此创建流程中显示。请先复制客户端信息，再保存草稿。保存后仍须在节点配置页预览、批准并下发，入站才会生效。</p>
        <div class="actions"><button type="button" class="outline" :disabled="busy" @click="copyCredentials">{{ credentialsCopied ? '客户端凭据已复制' : '复制客户端凭据' }}</button></div>
      </section>

      <p v-if="validationError" class="notice" role="alert">{{ validationError }}</p>
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
      <div class="actions inbound-form-actions">
        <button type="button" class="quiet" :disabled="busy || activeTab === tabs[0].key" @click="moveTab(-1)">上一步</button>
        <button type="submit" :disabled="busy">{{ activeTab === 'review' ? (busy ? '保存中…' : '保存入站草稿') : '下一步' }}</button>
      </div>
    </form>
  </PanelDialog>

  <PanelDialog v-if="download" title="下载生效的客户端配置" @close="download = null">
    <form @submit.prevent="downloadClient">
      <p>{{ destinationLabel(download.inbound.public_endpoint!) }}</p>
      <label>客户端 <select v-model="download.username" @change="download.password = ''">
        <option v-for="user in download.inbound.users" :key="user" :value="user">{{ user }}</option>
      </select></label>
      <label>{{ download.inbound.protocol === 'vless' ? '客户端 UUID' : '客户端密码' }} <input v-model="download.password" type="password" autocomplete="off" required /></label>
      <label>本地 SOCKS5 端口 <input v-model.number="download.localPort" type="number" min="1024" max="65535" required /></label>
      <p v-if="download.error" class="notice" role="alert">{{ download.error }}</p>
      <div class="actions"><button type="submit">下载 Xray 配置</button></div>
    </form>
  </PanelDialog>
</template>
