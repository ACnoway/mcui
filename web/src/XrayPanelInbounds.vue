<script setup lang="ts">
import { computed, ref } from 'vue'
import PanelDialog from './PanelDialog.vue'
import { destinationLabel, type Destination, type Network } from './xrayManagement'
import { buildXrayClient, type VLESSStream, type XraySubscription } from './xraySubscription'

type Protocol = '' | 'http' | 'vless' | 'vmess' | 'trojan'
type Inbound = { port: number; protocol?: string; users: string[]; public_endpoint?: Destination; tls_cert_sha256?: string; vless_stream?: VLESSStream; vless_flows?: Record<string, 'xtls-rprx-vision'> }
type Client = { username: string; credential: string; flow?: 'xtls-rprx-vision' | '' }
type ClientEdit = Client & { originalUsername?: string }
export type PanelInboundChange = { remove: true } | {
  protocol: Protocol; clients: Client[]; destination?: Destination; copy_routes_from?: number
  public_endpoint?: Destination; rotate_tls?: boolean; vless_stream?: VLESSStream
}

const props = defineProps<{
  inbounds: Inbound[]; network: Network | null; busy: boolean
  managedBindings: { port: number; credential: string }[]
  save: (port: number, change: PanelInboundChange) => Promise<void>
  multiClient: boolean; trojan: boolean; publicVless: boolean; appliedVerified: boolean
  addresses: string[]; trust?: XraySubscription['trojan_trust']; applied: Inbound[]; revision: number
}>()

const protocols: { value: Protocol; label: string }[] = [
  { value: '', label: 'SOCKS5' }, { value: 'http', label: 'HTTP' },
  { value: 'vless', label: 'VLESS' }, { value: 'vmess', label: 'VMess' },
  { value: 'trojan', label: 'Trojan/TLS' },
]
const form = ref<{
  port: number; editing: boolean; copyFrom?: number; protocol: Protocol; clients: ClientEdit[]; address: string; targetPort: number
  published: boolean; publicAddress: string; publicPort: number; rotateTLS: boolean
  transport: VLESSStream['network']; tls: boolean; path: string; host: string; serviceName: string; authority: string; multiMode: boolean; mode: NonNullable<VLESSStream['mode']>
} | null>(null)
const error = ref('')
const download = ref<{ inbound: Inbound; username: string; revision: number; localPort: number; password: string; error: string } | null>(null)
const duplicate = computed(() => !!form.value && !form.value.editing && props.inbounds.some(inbound => inbound.port === form.value?.port))
const duplicateClient = computed(() => {
  const names = (form.value?.clients ?? []).map(client => client.username).filter(Boolean)
  return new Set(names).size !== names.length
})
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
  const firstFree = Array.from({ length: 5 }, (_, index) => 1080 + index)
    .find(port => !props.inbounds.some(entry => entry.port === port)) ?? 1080
  form.value = {
    editing: !!inbound && !copy, copyFrom: copy ? inbound?.port : undefined, port: copy ? firstFree : inbound?.port ?? firstFree,
    protocol: protocols.find(option => option.value === inbound?.protocol)?.value ?? '',
    clients: inbound?.users.map(username => ({ username, credential: '', flow: inbound.vless_flows?.[username] ?? '', originalUsername: copy ? undefined : username })) ??
      [{ username: '', credential: '', flow: '' }],
    address: existing?.address ?? '', targetPort: existing?.port ?? 443,
    published: !copy && !!inbound?.public_endpoint, publicAddress: inbound?.public_endpoint?.address ?? props.addresses[0] ?? '',
    publicPort: inbound?.public_endpoint?.port ?? 443, rotateTLS: false,
    transport: inbound?.vless_stream?.network ?? 'tcp', path: inbound?.vless_stream?.path ?? '/',
    tls: inbound?.vless_stream?.security === 'tls',
    host: inbound?.vless_stream?.host ?? '', serviceName: inbound?.vless_stream?.service_name ?? '', mode: inbound?.vless_stream?.mode ?? 'auto',
    authority: inbound?.vless_stream?.authority ?? '', multiMode: inbound?.vless_stream?.multi_mode ?? false,
  }
  error.value = ''
}

function generateCredential(client: Client) {
  const draft = form.value
  if (!draft) return
  if (draft.protocol === 'vless' || draft.protocol === 'vmess') {
    client.credential = crypto.randomUUID()
    return
  }
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  client.credential = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

async function submit() {
  const draft = form.value
  if (!draft || props.busy || duplicate.value || duplicateClient.value) return
  error.value = ''
  try {
    await props.save(draft.port, {
      protocol: draft.protocol, clients: draft.clients.map(({ username, credential, flow }) => ({ username, credential,
        flow: draft.protocol === 'vless' && draft.transport === 'tcp' && draft.tls && flow ? flow : undefined })),
      destination: !draft.copyFrom && draft.address && targets(draft.port).length <= 1 ? { address: draft.address, port: draft.targetPort } : undefined,
      copy_routes_from: draft.copyFrom,
      public_endpoint: (draft.protocol === '' || draft.protocol === 'trojan' || draft.protocol === 'vless') && draft.published ? { address: draft.publicAddress, port: draft.publicPort } : undefined,
      rotate_tls: (draft.protocol === 'trojan' || (draft.protocol === 'vless' && draft.tls)) && draft.rotateTLS ? true : undefined,
      vless_stream: draft.protocol !== 'vless' || (draft.transport === 'tcp' && !draft.tls) ? undefined : draft.transport === 'tcp'
        ? { network: 'tcp', security: 'tls' }
        : draft.transport === 'grpc'
          ? { network: 'grpc', security: draft.tls ? 'tls' : undefined, service_name: draft.serviceName || undefined, authority: draft.authority || undefined, multi_mode: draft.multiMode || undefined }
          : { network: draft.transport, security: draft.tls ? 'tls' : undefined, path: draft.path, host: draft.host || undefined, ...(draft.transport === 'xhttp' ? { mode: draft.mode } : {}) },
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
        <th scope="row">{{ inbound.public_endpoint ? destinationLabel(inbound.public_endpoint) : `127.0.0.1:${inbound.port}` }}</th>
        <td>{{ protocolLabel(inbound.protocol) }}</td>
        <td>{{ inbound.users.join('、') }}<template v-if="centrallyBound(inbound.port)"> · 已在「客户端」绑定</template></td>
        <td>{{ !inbound.protocol ? '直连公网（内网目标拒绝）' : targets(inbound.port).map(destinationLabel).join('、') || '拒绝全部' }}</td>
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
    <form @submit.prevent="submit">
      <label>协议 <select v-model="form.protocol" :disabled="form.editing && centrallyBound(form.port)" @change="form.clients.forEach(client => client.credential = '')">
        <option v-for="protocol in protocols.filter(option => trojan || option.value !== 'trojan')" :key="protocol.value" :value="protocol.value">{{ protocol.label }}</option>
      </select></label>
      <label>监听端口 <input v-model.number="form.port" type="number" min="1024" max="65535" required :disabled="form.editing" /></label>
      <template v-if="form.protocol === 'vless'">
        <label><input v-model="form.tls" type="checkbox" :disabled="!trojan && !form.tls" /> 启用 TLS</label>
        <p v-if="form.tls" class="feedback">使用本节点共用的自动生成证书；客户端通过证书指纹验证。</p>
        <label>传输方式 <select v-model="form.transport">
          <option value="tcp">RAW / TCP</option><option value="ws">WebSocket</option><option value="grpc">gRPC</option>
          <option value="httpupgrade">HTTPUpgrade</option><option value="xhttp">XHTTP</option>
        </select></label>
        <template v-if="form.transport === 'grpc'">
          <label>gRPC serviceName <input v-model="form.serviceName" maxlength="128" pattern="[A-Za-z0-9_.\-]*" /></label>
          <label>gRPC authority <input v-model="form.authority" maxlength="253" pattern="[A-Za-z0-9.\-:]*" /></label>
          <label><input v-model="form.multiMode" type="checkbox" /> gRPC multiMode</label>
        </template>
        <template v-else-if="form.transport !== 'tcp'">
          <label>路径 <input v-model="form.path" required maxlength="256" pattern="/.*" /></label>
          <label>Host <input v-model="form.host" maxlength="253" pattern="[A-Za-z0-9.\-:]*" /></label>
          <label v-if="form.transport === 'xhttp'">XHTTP 模式 <select v-model="form.mode">
            <option value="auto">auto</option><option value="packet-up">packet-up</option><option value="stream-up">stream-up</option><option value="stream-one">stream-one</option>
          </select></label>
        </template>
      </template>
      <fieldset v-for="(client, index) in form.clients" :key="index">
        <legend>客户端 {{ index + 1 }}</legend>
        <label>用户名 <input v-model="client.username" pattern="[a-z][a-z0-9_\-]{0,23}" autocomplete="off"
          :disabled="boundClient(form.port, client)" required /></label>
        <template v-if="!boundClient(form.port, client)">
          <label>{{ form.protocol === 'vless' || form.protocol === 'vmess' ? 'UUID' : '密码' }}
            <input v-model="client.credential" autocomplete="off" :required="needsCredential(client)" :placeholder="needsCredential(client) ? '' : '留空保留原凭据'" />
          </label>
          <div class="actions">
            <button type="button" class="outline" :disabled="busy" @click="generateCredential(client)">生成凭据</button>
            <button v-if="form.clients.length > 1" type="button" class="quiet" :disabled="busy" @click="form.clients.splice(index, 1)">移除此客户端</button>
          </div>
        </template>
        <p v-else class="feedback">在「客户端」中解除绑定或轮换凭据。</p>
        <label v-if="form.protocol === 'vless' && form.transport === 'tcp' && form.tls">Flow
          <select v-model="client.flow"><option value="">无</option><option value="xtls-rprx-vision">xtls-rprx-vision</option></select>
        </label>
      </fieldset>
      <div v-if="multiClient && form.clients.length < 8" class="actions">
        <button type="button" class="outline" :disabled="busy" @click="form.clients.push({ username: '', credential: '', flow: '' })">添加客户端</button>
      </div>
      <template v-if="form.protocol === '' || form.protocol === 'trojan' || (form.protocol === 'vless' && (publicVless || form.published))">
        <label><input v-model="form.published" type="checkbox" :disabled="!addresses.length && !form.published" /> 启用公网 TCP 接入</label>
        <p v-if="form.protocol === 'vless' && form.published && !form.tls" class="feedback">此 VLESS 入口不提供传输加密，请在可信网络或受保护的传输通道中使用。</p>
        <p v-if="form.protocol === '' && form.published" class="feedback">公网 SOCKS5 使用明文 TCP。认证密码和代理流量没有传输加密，请仅在可信网络或受保护的隧道中使用。</p>
        <p v-if="!addresses.length" class="feedback">节点暂未上报可绑定的公网 IPv4。</p>
        <template v-if="form.published">
          <label>宿主公网 IPv4 <select v-model="form.publicAddress" required>
            <option v-if="!addresses.includes(form.publicAddress)" value="" disabled>请选择节点上报的地址</option>
            <option v-for="address in addresses" :key="address" :value="address">{{ address }}</option>
          </select></label>
          <label>公网 TCP 端口 <input v-model.number="form.publicPort" type="number" min="1" max="65535" required /></label>
        </template>
        <label v-if="(form.protocol === 'trojan' || (form.protocol === 'vless' && form.tls)) && inbounds.some(entry => entry.tls_cert_sha256)">
          <input v-model="form.rotateTLS" type="checkbox" /> 轮换此节点主控入站共用的 TLS 证书
        </label>
      </template>
      <p v-if="form.copyFrom">复制源入站的路由。请为新端口生成并保存各客户端凭据。</p>
      <p v-else-if="form.protocol === ''">SOCKS5 使用公网直连出站；节点策略会拒绝回环、私网、链路本地和元数据目标。</p>
      <p v-else-if="form.editing && targets(form.port).length > 1">此入站有多条放行规则。到「路由」编辑目标和顺序。</p>
      <template v-else>
        <label>允许的目标 IPv4 <input v-model.trim="form.address" inputmode="decimal" placeholder="留空拒绝全部" /></label>
        <label>目标 TCP 端口 <input v-model.number="form.targetPort" type="number" min="1" max="65535" :required="!!form.address" :disabled="!form.address" /></label>
      </template>
      <p v-if="duplicate" class="notice" role="alert">该端口已在草稿中使用。</p>
      <p v-if="duplicateClient" class="notice" role="alert">同一个入站的客户端用户名不能重复。</p>
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
      <div class="actions"><button type="submit" :disabled="busy || duplicate || duplicateClient">{{ busy ? '保存中…' : '保存' }}</button></div>
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
