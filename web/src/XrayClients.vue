<script setup lang="ts">
import { computed, onActivated, ref } from 'vue'
import LinkActions from './LinkActions.vue'
import PanelDialog from './PanelDialog.vue'
import { xrayProtocolName, type XrayProtocol } from './xraySubscription'

type Binding = { node_id: string; port: number; credential: string }
type DraftBinding = Binding & { generate?: boolean }
type BindingView = Binding & {
  node_name: string; protocol: XrayProtocol | ''; applied: boolean; panel_inbound?: boolean
  share_expires_at?: number; share_id?: string; delivery_expires_at?: number; delivery_id?: string; delivery_ready?: boolean
}
type ClientTraffic = { up: number; down: number; observed: number; scopes: number; has_gap: boolean }
type Client = { username: string; revision: number; bindings: BindingView[]; expires_at?: number; share_id?: string; traffic?: ClientTraffic }
type Port = { port: number; protocol: XrayProtocol | ''; credentials: string[] }
type Node = { id: string; name: string; panel_inbounds?: boolean; panel_multi_client?: boolean; inbounds: Port[] }
type Link = { id: string; token: string; expires_at: number }
type LinkResponse = { subscription?: Link; inbounds: (Binding & Link)[] }

const props = defineProps<{
  request: <T>(path: string) => Promise<T>
  mutate: <T>(path: string, body: Record<string, unknown>, method?: 'POST' | 'PUT') => Promise<T>
  initialNode: string
}>()
const emit = defineEmits<{ configure: [nodeID: string] }>()
const path = '/api/v1/admin/xray/clients'
const byteFormat = new Intl.NumberFormat('zh-CN')
const clients = ref<Client[]>([])
const nodes = ref<Node[]>([])
const search = ref('')
const nodeFilter = ref(props.initialNode)
const username = ref('')
const error = ref('')
const busy = ref(false)
const loading = ref(false)
const editing = ref<Client | null>(null)
const sharing = ref('')
const activeShare = computed(() => clients.value.find(client => client.username === sharing.value))
const issued = ref(new Map<string, { subscription?: Link; inbounds: Map<string, Link> }>())
const deliveries = ref(new Map<string, Link>())
const draft = ref<DraftBinding[]>([])
const selectedNode = ref('')
const selectedPort = ref<number | ''>('')
const credential = ref('')
const changedNodes = ref<string[]>([])
const filtered = computed(() => clients.value.filter(client => client.username.includes(search.value.trim().toLowerCase()) &&
  (!nodeFilter.value || client.bindings.some(binding => binding.node_id === nodeFilter.value))))
const selectedNodeOption = computed(() => nodes.value.find(node => node.id === selectedNode.value))
const availablePorts = computed(() => (selectedNodeOption.value?.inbounds ?? []).filter(port =>
  !draft.value.some(binding => binding.node_id === selectedNode.value && binding.port === port.port)))
const localCredential = computed(() => selectedNodeOption.value?.panel_inbounds ? undefined
  : draft.value.find(binding => binding.node_id === selectedNode.value)?.credential)
const portCredentials = computed(() => availablePorts.value.find(port => port.port === selectedPort.value)?.credentials ?? [])
const credentials = computed(() => portCredentials.value.filter(name =>
  (!localCredential.value || name === localCredential.value) && !clients.value.some(client => client.username !== editing.value?.username &&
    client.bindings.some(binding => binding.node_id === selectedNode.value && binding.credential === name))))
const generateCredential = '@generate'
const canGenerate = computed(() => {
  const user = editing.value?.username
  return !!user && !!selectedNodeOption.value?.panel_multi_client && selectedPort.value !== '' && portCredentials.value.length < 8 &&
    !portCredentials.value.includes(user) && !clients.value.some(client => client.username !== user &&
      client.bindings.some(binding => binding.node_id === selectedNode.value && binding.credential === user))
})

function bindingKey(binding: Binding) { return `${binding.node_id}:${binding.port}` }
function protocolLabel(protocol: Port['protocol']) { return protocol ? xrayProtocolName[protocol] : 'SOCKS5 / HTTP' }
function nodeLabel(id: string) {
  return nodes.value.find(node => node.id === id)?.name || editing.value?.bindings.find(binding => binding.node_id === id)?.node_name || id
}

function currentLink(client: Client, binding?: BindingView) {
  const links = issued.value.get(client.username)
  const link = binding ? links?.inbounds.get(bindingKey(binding)) : links?.subscription
  const id = binding ? binding.share_id : client.share_id
  return linkURL(link, id)
}

function linkURL(link: Link | undefined, id: string | undefined) {
  if (!link || id !== link.id || link.expires_at * 1000 <= Date.now()) return ''
  const url = new URL('/subscription/client', window.location.origin)
  url.hash = link.token
  return url.href
}

function deliveryKey(client: Client, binding: Binding) { return `${client.username}:${bindingKey(binding)}` }

function deliveryURL(client: Client, binding: BindingView) {
  return linkURL(deliveries.value.get(deliveryKey(client, binding)), binding.delivery_id)
}

function formatExpiry(expiry?: number) {
  if (!expiry) return '未签发'
  return expiry * 1000 <= Date.now() ? '已过期' : `${new Date(expiry * 1000).toLocaleString()} 到期`
}

async function refresh() {
  if (loading.value) return
  error.value = ''
  loading.value = true
  try {
    const result = await props.request<{ clients: Client[]; nodes: Node[] }>(path)
    clients.value = result.clients
    nodes.value = result.nodes
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : '读取客户端失败'
  } finally {
    loading.value = false
  }
}

async function update(operation: () => Promise<void>) {
  if (busy.value || loading.value) return
  error.value = ''
  busy.value = true
  try {
    await operation()
    await refresh()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : '更新客户端失败'
  } finally {
    busy.value = false
  }
}

function createClient() {
  const user = username.value
  return update(async () => {
    await props.mutate(path, { username: user })
    username.value = ''
    nodeFilter.value = ''
    search.value = user
  })
}

function editBindings(client: Client) {
  error.value = ''
  editing.value = client
  draft.value = client.bindings.map(({ node_id, port, credential }) => ({ node_id, port, credential }))
  selectedNode.value = ''
  selectedPort.value = ''
  credential.value = ''
}

function choosePort() {
  const preferred = localCredential.value ?? editing.value?.username ?? ''
  if (credentials.value.includes(preferred)) credential.value = preferred
  else if (canGenerate.value) credential.value = generateCredential
  else credential.value = credentials.value.length === 1 ? credentials.value[0] : ''
}

function addBinding() {
  if (!selectedNode.value || selectedPort.value === '' || draft.value.length >= 64) return
  const generate = credential.value === generateCredential
  const name = generate ? editing.value?.username : credential.value
  if (!name || (generate ? !canGenerate.value : !credentials.value.includes(name))) return
  draft.value.push({ node_id: selectedNode.value, port: selectedPort.value, credential: name, generate })
  selectedPort.value = ''
  credential.value = ''
}

function saveBindings() {
  const client = editing.value
  if (!client) return
  return update(async () => {
    const bindings = draft.value.map(({ node_id, port, credential }) => ({ node_id, port, credential }))
    const generate = bindings.filter((_, index) => draft.value[index].generate)
    const result = await props.mutate<{ deliveries?: (Binding & Link)[] }>(`${path}/${client.username}/bindings`, {
      revision: client.revision, bindings, ...(generate.length ? { generate } : {}),
    }, 'PUT')
    for (const link of result.deliveries ?? []) deliveries.value.set(deliveryKey(client, link), link)
    if (result.deliveries?.length) sharing.value = client.username
    const previous = new Set(client.bindings.map(binding => `${bindingKey(binding)}:${binding.credential}`))
    const next = new Set(draft.value.map(binding => `${bindingKey(binding)}:${binding.credential}`))
    changedNodes.value = [...new Set([
      ...client.bindings.filter(binding => !next.has(`${bindingKey(binding)}:${binding.credential}`)),
      ...draft.value.filter(binding => !previous.has(`${bindingKey(binding)}:${binding.credential}`)),
    ].map(binding => binding.node_id))]
    nodeFilter.value = ''
    editing.value = null
  })
}

function openShares(client: Client) {
  sharing.value = client.username
  void refresh()
}

function setLink(client: Client, action: 'issue' | 'revoke', binding?: BindingView) {
  if (action === 'revoke' && !confirm(binding ? '撤销此入站的分享和凭据领取链接？' : '撤销总订阅及所有入站的分享和凭据领取链接？')) return
  if (action === 'issue' && (binding ? binding.share_expires_at : client.expires_at) &&
    !confirm(binding ? '轮换此入站的分享链接？原链接会立即失效。' : '轮换总订阅和所有入站分享链接？原链接会立即失效。')) return
  return update(async () => {
    const result = await props.mutate<LinkResponse>(`${path}/${client.username}/share`, {
      action, ...(binding ? { node_id: binding.node_id, port: binding.port } : {}),
    })
    const links = binding ? issued.value.get(client.username) ?? { inbounds: new Map<string, Link>() }
      : { inbounds: new Map<string, Link>(), subscription: result.subscription }
    if (binding && action === 'revoke') links.inbounds.delete(bindingKey(binding))
    if (action === 'revoke') {
      for (const entry of binding ? [binding] : client.bindings) deliveries.value.delete(deliveryKey(client, entry))
    }
    for (const entry of result.inbounds) links.inbounds.set(bindingKey(entry), entry)
    issued.value.set(client.username, links)
  })
}

function rotateCredential(client: Client, binding: BindingView) {
  if (!confirm('生成新凭据和领取链接？节点应用新配置后，旧凭据将失效。')) return
  return update(async () => {
    const link = await props.mutate<Link>(`${path}/${client.username}/credential`, {
      node_id: binding.node_id, port: binding.port, revision: client.revision,
    })
    deliveries.value.set(deliveryKey(client, binding), link)
  })
}

function configureNode(id: string) {
  sharing.value = ''
  emit('configure', id)
}

onActivated(refresh)
</script>

<template>
  <section class="card page-stack">
    <form class="filters" @submit.prevent="createClient">
      <label>客户端用户名<input v-model.trim="username" required maxlength="24" pattern="[a-z][a-z0-9_\-]{0,23}" placeholder="例如 alice" :disabled="busy" /></label>
      <button type="submit" :disabled="busy || loading">创建客户端</button>
    </form>
    <div class="filters">
      <label>搜索客户端<input v-model="search" type="search" /></label>
      <button v-if="nodeFilter" type="button" class="outline" @click="nodeFilter = ''">查看全部节点</button>
      <button type="button" class="outline" :disabled="busy || loading" @click="refresh">刷新状态</button>
    </div>
    <p v-if="nodeFilter" class="feedback">筛选节点 {{ nodeLabel(nodeFilter) }}</p>
    <p v-if="error && !editing && !sharing" class="notice" role="alert">{{ error }}</p>
    <div v-if="changedNodes.length" class="actions" role="status">
      <span>绑定已保存。配置有变化的节点需要预览并下发。</span>
      <button v-for="id in changedNodes" :key="id" type="button" class="outline" @click="emit('configure', id)">{{ nodeLabel(id) }}</button>
    </div>
    <div v-if="filtered.length" class="table-wrap">
      <table class="data-table" aria-label="主控客户端">
        <thead><tr><th scope="col">客户端</th><th scope="col">入站</th><th scope="col">当前修订流量</th><th scope="col">总订阅</th><th scope="col">操作</th></tr></thead>
        <tbody><tr v-for="client in filtered" :key="client.username">
          <th scope="row">{{ client.username }}</th><td>{{ client.bindings.filter(binding => binding.applied).length }} / {{ client.bindings.length }} 已生效</td>
          <td>
            <template v-if="client.traffic">
              <span>↑ {{ byteFormat.format(client.traffic.up) }} B · ↓ {{ byteFormat.format(client.traffic.down) }} B</span>
              <small v-if="client.traffic.observed < client.traffic.scopes || client.traffic.has_gap">
                {{ client.traffic.observed }} / {{ client.traffic.scopes }} 项有样本
                <template v-if="client.traffic.has_gap"> · 采样过期或有缺口</template>
              </small>
            </template>
            <span v-else>暂无采样</span>
          </td>
          <td>{{ formatExpiry(client.expires_at) }}</td><td><div class="actions">
            <button type="button" class="outline" :disabled="busy" @click="editBindings(client)">分配入站</button>
            <button type="button" class="outline" :disabled="busy" @click="openShares(client)">分享</button>
          </div></td>
        </tr></tbody>
      </table>
    </div>
    <p v-else class="empty">{{ loading ? '正在读取客户端…' : clients.length ? '没有匹配的客户端。' : '创建客户端后，可为其分配多个节点的入站。' }}</p>
  </section>

  <PanelDialog v-if="editing" :title="`分配入站 · ${editing.username}`" @close="editing = null">
    <p v-if="error" class="notice" role="alert">{{ error }}</p>
    <ul v-if="draft.length" class="page-stack">
      <li v-for="(binding, index) in draft" :key="bindingKey(binding)">
        {{ nodeLabel(binding.node_id) }} · {{ binding.port }} · {{ binding.credential }}{{ binding.generate ? ' · 生成凭据' : '' }}
        <button type="button" class="quiet" :disabled="busy" @click="draft.splice(index, 1)">解除绑定</button>
      </li>
    </ul>
    <form v-if="nodes.length" class="filters" @submit.prevent="addBinding">
      <label>节点<select v-model="selectedNode" required :disabled="busy" @change="selectedPort = ''; credential = ''">
        <option value="" disabled>选择节点</option>
        <option v-for="node in nodes" :key="node.id" :value="node.id">{{ node.name }}</option>
      </select></label>
      <label>入站<select v-model="selectedPort" required :disabled="busy || !selectedNode" @change="choosePort">
        <option value="" disabled>选择入站</option>
        <option v-for="port in availablePorts" :key="port.port" :value="port.port">{{ port.port }} · {{ protocolLabel(port.protocol) }}</option>
      </select></label>
      <label>节点凭据名<select v-model="credential" required :disabled="busy || selectedPort === ''">
        <option value="" disabled>{{ selectedPort !== '' && !credentials.length && !canGenerate ? '当前入站无可用凭据' : '选择凭据' }}</option>
        <option v-if="canGenerate" :value="generateCredential">为 {{ editing.username }} 生成凭据</option>
        <option v-for="name in credentials" :key="name">{{ name }}</option>
      </select></label>
      <button type="submit" class="outline" :disabled="busy || !credential || draft.length >= 64">添加绑定</button>
    </form>
    <p v-else class="feedback">等待节点上报可用的入站和凭据。</p>
    <p v-if="editing.bindings.some(binding => !draft.some(item => bindingKey(item) === bindingKey(binding)))" class="feedback">
      解除绑定立即撤销对应的入站分享。下发后撤销该客户端的授权，主控定义的入站在移除最后一个客户端时停止监听。
    </p>
    <p>保存后，在受影响节点的「代理配置」中预览并下发。</p>
    <div class="actions"><button type="button" :disabled="busy || loading" @click="saveBindings">保存绑定</button></div>
  </PanelDialog>

  <PanelDialog v-if="activeShare" :title="`分享 · ${activeShare.username}`" @close="sharing = ''">
    <div class="page-stack">
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
      <section class="revision-summary">
        <strong>总订阅</strong><span>{{ formatExpiry(activeShare.expires_at) }}</span>
        <LinkActions v-if="currentLink(activeShare)" :url="currentLink(activeShare)" />
        <p v-else-if="activeShare.expires_at">链接正文在签发时显示。已保存的链接可用至到期或轮换。</p>
        <div class="actions">
          <button type="button" :disabled="busy || loading || !activeShare.bindings.some(binding => binding.applied)" @click="setLink(activeShare, 'issue')">
            {{ activeShare.expires_at ? '轮换总订阅和分享链接' : '签发总订阅和分享链接' }}</button>
          <button v-if="activeShare.expires_at || activeShare.bindings.some(binding => binding.share_expires_at || binding.delivery_expires_at)"
            type="button" class="danger" :disabled="busy || loading" @click="setLink(activeShare, 'revoke')">撤销全部链接</button>
          <button type="button" class="outline" :disabled="busy || loading" @click="refresh">刷新状态</button>
        </div>
      </section>
      <section class="page-stack">
        <h3>各入站分享</h3>
        <p v-if="!activeShare.bindings.length">请先分配入站。</p>
        <div v-for="binding in activeShare.bindings" :key="bindingKey(binding)" class="revision-summary">
          <strong>{{ binding.node_name || binding.node_id }} · {{ binding.port }} · {{ protocolLabel(binding.protocol) }}</strong>
          <span>{{ binding.applied ? formatExpiry(binding.share_expires_at) : '等待生效或节点暂不可用' }}</span>
          <LinkActions v-if="binding.applied && currentLink(activeShare, binding)" :url="currentLink(activeShare, binding)" label="入站分享链接" />
          <template v-if="binding.delivery_expires_at">
            <span>凭据领取链接 · {{ formatExpiry(binding.delivery_expires_at) }}</span>
            <p v-if="binding.delivery_expires_at * 1000 > Date.now() && !binding.delivery_ready">领取前请预览并下发，等节点确认生效。</p>
            <LinkActions v-if="deliveryURL(activeShare, binding)" :url="deliveryURL(activeShare, binding)" label="凭据领取链接" />
          </template>
          <div class="actions">
            <button v-if="!binding.applied || (binding.delivery_expires_at && !binding.delivery_ready)" type="button"
              class="outline" :disabled="busy || loading" @click="configureNode(binding.node_id)">查看节点配置</button>
            <button v-if="binding.applied" type="button" class="outline" :disabled="busy || loading" @click="setLink(activeShare, 'issue', binding)">{{ binding.share_expires_at ? '轮换入站链接' : '签发入站链接' }}</button>
            <button v-if="binding.panel_inbound" type="button" class="outline" :disabled="busy || loading" @click="rotateCredential(activeShare, binding)">轮换凭据并生成领取链接</button>
            <button v-if="binding.share_expires_at || binding.delivery_expires_at" type="button" class="danger"
              :disabled="busy || loading" @click="setLink(activeShare, 'revoke', binding)">撤销入站链接</button>
          </div>
        </div>
      </section>
    </div>
  </PanelDialog>
</template>
