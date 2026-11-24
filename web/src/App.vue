<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import AdminSidebar, { type AdminPage } from './AdminSidebar.vue'
import LinkActions from './LinkActions.vue'
import PanelDialog from './PanelDialog.vue'
import XrayNetworkEditor from './XrayNetworkEditor.vue'
import { copyNetwork, destinationLabel, type Destination, type Network } from './xrayManagement'
import { xrayProtocolName, type XrayProtocol, type XrayPublicEndpoint } from './xraySubscription'

type NodeRecord = { id: string; name: string; group: string; last_seen: number; disabled: boolean; pending: boolean }
type Audit = { at: number; actor: string; action: string; resource: string; outcome: string }
type StatusResult = { core?: string; load_state?: string; active_state?: string; sub_state?: string; observed_at?: string; error_code?: string }
type TaskAck = { status_version: number; status: string; result?: StatusResult }
type StatusTask = { task_id: string; node_id: string; sequence: number; created_by?: string; created_at?: string; approval: string; control?: string; operation: string; core: string; issued_at: string; expires_at: string; active: boolean; lease_deadline?: string; status: string; acks: TaskAck[] }
type ManagedAdmin = { id: string; username: string; role: string; node_ids: string[]; node_groups: string[]; disabled: boolean }
type AdminInfo = { id: string; username: string; role: string; csrf_token: string; mfa_recent: boolean; can_manage_admins: boolean; can_create_nodes: boolean; can_install_agents: boolean; can_disable_nodes: boolean; can_prepare_xray_installs: boolean; can_manage_xray: boolean; can_update_runtime: boolean }
type LoginResult = { status: 'ok'; csrf_token: string } | { status: 'setup_required'; totp_secret: string }
type RuntimeUpdate = {
  id: string; sequence: number; version: string; architecture: string; expires_at: string; current_pair_sha256?: string
  status: 'QUEUED' | 'DELIVERED' | 'COMMITTED' | 'ROLLED_BACK' | 'REJECTED' | 'EXPIRED'
}
type XrayOperation = 'core.install' | 'core.start' | 'core.stop' | 'core.upgrade' | 'core.downgrade' | 'core.uninstall' | 'config.apply'
type CoreXrayOperation = Exclude<XrayOperation, 'config.apply'>
type XrayConfigReference = { port: number; sha256: string; size: number }
type XrayPortProtocol = Exclude<XrayProtocol, 'socks'>
type XrayInbound = {
  port: number; protocol?: XrayPortProtocol; tls_cert_sha256?: string; reality_public_key?: string
  public_endpoint?: XrayPublicEndpoint; users: string[]
}
type XrayCatalog = {
  ports: number[]; users: string[] | null; http_ports?: number[]
  port_protocols?: Record<number, XrayPortProtocol>; protocol_users?: Partial<Record<XrayPortProtocol, string[]>>
  trojan_trust?: { sha256: string }
  reality_public_key?: string
  public_endpoints?: Record<number, XrayPublicEndpoint>
  routing_destinations?: Destination[]
}
type XrayDraft = { plan: XrayInbound[]; network: Network | null }
type XraySubscriptionRow = { username: string; eligible: boolean; active: boolean; expires_at?: number }
type PanelXrayOptions = {
  architecture: string
  current: {
    version: string; sha256: string; running: boolean; candidate?: XrayConfigReference; config?: XrayConfigReference; config_revision?: number
    catalog?: XrayCatalog; applied?: XrayInbound[]; applied_network?: Network
  }
  state: string; versions: string[]; catalog_version: number; config_ready: boolean
  draft: XrayInbound[] | null; draft_previewed: boolean
  draft_network?: Network | null
  usage?: { user_statistics: string; exact_quota: string; reason: string }
}
type XrayInstall = {
  proposal: {
    task_id: string; node_id: string; sequence: number; operation: XrayOperation
    version: string; architecture: string; sha256: string; manifest_version?: number
    current_version?: string; current_sha256?: string; requester_id: string; expires_at: number; config?: XrayConfigReference
  }
  status: 'AWAITING_SIGNATURE' | 'SIGNED_TASK_VERIFIED' | 'EXPIRED' | 'LEGACY'
}
type CoreCatalogAsset = { name: string; size: number; download_url: string; digest?: string }
type CoreCatalogRelease = { version: string; title: string; published_at: string; prerelease: boolean; url: string; assets: CoreCatalogAsset[] }
type CoreCatalogEntry = { id: string; name: string; repository: string; has_more: boolean; releases: CoreCatalogRelease[] }
type CoreCatalog = { retrieved_at: string; stale: boolean; page: number; has_more: boolean; cores: CoreCatalogEntry[] }
type CoreBackupAsset = { architecture: string; name: string; size: number; digest: string; source_url: string; storage_key: string }
type CoreBackup = { id: string; name: string; repository: string; version: string; release_url: string; cached_at: string; assets: CoreBackupAsset[] }
type CoreBackupManifest = { schema_version: number; updated_at: string; cores: CoreBackup[] }
class ApiError extends Error { constructor(readonly status: number, message: string) { super(message) } }
const username = ref('')
const password = ref('')
const code = ref('')
const nodes = ref<NodeRecord[]>([])
const audits = ref<Audit[]>([])
const tasks = ref<StatusTask[]>([])
const latestCoreTask = computed(() => tasks.value.find(task => task.core === 'xray' && task.operation.startsWith('core.') && task.operation !== 'core.status'))
const latestApplyTask = computed(() => tasks.value.find(task => task.operation === 'config.apply'))
const xrayInstalls = ref<XrayInstall[]>([])
const runtimeUpdates = ref<RuntimeUpdate[]>([])
const runtimeUpdateBusy = ref(false)
const runtimeUpdateError = ref('')
const runtimeUpdateStatus: Record<RuntimeUpdate['status'], string> = {
  QUEUED: '待领取', DELIVERED: '已领取，等待结果', COMMITTED: '更新已提交',
  ROLLED_BACK: '已恢复原版本', REJECTED: '节点拒绝', EXPIRED: '已过期',
}
const runtimeProofFields = [
  { name: 'authorization', label: '节点授权 JSON', limit: 8192 },
  { name: 'authorization_signature', label: '节点授权签名', limit: 64 },
  { name: 'manifest', label: '发布清单 JSON', limit: 1 << 20 },
  { name: 'manifest_signature', label: '发布清单签名', limit: 64 },
]
const xrayInstallInput = ref({
  operation: 'core.install' as CoreXrayOperation,
  version: '', architecture: 'amd64', sha256: '', manifest_version: '' as number | '',
  current_version: '', current_sha256: '',
})
const xrayOperationLabel: Record<XrayOperation, string> = {
  'core.install': '安装', 'core.start': '启动', 'core.stop': '停止',
  'core.upgrade': '升级', 'core.downgrade': '降级', 'core.uninstall': '卸载',
  'config.apply': '下发代理配置',
}
const legacyXrayOperations: CoreXrayOperation[] = ['core.install', 'core.start', 'core.stop', 'core.upgrade', 'core.downgrade', 'core.uninstall']
const xrayVersionChange = computed(() => xrayInstallInput.value.operation === 'core.upgrade' || xrayInstallInput.value.operation === 'core.downgrade')
const xrayUsesArtifact = computed(() => xrayInstallInput.value.operation === 'core.install' || xrayVersionChange.value)
const xrayInstallBusy = ref(false)
const xrayInstallError = ref('')
const xrayInstallStatus = { AWAITING_SIGNATURE: '待签发', SIGNED_TASK_VERIFIED: '已核验签发任务', EXPIRED: '已过期', LEGACY: '旧版记录' }
let xrayInstallRetry: { intent: string; id: string } | undefined
const panelXray = ref<PanelXrayOptions | null>(null)
const panelXrayOperation = ref<CoreXrayOperation>('core.install')
const panelXrayVersion = ref('')
const panelXrayError = ref('')
const panelXrayReadError = ref('')
const panelXraySubmitting = ref(false)
const xrayDraft = ref<XrayInbound[]>([])
const draftNetwork = ref<Network | null>(null)
const xrayDraftSaving = ref(false)
const draftConflict = ref(false)
const xraySubscriptions = ref<XraySubscriptionRow[]>([])
const xraySubscriptionLink = ref<{ username: string; url: string; expiresAt: number } | null>(null)
const xraySubscriptionBusy = ref(false)
const xraySubscriptionError = ref('')
const subscriptionsLoading = ref(false)
const subscriptionNotice = ref('')
const subscriptionSearch = ref('')
const subscriptionFilter = ref('')
const shareOpen = ref(false)
const shareUser = ref('')
const sharePort = ref<number | ''>('')
const shareQrFirst = ref(false)
const shareTab = ref<'subscription' | 'node'>('subscription')
const selectedConfigCore = ref<'' | 'xray'>('')
const draftTab = ref<'inbound' | 'client' | 'outbound' | 'routing'>('inbound')
const clientSearch = ref('')
const previewOpen = ref(false)
const coreDrawer = ref(false)
const addNodeOpen = ref(false)
const page = ref<AdminPage>('overview')
const pageTitle: Record<AdminPage, string> = {
  overview: '总览', nodes: '节点列表', config: '代理配置', subscriptions: '客户端订阅',
  audit: '审计日志', versions: 'Core 版本', tasks: '任务', admins: '管理员',
}
const now = ref(Date.now())
const xrayDraftDirty = computed(() => !matchesDraft(panelXray.value, { plan: xrayDraft.value, network: draftNetwork.value }))
const draftDisabled = computed(() => xrayDraftSaving.value || panelXraySubmitting.value || !!panelXrayReadError.value || draftConflict.value)
const xrayDraftPolicyChanged = computed(() => xrayDraft.value.some(inbound =>
  panelXray.value?.current.catalog?.ports.includes(inbound.port) &&
  (inbound.protocol !== approvedProtocol(inbound.port) || inbound.tls_cert_sha256 !== approvedTLSCert(inbound.port) ||
    inbound.reality_public_key !== approvedRealityKey(inbound.port) ||
    endpointLabel(inbound.public_endpoint, inbound.port) !== endpointLabel(approvedPublicEndpoint(inbound.port), inbound.port)),
))
const draftPorts = computed(() => [...new Set([
  ...(panelXray.value?.current.catalog?.ports ?? []),
  ...xrayDraft.value.map(inbound => inbound.port),
])].sort((left, right) => left - right))
const draftGrantCount = computed(() => xrayDraft.value.reduce((count, inbound) => count + inbound.users.length, 0))
const clients = computed(() => [...new Set([
  ...draftPorts.value.flatMap(port => draftUsers(port)),
  ...(panelXray.value?.current.applied ?? []).flatMap(inbound => inbound.users),
])].sort().filter(user => user.includes(clientSearch.value.trim().toLowerCase())))
const networkDestinations = computed(() => panelXray.value?.current.catalog?.routing_destinations ?? [])
let panelXrayRetry: { intent: string; id: string } | undefined
const panelXrayOperations = computed<CoreXrayOperation[]>(() => {
  if (!panelXray.value?.current.version) return ['core.install']
  return panelXray.value.current.running
    ? ['core.stop', 'core.upgrade', 'core.downgrade', 'core.uninstall']
    : ['core.start', 'core.upgrade', 'core.downgrade', 'core.uninstall']
})
const panelXrayUsesArtifact = computed(() => ['core.install', 'core.upgrade', 'core.downgrade'].includes(panelXrayOperation.value))
const panelXrayVersions = computed(() => {
  const options = panelXray.value
  if (!options) return []
  return options.versions.filter((version) => {
    const order = version.localeCompare(options.current.version, 'en', { numeric: true })
    if (panelXrayOperation.value === 'core.upgrade') return order > 0
    if (panelXrayOperation.value === 'core.downgrade') return order < 0
    return true
  })
})
watch(panelXrayOperations, (operations) => {
  if (!operations.includes(panelXrayOperation.value)) panelXrayOperation.value = operations[0]
})
watch(panelXrayVersions, (versions) => {
  if (!versions.includes(panelXrayVersion.value)) panelXrayVersion.value = versions[0] ?? ''
})
const coreCatalog = ref<CoreCatalog | null>(null)
const coreCatalogCore = ref('xray')
const coreCatalogPage = ref(1)
const coreCatalogLoading = ref(false)
const coreCatalogError = ref('')
const coreBackups = ref<CoreBackupManifest | null>(null)
const coreBackupError = ref('')
const managedAdmins = ref<ManagedAdmin[]>([])
const error = ref('')
const loading = ref(false)
const nodesLoading = ref(false)
const nodesError = ref('')
let lastNodeRefresh = 0
const loggedIn = ref(false)
const newNodeName = ref('')
const newNodeGroup = ref('default')
const installCommand = ref<{ node: NodeRecord; command: string; expires_at: number } | null>(null)
const generatingCommand = ref(false)
const commandCopied = ref(false)
const bootstrapToken = ref('')
const manualBootstrap = ref(false)
const bootstrapUser = ref('admin')
const bootstrapPassword = ref('')
const bootstrapTOTP = ref('')
const firstLoginSecret = ref('')
const firstLoginPassword = ref('')
const admin = ref<AdminInfo | null>(null)
const selectedNodeID = ref('')
const selectedNode = computed(() => nodes.value.find(node => node.id === selectedNodeID.value))
let nodeReads = new AbortController()
let inventoryRequest = 0
let tasksRequest = 0
const taskError = ref('')
const auditError = ref('')
const adminsError = ref('')
const nodeGroup = ref('')
const nodeStatusFilter = ref('')
const nodePage = ref(1)
const nodePageSize = 8
const coreSummaries = ref<Record<string, { version: string; running: boolean } | 'loading' | 'unknown'>>({})
const nodeGroups = computed(() => [...new Set(nodes.value.map(node => node.group))].sort())
const filteredNodes = computed(() => nodes.value.filter(node =>
  (!nodeGroup.value || node.group === nodeGroup.value) && (!nodeStatusFilter.value || nodeStatus(node) === nodeStatusFilter.value),
).sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id)))
const nodePageCount = computed(() => Math.max(1, Math.ceil(filteredNodes.value.length / nodePageSize)))
const visibleNodes = computed(() => filteredNodes.value.slice((nodePage.value - 1) * nodePageSize, nodePage.value * nodePageSize))
const overviewStatuses = ['在线', '离线', '待接入'] as const
const nodeCounts = computed(() => {
  const counts = { 在线: 0, 离线: 0, 待接入: 0, 已禁用: 0 }
  for (const node of nodes.value) counts[nodeStatus(node)]++
  return counts
})
const canReadCore = computed(() => !!admin.value?.can_manage_xray)
const installedXrayVersion = computed(() => panelXray.value?.current.version ?? '')
const subscriptionRows = computed(() => xraySubscriptions.value.filter(row =>
  row.username.includes(subscriptionSearch.value.trim().toLowerCase()) &&
  (!subscriptionFilter.value || subscriptionStatus(row) === subscriptionFilter.value),
))
const activeShareRow = computed(() => xraySubscriptions.value.find(row => row.username === shareUser.value))
const subscriptionInbounds = computed(() => panelXray.value?.current.applied ?? [])
const shareInbounds = computed(() => subscriptionInbounds.value.filter(inbound => inbound.users.includes(shareUser.value)))
const shareLink = computed(() => {
  const link = xraySubscriptionLink.value
  return activeShareRow.value && link?.username === activeShareRow.value.username && hasShareLink(activeShareRow.value) ? link : null
})
const canApplyXrayDraft = computed(() => {
  const options = panelXray.value
  return !!options?.config_ready && !panelXrayReadError.value && !draftConflict.value &&
    !xrayDraftSaving.value && !panelXraySubmitting.value &&
    (!options.current.catalog || (!xrayDraftDirty.value && !xrayDraftPolicyChanged.value))
})
const appliedConfigVerified = computed(() => {
  const current = panelXray.value?.current
  const task = tasks.value.find(item => item.operation === 'config.apply' && item.sequence === current?.config_revision)
  if (task?.status !== 'SUCCEEDED' || !current?.config) return false
  const proposal = xrayInstalls.value.find(item => item.proposal.task_id === task.task_id)?.proposal
  return !proposal?.config || proposal.config.sha256 === current.config.sha256
})
const latestApplyVerified = computed(() => appliedConfigVerified.value &&
  latestApplyTask.value?.sequence === panelXray.value?.current.config_revision)
const inboundChanges = computed(() => {
  const applied = panelXray.value?.current.applied ?? []
  const draft = panelXray.value?.draft ?? []
  const ports = [...new Set([...applied, ...draft].map(inbound => inbound.port))].sort((a, b) => a - b)
  return ports.map(port => ({
    port, before: applied.find(inbound => inbound.port === port), after: draft.find(inbound => inbound.port === port),
  })).filter(change => JSON.stringify(change.before) !== JSON.stringify(change.after))
})
const networkChanged = computed(() => JSON.stringify(panelXray.value?.current.applied_network ?? null) !==
  JSON.stringify(panelXray.value?.draft_network ?? null))
const draftStatus = computed(() => {
  const options = panelXray.value
  if (!options) return '状态不可用'
  if (draftConflict.value) return '主控草稿已更新'
  if (xrayDraftDirty.value || xrayDraftPolicyChanged.value) return '有未保存修改'
  if (options.config_ready) return '预览完成，可下发'
  if (options.draft_previewed && !options.current.candidate) return '草稿未通过节点策略校验'
  if (options.draft !== null && !options.draft_previewed) return '等待节点预览'
  if (options.draft_previewed) return '节点已预览，暂无可下发变更'
  return '暂无草稿'
})
const statusCore = ref('xray')
const newAdminUsername = ref('')
const newAdminPassword = ref('')
const newAdminRole = ref('auditor')
const newAdminGroups = ref('')
const newAdminNodeIDs = ref('')
const createdTOTP = ref('')
let csrfToken = ''
const selectedCoreCatalog = computed(() => coreCatalog.value?.cores.find((core) => core.id === coreCatalogCore.value) ?? null)

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? 'GET').toUpperCase()
  const headers = new Headers(init?.headers)
  headers.set('Content-Type', 'application/json')
  if (method !== 'GET' && csrfToken) headers.set('X-CSRF-Token', csrfToken)
  const response = await fetch(path, { credentials: 'same-origin', ...init, headers })
  if (!response.ok) throw new ApiError(response.status, (await response.text()).trim() || `HTTP ${response.status}`)
  return response.json() as Promise<T>
}
async function apiWithStepUp<T>(path: string, body: Record<string, unknown>): Promise<T> {
  try { return await api<T>(path, { method: 'POST', body: JSON.stringify(body) }) }
  catch (e) {
    if (!(e instanceof ApiError) || e.status !== 428) throw e
    const code = prompt('请重新输入 Authenticator 验证码')?.trim()
    if (!code) throw new Error('已取消 MFA 复验')
    return api<T>(path, { method: 'POST', body: JSON.stringify({ ...body, mfa_code: code }) })
  }
}
async function refreshNodes() {
  if (nodesLoading.value) return
  nodesLoading.value = true
  lastNodeRefresh = Date.now()
  const account = admin.value
  try {
    const records = await api<NodeRecord[]>('/api/v1/admin/nodes')
    if (admin.value !== account) return
    nodesError.value = ''
    nodes.value = records
    if (!selectedNode.value) selectNode('')
    coreSummaries.value = {}
    void loadVisibleCore()
  } catch (cause) {
    if (admin.value === account) nodesError.value = cause instanceof Error ? cause.message : '读取节点失败'
  } finally {
    nodesLoading.value = false
  }
}

async function loadAudit() {
  auditError.value = ''
  const account = admin.value
  try {
    const records = await api<Audit[]>('/api/v1/admin/audit')
    if (admin.value === account) audits.value = records.slice(-100).reverse()
  } catch (cause) {
    if (admin.value === account) auditError.value = cause instanceof Error ? cause.message : '读取审计失败'
  }
}

async function loadAdmins() {
  adminsError.value = ''
  const account = admin.value
  if (!account?.can_manage_admins) return
  try {
    const records = await api<ManagedAdmin[]>('/api/v1/admin/admins')
    if (admin.value === account) managedAdmins.value = records
  } catch (cause) {
    if (admin.value === account) adminsError.value = cause instanceof Error ? cause.message : '读取管理员失败'
  }
}
async function loadCoreBackups() {
  coreBackupError.value = ''
  try {
    coreBackups.value = await api<CoreBackupManifest>('/api/v1/admin/cores/backups')
  } catch (e) {
    coreBackupError.value = e instanceof Error ? e.message : '读取主控备用制品失败'
  }
}
async function loadCoreCatalog(page = 1, append = false) {
  coreCatalogLoading.value = true
  coreCatalogError.value = ''
  try {
    const next = await api<CoreCatalog>(`/api/v1/admin/cores/releases?page=${page}`)
    if (append && coreCatalog.value) {
      coreCatalog.value = {
        ...next,
        cores: next.cores.map((core) => {
          const previous = coreCatalog.value?.cores.find((item) => item.id === core.id)
          return { ...core, releases: [...(previous?.releases ?? []), ...core.releases] }
        }),
      }
    } else {
      coreCatalog.value = next
    }
    coreCatalogPage.value = page
  } catch (e) {
    coreCatalogError.value = e instanceof Error ? e.message : '读取官方发布目录失败'
  } finally {
    coreCatalogLoading.value = false
  }
}
function refreshCoreCatalog() { return loadCoreCatalog(1, false) }
function loadOlderCoreReleases() { return loadCoreCatalog(coreCatalogPage.value + 1, true) }
async function login() {
  loading.value = true
  error.value = ''
  try {
    const result = await api<LoginResult>('/api/v1/admin/login', {
      method: 'POST',
      body: JSON.stringify({ username: username.value, password: password.value, code: code.value }),
    })
    if (result.status === 'setup_required') {
      firstLoginSecret.value = result.totp_secret
      code.value = ''
      return
    }
    csrfToken = result.csrf_token
    admin.value = await api<AdminInfo>('/api/v1/admin/me')
    loggedIn.value = true
    password.value = ''
    code.value = ''
    await refreshNodes()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '登录失败'
  } finally {
    loading.value = false
  }
}
function clearFirstLogin() {
  firstLoginSecret.value = ''
  firstLoginPassword.value = ''
  password.value = ''
  code.value = ''
  error.value = ''
}
async function completeFirstLogin() {
  loading.value = true
  error.value = ''
  try {
    await api('/api/v1/admin/setup', {
      method: 'POST',
      body: JSON.stringify({
        username: username.value,
        initial_password: password.value,
        new_password: firstLoginPassword.value,
        totp_secret: firstLoginSecret.value,
        code: code.value,
      }),
    })
    clearFirstLogin()
    error.value = '密码与 MFA 已设置，请使用新密码登录'
  } catch (e) {
    error.value = e instanceof Error ? e.message : '首次登录设置失败'
  } finally {
    loading.value = false
  }
}
async function bootstrap() {
  loading.value = true; error.value = ''
  try { await api('/api/v1/bootstrap', { method: 'POST', body: JSON.stringify({ token: bootstrapToken.value, username: bootstrapUser.value, password: bootstrapPassword.value, totp_secret: bootstrapTOTP.value }) }); error.value = '管理员初始化成功，请登录'; bootstrapToken.value = ''; bootstrapPassword.value = '' }
  catch (e) { error.value = e instanceof Error ? e.message : '初始化失败' }
  finally { loading.value = false }
}
function nodeStatus(node: NodeRecord) {
  if (node.disabled) return '已禁用'
  if (node.pending) return '待接入'
  return now.value / 1000 - node.last_seen < 60 ? '在线' : '离线'
}

function openPage(next: AdminPage, node?: NodeRecord) {
  if (node && !switchNode(node.id)) return
  error.value = ''
  page.value = next
  if (next !== 'nodes') installCommand.value = null
  if (next !== 'admins') createdTOTP.value = ''
  if (next !== 'subscriptions') shareOpen.value = false
}

function openNodeList(status: string) {
  nodeGroup.value = ''
  nodeStatusFilter.value = status
  openPage('nodes')
}

function selectNode(id: string) {
  if (selectedNodeID.value === id) return
  nodeReads.abort()
  nodeReads = new AbortController()
  selectedNodeID.value = id
  selectedConfigCore.value = ''
  draftTab.value = 'inbound'
  clientSearch.value = ''
  tasks.value = []
  taskError.value = ''
  xrayInstalls.value = []
  xrayInstallError.value = ''
  runtimeUpdates.value = []
  runtimeUpdateError.value = ''
  panelXray.value = null
  panelXrayError.value = ''
  panelXrayReadError.value = ''
  xrayDraft.value = []
  draftNetwork.value = null
  draftConflict.value = false
  previewOpen.value = false
  xraySubscriptions.value = []
  xraySubscriptionLink.value = null
  xraySubscriptionError.value = ''
  subscriptionNotice.value = ''
  subscriptionsLoading.value = false
  shareOpen.value = false
  shareUser.value = ''
}

function switchNode(id: string) {
  if (selectedNodeID.value !== id && xrayDraftDirty.value && !confirm('放弃未保存的代理配置修改并切换节点？')) return false
  selectNode(id)
  return true
}

function changeSelectedNode(event: Event) {
  const select = event.target as HTMLSelectElement
  if (!switchNode(select.value)) select.value = selectedNodeID.value
}

function openCore(node: NodeRecord) {
  if (switchNode(node.id)) coreDrawer.value = true
}

function openCoreInstallation(node: NodeRecord) {
  openNodeList('')
  openCore(node)
}

function shareNode(node: NodeRecord) {
  if (!switchNode(node.id)) return
  openPage('subscriptions')
  openShare()
}

function coreSummary(node: NodeRecord) {
  const summary = coreSummaries.value[node.id]
  if (!canReadCore.value || node.disabled || node.pending) return '—'
  if (summary === 'loading') return '读取中…'
  if (!summary || summary === 'unknown') return '状态不可用'
  if (!summary.version) return '未安装'
  const reported = nodeStatus(node) === '离线' ? '上次上报 ' : ''
  return `${reported}Xray ${summary.version} · ${summary.running ? '运行中' : '已停止'}`
}

async function loadVisibleCore() {
  if (!canReadCore.value || page.value !== 'nodes' || !loggedIn.value) return
  const summaries = coreSummaries.value
  const account = admin.value
  await Promise.all(visibleNodes.value.map(async node => {
    if (nodeStatus(node) !== '在线' || summaries[node.id]) return
    summaries[node.id] = 'loading'
    try {
      const options = await api<PanelXrayOptions>(panelXrayPath(node.id))
      if (admin.value === account && summaries[node.id] === 'loading') summaries[node.id] = options.current
    } catch {
      if (summaries[node.id] === 'loading') summaries[node.id] = 'unknown'
    }
  }))
}

function subscriptionStatus(row: XraySubscriptionRow) {
  if (!row.expires_at) return '无有效链接'
  if (row.expires_at * 1000 <= now.value) return '已过期'
  return row.active ? '有效' : '暂不可用'
}

function hasShareLink(row: XraySubscriptionRow) {
  const link = xraySubscriptionLink.value
  return subscriptionStatus(row) === '有效' && link?.username === row.username && link.expiresAt === row.expires_at
}

function openShare(user = '', showQr = false) {
  shareUser.value = user || (xraySubscriptionLink.value?.username ?? xraySubscriptions.value[0]?.username ?? '')
  shareTab.value = 'subscription'
  shareQrFirst.value = showQr
  shareOpen.value = true
}

async function copyIssuedLink(row: XraySubscriptionRow) {
  const link = xraySubscriptionLink.value
  if (!link || !hasShareLink(row)) return
  try {
    await navigator.clipboard.writeText(link.url)
    if (xraySubscriptionLink.value === link) subscriptionNotice.value = '已复制订阅链接。'
  } catch {
    if (xraySubscriptionLink.value === link) openShare(row.username)
  }
}

function taskStatus(task: StatusTask) {
  const labels: Record<string, string> = {
    QUEUED: '待投递', DELIVERED: '已投递', RUNNING: '执行中', SUCCEEDED: '执行成功',
    FAILED: '执行失败', ROLLED_BACK: '已回滚', NEEDS_RECONCILIATION: '待对账', EXPIRED: '已过期',
  }
  return labels[task.status] ?? task.status
}

function operationLabel(operation: string) {
  if (operation === 'core.status') return '只读状态查询'
  return xrayOperationLabel[operation as XrayOperation] ?? operation
}

function discardDraft() {
  loadDraft(panelXray.value)
  draftConflict.value = false
  panelXrayError.value = ''
}

async function openPreview() {
  if (!selectedNode.value) return
  previewOpen.value = true
  await refreshNodeTasks(selectedNode.value.id)
}

async function createNode() {
  if (loading.value) return
  loading.value = true
  error.value = ''
  try {
    const node = await api<NodeRecord>('/api/v1/admin/nodes', {
      method: 'POST',
      body: JSON.stringify({ name: newNodeName.value.trim(), node_group: newNodeGroup.value.trim() }),
    })
    nodes.value.push(node)
    newNodeName.value = ''
    addNodeOpen.value = false
  } catch (e) {
    error.value = e instanceof Error ? e.message : '添加节点失败'
  } finally {
    loading.value = false
  }
}

async function generateInstallCommand(node: NodeRecord) {
  error.value = ''
  installCommand.value = null
  commandCopied.value = false
  generatingCommand.value = true
  try {
    const result = await apiWithStepUp<{ command: string; expires_at: number }>('/api/v1/admin/nodes/' + encodeURIComponent(node.id) + '/install-command', {})
    if (loggedIn.value && page.value === 'nodes') installCommand.value = { node, ...result }
  } catch (e) {
    error.value = e instanceof Error ? e.message : '生成安装命令失败'
  } finally {
    generatingCommand.value = false
  }
}

async function copyInstallCommand() {
  if (!installCommand.value) return
  try {
    await navigator.clipboard.writeText(installCommand.value.command)
    commandCopied.value = true
  } catch {
    error.value = '复制失败，请手动选中安装命令'
  }
}

async function disableNode(id: string) {
  if (!confirm('确认禁用该节点？')) return
  try { await apiWithStepUp('/api/v1/admin/nodes/disable', { node_id: id }); if (installCommand.value?.node.id === id) installCommand.value = null; await refreshNodes() }
  catch (e) { error.value = e instanceof Error ? e.message : '禁用失败' }
}
function splitScope(value: string) { return [...new Set(value.split(/[\s,]+/).map((part) => part.trim()).filter(Boolean))] }
async function createAdmin() {
  try {
    const result = await apiWithStepUp<{ totp_secret: string }>('/api/v1/admin/admins', {
      username: newAdminUsername.value,
      password: newAdminPassword.value,
      role: newAdminRole.value,
      node_groups: splitScope(newAdminGroups.value),
      node_ids: splitScope(newAdminNodeIDs.value),
    })
    createdTOTP.value = result.totp_secret
    newAdminUsername.value = ''; newAdminPassword.value = ''; newAdminGroups.value = ''; newAdminNodeIDs.value = ''
    await loadAdmins()
  } catch (e) { error.value = e instanceof Error ? e.message : '创建管理员失败' }
}
async function disableAdmin(id: string) {
  if (!confirm('确认禁用该管理员并撤销其全部会话？')) return
  try { await apiWithStepUp('/api/v1/admin/admins/disable', { admin_id: id }); await loadAdmins() }
  catch (e) { error.value = e instanceof Error ? e.message : '禁用管理员失败' }
}
async function loadTasks(nodeID: string) {
  const { signal } = nodeReads
  const request = ++tasksRequest
  try {
    const records = await api<StatusTask[]>(`/api/v1/admin/tasks?node_id=${encodeURIComponent(nodeID)}`, { signal })
    if (!signal.aborted && request === tasksRequest && selectedNodeID.value === nodeID) {
      tasks.value = records
      taskError.value = ''
    }
  } catch (e) {
    if (!signal.aborted && request === tasksRequest && selectedNodeID.value === nodeID) {
      taskError.value = e instanceof Error ? e.message : '读取任务失败'
    }
  }
}
async function loadXrayInstalls(nodeID: string) {
  if (!admin.value?.can_prepare_xray_installs && !admin.value?.can_manage_xray) return
  const { signal } = nodeReads
  xrayInstallError.value = ''
  try {
    const records = await api<XrayInstall[]>(`/api/v1/admin/xray-installs?node_id=${encodeURIComponent(nodeID)}`, { signal })
    if (!signal.aborted && selectedNodeID.value === nodeID) xrayInstalls.value = records
  } catch (e) {
    if (signal.aborted || selectedNodeID.value !== nodeID) return
    xrayInstalls.value = []
    xrayInstallError.value = e instanceof Error ? e.message : '读取 Xray 操作提案失败'
  }
}
async function refreshNodeTasks(nodeID: string, background = false) {
  if (selectedNodeID.value !== nodeID) return
  await Promise.all([loadTasks(nodeID), loadXrayInstalls(nodeID), loadPanelXray(nodeID, { background })])
}

function panelXrayPath(nodeID: string) {
  return `/api/v1/admin/nodes/${encodeURIComponent(nodeID)}/xray`
}

async function loadXraySubscriptions(nodeID: string) {
  if (!admin.value?.can_manage_xray || subscriptionsLoading.value) return
  const { signal } = nodeReads
  subscriptionsLoading.value = true
  try {
    const rows = await api<XraySubscriptionRow[]>(panelXrayPath(nodeID) + '/subscriptions', { signal })
    if (signal.aborted || selectedNodeID.value !== nodeID) return
    xraySubscriptions.value = rows
    const link = xraySubscriptionLink.value
    if (link && (link.expiresAt * 1000 <= now.value || !rows.some(row =>
      row.username === link.username && row.expires_at === link.expiresAt,
    ))) {
      xraySubscriptionLink.value = null
    }
    xraySubscriptionError.value = ''
  } catch (cause) {
    if (signal.aborted || selectedNodeID.value !== nodeID) return
    if (cause instanceof ApiError && [401, 403, 404].includes(cause.status)) {
      xraySubscriptions.value = []
      xraySubscriptionLink.value = null
    }
    xraySubscriptionError.value = cause instanceof Error ? cause.message : '读取订阅失败。'
  } finally {
    if (!signal.aborted) subscriptionsLoading.value = false
  }
}

async function refreshSubscriptions() {
  const id = selectedNodeID.value
  if (id) await Promise.all([loadPanelXray(id), loadXraySubscriptions(id)])
}

async function changeXraySubscription(row: XraySubscriptionRow, action: 'issue' | 'revoke') {
  const nodeID = selectedNode.value?.id
  if (!nodeID || xraySubscriptionBusy.value || subscriptionsLoading.value) return
  if (action === 'revoke' && !confirm(`撤销 ${row.username} 的订阅链接？`)) return
  if (action === 'issue' && row.active && !confirm(`轮换 ${row.username} 的订阅链接？旧链接会立即失效。`)) return
  const { signal } = nodeReads
  xraySubscriptionBusy.value = true
  xraySubscriptionError.value = ''
  try {
    const issued = await apiWithStepUp<{ token?: string; expires_at?: number }>(
      panelXrayPath(nodeID) + '/subscriptions', { action, username: row.username },
    )
    if (signal.aborted || selectedNodeID.value !== nodeID) return
    if (xraySubscriptionLink.value?.username === row.username) xraySubscriptionLink.value = null
    if (issued.token && issued.expires_at) {
      const link = new URL('/subscription', window.location.origin)
      link.hash = issued.token
      xraySubscriptionLink.value = { username: row.username, url: link.href, expiresAt: issued.expires_at }
      row.active = true
      row.expires_at = issued.expires_at
      openShare(row.username)
    } else if (action === 'revoke') {
      row.active = false
      row.expires_at = undefined
    }
    await loadXraySubscriptions(nodeID)
  } catch (cause) {
    if (!signal.aborted && selectedNodeID.value === nodeID) {
      xraySubscriptionError.value = cause instanceof Error ? cause.message : '更新订阅失败。'
    }
  } finally {
    xraySubscriptionBusy.value = false
  }
}

async function loadPanelXray(nodeID: string, { background = false, savedPlan }: {
  background?: boolean; savedPlan?: XrayDraft
} = {}) {
  if (!admin.value?.can_manage_xray) return
  const { signal } = nodeReads
  const request = ++inventoryRequest
  if (!background && !panelXraySubmitting.value && !xrayDraftSaving.value) panelXrayError.value = ''
  if (selectedNode.value?.disabled || selectedNode.value?.pending) {
    panelXray.value = null
    return
  }
  try {
    const options = await api<PanelXrayOptions>(panelXrayPath(nodeID), { signal })
    if (!signal.aborted && request === inventoryRequest && selectedNodeID.value === nodeID) {
      const previous = panelXray.value
      const savedDraftChanged = !previous || (options.draft === null) !== (previous.draft === null) ||
        !matchesDraft(options, { plan: previous.draft ?? [], network: previous.draft_network ?? null })
      const savedByThisPage = savedPlan && matchesDraft(options, savedPlan)
      if (savedDraftChanged && (!xrayDraftDirty.value || savedByThisPage)) {
        loadDraft(options)
      } else if (savedDraftChanged) {
        draftConflict.value = true
      }
      panelXray.value = options
      if (!options.current.version) {
        selectedConfigCore.value = ''
        previewOpen.value = false
      }
      panelXrayReadError.value = ''
      coreSummaries.value[nodeID] = options.current
    }
  } catch (e) {
    if (signal.aborted || request !== inventoryRequest || selectedNodeID.value !== nodeID) return
    coreSummaries.value[nodeID] = 'unknown'
    panelXrayReadError.value = e instanceof Error ? e.message : '读取节点 Xray 状态失败'
  }
}

function matchesDraft(options: PanelXrayOptions | null, draft: XrayDraft) {
  return JSON.stringify(options?.draft ?? []) === JSON.stringify(draft.plan) &&
    JSON.stringify(options?.draft_network ?? null) === JSON.stringify(draft.network)
}

function loadDraft(options: PanelXrayOptions | null) {
  xrayDraft.value = options?.draft?.map(inbound => ({ ...inbound, users: [...inbound.users] })) ?? []
  draftNetwork.value = copyNetwork(options?.draft_network)
}

function approvedProtocol(port: number): XrayPortProtocol | undefined {
  const catalog = panelXray.value?.current.catalog
  return catalog?.port_protocols?.[port] ?? (catalog?.http_ports?.includes(port) ? 'http' : undefined)
}

function approvedTLSCert(port: number) {
  if (approvedProtocol(port) === 'trojan') return panelXray.value?.current.catalog?.trojan_trust?.sha256
  return undefined
}

function approvedRealityKey(port: number) {
  if (approvedProtocol(port) === 'vless-reality') return panelXray.value?.current.catalog?.reality_public_key
  return undefined
}

function approvedPublicEndpoint(port: number) {
  return panelXray.value?.current.catalog?.public_endpoints?.[port]
}

function endpointLabel(endpoint: XrayPublicEndpoint | undefined, port: number) {
  return endpoint ? `${endpoint.address}:${endpoint.port}` : `127.0.0.1:${port}`
}

function inboundProtocolLabel(protocol: XrayInbound['protocol']) {
  if (protocol === 'http') return '仅 HTTP'
  return protocol ? xrayProtocolName[protocol] : 'SOCKS5 / HTTP'
}

function approvedUsers(port: number): string[] {
  const catalog = panelXray.value?.current.catalog
  if (!catalog?.ports.includes(port)) return []
  const protocol = approvedProtocol(port)
  return (protocol && protocol !== 'http' ? catalog.protocol_users?.[protocol] : catalog.users) ?? []
}

function draftHasUser(port: number, user: string) {
  return xrayDraft.value.find(inbound => inbound.port === port)?.users.includes(user) ?? false
}

function draftUsers(port: number) {
  return [...new Set([
    ...approvedUsers(port),
    ...(xrayDraft.value.find(inbound => inbound.port === port)?.users ?? []),
  ])].sort()
}

function canToggleDraftUser(port: number, user: string) {
  return draftHasUser(port, user) || (draftGrantCount.value < 16 && approvedUsers(port).includes(user))
}

function toggleDraftUser(port: number, user: string) {
  if (draftDisabled.value || !canToggleDraftUser(port, user)) return
  const existing = xrayDraft.value.find(inbound => inbound.port === port)
  const users = existing?.users ?? []
  const next = users.includes(user) ? users.filter(name => name !== user) : [...users, user].sort()
  xrayDraft.value = xrayDraft.value.filter(inbound => inbound.port !== port)
  if (next.length) {
    xrayDraft.value.push({
      port, protocol: existing ? existing.protocol : approvedProtocol(port),
      tls_cert_sha256: existing ? existing.tls_cert_sha256 : approvedTLSCert(port),
      reality_public_key: existing ? existing.reality_public_key : approvedRealityKey(port),
      public_endpoint: existing ? existing.public_endpoint : approvedPublicEndpoint(port), users: next,
    })
    xrayDraft.value.sort((left, right) => left.port - right.port)
  } else if (draftNetwork.value) {
    draftNetwork.value = { ...draftNetwork.value, routes: draftNetwork.value.routes.filter(route => route.inbound_port !== port) }
  }
}

async function saveXrayDraft() {
  const node = selectedNode.value
  const options = panelXray.value
  if (!node || !options?.current.catalog || xrayDraftSaving.value || panelXrayReadError.value || draftConflict.value) return
  const { signal } = nodeReads
  const { ports } = options.current.catalog
  const plan = xrayDraft.value.map(inbound => ports.includes(inbound.port) ? {
    port: inbound.port, protocol: approvedProtocol(inbound.port), tls_cert_sha256: approvedTLSCert(inbound.port),
    reality_public_key: approvedRealityKey(inbound.port), public_endpoint: approvedPublicEndpoint(inbound.port), users: inbound.users,
  } : inbound)
  const savedPlan = { plan, network: draftNetwork.value }
  xrayDraftSaving.value = true
  panelXrayError.value = ''
  try {
    await api(panelXrayPath(node.id) + '/draft', { method: 'PUT', body: JSON.stringify({ state: options.state, ...savedPlan }) })
    if (!signal.aborted && selectedNodeID.value === node.id) await loadPanelXray(node.id, { savedPlan })
  } catch (e) {
    if (!signal.aborted && selectedNodeID.value === node.id) panelXrayError.value = e instanceof Error ? e.message : '保存代理配置草稿失败'
  } finally {
    xrayDraftSaving.value = false
  }
}

async function submitPanelXray(operation: XrayOperation = panelXrayOperation.value) {
  const node = selectedNode.value
  const options = panelXray.value
  if (!node || !options || panelXraySubmitting.value || panelXrayReadError.value) return
  if (operation === 'config.apply' && !canApplyXrayDraft.value) return
  const { signal } = nodeReads
  const version = operation === 'config.apply' ? options.current.version : panelXrayUsesArtifact.value ? panelXrayVersion.value : ''
  const dangerous = operation === 'core.downgrade' || operation === 'core.uninstall' || operation === 'config.apply'
  const replacesConfig = version !== '' && panelXrayUsesArtifact.value && !!options.current.config
  if (dangerous || replacesConfig) {
    const target = version ? ` → ${version}` : ''
    const note = replacesConfig ? '切换版本会停用已应用的入站。' : ''
    const preview = operation === 'config.apply' ? `\n配置 SHA-256 ${options.current.candidate?.sha256}` : ''
    if (!confirm(`确认${xrayOperationLabel[operation]}节点「${node.name}」的 Xray ${options.current.version}${target}？${note}${preview}`)) return
  }
  const fields = { operation, version, state: options.state,
    catalog_version: version ? options.catalog_version : 0, confirm_operation: dangerous ? operation : '' }
  const intent = JSON.stringify({ node_id: node.id, ...fields })
  if (panelXrayRetry?.intent !== intent) panelXrayRetry = { intent, id: crypto.randomUUID().replaceAll('-', '') }
  panelXraySubmitting.value = true
  panelXrayError.value = ''
  try {
    const task = await apiWithStepUp<StatusTask>(panelXrayPath(node.id), { ...fields, task_id: panelXrayRetry.id })
    panelXrayRetry = undefined
    if (!signal.aborted && selectedNodeID.value === node.id) {
      tasks.value = [task, ...tasks.value.filter(record => record.task_id !== task.task_id)]
      previewOpen.value = false
      await refreshNodeTasks(node.id)
    }
  } catch (e) {
    if (!signal.aborted && selectedNodeID.value === node.id) panelXrayError.value = e instanceof Error ? e.message : '提交 Xray 任务失败'
  } finally {
    panelXraySubmitting.value = false
  }
}

function runtimeUpdatePath(nodeID: string) {
  return `/api/v1/admin/nodes/${encodeURIComponent(nodeID)}/runtime-updates`
}

async function loadRuntimeUpdates(nodeID: string) {
  if (!admin.value?.can_update_runtime) return
  runtimeUpdateError.value = ''
  try {
    const updates = await api<RuntimeUpdate[]>(runtimeUpdatePath(nodeID))
    if (selectedNode.value?.id === nodeID) runtimeUpdates.value = updates
  } catch (e) {
    if (selectedNode.value?.id === nodeID) runtimeUpdateError.value = e instanceof Error ? e.message : '读取运行时更新失败'
  }
}

function encodeRuntimeProof(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(new Error('读取签名材料失败'))
    reader.onload = () => resolve(String(reader.result).split(',', 2)[1])
    reader.readAsDataURL(file)
  })
}

async function submitRuntimeUpdate(event: Event) {
  const nodeID = selectedNode.value?.id
  if (!nodeID || runtimeUpdateBusy.value || !(event.currentTarget instanceof HTMLFormElement)) return
  const form = event.currentTarget
  const files = new FormData(form)
  runtimeUpdateBusy.value = true
  runtimeUpdateError.value = ''
  try {
    const proof: Record<string, string> = {}
    for (const { name, label, limit } of runtimeProofFields) {
      const file = files.get(name)
      if (!(file instanceof File) || !file.size || file.size > limit) throw new Error(`${label}文件大小无效`)
      proof[name] = await encodeRuntimeProof(file)
    }
    await apiWithStepUp<RuntimeUpdate>(runtimeUpdatePath(nodeID), { package: proof })
    form.reset()
    if (selectedNode.value?.id === nodeID) await loadRuntimeUpdates(nodeID)
  } catch (e) {
    if (selectedNode.value?.id === nodeID) runtimeUpdateError.value = e instanceof Error ? e.message : '提交运行时更新失败'
  } finally {
    runtimeUpdateBusy.value = false
  }
}
async function createXrayInstall() {
  const nodeID = selectedNode.value?.id
  if (!nodeID || xrayInstallBusy.value) return
  const { operation, version, architecture, sha256, manifest_version, current_version, current_sha256 } = xrayInstallInput.value
  const fields = {
    operation, version, architecture, sha256, node_id: nodeID,
    manifest_version: xrayUsesArtifact.value ? manifest_version : undefined,
    current_version: xrayVersionChange.value ? current_version : undefined,
    current_sha256: xrayVersionChange.value ? current_sha256 : undefined,
  }
  const intent = JSON.stringify(fields)
  if (xrayInstallRetry?.intent !== intent) xrayInstallRetry = { intent, id: crypto.randomUUID().replaceAll('-', '') }
  xrayInstallError.value = ''
  xrayInstallBusy.value = true
  try {
    await apiWithStepUp<XrayInstall>('/api/v1/admin/xray-installs', { ...fields, task_id: xrayInstallRetry.id })
    xrayInstallRetry = undefined
    if (selectedNode.value?.id === nodeID) await loadXrayInstalls(nodeID)
  } catch (e) {
    xrayInstallError.value = e instanceof Error ? e.message : '预留 Xray 操作序号失败'
  } finally {
    xrayInstallBusy.value = false
  }
}
function downloadXrayProposal(install: XrayInstall) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(install.proposal, null, 2) + '\n'], { type: 'application/json' }))
  const link = document.createElement('a')
  link.href = url
  link.download = `proposal-${install.proposal.task_id}.json`
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
async function readXrayJSON(file: File): Promise<unknown> {
  if (file.size === 0 || file.size > 16 * 1024) throw new Error('JSON 文件应为 1 到 16384 字节')
  return JSON.parse(await file.text())
}
async function uploadSignedXrayInstall(install: XrayInstall, event: Event) {
  if (xrayInstallBusy.value) return
  const form = event.currentTarget as HTMLFormElement
  const fields = new FormData(form)
  const signedTask = fields.get('task')
  const signedRequest = fields.get('request')
  if (!(signedTask instanceof File) || !(signedRequest instanceof File)) return
  xrayInstallError.value = ''
  xrayInstallBusy.value = true
  try {
    const [task, request] = await Promise.all([readXrayJSON(signedTask), readXrayJSON(signedRequest)])
    const { task_id, node_id } = install.proposal
    await apiWithStepUp<XrayInstall>(`/api/v1/admin/xray-installs/${encodeURIComponent(task_id)}/signed-task`, { request, task })
    form.reset()
    if (selectedNode.value?.id === node_id) await loadXrayInstalls(node_id)
  } catch (e) {
    xrayInstallError.value = e instanceof Error ? e.message : '核验签发任务失败'
  } finally {
    xrayInstallBusy.value = false
  }
}
function xrayTask(id: string) {
  return tasks.value.find(task => task.task_id === id)
}
function xrayTaskResult(install: XrayInstall) {
  const status = xrayTask(install.proposal.task_id)?.status
  if (status === 'NEEDS_RECONCILIATION') return '待对账'
  if (status === 'SUCCEEDED') return '已' + xrayOperationLabel[install.proposal.operation]
  if (status === 'FAILED') return '执行失败'
  if (status === 'ROLLED_BACK') return '已回滚'
  return status
}
async function dispatchXrayInstall(install: XrayInstall) {
  if (xrayInstallBusy.value) return
  const { task_id, node_id, operation, version, architecture, sha256, current_version, current_sha256 } = install.proposal
  let message = `确认向节点 ${node_id} 投递 Xray ${xrayOperationLabel[operation]}任务？`
  let confirmOperation: XrayOperation | undefined
  if (operation === 'core.downgrade') {
    message = `确认将节点 ${node_id} 的 Xray（${architecture}）从 ${current_version} 降级到 ${version}？\n当前 SHA-256 ${current_sha256}\n目标 SHA-256 ${sha256}`
    confirmOperation = operation
  } else if (operation === 'core.uninstall') {
    message = `确认卸载节点 ${node_id} 的 Xray ${version}（${architecture}）？\nSHA-256 ${sha256}`
    confirmOperation = operation
  }
  if (!confirm(message)) return
  xrayInstallError.value = ''
  xrayInstallBusy.value = true
  try {
    await apiWithStepUp<StatusTask>(`/api/v1/admin/xray-installs/${encodeURIComponent(task_id)}/dispatch`, { confirm_operation: confirmOperation })
    if (selectedNode.value?.id === node_id) await refreshNodeTasks(node_id)
  } catch (e) {
    xrayInstallError.value = e instanceof Error ? e.message : '投递 Xray 操作失败'
  } finally {
    xrayInstallBusy.value = false
  }
}
async function createStatusTask() {
  const nodeID = selectedNodeID.value
  if (!nodeID) return
  error.value = ''
  try {
    const requestID = crypto.randomUUID().replaceAll('-', '')
    await api<StatusTask>('/api/v1/admin/tasks', { method: 'POST', body: JSON.stringify({ request_id: requestID, node_id: nodeID, core: statusCore.value }) })
    if (selectedNodeID.value === nodeID) await loadTasks(nodeID)
  } catch (e) { error.value = e instanceof Error ? e.message : '创建状态查询失败' }
}
async function controlStatusTask(task: StatusTask, action: 'cancel' | 'skip' | 'void') {
  const message = action === 'cancel'
    ? '确认取消该只读查询？仅尚未开始的任务会被取消。'
    : action === 'void' ? '确认关闭该从未投递的只读查询序号？已投递任务不能这样关闭。' : '确认跳过该已过期的只读查询？'
  if (!confirm(message)) return
  error.value = ''
  try {
    const requestID = crypto.randomUUID().replaceAll('-', '')
    await api<StatusTask>(`/api/v1/admin/tasks/${encodeURIComponent(task.task_id)}/${action}`, { method: 'POST', body: JSON.stringify({ request_id: requestID }) })
    if (selectedNodeID.value === task.node_id) await loadTasks(task.node_id)
  } catch (e) { error.value = e instanceof Error ? e.message : action === 'cancel' ? '取消任务失败' : action === 'void' ? '关闭未投递任务失败' : '跳过任务失败' }
}
async function logout() {
  try {
    await api('/api/v1/admin/logout', { method: 'POST', body: '{}' })
  } finally {
    csrfToken = ''
    admin.value = null
    loggedIn.value = false
    selectNode('')
    page.value = 'overview'
    coreDrawer.value = false
    addNodeOpen.value = false
    nodes.value = []
    nodesError.value = ''
    coreSummaries.value = {}
    audits.value = []
    managedAdmins.value = []
    xrayInstallRetry = undefined
    panelXrayRetry = undefined
    createdTOTP.value = ''
    installCommand.value = null
  }
}

watch([nodeGroup, nodeStatusFilter], () => { nodePage.value = 1 })
watch(shareUser, () => { sharePort.value = '' })
watch(nodePageCount, count => { nodePage.value = Math.min(nodePage.value, count) })
watch([page, loggedIn, () => visibleNodes.value.map(node => node.id + ':' + node.last_seen).join(',')], loadVisibleCore)

watch(page, next => {
  if (next === 'audit') void loadAudit()
  if (next === 'versions') void Promise.all([loadCoreCatalog(), loadCoreBackups()])
  if (next === 'admins') void loadAdmins()
})

watch([page, selectedNodeID, coreDrawer], ([next, id, drawer]) => {
  if (!id && (next === 'subscriptions' || next === 'tasks')) {
    selectNode((nodes.value.find(node => !node.disabled && !node.pending) ?? nodes.value[0])?.id ?? '')
    return
  }
  if (!id) return
  if (drawer || next === 'config') void refreshNodeTasks(id)
  if (next === 'subscriptions') void refreshSubscriptions()
  if (next === 'tasks') void Promise.all([loadTasks(id), loadRuntimeUpdates(id)])
})

const refreshTimer = window.setInterval(() => {
  now.value = Date.now()
  if (document.hidden || !loggedIn.value) return
  if ((page.value === 'overview' || page.value === 'nodes') && now.value - lastNodeRefresh >= 30_000) {
    void refreshNodes()
  }
  const id = selectedNodeID.value
  if (!id || panelXraySubmitting.value || xrayDraftSaving.value) return
  const awaitingCore = coreDrawer.value && latestCoreTask.value?.active
  const awaitingConfig = page.value === 'config' && latestApplyTask.value &&
    (latestApplyTask.value.active || (latestApplyTask.value.status === 'SUCCEEDED' && !latestApplyVerified.value &&
      now.value - Date.parse(latestApplyTask.value.issued_at) < 120_000))
  if (awaitingCore || awaitingConfig) void refreshNodeTasks(id, true)
}, 8_000)

onUnmounted(() => {
  window.clearInterval(refreshTimer)
  nodeReads.abort()
})

onMounted(async () => {
  try {
    admin.value = await api<AdminInfo>('/api/v1/admin/me')
    csrfToken = admin.value.csrf_token
    loggedIn.value = true
    await refreshNodes()
  } catch {
    loggedIn.value = false
    try {
      manualBootstrap.value = (await api<{ manual_bootstrap: boolean }>('/api/v1/admin/setup')).manual_bootstrap
    } catch {
      manualBootstrap.value = false
    }
  }
})
</script>

<template>
  <main v-if="!loggedIn" class="shell auth-shell">
    <header class="brand auth-brand"><span class="brand-mark" aria-hidden="true">M</span><h1>MCUI</h1></header>
    <p v-if="error" class="notice" role="status">{{ error }}</p>
    <section class="auth-grid">
      <form v-if="firstLoginSecret" class="card" @submit.prevent="completeFirstLogin">
        <h2>设置管理员密码和 MFA</h2>
        <label>新密码（至少 12 位）<input v-model="firstLoginPassword" type="password" autocomplete="new-password" minlength="12" maxlength="1024" required /></label>
        <label>把此密钥添加到身份验证器<input :value="firstLoginSecret" readonly autocomplete="off" /></label>
        <label>身份验证器验证码<input v-model="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required /></label>
        <button :disabled="loading">保存设置</button>
        <button class="outline" type="button" :disabled="loading" @click="clearFirstLogin">返回登录</button>
      </form>
      <form v-else class="card" @submit.prevent="login">
        <h2>管理员登录</h2>
        <label>用户名<input v-model="username" autocomplete="username" required /></label>
        <label>密码<input v-model="password" type="password" autocomplete="current-password" required /></label>
        <label>身份验证器验证码（首次登录可留空）<input v-model="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" /></label>
        <button :disabled="loading">登录</button>
      </form>
      <form v-if="manualBootstrap && !firstLoginSecret" class="card secondary" @submit.prevent="bootstrap"><h2>初始化安全管理员</h2><label>初始化令牌<input v-model="bootstrapToken" type="password" required /></label><label>用户名<input v-model="bootstrapUser" required /></label><label>密码（至少 12 位）<input v-model="bootstrapPassword" type="password" minlength="12" required /></label><label>TOTP 密钥（Base32）<input v-model="bootstrapTOTP" autocomplete="off" required /></label><button class="outline" :disabled="loading">创建管理员</button></form>
    </section>
  </main>

  <div v-else class="admin-layout">
    <AdminSidebar :page="page" :username="admin?.username ?? ''" :can-manage-admins="!!admin?.can_manage_admins"
      @navigate="openPage" @logout="logout" />
    <main class="admin-main">
      <header class="page-header section-head">
        <h1>{{ pageTitle[page] }}</h1>
        <div v-if="page === 'overview' || page === 'nodes'" class="actions">
          <button class="outline" type="button" :disabled="nodesLoading" @click="refreshNodes">{{ nodesLoading ? '刷新中…' : '刷新节点' }}</button>
          <button v-if="page === 'nodes' && admin?.can_create_nodes" type="button" @click="addNodeOpen = true">添加节点</button>
        </div>
        <div v-if="page === 'config'" class="actions config-selectors">
          <label class="node-select">Agent
            <select :value="selectedNodeID" :disabled="!canReadCore" @change="changeSelectedNode">
              <option value="" disabled>请选择 Agent</option>
              <option v-for="node in nodes" :key="node.id" :value="node.id">{{ node.name }} · {{ node.group }}</option>
            </select>
          </label>
          <label class="node-select">Core 类型
            <select v-model="selectedConfigCore" :disabled="!canReadCore || !selectedNode || selectedNode.pending || selectedNode.disabled || !installedXrayVersion || !!panelXrayReadError">
              <option value="" disabled>请选择 Core 类型</option>
              <option v-if="installedXrayVersion && !panelXrayReadError" value="xray">Xray {{ installedXrayVersion }}</option>
            </select>
          </label>
        </div>
        <label v-else-if="page === 'subscriptions' || page === 'tasks'" class="node-select">当前节点
          <select :value="selectedNodeID" @change="changeSelectedNode">
            <option v-if="!selectedNodeID" value="" disabled>请选择节点</option>
            <option v-for="node in nodes" :key="node.id" :value="node.id">{{ node.name }} · {{ node.group }}</option>
          </select>
        </label>
      </header>
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
      <p v-if="nodesError && (page === 'overview' || page === 'nodes')" class="notice" role="alert">{{ nodesError }}</p>

      <template v-if="page === 'overview'">
        <section class="metrics" aria-label="节点状态">
          <button v-for="status in overviewStatuses" :key="status" class="metric" type="button" @click="openNodeList(status)">
            <span :class="['status', status === '在线' ? 'on' : status === '离线' ? 'off' : 'idle']">{{ status }}</span>
            <strong>{{ nodeCounts[status] }}</strong>
          </button>
        </section>
        <section class="card overview-nodes">
          <div>
            <h2>节点管理</h2>
            <p>共 {{ nodes.length }} 个节点<span v-if="nodeCounts.已禁用">，{{ nodeCounts.已禁用 }} 个已禁用</span></p>
          </div>
          <button type="button" @click="openNodeList('')">查看节点列表</button>
        </section>
      </template>

      <section v-else-if="page === 'nodes'" class="card">
        <div class="filters">
          <label>分组<select v-model="nodeGroup"><option value="">全部分组</option><option v-for="group in nodeGroups" :key="group">{{ group }}</option></select></label>
          <label>Agent 状态<select v-model="nodeStatusFilter"><option value="">全部状态</option>
            <option v-for="status in [...overviewStatuses, '已禁用']" :key="status">{{ status }}</option>
          </select></label>
        </div>
        <div v-if="visibleNodes.length" class="table-wrap">
          <table class="data-table" aria-label="节点列表">
            <thead><tr><th scope="col">节点</th><th scope="col">分组</th><th scope="col">Agent</th><th scope="col">Core</th><th scope="col">操作</th></tr></thead>
            <tbody>
              <tr v-for="node in visibleNodes" :key="node.id">
                <th scope="row"><strong>{{ node.name }}</strong><small class="mono">{{ node.id }}</small></th>
                <td>{{ node.group }}</td>
                <td>
                  <span :class="['status', nodeStatus(node) === '在线' ? 'on' : nodeStatus(node) === '待接入' ? 'idle' : 'off']">{{ nodeStatus(node) }}</span>
                  <small v-if="node.last_seen">{{ new Date(node.last_seen * 1000).toLocaleString() }}</small>
                </td>
                <td>{{ coreSummary(node) }}</td>
                <td><div class="actions">
                  <button v-if="admin?.can_manage_xray || admin?.can_prepare_xray_installs" type="button" class="outline" @click="openCore(node)">管理 Core</button>
                  <button v-if="admin?.can_manage_xray && !node.disabled" type="button" class="quiet" @click="openPage('config', node)">代理配置</button>
                  <button v-if="admin?.can_manage_xray && !node.disabled" type="button" class="quiet" @click="shareNode(node)">分享</button>
                  <button v-if="admin?.can_install_agents && !node.disabled" type="button" class="quiet"
                    :disabled="generatingCommand" @click="generateInstallCommand(node)">生成安装命令</button>
                  <button v-if="admin?.can_disable_nodes && !node.disabled" type="button" class="danger" @click="disableNode(node.id)">禁用</button>
                </div></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="empty">{{ nodesLoading ? '正在读取节点…' : nodes.length ? '没有符合筛选条件的节点。' : '暂无节点。' }}</p>
        <div v-if="nodePageCount > 1" class="pager actions">
          <button type="button" class="outline" :disabled="nodePage === 1" @click="nodePage--">上一页</button>
          <span>{{ nodePage }} / {{ nodePageCount }}</span>
          <button type="button" class="outline" :disabled="nodePage === nodePageCount" @click="nodePage++">下一页</button>
        </div>
      </section>

      <section v-else-if="page === 'config'" class="card page-stack">
        <p v-if="!admin?.can_manage_xray" class="empty">当前账号没有代理配置权限。</p>
        <p v-else-if="!selectedNode" class="empty">请先从页头选择 Agent。</p>
        <p v-else-if="selectedNode.disabled" class="empty">此 Agent 已禁用。</p>
        <p v-else-if="selectedNode.pending" class="empty">此 Agent 尚未接入。请先在节点管理中完成接入。</p>
        <div v-else-if="panelXrayReadError" class="empty">
          <p role="alert">无法读取此 Agent 的 Core 安装状态。{{ panelXrayReadError }}</p>
          <button type="button" class="outline" @click="loadPanelXray(selectedNode.id)">重试读取 Core</button>
        </div>
        <p v-else-if="!panelXray" class="empty" role="status">正在读取 Agent 上报的 Core 安装状态…</p>
        <div v-else-if="!installedXrayVersion" class="empty">
          <p>此 Agent 尚未安装可配置的 Core。请前往节点管理安装。</p>
          <button type="button" @click="openCoreInstallation(selectedNode)">前往节点管理安装 Core</button>
        </div>
        <p v-else-if="selectedConfigCore !== 'xray'" class="empty">请选择已安装的 Core 类型后进行配置。</p>
        <template v-else>
          <div class="context-bar">
            <span v-if="panelXray?.current.config_revision">{{ appliedConfigVerified ? '已生效修订' : '节点上报修订' }} <strong>{{ panelXray.current.config_revision }}</strong></span>
            <span v-else>暂无生效修订</span>
            <span class="status idle">{{ draftStatus }}</span>
          </div>
          <div class="tabs" role="group" aria-label="代理配置类型">
            <button type="button" :aria-pressed="draftTab === 'inbound'" @click="draftTab = 'inbound'">入站</button>
            <button type="button" :aria-pressed="draftTab === 'client'" @click="draftTab = 'client'">客户端</button>
            <button type="button" :aria-pressed="draftTab === 'routing'" @click="draftTab = 'routing'">路由</button>
            <button type="button" :aria-pressed="draftTab === 'outbound'" @click="draftTab = 'outbound'">出站</button>
          </div>
          <p v-if="panelXrayError" class="notice" role="alert">{{ panelXrayError }}</p>
          <p v-if="draftConflict" class="notice" role="alert">主控草稿已更新。放弃未保存修改后，重新核对当前草稿。</p>
          <template v-if="draftTab === 'inbound'">
            <div v-if="panelXray?.current.catalog && draftPorts.length" class="table-wrap">
              <table class="data-table inbound-table" aria-label="入站授权草稿">
                <thead><tr><th scope="col">入站</th><th scope="col">协议</th><th scope="col">监听及接入端口</th><th scope="col">用户授权</th></tr></thead>
                <tbody>
                  <tr v-for="port in draftPorts" :key="port">
                    <th scope="row">入站 {{ port }}</th>
                    <td>{{ panelXray.current.catalog.ports.includes(port) ? inboundProtocolLabel(approvedProtocol(port)) : '已移出节点目录' }}</td>
                    <td><span>{{ port }}</span><small>{{ endpointLabel(approvedPublicEndpoint(port), port) }}</small></td>
                    <td>
                      <details>
                        <summary>{{ xrayDraft.find(inbound => inbound.port === port)?.users.join('、') || '未授权' }} · 查看与编辑</summary>
                        <fieldset class="inbound-users" :disabled="draftDisabled">
                          <legend class="sr-only">入站 {{ port }} 用户授权</legend>
                          <p v-if="approvedTLSCert(port)">TLS 证书 SHA-256 <code>{{ approvedTLSCert(port) }}</code></p>
                          <p v-if="approvedRealityKey(port)">REALITY 公钥 <code>{{ approvedRealityKey(port) }}</code></p>
                          <label v-for="user in draftUsers(port)" :key="user">
                            <input type="checkbox" :checked="draftHasUser(port, user)"
                              :disabled="!canToggleDraftUser(port, user)"
                              @change="toggleDraftUser(port, user)" />{{ user }}
                          </label>
                          <p v-if="!draftUsers(port).length">节点尚未登记此协议的凭据。</p>
                        </fieldset>
                      </details>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p v-else class="empty">{{ panelXray ? '节点尚未上报面板可管理的入站目录。' : '等待节点上报 Xray 状态。' }}</p>
            <div v-if="panelXray?.current.config" class="revision-summary">
              <strong>节点当前配置</strong>
              <code>{{ panelXray.current.config.sha256 }}</code>
              <ul v-if="panelXray.current.applied?.length">
                <li v-for="inbound in panelXray.current.applied" :key="inbound.port">
                  {{ endpointLabel(inbound.public_endpoint, inbound.port) }} · {{ inboundProtocolLabel(inbound.protocol) }} · {{ inbound.users.join('、') }}
                </li>
              </ul>
              <span v-else>{{ panelXray.current.applied ? '无已授权入站' : endpointLabel(undefined, panelXray.current.config.port) }}</span>
            </div>
          </template>
          <template v-else-if="draftTab === 'client'">
            <div class="filters">
              <label>客户端<input v-model="clientSearch" type="search" placeholder="搜索用户名" /></label>
              <button type="button" class="outline" @click="openPage('subscriptions')">管理订阅</button>
            </div>
            <div v-if="clients.length" class="table-wrap">
              <table class="data-table" aria-label="客户端授权">
                <thead><tr><th scope="col">客户端</th><th scope="col">生效入站</th><th scope="col">入站授权草稿</th></tr></thead>
                <tbody>
                  <tr v-for="user in clients" :key="user">
                    <th scope="row">{{ user }}</th>
                    <td>{{ subscriptionInbounds.filter(inbound => inbound.users.includes(user)).map(inbound => inbound.port).join('、') || '—' }}</td>
                    <td><fieldset class="inbound-users" :disabled="draftDisabled">
                      <legend class="sr-only">{{ user }} 的入站授权</legend>
                      <label v-for="port in draftPorts.filter(port => draftUsers(port).includes(user))" :key="port">
                        <input type="checkbox" :checked="draftHasUser(port, user)" :disabled="!canToggleDraftUser(port, user)"
                          @change="toggleDraftUser(port, user)" />{{ port }} · {{ inboundProtocolLabel(approvedProtocol(port)) }}
                      </label>
                      <p v-if="!draftPorts.some(port => draftUsers(port).includes(user))">节点已移除此客户端的凭据。</p>
                    </fieldset></td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p v-else class="empty">{{ clientSearch ? '没有匹配的客户端。' : '节点尚未登记客户端凭据。' }}</p>
          </template>
          <XrayNetworkEditor v-else-if="panelXray.current.catalog" :tab="draftTab" :network="draftNetwork"
            :destinations="networkDestinations" :inbound-ports="xrayDraft.map(inbound => inbound.port)" :disabled="draftDisabled"
            @change="draftNetwork = $event" />
          <p v-else class="empty">节点尚未上报代理配置目录。</p>
          <p v-if="draftGrantCount >= 16 && (draftTab === 'inbound' || draftTab === 'client')" class="feedback">已达到每个节点 16 条入站授权的上限。</p>
          <p v-if="xrayDraftPolicyChanged">节点批准的端口、接入地址或服务端身份有变化。核对后重新保存草稿。</p>
          <p v-if="latestApplyTask" role="status">最近下发 #{{ latestApplyTask.sequence }} · {{ taskStatus(latestApplyTask) }}
            <template v-if="latestApplyTask.status === 'SUCCEEDED' && !latestApplyVerified">，等待节点上报对应修订</template>
          </p>
          <div class="actions">
            <button type="button" class="outline" :disabled="!panelXray?.current.catalog || !!panelXrayReadError || draftConflict || xrayDraftSaving || panelXraySubmitting || (!xrayDraftDirty && !xrayDraftPolicyChanged && panelXray.draft !== null)"
              @click="saveXrayDraft">{{ xrayDraftSaving ? '保存中…' : '保存草稿' }}</button>
            <button type="button" class="outline" :disabled="!panelXray || xrayDraftDirty || draftConflict" @click="openPreview">预览变更</button>
            <button type="button" :disabled="!canApplyXrayDraft" @click="openPreview">下发配置</button>
            <button type="button" class="quiet" @click="refreshNodeTasks(selectedNode.id)">刷新状态</button>
            <button v-if="xrayDraftDirty || draftConflict" type="button" class="quiet" :disabled="xrayDraftSaving" @click="discardDraft">放弃未保存修改</button>
          </div>
        </template>
      </section>

      <section v-else-if="page === 'subscriptions'" class="card">
        <p v-if="!admin?.can_manage_xray" class="empty">当前账号没有客户端订阅管理权限。</p>
        <p v-else-if="!selectedNode" class="empty">添加节点或从页头选择节点。</p>
        <template v-else>
          <div class="filters">
            <label>用户名<input v-model="subscriptionSearch" type="search" placeholder="搜索用户名" /></label>
            <label>订阅状态<select v-model="subscriptionFilter">
              <option value="">全部状态</option>
              <option v-for="status in ['有效', '无有效链接', '已过期', '暂不可用']" :key="status">{{ status }}</option>
            </select></label>
            <button type="button" class="outline" :disabled="subscriptionsLoading || xraySubscriptionBusy"
              @click="refreshSubscriptions">刷新订阅</button>
          </div>
          <p v-if="xraySubscriptionError" class="notice" role="alert">{{ xraySubscriptionError }}</p>
          <p v-if="subscriptionNotice" class="feedback" role="status">{{ subscriptionNotice }}</p>
          <div v-if="subscriptionRows.length" class="table-wrap">
            <table class="data-table" aria-label="客户端订阅">
              <thead><tr><th scope="col">客户端</th><th scope="col">已授权入站</th><th scope="col">订阅状态</th><th scope="col">到期时间</th><th scope="col">操作</th></tr></thead>
              <tbody>
                <tr v-for="row in subscriptionRows" :key="row.username">
                  <th scope="row"><button type="button" class="text-button" @click="openShare(row.username)">{{ row.username }}</button></th>
                  <td>{{ subscriptionInbounds.filter(inbound => inbound.users.includes(row.username)).map(inbound => inbound.port).join('、') || '—' }}</td>
                  <td><span :class="['status', subscriptionStatus(row) === '有效' ? 'on' : 'idle']">{{ subscriptionStatus(row) }}</span></td>
                  <td>{{ row.expires_at ? new Date(row.expires_at * 1000).toLocaleString() : '—' }}</td>
                  <td><div class="actions">
                    <template v-if="hasShareLink(row)">
                      <button type="button" class="outline" @click="copyIssuedLink(row)">复制订阅</button>
                      <button type="button" class="outline" @click="openShare(row.username, true)">二维码</button>
                    </template>
                    <button v-if="row.eligible && !row.expires_at" type="button" :disabled="xraySubscriptionBusy || subscriptionsLoading"
                      @click="changeXraySubscription(row, 'issue')">签发链接</button>
                    <details v-else-if="row.expires_at" class="row-menu">
                      <summary>更多</summary>
                      <div class="actions">
                        <button v-if="row.eligible" type="button" class="outline" :disabled="xraySubscriptionBusy || subscriptionsLoading"
                          @click="changeXraySubscription(row, 'issue')">{{ row.active ? '轮换链接' : '重新签发' }}</button>
                        <button type="button" class="danger" :disabled="xraySubscriptionBusy || subscriptionsLoading"
                          @click="changeXraySubscription(row, 'revoke')">撤销</button>
                      </div>
                    </details>
                  </div></td>
                </tr>
              </tbody>
            </table>
          </div>
          <p v-else class="empty">{{ subscriptionsLoading ? '正在读取订阅…' : xraySubscriptions.length ? '没有符合筛选条件的客户端。' : '节点报告已生效的用户授权后可签发订阅。' }}</p>
        </template>
      </section>

      <section v-else-if="page === 'audit'" class="card">
        <div class="section-head"><h2>安全事件</h2><button type="button" class="outline" @click="loadAudit">刷新日志</button></div>
        <p v-if="auditError" class="notice" role="alert">{{ auditError }}</p>
        <div v-if="audits.length" class="table-wrap">
          <table class="data-table" aria-label="审计日志">
            <thead><tr><th scope="col">时间</th><th scope="col">操作者</th><th scope="col">操作</th><th scope="col">资源</th><th scope="col">结果</th></tr></thead>
            <tbody><tr v-for="(event, index) in audits" :key="index">
              <td>{{ new Date(event.at * 1000).toLocaleString() }}</td><td>{{ event.actor }}</td><td>{{ event.action }}</td><td>{{ event.resource }}</td><td>{{ event.outcome }}</td>
            </tr></tbody>
          </table>
        </div>
        <p v-else-if="!auditError" class="empty">暂无事件。</p>
      </section>

      <template v-else-if="page === 'versions'">
      <section class="card core-catalog"><div class="section-head"><div><h2>主控备用制品</h2></div><button class="outline" @click="loadCoreBackups">刷新状态</button></div><p>主控从官方 Releases 同步每种 Core 最新稳定版的 amd64/arm64 制品，每种 Core 只保留一版。远程 Xray 安装优先访问官方源。官方源不可用时，只有与签名清单完全匹配的缓存才能用于安装。</p><p v-if="coreBackupError" class="catalog-error">{{ coreBackupError }}</p><p v-if="coreBackups?.updated_at" class="catalog-stale">最近更新：{{ new Date(coreBackups.updated_at).toLocaleString() }}</p><div v-if="coreBackups?.cores.length" class="release-list"><article v-for="core in coreBackups.cores" :key="core.id" class="release-row"><div class="release-heading"><div><strong>{{ core.name }} {{ core.version }}</strong><small>{{ core.repository }} · 缓存于 {{ new Date(core.cached_at).toLocaleString() }}</small></div><a :href="core.release_url" target="_blank" rel="noopener noreferrer">官方发布页 ↗</a></div><div v-for="asset in core.assets" :key="asset.architecture" class="release-asset"><span>{{ asset.architecture }} · {{ asset.name }}</span><small>{{ (asset.size / 1048576).toFixed(1) }} MiB · {{ asset.digest }}</small></div></article></div><div v-else-if="!coreBackupError" class="empty">主控尚未缓存备用制品；后台会在启动后从官方源同步。</div></section>
      <section class="card core-catalog"><div class="section-head"><div><h2>Core 官方版本目录</h2></div><button class="outline" :disabled="coreCatalogLoading" @click="refreshCoreCatalog">{{ coreCatalogLoading ? '读取中…' : '刷新目录' }}</button></div><p>目录来自官方 GitHub Releases，每页 10 个、最多浏览最近 100 个版本。此目录用于发现版本。面板安装可选版本来自已验签的 Xray 发布清单。</p><p v-if="coreCatalog?.stale" class="catalog-stale">上游暂不可用，当前显示缓存目录（{{ new Date(coreCatalog.retrieved_at).toLocaleString() }}）。</p><p v-if="coreCatalogError" class="catalog-error">{{ coreCatalogError }}</p><div v-if="coreCatalog" class="catalog-layout"><label>Core<select v-model="coreCatalogCore"><option v-for="core in coreCatalog.cores" :key="core.id" :value="core.id">{{ core.name }}（{{ core.repository }}）</option></select></label><div><div v-if="selectedCoreCatalog?.releases.length" class="release-list"><article v-for="release in selectedCoreCatalog.releases" :key="release.version" class="release-row"><div class="release-heading"><div><strong>{{ release.version }}</strong><span v-if="release.prerelease" class="release-badge">预发布</span><small>{{ release.title }} · {{ new Date(release.published_at).toLocaleDateString() }}</small></div><a :href="release.url" target="_blank" rel="noopener noreferrer">官方发布页 ↗</a></div><details v-if="release.assets.length"><summary>{{ release.assets.length }} 个发布制品</summary><div v-for="asset in release.assets" :key="asset.name" class="release-asset"><a :href="asset.download_url" target="_blank" rel="noopener noreferrer">{{ asset.name }}</a><small>{{ (asset.size / 1048576).toFixed(1) }} MiB · {{ asset.digest || '上游未提供 SHA-256' }}</small></div></details><small v-else>此版本没有可用的官方制品链接</small></article></div><div v-else class="empty">{{ selectedCoreCatalog ? '官方目录中没有可显示的版本' : '正在加载发布目录' }}</div><button v-if="selectedCoreCatalog?.has_more" class="outline load-older" :disabled="coreCatalogLoading" @click="loadOlderCoreReleases">{{ coreCatalogLoading ? '读取中…' : '加载较早版本' }}</button></div></div></section>
      </template>

      <template v-else-if="page === 'tasks'">
        <section v-if="selectedNode" class="card page-stack">
          <div class="section-head"><h2>节点任务记录</h2><button class="outline" type="button" @click="loadTasks(selectedNode.id)">刷新任务</button></div>
          <form v-if="(admin?.role === 'security_admin' || admin?.role === 'operator') && !selectedNode.disabled && !selectedNode.pending"
            class="filters" @submit.prevent="createStatusTask">
            <label>Core<select v-model="statusCore"><option value="xray">Xray</option><option value="sing-box">sing-box</option><option value="mita">Mita</option></select></label>
            <button type="submit">签发只读查询</button>
          </form>
          <p v-if="taskError" class="notice" role="alert">{{ taskError }}</p>
          <div v-if="tasks.length" class="table-wrap">
            <table class="data-table" aria-label="节点任务记录">
              <thead><tr><th scope="col">任务</th><th scope="col">来源</th><th scope="col">状态与回执</th><th scope="col">操作</th></tr></thead>
              <tbody>
                <tr v-for="task in tasks" :key="task.task_id">
                  <th scope="row">#{{ task.sequence }} · {{ operationLabel(task.operation) }}
                    <small>{{ task.core }} · {{ new Date(task.created_at || task.issued_at).toLocaleString() }}</small>
                    <small class="mono">{{ task.task_id }}</small>
                  </th>
                  <td>{{ task.created_by || '审计记录可查' }}<small>{{ task.approval }}</small></td>
                  <td>
                    <span :class="['status', task.status === 'SUCCEEDED' ? 'on' : task.active ? 'idle' : 'off']">{{ taskStatus(task) }}</span>
                    <small v-if="task.control">{{ task.control === 'cancel' ? '取消待处理' : '跳过待处理' }}</small>
                    <details v-if="task.acks?.length">
                      <summary>执行回执</summary>
                      <ul><li v-for="ack in task.acks" :key="ack.status_version">
                        {{ ack.status_version }} · {{ ack.status }}
                        <small v-if="ack.result?.active_state">{{ ack.result.active_state }} / {{ ack.result.sub_state }} · {{ ack.result.load_state }}</small>
                        <small v-if="ack.result?.error_code">失败代码 {{ ack.result.error_code }}</small>
                      </li></ul>
                    </details>
                  </td>
                  <td><div v-if="task.operation === 'core.status' && task.active && (admin?.role === 'security_admin' || admin?.role === 'operator')" class="actions">
                    <button v-if="now < Date.parse(task.expires_at) && task.control !== 'cancel'" type="button" class="danger" @click="controlStatusTask(task, 'cancel')">取消待处理</button>
                    <button v-if="task.status === 'QUEUED' && !task.lease_deadline && !task.control" type="button" class="danger" @click="controlStatusTask(task, 'void')">关闭未投递任务</button>
                    <button v-if="now >= Date.parse(task.expires_at) && task.control !== 'skip'" type="button" class="outline" @click="controlStatusTask(task, 'skip')">跳过已过期任务</button>
                  </div></td>
                </tr>
              </tbody>
            </table>
          </div>
          <p v-else-if="!taskError" class="empty">暂无任务记录。</p>
        </section>
        <p v-else class="empty">添加节点或从页头选择节点。</p>
      <section v-if="selectedNode && admin?.can_update_runtime" :key="selectedNode.id" class="card">
        <div class="section-head">
          <h2>Agent / Helper 成对更新</h2>
          <button class="outline" @click="loadRuntimeUpdates(selectedNode.id)">刷新结果</button>
        </div>
        <form v-if="!selectedNode.disabled && !selectedNode.pending" class="node-row" @submit.prevent="submitRuntimeUpdate">
          <label v-for="field in runtimeProofFields" :key="field.name">{{ field.label }}<input :name="field.name" type="file" required /></label>
          <button :disabled="runtimeUpdateBusy">验证签名并投递</button>
        </form>
        <p v-if="runtimeUpdateError" class="error" role="alert">{{ runtimeUpdateError }}</p>
        <p v-if="!runtimeUpdates.length" class="empty">暂无成对更新记录</p>
        <div v-for="update in runtimeUpdates" :key="update.id" class="audit-row">
          <div>
            <strong>{{ update.version }} · {{ update.architecture }} · #{{ update.sequence }}</strong>
            <small v-if="update.current_pair_sha256">当前成对 SHA-256 {{ update.current_pair_sha256 }}</small>
          </div>
          <span>{{ runtimeUpdateStatus[update.status] }}</span>
        </div>
      </section>
      </template>

      <template v-else-if="page === 'admins'">
        <p v-if="adminsError" class="notice" role="alert">{{ adminsError }}</p>
      <section v-if="admin?.can_manage_admins" class="admin-grid">
        <form class="card" @submit.prevent="createAdmin"><h2>开通范围账号</h2><p>仅创建节点范围受限的审计员或运维员。运维员可创建只读状态查询任务；范围不可超出当前安全管理员的授权。</p><label>用户名<input v-model="newAdminUsername" autocomplete="off" required /></label><label>初始密码（至少 12 位）<input v-model="newAdminPassword" type="password" autocomplete="new-password" minlength="12" required /></label><label>角色<select v-model="newAdminRole"><option value="auditor">审计员</option><option value="operator">运维员（只读状态查询）</option></select></label><label>节点组范围<input v-model="newAdminGroups" placeholder="west, east" autocomplete="off" /></label><label>节点 ID 范围<input v-model="newAdminNodeIDs" placeholder="node-…" autocomplete="off" /></label><button :disabled="loading">创建范围账号</button><p v-if="createdTOTP" class="invite">一次性 TOTP 密钥：{{ createdTOTP }}<br />请通过可信渠道交给该账号持有人；此页面退出后不再显示。</p></form>
        <section class="card"><h2>管理员账号</h2><div v-for="account in managedAdmins" :key="account.id" class="admin-row"><div><strong>{{ account.username }}</strong><span>{{ account.role }} · {{ account.node_groups.join(', ') || '指定节点' }}{{ account.node_ids.length ? ` · ${account.node_ids.join(', ')}` : '' }}</span></div><span class="status" :class="account.disabled ? 'off' : 'on'">{{ account.disabled ? '已禁用' : '启用中' }}</span><button v-if="!account.disabled && account.id !== admin?.id && account.role !== 'security_admin'" class="danger" @click="disableAdmin(account.id)">禁用</button></div><p v-if="!managedAdmins.length" class="empty">暂无可管理的范围账号</p></section>
      </section>
      </template>
    </main>

    <PanelDialog v-if="addNodeOpen" title="添加节点" @close="addNodeOpen = false">
      <form class="stack-form" @submit.prevent="createNode">
        <p v-if="error" class="notice" role="alert">{{ error }}</p>
        <label>节点名称<input v-model.trim="newNodeName" name="name" required autofocus /></label>
        <label>分组<input v-model.trim="newNodeGroup" name="group" required /></label>
        <button type="submit" :disabled="loading">添加节点</button>
      </form>
    </PanelDialog>

    <PanelDialog v-if="installCommand" :title="'安装 Agent · ' + installCommand.node.name" @close="installCommand = null">
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
      <label>在节点服务器终端执行<textarea :value="installCommand.command" readonly rows="8" spellcheck="false"></textarea></label>
      <p>一次性命令，{{ new Date(installCommand.expires_at * 1000).toLocaleString() }} 过期。补发命令会使未兑换的旧命令失效。</p>
      <button type="button" @click="copyInstallCommand">{{ commandCopied ? '已复制' : '复制命令' }}</button>
    </PanelDialog>

    <PanelDialog v-if="coreDrawer && selectedNode" :title="'管理 Core · ' + selectedNode.name" drawer @close="coreDrawer = false">
      <div class="page-stack">
        <div class="context-bar">
          <span>Agent <strong>{{ nodeStatus(selectedNode) }}</strong></span>
          <span>Xray <strong>{{ panelXray?.current.version || (panelXray ? '未安装' : '状态不可用') }}</strong></span>
          <span v-if="panelXray?.current.version">{{ panelXray.current.running ? '运行中' : '已停止' }}</span>
        </div>
        <div class="actions">
          <button class="outline" type="button" @click="refreshNodeTasks(selectedNode.id)">刷新状态和任务</button>
          <button class="quiet" type="button" @click="coreDrawer = false; openPage('tasks')">查看任务历史</button>
        </div>
        <p v-if="panelXrayReadError || panelXrayError || taskError" class="notice" role="alert">{{ panelXrayError || panelXrayReadError || taskError }}</p>
        <p v-if="selectedNode.disabled || selectedNode.pending">节点接入且启用后可管理 Xray。</p>
        <form v-if="admin?.can_manage_xray && panelXray && !selectedNode.disabled && !selectedNode.pending"
          class="stack-form" @submit.prevent="submitPanelXray()">
          <p>节点架构 {{ panelXray.architecture }}</p>
          <label>操作<select v-model="panelXrayOperation">
            <option v-for="operation in panelXrayOperations" :key="operation" :value="operation">{{ xrayOperationLabel[operation] }}</option>
          </select></label>
          <label v-if="panelXrayUsesArtifact">目标版本<select v-model="panelXrayVersion" required>
            <option v-if="!panelXrayVersions.length" value="" disabled>暂无可用版本</option>
            <option v-for="version in panelXrayVersions" :key="version" :value="version">{{ version }}</option>
          </select></label>
          <button type="submit" :disabled="!!panelXrayReadError || panelXraySubmitting || (panelXrayUsesArtifact && !panelXrayVersion)">
            {{ panelXraySubmitting ? '提交中…' : '提交任务' }}
          </button>
        </form>
        <div v-if="admin?.can_manage_xray" class="revision-summary" role="status">
          <strong>最近一次 Core 操作</strong>
          <p v-if="latestCoreTask">#{{ latestCoreTask.sequence }} · {{ operationLabel(latestCoreTask.operation) }} · {{ taskStatus(latestCoreTask) }}</p>
          <p v-else>暂无操作记录。</p>
        </div>
      <section v-if="selectedNode && admin?.can_prepare_xray_installs" class="card">
        <div class="section-head">
          <h2>独立签发提案</h2>
          <button class="outline" @click="refreshNodeTasks(selectedNode.id)">刷新提案和结果</button>
        </div>
        <p>当前账号 ID：{{ admin.id }}。提案预留节点的下一个任务序号，有效期 30 分钟。</p>
        <form v-if="!selectedNode.disabled && !selectedNode.pending" class="node-row" @submit.prevent="createXrayInstall">
          <label>操作<select v-model="xrayInstallInput.operation">
            <option v-for="operation in legacyXrayOperations" :key="operation" :value="operation">{{ xrayOperationLabel[operation] }}</option>
          </select></label>
          <label>架构<select v-model="xrayInstallInput.architecture"><option>amd64</option><option>arm64</option></select></label>
          <template v-if="xrayVersionChange">
            <label>已安装版本<input v-model.trim="xrayInstallInput.current_version" placeholder="v26.10.31" required /></label>
            <label>已安装 SHA-256<input v-model.trim="xrayInstallInput.current_sha256" pattern="[a-f0-9]{64}" maxlength="64" spellcheck="false" required /></label>
          </template>
          <label>{{ xrayUsesArtifact ? '目标版本' : '已安装版本' }}<input v-model.trim="xrayInstallInput.version" placeholder="v26.10.31" required /></label>
          <label>{{ xrayUsesArtifact ? '目标 SHA-256' : '已安装 SHA-256' }}<input v-model.trim="xrayInstallInput.sha256" pattern="[a-f0-9]{64}" maxlength="64" spellcheck="false" required /></label>
          <label v-if="xrayUsesArtifact">制品清单版本<input v-model.number="xrayInstallInput.manifest_version" type="number" min="1" max="9007199254740991" required /></label>
          <button :disabled="xrayInstallBusy">预留序号并创建提案</button>
        </form>
        <p v-if="xrayInstallError" class="error" role="alert">{{ xrayInstallError }}</p>
        <p v-if="!xrayInstalls.length && !xrayInstallError" class="empty">暂无与你相关的 Xray 操作提案。</p>
        <div v-for="install in xrayInstalls" :key="install.proposal.task_id" class="audit-row">
          <div>
            <strong>#{{ install.proposal.sequence }} · {{ xrayOperationLabel[install.proposal.operation] }} Xray {{ install.proposal.version }} · {{ install.proposal.architecture }}</strong>
            <small v-if="install.proposal.current_version">节点已安装版本 {{ install.proposal.current_version }}</small>
            <span>{{ xrayInstallStatus[install.status] }} · {{ new Date(install.proposal.expires_at * 1000).toLocaleString() }} 过期</span>
            <small v-if="xrayTask(install.proposal.task_id)" aria-live="polite">
              任务结果 {{ xrayTaskResult(install) }}
            </small>
          </div>
          <button v-if="install.status === 'AWAITING_SIGNATURE'" class="outline" @click="downloadXrayProposal(install)">下载提案 JSON</button>
          <form v-if="install.status === 'AWAITING_SIGNATURE'" class="node-row" @submit.prevent="uploadSignedXrayInstall(install, $event)">
            <label>运维员签名请求 JSON<input name="request" type="file" accept=".json,application/json" required /></label>
            <label>独立签发任务 JSON<input name="task" type="file" accept=".json,application/json" required /></label>
            <button :disabled="xrayInstallBusy">核验签发任务</button>
          </form>
          <button v-if="install.status === 'SIGNED_TASK_VERIFIED' && !xrayTask(install.proposal.task_id)"
            :disabled="xrayInstallBusy" @click="dispatchXrayInstall(install)">投递{{ xrayOperationLabel[install.proposal.operation] }}任务</button>
        </div>
      </section>
      </div>
    </PanelDialog>

    <PanelDialog v-if="previewOpen && panelXray && selectedNode" :title="'预览变更 · ' + selectedNode.name" @close="previewOpen = false">
      <p role="status">{{ draftStatus }}</p>
      <p v-if="panelXrayReadError || panelXrayError" class="notice" role="alert">{{ panelXrayError || panelXrayReadError }}</p>
      <p v-if="panelXray.current.candidate">候选配置 SHA-256 <code>{{ panelXray.current.candidate.sha256 }}</code></p>
      <div v-if="inboundChanges.length" class="table-wrap">
        <table class="data-table" aria-label="受控入站变更">
          <thead><tr><th scope="col">监听端口</th><th scope="col">当前授权</th><th scope="col">草稿授权</th></tr></thead>
          <tbody><tr v-for="change in inboundChanges" :key="change.port">
            <th scope="row">{{ change.port }}</th>
            <td><template v-if="change.before">{{ change.before.users.join('、') }}<small>{{ inboundProtocolLabel(change.before.protocol) }} · {{ endpointLabel(change.before.public_endpoint, change.port) }}</small></template><span v-else>—</span></td>
            <td><template v-if="change.after">{{ change.after.users.join('、') }}<small>{{ inboundProtocolLabel(change.after.protocol) }} · {{ endpointLabel(change.after.public_endpoint, change.port) }}</small></template><span v-else>—</span></td>
          </tr></tbody>
        </table>
      </div>
      <p v-else-if="panelXray.current.candidate && !panelXray.current.catalog">
        候选入站 {{ endpointLabel(undefined, panelXray.current.candidate.port) }}
      </p>
      <p v-else>暂无用户授权差异。</p>
      <div v-if="networkChanged" class="table-wrap">
        <table class="data-table" aria-label="出站和路由变更">
          <thead><tr><th scope="col">版本</th><th scope="col">出站</th><th scope="col">TCP 放行规则</th></tr></thead>
          <tbody>
            <tr v-for="entry in [{ label: '当前', value: panelXray.current.applied_network }, { label: '草稿', value: panelXray.draft_network }]" :key="entry.label">
              <th scope="row">{{ entry.label }}</th>
              <td v-if="!entry.value">节点默认出站</td>
              <td v-else>
                <div v-for="outbound in entry.value.outbounds" :key="outbound.tag">{{ outbound.tag }} · {{ destinationLabel(outbound.destination) }}</div>
                <span v-if="!entry.value.outbounds.length">仅拒绝出站</span>
              </td>
              <td v-if="!entry.value">节点默认路由</td>
              <td v-else>
                <div v-for="(route, index) in entry.value.routes" :key="`${route.inbound_port}-${route.outbound_tag}`">{{ index + 1 }}. 入站 {{ route.inbound_port }} → {{ route.outbound_tag }}</div>
                <span v-if="!entry.value.routes.length">拒绝全部流量</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="actions">
        <button class="outline" type="button" @click="refreshNodeTasks(selectedNode.id)">刷新预览</button>
        <button type="button" :disabled="!canApplyXrayDraft" @click="submitPanelXray('config.apply')">确认下发</button>
      </div>
    </PanelDialog>

    <PanelDialog v-if="shareOpen && selectedNode" :title="'分享 · ' + selectedNode.name" @close="shareOpen = false">
      <div class="page-stack">
        <label>客户端<select v-model="shareUser">
          <option value="" disabled>选择客户端</option>
          <option v-for="row in xraySubscriptions" :key="row.username" :value="row.username">{{ row.username }}</option>
        </select></label>
        <div class="tabs" role="group" aria-label="分享类型">
          <button type="button" :aria-pressed="shareTab === 'subscription'" @click="shareTab = 'subscription'">订阅链接</button>
          <button type="button" :aria-pressed="shareTab === 'node'" @click="shareTab = 'node'">节点分享</button>
        </div>
        <p v-if="xraySubscriptionError" class="notice" role="alert">{{ xraySubscriptionError }}</p>
        <div v-if="shareTab === 'node'" class="revision-summary">
          <label>已授权入站<select v-model.number="sharePort" :disabled="!shareInbounds.length">
            <option value="">{{ shareInbounds.length ? '选择入站' : '暂无可选入站' }}</option>
            <option v-for="inbound in shareInbounds" :key="inbound.port" :value="inbound.port">
              {{ endpointLabel(inbound.public_endpoint, inbound.port) }} · {{ inboundProtocolLabel(inbound.protocol) }}
            </option>
          </select></label>
          <p>指定节点、入站和用户的领取链接待后端接入。</p>
        </div>
        <template v-else-if="shareLink">
          <p>有效至 {{ new Date(shareLink.expiresAt * 1000).toLocaleString() }}。请妥善保存刚签发的链接，刷新或重新登录后需要轮换才能生成新链接。</p>
          <LinkActions :key="shareLink.url" :url="shareLink.url" :show-qr="shareQrFirst" />
        </template>
        <template v-else-if="activeShareRow">
          <p v-if="subscriptionStatus(activeShareRow) === '有效'">订阅有效。查看已签发链接待后端接入，现有客户端可继续使用原链接。</p>
          <p v-else>{{ subscriptionStatus(activeShareRow) }}</p>
          <div class="actions">
            <button v-if="activeShareRow.eligible" type="button" :disabled="xraySubscriptionBusy || subscriptionsLoading"
              @click="changeXraySubscription(activeShareRow, 'issue')">{{ activeShareRow.active ? '轮换链接' : activeShareRow.expires_at ? '重新签发' : '签发链接' }}</button>
          </div>
        </template>
        <p v-else>{{ subscriptionsLoading ? '正在读取客户端…' : '选择一个客户端查看分享选项。' }}</p>
      </div>
    </PanelDialog>
  </div>
</template>
