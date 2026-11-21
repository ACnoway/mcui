<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'

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
type PanelXrayOptions = {
  architecture: string
  current: { version: string; sha256: string; running: boolean; candidate?: XrayConfigReference; config?: XrayConfigReference; config_revision?: number }
  state: string; versions: string[]; catalog_version: number; config_ready: boolean
}
type XrayInstall = {
  proposal: {
    task_id: string; node_id: string; sequence: number; operation: XrayOperation
    version: string; architecture: string; sha256: string; manifest_version?: number
    current_version?: string; current_sha256?: string; requester_id: string; expires_at: number
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
const statusTasks = computed(() => tasks.value.filter(task => task.operation === 'core.status'))
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
  'config.apply': '下发受控 SOCKS5 入站',
}
const legacyXrayOperations: CoreXrayOperation[] = ['core.install', 'core.start', 'core.stop', 'core.upgrade', 'core.downgrade', 'core.uninstall']
const xrayVersionChange = computed(() => xrayInstallInput.value.operation === 'core.upgrade' || xrayInstallInput.value.operation === 'core.downgrade')
const xrayUsesArtifact = computed(() => xrayInstallInput.value.operation === 'core.install' || xrayVersionChange.value)
const xrayInstallBusy = ref(false)
const xrayInstallError = ref('')
const xrayInstallStatus = { AWAITING_SIGNATURE: '待签发', SIGNED_TASK_VERIFIED: '已核验签发任务', EXPIRED: '已过期', LEGACY: '旧版记录' }
let xrayInstallRetry: { intent: string; id: string } | undefined
const panelXray = ref<PanelXrayOptions | null>(null)
const panelXrayOperation = ref<XrayOperation>('core.install')
const panelXrayVersion = ref('')
const panelXrayError = ref('')
const panelXraySubmitting = ref(false)
let panelXrayRetry: { intent: string; id: string } | undefined
const panelXrayOperations = computed<XrayOperation[]>(() => {
  if (!panelXray.value?.current.version) return ['core.install']
  const operations: XrayOperation[] = ['core.start', 'core.stop', 'core.upgrade', 'core.downgrade', 'core.uninstall']
  if (panelXray.value.config_ready) operations.push('config.apply')
  return operations
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
const selectedNode = ref<NodeRecord | null>(null)
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
async function refresh() {
  const adminRequest = admin.value?.can_manage_admins ? api<ManagedAdmin[]>('/api/v1/admin/admins') : Promise.resolve([] as ManagedAdmin[])
  const [nodeData, auditData, adminData] = await Promise.all([api<NodeRecord[]>('/api/v1/admin/nodes'), api<Audit[]>('/api/v1/admin/audit'), adminRequest])
  nodes.value = nodeData
  audits.value = auditData.slice(-100).reverse()
  managedAdmins.value = adminData
  await Promise.all([loadCoreCatalog(), loadCoreBackups()])
  if (selectedNode.value) {
    selectedNode.value = nodeData.find(node => node.id === selectedNode.value?.id) ?? null
    if (selectedNode.value) await refreshNodeTasks(selectedNode.value.id)
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
    await refresh()
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
  return Date.now() / 1000 - node.last_seen < 60 ? '在线' : '离线'
}

async function createNode() {
  error.value = ''
  try {
    const node = await api<NodeRecord>('/api/v1/admin/nodes', {
      method: 'POST',
      body: JSON.stringify({ name: newNodeName.value.trim(), node_group: newNodeGroup.value.trim() }),
    })
    nodes.value.push(node)
    newNodeName.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '添加节点失败'
  }
}

async function generateInstallCommand(node: NodeRecord) {
  error.value = ''
  installCommand.value = null
  commandCopied.value = false
  generatingCommand.value = true
  try {
    const result = await apiWithStepUp<{ command: string; expires_at: number }>('/api/v1/admin/nodes/' + encodeURIComponent(node.id) + '/install-command', {})
    if (loggedIn.value) installCommand.value = { node, ...result }
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
  try { await apiWithStepUp('/api/v1/admin/nodes/disable', { node_id: id }); if (installCommand.value?.node.id === id) installCommand.value = null; await refresh() }
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
    await refresh()
  } catch (e) { error.value = e instanceof Error ? e.message : '创建管理员失败' }
}
async function disableAdmin(id: string) {
  if (!confirm('确认禁用该管理员并撤销其全部会话？')) return
  try { await apiWithStepUp('/api/v1/admin/admins/disable', { admin_id: id }); await refresh() }
  catch (e) { error.value = e instanceof Error ? e.message : '禁用管理员失败' }
}
async function loadTasks(nodeID: string) { try { tasks.value = await api<StatusTask[]>(`/api/v1/admin/tasks?node_id=${encodeURIComponent(nodeID)}`) } catch (e) { tasks.value = []; error.value = e instanceof Error ? e.message : '读取任务失败' } }
async function loadXrayInstalls(nodeID: string) {
  if (!admin.value?.can_prepare_xray_installs && !admin.value?.can_manage_xray) return
  xrayInstallError.value = ''
  try {
    const records = await api<XrayInstall[]>(`/api/v1/admin/xray-installs?node_id=${encodeURIComponent(nodeID)}`)
    if (selectedNode.value?.id === nodeID) xrayInstalls.value = records
  } catch (e) {
    if (selectedNode.value?.id !== nodeID) return
    xrayInstalls.value = []
    xrayInstallError.value = e instanceof Error ? e.message : '读取 Xray 操作提案失败'
  }
}
async function refreshNodeTasks(nodeID: string) {
  await Promise.all([loadTasks(nodeID), loadXrayInstalls(nodeID), loadPanelXray(nodeID), loadRuntimeUpdates(nodeID)])
}
async function showNode(id: string) { try { selectedNode.value = await api<NodeRecord>(`/api/v1/admin/nodes/${encodeURIComponent(id)}`); xrayInstalls.value = []; panelXray.value = null; runtimeUpdates.value = []; await refreshNodeTasks(id) } catch (e) { error.value = e instanceof Error ? e.message : '读取节点失败' } }

function panelXrayPath(nodeID: string) {
  return `/api/v1/admin/nodes/${encodeURIComponent(nodeID)}/xray`
}

async function loadPanelXray(nodeID: string) {
  if (!admin.value?.can_manage_xray) return
  panelXrayError.value = ''
  if (selectedNode.value?.disabled || selectedNode.value?.pending) {
    panelXray.value = null
    return
  }
  try {
    const options = await api<PanelXrayOptions>(panelXrayPath(nodeID))
    if (selectedNode.value?.id === nodeID) panelXray.value = options
  } catch (e) {
    if (selectedNode.value?.id !== nodeID) return
    panelXray.value = null
    panelXrayError.value = e instanceof Error ? e.message : '读取节点 Xray 状态失败'
  }
}

async function submitPanelXray() {
  const node = selectedNode.value
  const options = panelXray.value
  if (!node || !options || panelXraySubmitting.value) return
  const operation = panelXrayOperation.value
  const version = operation === 'config.apply' ? options.current.version : panelXrayUsesArtifact.value ? panelXrayVersion.value : ''
  const dangerous = operation === 'core.downgrade' || operation === 'core.uninstall' || operation === 'config.apply'
  const replacesConfig = version !== '' && panelXrayUsesArtifact.value && !!options.current.config
  if (dangerous || replacesConfig) {
    const target = version ? ` → ${version}` : ''
    const note = replacesConfig ? '切换版本会停用已应用的入站。' : ''
    if (!confirm(`确认${xrayOperationLabel[operation]}节点「${node.name}」的 Xray ${options.current.version}${target}？${note}`)) return
  }
  const fields = { operation, version, state: options.state,
    catalog_version: version ? options.catalog_version : 0, confirm_operation: dangerous ? operation : '' }
  const intent = JSON.stringify({ node_id: node.id, ...fields })
  if (panelXrayRetry?.intent !== intent) panelXrayRetry = { intent, id: crypto.randomUUID().replaceAll('-', '') }
  panelXraySubmitting.value = true
  panelXrayError.value = ''
  try {
    await apiWithStepUp<StatusTask>(panelXrayPath(node.id), { ...fields, task_id: panelXrayRetry.id })
    panelXrayRetry = undefined
    if (selectedNode.value?.id === node.id) await refreshNodeTasks(node.id)
  } catch (e) {
    if (selectedNode.value?.id === node.id) panelXrayError.value = e instanceof Error ? e.message : '提交 Xray 任务失败'
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
  if (!selectedNode.value) return
  error.value = ''
  try {
    const requestID = crypto.randomUUID().replaceAll('-', '')
    await api<StatusTask>('/api/v1/admin/tasks', { method: 'POST', body: JSON.stringify({ request_id: requestID, node_id: selectedNode.value.id, core: statusCore.value }) })
    await loadTasks(selectedNode.value.id)
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
    if (selectedNode.value) await loadTasks(selectedNode.value.id)
  } catch (e) { error.value = e instanceof Error ? e.message : action === 'cancel' ? '取消任务失败' : action === 'void' ? '关闭未投递任务失败' : '跳过任务失败' }
}
async function logout() { try { await api('/api/v1/admin/logout', { method: 'POST', body: '{}' }) } finally { csrfToken = ''; admin.value = null; selectedNode.value = null; loggedIn.value = false; nodes.value = []; audits.value = []; tasks.value = []; xrayInstalls.value = []; xrayInstallRetry = undefined; managedAdmins.value = []; createdTOTP.value = ''; installCommand.value = null } }
onMounted(async () => {
  try {
    admin.value = await api<AdminInfo>('/api/v1/admin/me')
    csrfToken = admin.value.csrf_token
    await refresh()
    loggedIn.value = true
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
  <main class="shell">
    <header class="topbar"><div><span class="eyebrow">MCUI / CONTROL PLANE</span><h1>节点管理</h1></div><button v-if="loggedIn" class="quiet" @click="logout">退出登录</button></header>
    <p v-if="error" class="notice">{{ error }}</p>
    <section v-if="!loggedIn" class="auth-grid">
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
    <template v-else>
      <section class="metrics"><div class="metric"><span>登记节点</span><strong>{{ nodes.length }}</strong></div><div class="metric"><span>在线心跳</span><strong>{{ nodes.filter(n => nodeStatus(n) === '在线').length }}</strong></div><div class="metric"><span>当前阶段</span><strong>03 / CORE LIFECYCLE</strong></div><div class="metric"><span>当前账号</span><strong>{{ admin?.role }}</strong></div></section>
      <section class="card core-catalog"><div class="section-head"><div><span class="eyebrow">MASTER BACKUP ARTIFACTS</span><h2>主控备用制品</h2></div><button class="outline" @click="loadCoreBackups">刷新状态</button></div><p>主控从官方 Releases 同步每种 Core 最新稳定版的 amd64/arm64 制品，每种 Core 只保留一版。远程 Xray 安装优先访问官方源。官方源不可用时，只有与签名清单完全匹配的缓存才能用于安装。</p><p v-if="coreBackupError" class="catalog-error">{{ coreBackupError }}</p><p v-if="coreBackups?.updated_at" class="catalog-stale">最近更新：{{ new Date(coreBackups.updated_at).toLocaleString() }}</p><div v-if="coreBackups?.cores.length" class="release-list"><article v-for="core in coreBackups.cores" :key="core.id" class="release-row"><div class="release-heading"><div><strong>{{ core.name }} {{ core.version }}</strong><small>{{ core.repository }} · 缓存于 {{ new Date(core.cached_at).toLocaleString() }}</small></div><a :href="core.release_url" target="_blank" rel="noopener noreferrer">官方发布页 ↗</a></div><div v-for="asset in core.assets" :key="asset.architecture" class="release-asset"><span>{{ asset.architecture }} · {{ asset.name }}</span><small>{{ (asset.size / 1048576).toFixed(1) }} MiB · {{ asset.digest }}</small></div></article></div><div v-else-if="!coreBackupError" class="empty">主控尚未缓存备用制品；后台会在启动后从官方源同步。</div></section>
      <section class="card core-catalog"><div class="section-head"><div><span class="eyebrow">OFFICIAL RELEASE CATALOG</span><h2>Core 官方版本目录</h2></div><button class="outline" :disabled="coreCatalogLoading" @click="refreshCoreCatalog">{{ coreCatalogLoading ? '读取中…' : '刷新目录' }}</button></div><p>目录来自官方 GitHub Releases，每页 10 个、最多浏览最近 100 个版本。此目录用于发现版本。面板安装可选版本来自已验签的 Xray 发布清单。</p><p v-if="coreCatalog?.stale" class="catalog-stale">上游暂不可用，当前显示缓存目录（{{ new Date(coreCatalog.retrieved_at).toLocaleString() }}）。</p><p v-if="coreCatalogError" class="catalog-error">{{ coreCatalogError }}</p><div v-if="coreCatalog" class="catalog-layout"><label>Core<select v-model="coreCatalogCore"><option v-for="core in coreCatalog.cores" :key="core.id" :value="core.id">{{ core.name }}（{{ core.repository }}）</option></select></label><div><div v-if="selectedCoreCatalog?.releases.length" class="release-list"><article v-for="release in selectedCoreCatalog.releases" :key="release.version" class="release-row"><div class="release-heading"><div><strong>{{ release.version }}</strong><span v-if="release.prerelease" class="release-badge">预发布</span><small>{{ release.title }} · {{ new Date(release.published_at).toLocaleDateString() }}</small></div><a :href="release.url" target="_blank" rel="noopener noreferrer">官方发布页 ↗</a></div><details v-if="release.assets.length"><summary>{{ release.assets.length }} 个发布制品</summary><div v-for="asset in release.assets" :key="asset.name" class="release-asset"><a :href="asset.download_url" target="_blank" rel="noopener noreferrer">{{ asset.name }}</a><small>{{ (asset.size / 1048576).toFixed(1) }} MiB · {{ asset.digest || '上游未提供 SHA-256' }}</small></div></details><small v-else>此版本没有可用的官方制品链接</small></article></div><div v-else class="empty">{{ selectedCoreCatalog ? '官方目录中没有可显示的版本' : '正在加载发布目录' }}</div><button v-if="selectedCoreCatalog?.has_more" class="outline load-older" :disabled="coreCatalogLoading" @click="loadOlderCoreReleases">{{ coreCatalogLoading ? '读取中…' : '加载较早版本' }}</button></div></div></section>
      <section class="card">
        <div class="section-head">
          <h2>节点管理</h2>
          <button @click="refresh">刷新</button>
        </div>
        <form v-if="admin?.can_create_nodes" class="node-row" @submit.prevent="createNode">
          <label>节点名称<input v-model="newNodeName" maxlength="64" required /></label>
          <label>节点分组<input v-model="newNodeGroup" maxlength="64" required /></label>
          <button>添加节点</button>
        </form>
        <div v-if="!nodes.length" class="empty">暂无节点。</div>
        <div v-for="node in nodes" :key="node.id" class="node-row">
          <div class="node-avatar">{{ node.name.slice(0,1).toUpperCase() }}</div>
          <div class="node-main"><strong>{{ node.name }}</strong><span>{{ node.id }} · {{ node.group }}</span></div>
          <span class="status" :class="node.disabled ? 'off' : nodeStatus(node) === '在线' ? 'on' : 'idle'">{{ nodeStatus(node) }}</span>
          <button class="outline" @click="showNode(node.id)">详情</button>
          <button v-if="admin?.can_install_agents && !node.disabled" class="outline" :disabled="generatingCommand" @click="generateInstallCommand(node)">生成安装命令</button>
          <button v-if="admin?.can_disable_nodes && !node.disabled" class="danger" @click="disableNode(node.id)">禁用</button>
        </div>
        <div v-if="installCommand" class="install-command">
          <label>在 {{ installCommand.node.name }} 的服务器终端执行
            <textarea :value="installCommand.command" readonly rows="9" spellcheck="false"></textarea>
          </label>
          <small>一次性命令，{{ new Date(installCommand.expires_at * 1000).toLocaleTimeString() }} 过期。补发命令会使未兑换的旧命令失效。</small>
          <div class="section-head">
            <button @click="copyInstallCommand">{{ commandCopied ? '已复制' : '复制命令' }}</button>
            <button class="quiet" @click="installCommand = null">关闭</button>
          </div>
        </div>
        <div v-if="selectedNode" class="audit-row">
          <span>{{ selectedNode.name }} · {{ selectedNode.id }} · {{ selectedNode.group }} · {{ nodeStatus(selectedNode) }}
            <template v-if="selectedNode.last_seen"> · 最近心跳 {{ new Date(selectedNode.last_seen*1000).toLocaleString() }}</template>
          </span>
          <button class="quiet" @click="selectedNode = null">关闭</button>
        </div>
      </section>
      <section v-if="selectedNode" class="card"><div class="section-head"><div><span class="eyebrow">SIGNED STATUS TASKS</span><h2>只读状态查询</h2></div><button class="outline" @click="loadTasks(selectedNode.id)">刷新任务</button></div><div class="node-row"><label>Core<select v-model="statusCore"><option value="xray">Xray</option><option value="sing-box">sing-box</option><option value="mita">Mita</option></select></label><button @click="createStatusTask">签发查询任务</button></div><div v-if="!statusTasks.length" class="empty">暂无任务；查询任务只读取固定 Core 服务状态。</div><div v-for="task in statusTasks" :key="task.task_id" class="audit-row task-row"><div><strong>{{ task.core }} · #{{ task.sequence }}</strong><span>{{ task.task_id }} · {{ task.created_at ? new Date(task.created_at).toLocaleString() : new Date(task.issued_at).toLocaleString() }}</span><small>来源：{{ task.created_by || '审计记录可查' }} · 审批：无需单独审批 · 步骤：{{ task.operation }}</small><small v-if="task.control">控制消息：{{ task.control === 'cancel' ? '取消待处理' : '跳过待处理' }}</small></div><span class="status" :class="task.status === 'SUCCEEDED' ? 'on' : task.active ? 'idle' : 'off'">{{ task.status }}</span><button v-if="task.active && (admin?.role === 'security_admin' || admin?.role === 'operator') && Date.now() < Date.parse(task.expires_at) && task.control !== 'cancel'" class="danger" @click="controlStatusTask(task, 'cancel')">取消待处理</button><button v-if="task.active && task.status === 'QUEUED' && !task.lease_deadline && !task.control && (admin?.role === 'security_admin' || admin?.role === 'operator')" class="danger" @click="controlStatusTask(task, 'void')">关闭未投递任务</button><button v-if="task.active && (admin?.role === 'security_admin' || admin?.role === 'operator') && Date.now() >= Date.parse(task.expires_at) && task.control !== 'skip'" class="outline" @click="controlStatusTask(task, 'skip')">跳过已过期任务</button><div v-for="ack in task.acks" :key="ack.status_version" class="task-ack"><small>{{ ack.status_version }} · {{ ack.status }}</small><small v-if="ack.result?.active_state">{{ ack.result.active_state }} / {{ ack.result.sub_state }} · {{ ack.result.load_state }}</small><small v-if="ack.result?.error_code">失败代码：{{ ack.result.error_code }}</small></div></div></section>
      <section v-if="selectedNode && admin?.can_manage_xray" class="card">
        <div class="section-head">
          <h2>Xray 远程管理</h2>
          <button class="outline" @click="refreshNodeTasks(selectedNode.id)">刷新状态和任务</button>
        </div>
        <p v-if="selectedNode.disabled || selectedNode.pending">节点上线后可管理 Xray。</p>
        <p v-if="panelXray">节点架构 {{ panelXray.architecture }} · {{ panelXray.current.version || '未安装' }}</p>
        <p v-if="panelXray?.current.config">
          已应用 SOCKS5 127.0.0.1:{{ panelXray.current.config.port }} · 修订 {{ panelXray.current.config_revision }}
          · SHA-256 <code>{{ panelXray.current.config.sha256 }}</code>
        </p>
        <p v-if="panelXrayOperation === 'config.apply' && panelXray?.current.candidate">
          候选入站 127.0.0.1:{{ panelXray.current.candidate.port }} · SHA-256 <code>{{ panelXray.current.candidate.sha256 }}</code>
        </p>
        <form v-if="panelXray" class="node-row" @submit.prevent="submitPanelXray">
          <label>操作<select v-model="panelXrayOperation">
            <option v-for="operation in panelXrayOperations" :key="operation" :value="operation">{{ xrayOperationLabel[operation] }}</option>
          </select></label>
          <label v-if="panelXrayUsesArtifact">目标版本<select v-model="panelXrayVersion" required>
            <option v-if="!panelXrayVersions.length" value="" disabled>暂无可用版本</option>
            <option v-for="version in panelXrayVersions" :key="version" :value="version">{{ version }}</option>
          </select></label>
          <button :disabled="panelXraySubmitting || (panelXrayUsesArtifact && !panelXrayVersion)">提交任务</button>
        </form>
        <p v-if="panelXrayError || xrayInstallError" class="error" role="alert">{{ panelXrayError || xrayInstallError }}</p>
        <div v-for="install in xrayInstalls" :key="install.proposal.task_id" class="audit-row">
          <div>
            <strong>#{{ install.proposal.sequence }} · {{ xrayOperationLabel[install.proposal.operation] }} Xray {{ install.proposal.version }}</strong>
            <span v-if="xrayTask(install.proposal.task_id)">{{ xrayTaskResult(install) }}</span>
            <span v-else>{{ xrayInstallStatus[install.status] }}</span>
          </div>
        </div>
      </section>
      <section v-if="selectedNode && admin?.can_prepare_xray_installs" class="card">
        <div class="section-head">
          <h2>Xray 远程管理</h2>
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
      <section class="card"><span class="eyebrow">AUDIT TRAIL</span><h2>安全事件</h2><div v-for="(event, i) in audits" :key="i" class="audit-row"><time>{{ new Date(event.at*1000).toLocaleString() }}</time><span>{{ event.action }}</span><small>{{ event.outcome }}</small></div><p v-if="!audits.length" class="empty">暂无事件</p></section>
      <section v-if="admin?.can_manage_admins" class="admin-grid">
        <form class="card" @submit.prevent="createAdmin"><span class="eyebrow">SCOPED ACCESS</span><h2>开通范围账号</h2><p>仅创建节点范围受限的审计员或运维员。运维员可创建只读状态查询任务；范围不可超出当前安全管理员的授权。</p><label>用户名<input v-model="newAdminUsername" autocomplete="off" required /></label><label>初始密码（至少 12 位）<input v-model="newAdminPassword" type="password" autocomplete="new-password" minlength="12" required /></label><label>角色<select v-model="newAdminRole"><option value="auditor">审计员</option><option value="operator">运维员（只读状态查询）</option></select></label><label>节点组范围<input v-model="newAdminGroups" placeholder="west, east" autocomplete="off" /></label><label>节点 ID 范围<input v-model="newAdminNodeIDs" placeholder="node-…" autocomplete="off" /></label><button :disabled="loading">创建范围账号</button><p v-if="createdTOTP" class="invite">一次性 TOTP 密钥：{{ createdTOTP }}<br />请通过可信渠道交给该账号持有人；此页面退出后不再显示。</p></form>
        <section class="card"><span class="eyebrow">ADMIN ACCOUNTS</span><h2>管理员账号</h2><div v-for="account in managedAdmins" :key="account.id" class="admin-row"><div><strong>{{ account.username }}</strong><span>{{ account.role }} · {{ account.node_groups.join(', ') || '指定节点' }}{{ account.node_ids.length ? ` · ${account.node_ids.join(', ')}` : '' }}</span></div><span class="status" :class="account.disabled ? 'off' : 'on'">{{ account.disabled ? '已禁用' : '启用中' }}</span><button v-if="!account.disabled && account.id !== admin?.id && account.role !== 'security_admin'" class="danger" @click="disableAdmin(account.id)">禁用</button></div><p v-if="!managedAdmins.length" class="empty">暂无可管理的范围账号</p></section>
      </section>
    </template>
    <footer>管理请求需经服务端认证与授权。启用远程 Xray 的节点可执行独立签发的生命周期任务。</footer>
  </main>
</template>
