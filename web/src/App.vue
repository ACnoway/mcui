<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

type NodeRecord = { id: string; name: string; group: string; last_seen: number; disabled: boolean; pending: boolean }
type Audit = { at: number; actor: string; action: string; resource: string; outcome: string }
type StatusResult = { core?: string; load_state?: string; active_state?: string; sub_state?: string; observed_at?: string; error_code?: string }
type TaskAck = { status_version: number; status: string; result?: StatusResult }
type StatusTask = { task_id: string; node_id: string; sequence: number; created_by?: string; created_at?: string; approval: string; control?: string; operation: string; core: string; issued_at: string; expires_at: string; active: boolean; lease_deadline?: string; status: string; acks: TaskAck[] }
type ManagedAdmin = { id: string; username: string; role: string; node_ids: string[]; node_groups: string[]; disabled: boolean }
type AdminInfo = { id: string; username: string; role: string; csrf_token: string; mfa_recent: boolean; can_create_nodes: boolean; can_install_agents: boolean; can_disable_nodes: boolean; can_prepare_xray_installs: boolean }
type XrayInstall = {
  proposal: { task_id: string; node_id: string; sequence: number; version: string; architecture: string; sha256: string; manifest_version: number; requester_id: string; approver_id: string; expires_at: number }
  approval_id?: string
  status: 'AWAITING_APPROVAL' | 'APPROVAL_RECORDED' | 'SIGNED_TASK_VERIFIED' | 'EXPIRED'
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
const xrayInstallInput = ref({ version: '', architecture: 'amd64', sha256: '', manifest_version: '' as number | '', approver_id: '' })
const xrayInstallBusy = ref(false)
const xrayInstallError = ref('')
const xrayInstallStatus = { AWAITING_APPROVAL: '待审批', APPROVAL_RECORDED: '已登记审批', SIGNED_TASK_VERIFIED: '已核验签发任务', EXPIRED: '已过期' }
let xrayInstallRetry: { intent: string; id: string } | undefined
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
const bootstrapUser = ref('admin')
const bootstrapPassword = ref('')
const bootstrapTOTP = ref('')
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
  const adminRequest = admin.value?.role === 'security_admin' ? api<ManagedAdmin[]>('/api/v1/admin/admins') : Promise.resolve([] as ManagedAdmin[])
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
  loading.value = true; error.value = ''
  try { const result = await api<{ csrf_token: string }>('/api/v1/admin/login', { method: 'POST', body: JSON.stringify({ username: username.value, password: password.value, code: code.value }) }); csrfToken = result.csrf_token; admin.value = await api<AdminInfo>('/api/v1/admin/me'); loggedIn.value = true; password.value = ''; code.value = ''; await refresh() }
  catch (e) { error.value = e instanceof Error ? e.message : '登录失败' }
  finally { loading.value = false }
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
  if (!admin.value?.can_prepare_xray_installs) return
  xrayInstallError.value = ''
  try {
    const records = await api<XrayInstall[]>(`/api/v1/admin/xray-installs?node_id=${encodeURIComponent(nodeID)}`)
    if (selectedNode.value?.id === nodeID) xrayInstalls.value = records
  } catch (e) {
    if (selectedNode.value?.id !== nodeID) return
    xrayInstalls.value = []
    xrayInstallError.value = e instanceof Error ? e.message : '读取 Xray 安装提案失败'
  }
}
async function refreshNodeTasks(nodeID: string) {
  await Promise.all([loadTasks(nodeID), loadXrayInstalls(nodeID)])
}
async function showNode(id: string) { try { selectedNode.value = await api<NodeRecord>(`/api/v1/admin/nodes/${encodeURIComponent(id)}`); xrayInstalls.value = []; await refreshNodeTasks(id) } catch (e) { error.value = e instanceof Error ? e.message : '读取节点失败' } }
async function createXrayInstall() {
  const nodeID = selectedNode.value?.id
  if (!nodeID || xrayInstallBusy.value) return
  const fields = { ...xrayInstallInput.value, node_id: nodeID }
  const intent = JSON.stringify(fields)
  if (xrayInstallRetry?.intent !== intent) xrayInstallRetry = { intent, id: crypto.randomUUID().replaceAll('-', '') }
  xrayInstallError.value = ''
  xrayInstallBusy.value = true
  try {
    await apiWithStepUp<XrayInstall>('/api/v1/admin/xray-installs', { ...fields, task_id: xrayInstallRetry.id })
    xrayInstallRetry = undefined
    if (selectedNode.value?.id === nodeID) await loadXrayInstalls(nodeID)
  } catch (e) {
    xrayInstallError.value = e instanceof Error ? e.message : '预留安装序号失败'
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
async function uploadXrayApproval(install: XrayInstall, event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file || xrayInstallBusy.value) return
  xrayInstallError.value = ''
  xrayInstallBusy.value = true
  try {
    const approval = await readXrayJSON(file)
    const { task_id, node_id } = install.proposal
    await apiWithStepUp<XrayInstall>(`/api/v1/admin/xray-installs/${encodeURIComponent(task_id)}/approve`, { approval })
    if (selectedNode.value?.id === node_id) await loadXrayInstalls(node_id)
  } catch (e) {
    xrayInstallError.value = e instanceof Error ? e.message : '登记安装审批失败'
  } finally {
    xrayInstallBusy.value = false
  }
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
  const approvalFile = fields.get('approval')
  if (!(signedTask instanceof File) || !(approvalFile instanceof File)) return
  xrayInstallError.value = ''
  xrayInstallBusy.value = true
  try {
    const [task, approval] = await Promise.all([readXrayJSON(signedTask), readXrayJSON(approvalFile)])
    const { task_id, node_id } = install.proposal
    await apiWithStepUp<XrayInstall>(`/api/v1/admin/xray-installs/${encodeURIComponent(task_id)}/signed-task`, { approval, task })
    form.reset()
    if (selectedNode.value?.id === node_id) await loadXrayInstalls(node_id)
  } catch (e) {
    xrayInstallError.value = e instanceof Error ? e.message : '核验签发任务失败'
  } finally {
    xrayInstallBusy.value = false
  }
}
function xrayTask(id: string) {
  return tasks.value.find(task => task.task_id === id && task.operation === 'core.install')
}
async function dispatchXrayInstall(install: XrayInstall) {
  if (xrayInstallBusy.value || !confirm('确认将该签发任务投递到指定节点？')) return
  const { task_id, node_id } = install.proposal
  xrayInstallError.value = ''
  xrayInstallBusy.value = true
  try {
    await apiWithStepUp<StatusTask>(`/api/v1/admin/xray-installs/${encodeURIComponent(task_id)}/dispatch`, {})
    if (selectedNode.value?.id === node_id) await refreshNodeTasks(node_id)
  } catch (e) {
    xrayInstallError.value = e instanceof Error ? e.message : '投递 Xray 安装失败'
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
onMounted(async () => { try { admin.value = await api<AdminInfo>('/api/v1/admin/me'); csrfToken = admin.value.csrf_token; await refresh(); loggedIn.value = true } catch { loggedIn.value = false } })
</script>

<template>
  <main class="shell">
    <header class="topbar"><div><span class="eyebrow">MCUI / CONTROL PLANE</span><h1>节点管理</h1></div><button v-if="loggedIn" class="quiet" @click="logout">退出登录</button></header>
    <p v-if="error" class="notice">{{ error }}</p>
    <section v-if="!loggedIn" class="auth-grid">
      <form class="card" @submit.prevent="login"><span class="eyebrow">ADMIN ACCESS</span><h2>管理员登录</h2><label>用户名<input v-model="username" autocomplete="username" required /></label><label>密码<input v-model="password" type="password" autocomplete="current-password" required /></label><label>Authenticator 验证码<input v-model="code" inputmode="numeric" autocomplete="one-time-code" minlength="6" maxlength="6" required /></label><button :disabled="loading">登录</button></form>
      <form class="card secondary" @submit.prevent="bootstrap"><span class="eyebrow">FIRST RUN ONLY</span><h2>初始化安全管理员</h2><p>仅在服务端设置 MCUI_BOOTSTRAP_TOKEN 后可用。</p><label>初始化令牌<input v-model="bootstrapToken" type="password" required /></label><label>用户名<input v-model="bootstrapUser" required /></label><label>密码（至少 12 位）<input v-model="bootstrapPassword" type="password" minlength="12" required /></label><label>TOTP 密钥（Base32）<input v-model="bootstrapTOTP" autocomplete="off" required /></label><button class="outline" :disabled="loading">创建管理员</button></form>
    </section>
    <template v-else>
      <section class="metrics"><div class="metric"><span>登记节点</span><strong>{{ nodes.length }}</strong></div><div class="metric"><span>在线心跳</span><strong>{{ nodes.filter(n => nodeStatus(n) === '在线').length }}</strong></div><div class="metric"><span>当前阶段</span><strong>03 / CORE LIFECYCLE</strong></div><div class="metric"><span>当前账号</span><strong>{{ admin?.role }}</strong></div></section>
      <section class="card core-catalog"><div class="section-head"><div><span class="eyebrow">MASTER BACKUP ARTIFACTS</span><h2>主控备用制品</h2></div><button class="outline" @click="loadCoreBackups">刷新状态</button></div><p>主控从官方 Releases 同步每种 Core 最新稳定版的 amd64/arm64 制品，每种 Core 只保留一版。正常安装流程将由 Agent 直接访问官方源；主控副本仅作为备用，未来只有精确版本、架构和 SHA-256 全部匹配时才能使用，不能静默切换版本。当前尚未开放安装。</p><p>SHA-256 来自 GitHub Releases API，尚未由项目 TUF targets 签署，因此这些缓存不构成安装授权。</p><p v-if="coreBackupError" class="catalog-error">{{ coreBackupError }}</p><p v-if="coreBackups?.updated_at" class="catalog-stale">最近更新：{{ new Date(coreBackups.updated_at).toLocaleString() }}</p><div v-if="coreBackups?.cores.length" class="release-list"><article v-for="core in coreBackups.cores" :key="core.id" class="release-row"><div class="release-heading"><div><strong>{{ core.name }} {{ core.version }}</strong><small>{{ core.repository }} · 缓存于 {{ new Date(core.cached_at).toLocaleString() }}</small></div><a :href="core.release_url" target="_blank" rel="noopener noreferrer">官方发布页 ↗</a></div><div v-for="asset in core.assets" :key="asset.architecture" class="release-asset"><span>{{ asset.architecture }} · {{ asset.name }}</span><small>{{ (asset.size / 1048576).toFixed(1) }} MiB · {{ asset.digest }}</small></div></article></div><div v-else-if="!coreBackupError" class="empty">主控尚未缓存备用制品；后台会在启动后从官方源同步。</div></section>
      <section class="card core-catalog"><div class="section-head"><div><span class="eyebrow">OFFICIAL RELEASE CATALOG</span><h2>Core 官方版本目录</h2></div><button class="outline" :disabled="coreCatalogLoading" @click="refreshCoreCatalog">{{ coreCatalogLoading ? '读取中…' : '刷新目录' }}</button></div><p>目录来自官方 GitHub Releases，每页 10 个、最多浏览最近 100 个版本。官方版本列表用于发现版本，尚不代表制品已获安装授权；安装任务与 Helper 安装事务仍未开放。</p><p v-if="coreCatalog?.stale" class="catalog-stale">上游暂不可用，当前显示缓存目录（{{ new Date(coreCatalog.retrieved_at).toLocaleString() }}）。</p><p v-if="coreCatalogError" class="catalog-error">{{ coreCatalogError }}</p><div v-if="coreCatalog" class="catalog-layout"><label>Core<select v-model="coreCatalogCore"><option v-for="core in coreCatalog.cores" :key="core.id" :value="core.id">{{ core.name }}（{{ core.repository }}）</option></select></label><div><div v-if="selectedCoreCatalog?.releases.length" class="release-list"><article v-for="release in selectedCoreCatalog.releases" :key="release.version" class="release-row"><div class="release-heading"><div><strong>{{ release.version }}</strong><span v-if="release.prerelease" class="release-badge">预发布</span><small>{{ release.title }} · {{ new Date(release.published_at).toLocaleDateString() }}</small></div><a :href="release.url" target="_blank" rel="noopener noreferrer">官方发布页 ↗</a></div><details v-if="release.assets.length"><summary>{{ release.assets.length }} 个发布制品</summary><div v-for="asset in release.assets" :key="asset.name" class="release-asset"><a :href="asset.download_url" target="_blank" rel="noopener noreferrer">{{ asset.name }}</a><small>{{ (asset.size / 1048576).toFixed(1) }} MiB · {{ asset.digest || '上游未提供 SHA-256' }}</small></div></details><small v-else>此版本没有可用的官方制品链接</small></article></div><div v-else class="empty">{{ selectedCoreCatalog ? '官方目录中没有可显示的版本' : '正在加载发布目录' }}</div><button v-if="selectedCoreCatalog?.has_more" class="outline load-older" :disabled="coreCatalogLoading" @click="loadOlderCoreReleases">{{ coreCatalogLoading ? '读取中…' : '加载较早版本' }}</button></div></div></section>
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
      <section v-if="selectedNode && admin?.can_prepare_xray_installs" class="card">
        <div class="section-head">
          <h2>Xray 安装审批</h2>
          <button class="outline" @click="refreshNodeTasks(selectedNode.id)">刷新审批和结果</button>
        </div>
        <p>当前账号 ID：{{ admin.id }}。安装提案预留节点的下一个任务序号，有效期 30 分钟。</p>
        <form v-if="admin.role === 'operator' && !selectedNode.disabled && !selectedNode.pending" class="node-row" @submit.prevent="createXrayInstall">
          <label>精确版本<input v-model.trim="xrayInstallInput.version" placeholder="v26.10.31" required /></label>
          <label>架构<select v-model="xrayInstallInput.architecture"><option>amd64</option><option>arm64</option></select></label>
          <label>SHA-256<input v-model.trim="xrayInstallInput.sha256" pattern="[a-f0-9]{64}" maxlength="64" spellcheck="false" required /></label>
          <label>TUF Core 清单版本<input v-model.number="xrayInstallInput.manifest_version" type="number" min="1" max="9007199254740991" required /></label>
          <label>安全管理员 ID<input v-model.trim="xrayInstallInput.approver_id" maxlength="128" required /></label>
          <button :disabled="xrayInstallBusy">预留序号并创建提案</button>
        </form>
        <p v-if="xrayInstallError" class="error" role="alert">{{ xrayInstallError }}</p>
        <p v-if="!xrayInstalls.length && !xrayInstallError" class="empty">暂无与你相关的安装提案。</p>
        <div v-for="install in xrayInstalls" :key="install.proposal.task_id" class="audit-row">
          <div>
            <strong>#{{ install.proposal.sequence }} · Xray {{ install.proposal.version }} · {{ install.proposal.architecture }}</strong>
            <span>{{ xrayInstallStatus[install.status] }} · {{ new Date(install.proposal.expires_at * 1000).toLocaleString() }} 过期</span>
            <small v-if="xrayTask(install.proposal.task_id)" aria-live="polite">任务结果 {{ xrayTask(install.proposal.task_id)?.status }}</small>
          </div>
          <button class="outline" @click="downloadXrayProposal(install)">下载提案 JSON</button>
          <label v-if="admin.id === install.proposal.approver_id && install.status === 'AWAITING_APPROVAL'">
            登记双签审批 JSON
            <input type="file" accept=".json,application/json" :disabled="xrayInstallBusy" @change="uploadXrayApproval(install, $event)" />
          </label>
          <form v-if="admin.id === install.proposal.approver_id && install.status === 'APPROVAL_RECORDED'" class="node-row" @submit.prevent="uploadSignedXrayInstall(install, $event)">
            <label>原始审批 JSON<input name="approval" type="file" accept=".json,application/json" required /></label>
            <label>独立签发任务 JSON<input name="task" type="file" accept=".json,application/json" required /></label>
            <button :disabled="xrayInstallBusy">核验签发任务</button>
          </form>
          <button v-if="admin.id === install.proposal.approver_id && install.status === 'SIGNED_TASK_VERIFIED' && !xrayTask(install.proposal.task_id)"
            :disabled="xrayInstallBusy" @click="dispatchXrayInstall(install)">投递安装任务</button>
        </div>
      </section>
      <section class="card"><span class="eyebrow">AUDIT TRAIL</span><h2>安全事件</h2><div v-for="(event, i) in audits" :key="i" class="audit-row"><time>{{ new Date(event.at*1000).toLocaleString() }}</time><span>{{ event.action }}</span><small>{{ event.outcome }}</small></div><p v-if="!audits.length" class="empty">暂无事件</p></section>
      <section v-if="admin?.role === 'security_admin'" class="admin-grid">
        <form class="card" @submit.prevent="createAdmin"><span class="eyebrow">SCOPED ACCESS</span><h2>开通范围账号</h2><p>仅创建节点范围受限的审计员或运维员。运维员可创建只读状态查询任务；范围不可超出当前安全管理员的授权。</p><label>用户名<input v-model="newAdminUsername" autocomplete="off" required /></label><label>初始密码（至少 12 位）<input v-model="newAdminPassword" type="password" autocomplete="new-password" minlength="12" required /></label><label>角色<select v-model="newAdminRole"><option value="auditor">审计员</option><option value="operator">运维员（只读状态查询）</option></select></label><label>节点组范围<input v-model="newAdminGroups" placeholder="west, east" autocomplete="off" /></label><label>节点 ID 范围<input v-model="newAdminNodeIDs" placeholder="node-…" autocomplete="off" /></label><button :disabled="loading">创建范围账号</button><p v-if="createdTOTP" class="invite">一次性 TOTP 密钥：{{ createdTOTP }}<br />请通过可信渠道交给该账号持有人；此页面退出后不再显示。</p></form>
        <section class="card"><span class="eyebrow">ADMIN ACCOUNTS</span><h2>管理员账号</h2><div v-for="account in managedAdmins" :key="account.id" class="admin-row"><div><strong>{{ account.username }}</strong><span>{{ account.role }} · {{ account.node_groups.join(', ') || '指定节点' }}{{ account.node_ids.length ? ` · ${account.node_ids.join(', ')}` : '' }}</span></div><span class="status" :class="account.disabled ? 'off' : 'on'">{{ account.disabled ? '已禁用' : '启用中' }}</span><button v-if="!account.disabled && account.id !== admin?.id && account.role !== 'security_admin'" class="danger" @click="disableAdmin(account.id)">禁用</button></div><p v-if="!managedAdmins.length" class="empty">暂无可管理的范围账号</p></section>
      </section>
    </template>
    <footer>管理请求需经服务端认证与授权。Core 官方版本目录仅供查看；启用 Xray 的节点可通过独立审批安装 Core。</footer>
  </main>
</template>
