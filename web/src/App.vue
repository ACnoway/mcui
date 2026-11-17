<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

type NodeRecord = { id: string; name: string; group: string; last_seen: number; disabled: boolean; needs_reenrollment?: boolean }
type Audit = { at: number; actor: string; action: string; resource: string; outcome: string }
type StatusResult = { core?: string; load_state?: string; active_state?: string; sub_state?: string; observed_at?: string; error_code?: string }
type TaskAck = { status_version: number; status: string; result?: StatusResult }
type StatusTask = { task_id: string; node_id: string; sequence: number; created_by?: string; created_at?: string; approval: string; control?: string; operation: string; core: string; issued_at: string; expires_at: string; active: boolean; lease_deadline?: string; status: string; acks: TaskAck[] }
type ManagedAdmin = { id: string; username: string; role: string; node_ids: string[]; node_groups: string[]; disabled: boolean }
type AdminInfo = { id: string; username: string; role: string; csrf_token: string; mfa_recent: boolean; can_create_invites: boolean; can_disable_nodes: boolean }
type CoreCatalogAsset = { name: string; size: number; download_url: string; digest?: string }
type CoreCatalogRelease = { version: string; title: string; published_at: string; prerelease: boolean; url: string; assets: CoreCatalogAsset[] }
type CoreCatalogEntry = { id: string; name: string; repository: string; releases: CoreCatalogRelease[] }
type CoreCatalog = { retrieved_at: string; stale: boolean; cores: CoreCatalogEntry[] }
class ApiError extends Error { constructor(readonly status: number, message: string) { super(message) } }
const username = ref('')
const password = ref('')
const code = ref('')
const nodes = ref<NodeRecord[]>([])
const audits = ref<Audit[]>([])
const tasks = ref<StatusTask[]>([])
const coreCatalog = ref<CoreCatalog | null>(null)
const coreCatalogCore = ref('xray')
const coreCatalogLoading = ref(false)
const coreCatalogError = ref('')
const managedAdmins = ref<ManagedAdmin[]>([])
const error = ref('')
const loading = ref(false)
const loggedIn = ref(false)
const invite = ref('')
const inviteGroup = ref('default')
const inviteTTL = ref(3600)
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
  await loadCoreCatalog()
  if (selectedNode.value) await loadTasks(selectedNode.value.id)
}
async function loadCoreCatalog() {
  coreCatalogLoading.value = true
  coreCatalogError.value = ''
  try {
    coreCatalog.value = await api<CoreCatalog>('/api/v1/admin/cores/releases')
  } catch (e) {
    coreCatalogError.value = e instanceof Error ? e.message : '读取官方发布目录失败'
  } finally {
    coreCatalogLoading.value = false
  }
}
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
async function createInvite() {
  try { const result = await apiWithStepUp<{ invite: string }>('/api/v1/admin/invites', { node_group: inviteGroup.value, ttl_seconds: inviteTTL.value }); invite.value = result.invite }
  catch (e) { error.value = e instanceof Error ? e.message : '创建邀请失败' }
}
async function disableNode(id: string) {
  if (!confirm('确认禁用该节点？')) return
  try { await apiWithStepUp('/api/v1/admin/nodes/disable', { node_id: id }); await refresh() }
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
async function showNode(id: string) { try { selectedNode.value = await api<NodeRecord>(`/api/v1/admin/nodes/${encodeURIComponent(id)}`); await loadTasks(id) } catch (e) { error.value = e instanceof Error ? e.message : '读取节点失败' } }
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
async function logout() { try { await api('/api/v1/admin/logout', { method: 'POST', body: '{}' }) } finally { csrfToken = ''; admin.value = null; selectedNode.value = null; loggedIn.value = false; nodes.value = []; audits.value = []; tasks.value = []; managedAdmins.value = []; createdTOTP.value = '' } }
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
      <section class="metrics"><div class="metric"><span>登记节点</span><strong>{{ nodes.length }}</strong></div><div class="metric"><span>在线心跳</span><strong>{{ nodes.filter(n => !n.disabled && Date.now()/1000 - n.last_seen < 60).length }}</strong></div><div class="metric"><span>当前阶段</span><strong>03 / CORE LIFECYCLE</strong></div><div class="metric"><span>当前账号</span><strong>{{ admin?.role }}</strong></div></section>
      <section class="card core-catalog"><div class="section-head"><div><span class="eyebrow">OFFICIAL RELEASE CATALOG</span><h2>Core 官方版本目录</h2></div><button class="outline" :disabled="coreCatalogLoading" @click="loadCoreCatalog">{{ coreCatalogLoading ? '读取中…' : '刷新目录' }}</button></div><p>目录来自官方 GitHub Releases。官方版本列表用于发现版本，尚不代表制品已获安装授权；安装任务与 Helper 安装事务仍未开放。</p><p v-if="coreCatalog?.stale" class="catalog-stale">上游暂不可用，当前显示缓存目录（{{ new Date(coreCatalog.retrieved_at).toLocaleString() }}）。</p><p v-if="coreCatalogError" class="catalog-error">{{ coreCatalogError }}</p><div v-if="coreCatalog" class="catalog-layout"><label>Core<select v-model="coreCatalogCore"><option v-for="core in coreCatalog.cores" :key="core.id" :value="core.id">{{ core.name }}（{{ core.repository }}）</option></select></label><div v-if="selectedCoreCatalog?.releases.length" class="release-list"><article v-for="release in selectedCoreCatalog.releases" :key="release.version" class="release-row"><div class="release-heading"><div><strong>{{ release.version }}</strong><span v-if="release.prerelease" class="release-badge">预发布</span><small>{{ release.title }} · {{ new Date(release.published_at).toLocaleDateString() }}</small></div><a :href="release.url" target="_blank" rel="noopener noreferrer">官方发布页 ↗</a></div><details v-if="release.assets.length"><summary>{{ release.assets.length }} 个发布制品</summary><div v-for="asset in release.assets" :key="asset.name" class="release-asset"><a :href="asset.download_url" target="_blank" rel="noopener noreferrer">{{ asset.name }}</a><small>{{ (asset.size / 1048576).toFixed(1) }} MiB · {{ asset.digest || '上游未提供 SHA-256' }}</small></div></details><small v-else>此版本没有可用的官方制品链接</small></article></div><div v-else class="empty">{{ selectedCoreCatalog ? '官方目录中没有可显示的版本' : '正在加载发布目录' }}</div></div></section>
      <section class="card"><div class="section-head"><div><span class="eyebrow">INVENTORY</span><h2>节点</h2></div><button @click="refresh">刷新</button></div><div v-if="!nodes.length" class="empty">暂无已注册节点。先创建一次性邀请，再在空 Agent 上注册。</div><div v-for="node in nodes" :key="node.id" class="node-row"><div class="node-avatar">{{ node.name.slice(0,1).toUpperCase() }}</div><div class="node-main"><strong>{{ node.name }}</strong><span>{{ node.id }} · {{ node.group }}</span></div><span class="status" :class="node.disabled ? 'off' : Date.now()/1000-node.last_seen < 60 ? 'on' : 'idle'">{{ node.disabled ? '已禁用' : Date.now()/1000-node.last_seen < 60 ? '在线' : '离线' }}</span><button class="outline" @click="showNode(node.id)">详情</button><button v-if="admin?.can_disable_nodes && !node.disabled" class="danger" @click="disableNode(node.id)">禁用</button></div><div v-if="selectedNode" class="audit-row"><span>节点详情：{{ selectedNode.name }} · {{ selectedNode.id }} · {{ selectedNode.group }} · 最近心跳 {{ new Date(selectedNode.last_seen*1000).toLocaleString() }}<span v-if="selectedNode.needs_reenrollment"> · 需要重新注册</span></span><button class="quiet" @click="selectedNode = null">关闭</button></div></section>
      <section v-if="selectedNode" class="card"><div class="section-head"><div><span class="eyebrow">SIGNED STATUS TASKS</span><h2>只读状态查询</h2></div><button class="outline" @click="loadTasks(selectedNode.id)">刷新任务</button></div><div class="node-row"><label>Core<select v-model="statusCore"><option value="xray">Xray</option><option value="sing-box">sing-box</option><option value="mita">Mita</option></select></label><button @click="createStatusTask">签发查询任务</button></div><div v-if="!tasks.length" class="empty">暂无任务；查询任务只读取固定 Core 服务状态。</div><div v-for="task in tasks" :key="task.task_id" class="audit-row task-row"><div><strong>{{ task.core }} · #{{ task.sequence }}</strong><span>{{ task.task_id }} · {{ task.created_at ? new Date(task.created_at).toLocaleString() : new Date(task.issued_at).toLocaleString() }}</span><small>来源：{{ task.created_by || '审计记录可查' }} · 审批：无需单独审批 · 步骤：{{ task.operation }}</small><small v-if="task.control">控制消息：{{ task.control === 'cancel' ? '取消待处理' : '跳过待处理' }}</small></div><span class="status" :class="task.status === 'SUCCEEDED' ? 'on' : task.active ? 'idle' : 'off'">{{ task.status }}</span><button v-if="task.active && (admin?.role === 'security_admin' || admin?.role === 'operator') && Date.now() < Date.parse(task.expires_at) && task.control !== 'cancel'" class="danger" @click="controlStatusTask(task, 'cancel')">取消待处理</button><button v-if="task.active && task.status === 'QUEUED' && !task.lease_deadline && !task.control && (admin?.role === 'security_admin' || admin?.role === 'operator')" class="danger" @click="controlStatusTask(task, 'void')">关闭未投递任务</button><button v-if="task.active && (admin?.role === 'security_admin' || admin?.role === 'operator') && Date.now() >= Date.parse(task.expires_at) && task.control !== 'skip'" class="outline" @click="controlStatusTask(task, 'skip')">跳过已过期任务</button><div v-for="ack in task.acks" :key="ack.status_version" class="task-ack"><small>{{ ack.status_version }} · {{ ack.status }}</small><small v-if="ack.result?.active_state">{{ ack.result.active_state }} / {{ ack.result.sub_state }} · {{ ack.result.load_state }}</small><small v-if="ack.result?.error_code">失败代码：{{ ack.result.error_code }}</small></div></div></section>
      <section class="bottom-grid"><form v-if="admin?.can_create_invites" class="card" @submit.prevent="createInvite"><span class="eyebrow">ONE-TIME ENROLLMENT</span><h2>注册邀请</h2><label>节点组<input v-model="inviteGroup" required /></label><label>有效期（秒）<input v-model.number="inviteTTL" type="number" min="60" max="86400" required /></label><button>创建邀请</button><p v-if="invite" class="invite">{{ invite }}</p></form><section class="card"><span class="eyebrow">AUDIT TRAIL</span><h2>安全事件</h2><div v-for="(event, i) in audits" :key="i" class="audit-row"><time>{{ new Date(event.at*1000).toLocaleString() }}</time><span>{{ event.action }}</span><small>{{ event.outcome }}</small></div><p v-if="!audits.length" class="empty">暂无事件</p></section></section>
      <section v-if="admin?.role === 'security_admin'" class="admin-grid">
        <form class="card" @submit.prevent="createAdmin"><span class="eyebrow">SCOPED ACCESS</span><h2>开通范围账号</h2><p>仅创建节点范围受限的审计员或运维员。运维员可创建只读状态查询任务；范围不可超出当前安全管理员的授权。</p><label>用户名<input v-model="newAdminUsername" autocomplete="off" required /></label><label>初始密码（至少 12 位）<input v-model="newAdminPassword" type="password" autocomplete="new-password" minlength="12" required /></label><label>角色<select v-model="newAdminRole"><option value="auditor">审计员</option><option value="operator">运维员（只读状态查询）</option></select></label><label>节点组范围<input v-model="newAdminGroups" placeholder="west, east" autocomplete="off" /></label><label>节点 ID 范围<input v-model="newAdminNodeIDs" placeholder="node-…" autocomplete="off" /></label><button :disabled="loading">创建范围账号</button><p v-if="createdTOTP" class="invite">一次性 TOTP 密钥：{{ createdTOTP }}<br />请通过可信渠道交给该账号持有人；此页面退出后不再显示。</p></form>
        <section class="card"><span class="eyebrow">ADMIN ACCOUNTS</span><h2>管理员账号</h2><div v-for="account in managedAdmins" :key="account.id" class="admin-row"><div><strong>{{ account.username }}</strong><span>{{ account.role }} · {{ account.node_groups.join(', ') || '指定节点' }}{{ account.node_ids.length ? ` · ${account.node_ids.join(', ')}` : '' }}</span></div><span class="status" :class="account.disabled ? 'off' : 'on'">{{ account.disabled ? '已禁用' : '启用中' }}</span><button v-if="!account.disabled && account.id !== admin?.id && account.role !== 'security_admin'" class="danger" @click="disableAdmin(account.id)">禁用</button></div><p v-if="!managedAdmins.length" class="empty">暂无可管理的范围账号</p></section>
      </section>
    </template>
    <footer>管理请求需经服务端认证与授权。Core 官方版本目录仅供查看；Agent 安装包不包含 Core，安装与其他节点副作用操作仍关闭。</footer>
  </main>
</template>
