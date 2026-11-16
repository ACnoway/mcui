<script setup lang="ts">
import { onMounted, ref } from 'vue'

type NodeRecord = { id: string; name: string; group: string; last_seen: number; disabled: boolean }
type Audit = { at: number; actor: string; action: string; resource: string; outcome: string }
const username = ref('')
const password = ref('')
const code = ref('')
const nodes = ref<NodeRecord[]>([])
const audits = ref<Audit[]>([])
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

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: 'same-origin', ...init, headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) } })
  if (!response.ok) throw new Error((await response.text()).trim() || `HTTP ${response.status}`)
  return response.json() as Promise<T>
}
async function refresh() {
  const [nodeData, auditData] = await Promise.all([api<NodeRecord[]>('/api/v1/admin/nodes'), api<Audit[]>('/api/v1/admin/audit')])
  nodes.value = nodeData
  audits.value = auditData.slice(-100).reverse()
}
async function login() {
  loading.value = true; error.value = ''
  try { await api('/api/v1/admin/login', { method: 'POST', body: JSON.stringify({ username: username.value, password: password.value, code: code.value }) }); loggedIn.value = true; password.value = ''; code.value = ''; await refresh() }
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
  try { const result = await api<{ invite: string }>('/api/v1/admin/invites', { method: 'POST', body: JSON.stringify({ node_group: inviteGroup.value, ttl_seconds: inviteTTL.value }) }); invite.value = result.invite }
  catch (e) { error.value = e instanceof Error ? e.message : '创建邀请失败' }
}
async function disableNode(id: string) {
  if (!confirm('确认禁用该节点？')) return
  try { await api('/api/v1/admin/nodes/disable', { method: 'POST', body: JSON.stringify({ node_id: id }) }); await refresh() }
  catch (e) { error.value = e instanceof Error ? e.message : '禁用失败' }
}
async function logout() { try { await api('/api/v1/admin/logout', { method: 'POST', body: '{}' }) } finally { loggedIn.value = false; nodes.value = []; audits.value = [] } }
onMounted(async () => { try { await refresh(); loggedIn.value = true } catch { loggedIn.value = false } })
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
      <section class="metrics"><div class="metric"><span>登记节点</span><strong>{{ nodes.length }}</strong></div><div class="metric"><span>在线心跳</span><strong>{{ nodes.filter(n => !n.disabled && Date.now()/1000 - n.last_seen < 60).length }}</strong></div><div class="metric"><span>当前阶段</span><strong>01 / IDENTITY</strong></div></section>
      <section class="card"><div class="section-head"><div><span class="eyebrow">INVENTORY</span><h2>节点</h2></div><button @click="refresh">刷新</button></div><div v-if="!nodes.length" class="empty">暂无已注册节点。先创建一次性邀请，再在空 Agent 上注册。</div><div v-for="node in nodes" :key="node.id" class="node-row"><div class="node-avatar">{{ node.name.slice(0,1).toUpperCase() }}</div><div class="node-main"><strong>{{ node.name }}</strong><span>{{ node.id }} · {{ node.group }}</span></div><span class="status" :class="node.disabled ? 'off' : Date.now()/1000-node.last_seen < 60 ? 'on' : 'idle'">{{ node.disabled ? '已禁用' : Date.now()/1000-node.last_seen < 60 ? '在线' : '离线' }}</span><button v-if="!node.disabled" class="danger" @click="disableNode(node.id)">禁用</button></div></section>
      <section class="bottom-grid"><form class="card" @submit.prevent="createInvite"><span class="eyebrow">ONE-TIME ENROLLMENT</span><h2>注册邀请</h2><label>节点组<input v-model="inviteGroup" required /></label><label>有效期（秒）<input v-model.number="inviteTTL" type="number" min="60" max="86400" required /></label><button>创建邀请</button><p v-if="invite" class="invite">{{ invite }}</p></form><section class="card"><span class="eyebrow">AUDIT TRAIL</span><h2>安全事件</h2><div v-for="(event, i) in audits" :key="i" class="audit-row"><time>{{ new Date(event.at*1000).toLocaleString() }}</time><span>{{ event.action }}</span><small>{{ event.outcome }}</small></div><p v-if="!audits.length" class="empty">暂无事件</p></section></section>
    </template>
    <footer>管理请求需经服务端认证与授权。Agent 安装包不包含 Core；此阶段不开放节点副作用操作。</footer>
  </main>
</template>
