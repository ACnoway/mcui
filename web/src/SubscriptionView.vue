<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import LinkActions from './LinkActions.vue'
import { buildXrayClient, subscriptionEndpoint, subscriptionProtocol, validSubscription, xrayProtocolName, type XraySubscription } from './xraySubscription'

type Entry = { key: string; node: string; port: number; config: XraySubscription }
type Selection = { username: string; expiresAt: number; entries: Entry[]; credential?: string }
const selection = ref<Selection | null>(null)
const endpointKey = ref('')
const activeEntry = computed(() => selection.value?.entries.find(entry => entry.key === endpointKey.value))
const subscriptionURL = ref('')
const status = ref('正在读取订阅…')
const error = ref('')
const password = ref('')
const localPort = ref<number>(10808)
let expiryTimer = 0
let subscriptionRead: AbortController | undefined
const credentialLabel = computed(() => {
  const entry = activeEntry.value
  if (!entry) return '节点提供的凭据'
  const protocol = subscriptionProtocol(entry.config, entry.port)
  if (protocol === 'vless' || protocol === 'vmess') return '节点提供的 UUID'
  if (protocol === 'shadowsocks') return 'Shadowsocks 密钥（服务端密钥:用户密钥）'
  if (protocol === 'trojan') return '节点提供的 Trojan 密码'
  if (protocol === 'vless-reality') return '节点提供的 VLESS UUID:REALITY Short ID'
  return '节点提供的密码'
})
watch(endpointKey, () => {
  password.value = ''
  error.value = ''
  const entry = activeEntry.value
  if (entry?.config.ports.includes(localPort.value)) {
    localPort.value = 10808
    while (entry.config.ports.includes(localPort.value)) localPort.value++
  }
})

function parseSelection(data: unknown, clientPage: boolean): Selection | null {
  if (!clientPage) {
    if (!validSubscription(data)) return null
    return {
      username: data.username, expiresAt: data.expires_at,
      entries: data.ports.map(port => ({ key: String(port), port, node: '', config: data })),
    }
  }
  if (!data || typeof data !== 'object') return null
  const payload = data as { schema_version?: number; username?: string; expires_at?: number; entries?: unknown[]; credential?: unknown }
  if (payload.schema_version !== 1 || typeof payload.username !== 'string' || !/^[a-z][a-z0-9_-]{0,23}$/.test(payload.username) ||
    typeof payload.expires_at !== 'number' || !Number.isSafeInteger(payload.expires_at) || payload.expires_at <= 0 ||
    !Array.isArray(payload.entries) || !payload.entries.length || payload.entries.length > 64) return null
  const entries: Entry[] = []
  const keys = new Set<string>()
  for (const item of payload.entries) {
    if (!item || typeof item !== 'object') return null
    const entry = item as { node_id?: string; node_name?: string; config?: unknown }
    if (typeof entry.node_id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(entry.node_id) || typeof entry.node_name !== 'string' ||
      !validSubscription(entry.config) || entry.config.ports.length !== 1 || entry.config.expires_at !== payload.expires_at) return null
    const port = entry.config.ports[0]
    const key = `${entry.node_id}:${port}`
    if (keys.has(key)) return null
    keys.add(key)
    entries.push({ key, node: entry.node_name || entry.node_id, port, config: entry.config })
  }
  const credential = payload.credential
  if (credential !== undefined && (entries.length !== 1 || typeof credential !== 'string' ||
    !/^(?:[A-Za-z0-9_-]{43}|[0-9a-f-]{36})$/.test(credential))) return null
  return { username: payload.username, expiresAt: payload.expires_at, entries, credential }
}

async function loadSubscription() {
  subscriptionRead?.abort()
  const request = new AbortController()
  subscriptionRead = request
  window.clearInterval(expiryTimer)
  selection.value = null
  endpointKey.value = ''
  subscriptionURL.value = ''
  password.value = ''
  error.value = ''
  localPort.value = 10808
  status.value = '正在读取订阅…'
  const token = window.location.hash.slice(1)
  const pathname = window.location.pathname
  const clientPage = pathname === '/subscription/client'
  window.history.replaceState(null, '', pathname)
  if (window.location.protocol !== 'https:' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.[A-Za-z0-9_-]{43}$/.test(token)) {
    status.value = '请打开管理员提供的 HTTPS 订阅链接。'
    return
  }
  try {
    const response = await fetch(clientPage ? '/api/v1/client-subscription' : '/api/v1/subscription', {
      headers: { Authorization: `Bearer ${token}` },
      credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: request.signal,
    })
    if (request.signal.aborted) return
    if (response.status === 429) {
      status.value = '读取过于频繁，请稍后重新打开订阅链接。'
      return
    }
    if (!response.ok) {
      status.value = response.status === 503 ? '订阅服务暂不可用，请稍后重试。' : '订阅已失效或节点授权暂不可用。'
      return
    }
    const data: unknown = await response.json()
    if (request.signal.aborted) return
    const parsed = parseSelection(data, clientPage)
    if (!parsed) throw new Error()
    const link = new URL(pathname, window.location.origin)
    link.hash = token
    selection.value = parsed
    subscriptionURL.value = link.href
    endpointKey.value = parsed.entries[0].key
    status.value = ''
    updateExpiry()
    if (selection.value) expiryTimer = window.setInterval(updateExpiry, 5000)
  } catch {
    if (!request.signal.aborted) status.value = '无法读取订阅，请重新打开链接重试。'
  }
}

onMounted(() => {
  window.addEventListener('hashchange', loadSubscription)
  void loadSubscription()
})

onUnmounted(() => {
  window.removeEventListener('hashchange', loadSubscription)
  subscriptionRead?.abort()
  window.clearInterval(expiryTimer)
})

function updateExpiry() {
  if (!selection.value || Date.now() < selection.value.expiresAt * 1000) return
  window.clearInterval(expiryTimer)
  status.value = '订阅已到期，请联系管理员。'
  selection.value = null
  subscriptionURL.value = ''
  password.value = ''
}

function downloadClient() {
  updateExpiry()
  const entry = activeEntry.value
  if (!entry) return
  error.value = ''
  try {
    const config = buildXrayClient(entry.config, entry.port, localPort.value, selection.value?.credential ?? password.value)
    const url = URL.createObjectURL(new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' }))
    const download = document.createElement('a')
    download.href = url
    download.download = 'xray-client.json'
    download.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
    password.value = ''
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : '配置生成失败。'
  }
}
</script>

<template>
  <main class="shell subscription-view">
    <header class="subscription-heading">
      <div class="brand"><span class="brand-mark" aria-hidden="true">M</span><strong>MCUI</strong></div>
      <h1>Xray 客户端订阅</h1>
      <p v-if="status" class="notice" role="status">{{ status }}</p>
      <div v-if="selection" class="context-bar">
        <span class="status on">有效</span>
        <strong>{{ selection.username }}</strong>
        <span>{{ new Date(selection.expiresAt * 1000).toLocaleString() }} 到期</span>
      </div>
    </header>
    <template v-if="selection">
      <section class="card subscription-config">
        <div class="section-head"><h2>可用入站</h2><small v-if="activeEntry">修订 {{ activeEntry.config.revision }}</small></div>
        <form class="stack-form" @submit.prevent="downloadClient">
          <fieldset class="endpoint-list">
            <legend class="sr-only">选择获准的入站</legend>
            <label v-for="entry in selection.entries" :key="entry.key" class="endpoint-option">
              <input v-model="endpointKey" type="radio" name="endpoint" :value="entry.key" />
              <span><strong><template v-if="entry.node">{{ entry.node }} · 入站 {{ entry.port }} · </template>{{ xrayProtocolName[subscriptionProtocol(entry.config, entry.port)] }}</strong>
                <small class="mono">{{ subscriptionEndpoint(entry.config, entry.port).address }}:{{ subscriptionEndpoint(entry.config, entry.port).port }}</small>
              </span>
            </label>
          </fieldset>
          <label>客户端 SOCKS5 监听端口
            <input v-model.number="localPort" type="number" required min="1024" max="65535" />
          </label>
          <label v-if="!selection.credential">{{ credentialLabel }}
            <input v-model="password" type="password" required maxlength="89" autocomplete="off" />
          </label>
          <details v-else-if="activeEntry">
            <summary>查看本地 SOCKS5 凭据</summary>
            <p>用户名 <code>{{ activeEntry.config.username }}</code></p>
            <p>密码 <code>{{ selection.credential }}</code></p>
          </details>
          <p v-if="activeEntry && activeEntry.config.username !== selection.username">节点凭据名 {{ activeEntry.config.username }}</p>
          <button type="submit">生成并下载 Xray 配置</button>
          <p v-if="error" class="error" role="alert">{{ error }}</p>
        </form>
      </section>
      <section v-if="!selection.credential" class="card">
        <h2>订阅链接</h2>
        <LinkActions :url="subscriptionURL" />
      </section>
      <section class="card">
        <h2>使用帮助</h2>
        <ol class="subscription-help">
          <li v-if="!selection.credential">选择入站，输入管理员交付的凭据并下载 <code>xray-client.json</code>。</li>
          <li>妥善保存配置文件，在客户端运行 <code>xray run -config xray-client.json</code>。</li>
          <li>使用回环端点时，请在能访问节点回环地址的环境中连接。</li>
        </ol>
        <p>凭据仅用于在本机生成配置，下载文件包含凭据。</p>
      </section>
    </template>
  </main>
</template>
