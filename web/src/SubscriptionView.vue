<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import LinkActions from './LinkActions.vue'
import { buildXrayClient, subscriptionEndpoint, subscriptionProtocol, validSubscription, xrayProtocolName, type XraySubscription } from './xraySubscription'

const subscription = ref<XraySubscription | null>(null)
const subscriptionURL = ref('')
const status = ref('正在读取订阅…')
const error = ref('')
const password = ref('')
const proxyPort = ref<number>(0)
const localPort = ref<number>(10808)
let expiryTimer = 0
const credentialLabel = computed(() => {
  if (!subscription.value) return '节点提供的凭据'
  const protocol = subscriptionProtocol(subscription.value, proxyPort.value)
  if (protocol === 'vless' || protocol === 'vmess') return '节点提供的 UUID'
  if (protocol === 'shadowsocks') return 'Shadowsocks 密钥（服务端密钥:用户密钥）'
  if (protocol === 'trojan') return '节点提供的 Trojan 密码'
  if (protocol === 'vless-reality') return '节点提供的 VLESS UUID:REALITY Short ID'
  return '节点提供的密码'
})
watch(proxyPort, () => {
  password.value = ''
  error.value = ''
})

onMounted(async () => {
  const token = window.location.hash.slice(1)
  window.history.replaceState(null, '', window.location.pathname)
  if (window.location.protocol !== 'https:' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.[A-Za-z0-9_-]{43}$/.test(token)) {
    status.value = '请打开管理员提供的 HTTPS 订阅链接。'
    return
  }
  try {
    const response = await fetch('/api/v1/subscription', {
      headers: { Authorization: `Bearer ${token}` },
      credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    })
    if (response.status === 429) {
      status.value = '读取过于频繁，请稍后重新打开订阅链接。'
      return
    }
    if (!response.ok) {
      status.value = response.status === 503 ? '订阅服务暂不可用，请稍后重试。' : '订阅已失效或节点授权暂不可用。'
      return
    }
    const data: unknown = await response.json()
    if (!validSubscription(data)) throw new Error()
    const link = new URL('/subscription', window.location.origin)
    link.hash = token
    subscription.value = data
    subscriptionURL.value = link.href
    proxyPort.value = data.ports[0]
    while (data.ports.includes(localPort.value)) localPort.value++
    status.value = ''
    updateExpiry()
    if (subscription.value) expiryTimer = window.setInterval(updateExpiry, 5000)
  } catch {
    status.value = '无法读取订阅，请重新打开链接重试。'
  }
})

onUnmounted(() => window.clearInterval(expiryTimer))

function updateExpiry() {
  if (!subscription.value || Date.now() < subscription.value.expires_at * 1000) return
  window.clearInterval(expiryTimer)
  status.value = '订阅已到期，请联系管理员。'
  subscription.value = null
  subscriptionURL.value = ''
  password.value = ''
}

function downloadClient() {
  updateExpiry()
  if (!subscription.value) return
  error.value = ''
  try {
    const config = buildXrayClient(subscription.value, proxyPort.value, localPort.value, password.value)
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
      <div v-if="subscription" class="context-bar">
        <span class="status on">有效</span>
        <strong>{{ subscription.username }}</strong>
        <span>{{ new Date(subscription.expires_at * 1000).toLocaleString() }} 到期</span>
      </div>
    </header>
    <template v-if="subscription">
      <section class="card subscription-config">
        <div class="section-head"><h2>可用配置</h2><small>修订 {{ subscription.revision }}</small></div>
        <form class="stack-form" @submit.prevent="downloadClient">
          <fieldset class="endpoint-list">
            <legend class="sr-only">选择获准的入站</legend>
            <label v-for="port in subscription.ports" :key="port" class="endpoint-option">
              <input v-model="proxyPort" type="radio" name="endpoint" :value="port" />
              <span><strong>{{ xrayProtocolName[subscriptionProtocol(subscription, port)] }}</strong>
                <small class="mono">{{ subscriptionEndpoint(subscription, port).address }}:{{ subscriptionEndpoint(subscription, port).port }}</small>
              </span>
            </label>
          </fieldset>
          <label>客户端 SOCKS5 监听端口
            <input v-model.number="localPort" type="number" required min="1024" max="65535" />
          </label>
          <label>{{ credentialLabel }}
            <input v-model="password" type="password" required maxlength="89" autocomplete="off" />
          </label>
          <button type="submit">生成并下载 Xray 配置</button>
          <p v-if="error" class="error" role="alert">{{ error }}</p>
        </form>
      </section>
      <section class="card">
        <h2>订阅链接</h2>
        <LinkActions :url="subscriptionURL" />
      </section>
      <section class="card">
        <h2>使用帮助</h2>
        <ol class="subscription-help">
          <li>选择入站，输入节点管理员交付的凭据并下载 <code>xray-client.json</code>。</li>
          <li>妥善保存配置文件，在客户端运行 <code>xray run -config xray-client.json</code>。</li>
          <li>使用回环端点时，请在能访问节点回环地址的环境中连接。</li>
        </ol>
        <p>凭据仅用于在本机生成配置，下载文件包含凭据。</p>
      </section>
    </template>
  </main>
</template>
