<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { buildXrayClient, validSubscription, type XraySubscription } from './xraySubscription'

const subscription = ref<XraySubscription | null>(null)
const status = ref('正在读取订阅…')
const error = ref('')
const password = ref('')
const proxyPort = ref<number>(0)
const localPort = ref<number>(10808)

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
      status.value = '订阅已失效或节点授权暂不可用。'
      return
    }
    const data: unknown = await response.json()
    if (!validSubscription(data)) throw new Error()
    subscription.value = data
    proxyPort.value = data.ports[0]
    while (data.ports.includes(localPort.value)) localPort.value++
    status.value = ''
  } catch {
    status.value = '无法读取订阅，请重新打开链接重试。'
  }
})

function downloadClient() {
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
  <main class="shell">
    <section class="card subscription-view">
      <h1>Xray 客户端订阅</h1>
      <p v-if="status" role="status">{{ status }}</p>
      <form v-if="subscription" @submit.prevent="downloadClient">
        <p>账号 {{ subscription.username }} · 修订 {{ subscription.revision }} · {{ new Date(subscription.expires_at * 1000).toLocaleString() }} 到期</p>
        <p>在能访问节点回环端口的环境运行 Xray 客户端。密码仅用于生成本地文件。</p>
        <label>节点端口
          <select v-model="proxyPort">
            <option v-for="port in subscription.ports" :key="port" :value="port">127.0.0.1:{{ port }} · {{ subscription.http_ports?.includes(port) ? 'HTTP' : 'SOCKS5' }}</option>
          </select>
        </label>
        <label>客户端 SOCKS5 监听端口
          <input v-model.number="localPort" type="number" required min="1024" max="65535" />
        </label>
        <label>节点提供的密码
          <input v-model="password" type="password" required minlength="43" maxlength="43" autocomplete="off" />
        </label>
        <button>下载 Xray 客户端配置</button>
        <p v-if="error" class="error" role="alert">{{ error }}</p>
      </form>
    </section>
  </main>
</template>
