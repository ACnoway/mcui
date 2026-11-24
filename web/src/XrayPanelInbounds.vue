<script setup lang="ts">
import { computed, ref } from 'vue'
import PanelDialog from './PanelDialog.vue'
import { destinationLabel, type Destination, type Network } from './xrayManagement'
import { buildXrayClient, type XraySubscription } from './xraySubscription'

type Protocol = '' | 'http' | 'vless' | 'vmess' | 'trojan'
type Inbound = { port: number; protocol?: string; users: string[]; public_endpoint?: Destination; tls_cert_sha256?: string }
export type PanelInboundChange = { remove: true } | {
  protocol: Protocol; username: string; credential: string; destination?: Destination
  public_endpoint?: Destination; rotate_tls?: boolean
}

const props = defineProps<{
  inbounds: Inbound[]; network: Network | null; busy: boolean
  managedBindings: { port: number; credential: string }[]
  save: (port: number, change: PanelInboundChange) => Promise<void>
  trojan: boolean; addresses: string[]; trust?: XraySubscription['trojan_trust']; applied: Inbound[]; revision: number
}>()

const protocols: { value: Protocol; label: string }[] = [
  { value: '', label: 'SOCKS5' }, { value: 'http', label: 'HTTP' },
  { value: 'vless', label: 'VLESS' }, { value: 'vmess', label: 'VMess' },
  { value: 'trojan', label: 'Trojan/TLS' },
]
const form = ref<{
  port: number; editing: boolean; protocol: Protocol; username: string; credential: string; address: string; targetPort: number
  published: boolean; publicAddress: string; publicPort: number; rotateTLS: boolean
} | null>(null)
const error = ref('')
const download = ref<{ inbound: Inbound; revision: number; localPort: number; password: string; error: string } | null>(null)
const duplicate = computed(() => !!form.value && !form.value.editing && props.inbounds.some(inbound => inbound.port === form.value?.port))
const needsCredential = computed(() => {
  const draft = form.value
  const prior = draft && props.inbounds.find(inbound => inbound.port === draft.port)
  return !draft?.editing || !prior || (prior.protocol ?? '') !== draft.protocol || prior.users[0] !== draft.username
})

function protocolLabel(protocol?: string) {
  return protocols.find(option => option.value === (protocol ?? ''))?.label ?? protocol
}

function centrallyBound(port: number) {
  return props.managedBindings.some(binding => binding.port === port)
}

function target(port: number) {
  const tag = props.network?.routes.find(route => route.inbound_port === port)?.outbound_tag
  return props.network?.outbounds.find(outbound => outbound.tag === tag)?.destination
}

function open(inbound?: Inbound) {
  const existing = inbound && target(inbound.port)
  const firstFree = Array.from({ length: 5 }, (_, index) => 1080 + index)
    .find(port => !props.inbounds.some(entry => entry.port === port)) ?? 1080
  form.value = {
    editing: !!inbound, port: inbound?.port ?? firstFree,
    protocol: protocols.find(option => option.value === inbound?.protocol)?.value ?? '',
    username: inbound?.users[0] ?? '', credential: '', address: existing?.address ?? '', targetPort: existing?.port ?? 443,
    published: !!inbound?.public_endpoint, publicAddress: inbound?.public_endpoint?.address ?? props.addresses[0] ?? '',
    publicPort: inbound?.public_endpoint?.port ?? 443, rotateTLS: false,
  }
  error.value = ''
}

function generateCredential() {
  const draft = form.value
  if (!draft) return
  if (draft.protocol === 'vless' || draft.protocol === 'vmess') {
    draft.credential = crypto.randomUUID()
    return
  }
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  draft.credential = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

async function submit() {
  const draft = form.value
  if (!draft || props.busy || duplicate.value) return
  error.value = ''
  try {
    await props.save(draft.port, {
      protocol: draft.protocol, username: draft.username, credential: draft.credential,
      destination: draft.address ? { address: draft.address, port: draft.targetPort } : undefined,
      public_endpoint: draft.protocol === 'trojan' && draft.published ? { address: draft.publicAddress, port: draft.publicPort } : undefined,
      rotate_tls: draft.protocol === 'trojan' && draft.rotateTLS ? true : undefined,
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
  if (!props.trust) return undefined
  return props.applied.find(entry => entry.port === port && entry.protocol === 'trojan' &&
    entry.public_endpoint && entry.tls_cert_sha256 === props.trust?.sha256)
}

function openDownload(port: number) {
  const inbound = appliedPublic(port)
  if (inbound) download.value = { inbound, revision: props.revision, localPort: port === 10808 ? 10809 : 10808, password: '', error: '' }
}

function downloadClient() {
  const dialog = download.value
  if (!dialog) return
  const { inbound, localPort, password } = dialog
  const active = appliedPublic(inbound.port)
  if (!active?.public_endpoint || dialog.revision !== props.revision || active.users[0] !== inbound.users[0] ||
      destinationLabel(active.public_endpoint) !== destinationLabel(inbound.public_endpoint!) ||
      active.tls_cert_sha256 !== inbound.tls_cert_sha256) {
    dialog.error = '生效入站已变化，请重新打开客户端配置。'
    return
  }
  try {
    const metadata: XraySubscription = {
      schema_version: 4, username: active.users[0], address: '127.0.0.1', ports: [active.port],
      port_protocols: { [active.port]: 'trojan' }, public_endpoints: { [active.port]: active.public_endpoint },
      trojan_trust: props.trust, revision: props.revision, expires_at: Math.floor(Date.now() / 1000) + 60,
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
      <thead><tr><th scope="col">监听</th><th scope="col">协议</th><th scope="col">客户端</th><th scope="col">TCP 目标</th><th scope="col">操作</th></tr></thead>
      <tbody><tr v-for="inbound in inbounds" :key="inbound.port">
        <th scope="row">{{ inbound.public_endpoint ? destinationLabel(inbound.public_endpoint) : `127.0.0.1:${inbound.port}` }}</th>
        <td>{{ protocolLabel(inbound.protocol) }}</td>
        <td>{{ inbound.users[0] }}<template v-if="centrallyBound(inbound.port)"> · 已在「客户端」绑定</template></td>
        <td>{{ target(inbound.port) ? destinationLabel(target(inbound.port)!) : '拒绝全部' }}</td>
        <td><div class="actions">
          <button type="button" class="outline" :disabled="busy" @click="open(inbound)">编辑</button>
          <button v-if="!centrallyBound(inbound.port)" type="button" class="quiet" :disabled="busy" @click="remove(inbound.port)">删除</button>
          <button v-if="appliedPublic(inbound.port)" type="button" class="outline" @click="openDownload(inbound.port)">客户端配置</button>
        </div></td>
      </tr></tbody>
    </table>
  </div>
  <p v-else class="empty">暂无入站。</p>

  <PanelDialog v-if="form" :title="form.editing ? `编辑入站 · ${form.port}` : '添加入站'" @close="form = null">
    <form @submit.prevent="submit">
      <label>协议 <select v-model="form.protocol" :disabled="form.editing && centrallyBound(form.port)" @change="form.credential = ''">
        <option v-for="protocol in protocols.filter(option => trojan || option.value !== 'trojan')" :key="protocol.value" :value="protocol.value">{{ protocol.label }}</option>
      </select></label>
      <label>监听端口 <input v-model.number="form.port" type="number" min="1024" max="65535" required :disabled="form.editing" /></label>
      <label>客户端用户名 <input v-model="form.username" pattern="[a-z][a-z0-9_\-]{0,23}" autocomplete="off"
        :disabled="form.editing && centrallyBound(form.port)" required /></label>
      <template v-if="!form.editing || !centrallyBound(form.port)">
        <label>{{ form.protocol === 'vless' || form.protocol === 'vmess' ? 'UUID' : '密码' }}
          <input v-model="form.credential" autocomplete="off" :required="needsCredential" :placeholder="needsCredential ? '' : '留空保留原凭据'" />
        </label>
        <div class="actions"><button type="button" class="outline" :disabled="busy" @click="generateCredential">生成凭据</button></div>
        <p class="feedback">请在保存前复制客户端凭据。</p>
      </template>
      <p v-else class="feedback">可在「客户端」的分享面板轮换凭据。</p>
      <template v-if="form.protocol === 'trojan'">
        <label><input v-model="form.published" type="checkbox" :disabled="!addresses.length && !form.published" /> 启用公网 TCP 接入</label>
        <p v-if="!addresses.length" class="feedback">节点暂未上报可绑定的公网 IPv4。</p>
        <template v-if="form.published">
          <label>宿主公网 IPv4 <select v-model="form.publicAddress" required>
            <option v-if="!addresses.includes(form.publicAddress)" value="" disabled>请选择节点上报的地址</option>
            <option v-for="address in addresses" :key="address" :value="address">{{ address }}</option>
          </select></label>
          <label>公网 TCP 端口 <input v-model.number="form.publicPort" type="number" min="1" max="65535" required /></label>
        </template>
        <label v-if="inbounds.some(entry => entry.protocol === 'trojan')">
          <input v-model="form.rotateTLS" type="checkbox" /> 轮换此节点主控入站共用的 TLS 证书
        </label>
      </template>
      <label>允许的目标 IPv4 <input v-model.trim="form.address" inputmode="decimal" placeholder="留空拒绝全部" /></label>
      <label>目标 TCP 端口 <input v-model.number="form.targetPort" type="number" min="1" max="65535" :required="!!form.address" :disabled="!form.address" /></label>
      <p v-if="duplicate" class="notice" role="alert">该端口已在草稿中使用。</p>
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
      <div class="actions"><button type="submit" :disabled="busy || duplicate">{{ busy ? '保存中…' : '保存' }}</button></div>
    </form>
  </PanelDialog>

  <PanelDialog v-if="download" title="下载生效的 Trojan 客户端配置" @close="download = null">
    <form @submit.prevent="downloadClient">
      <p>{{ destinationLabel(download.inbound.public_endpoint!) }} · {{ download.inbound.users[0] }}</p>
      <label>客户端密码 <input v-model="download.password" type="password" autocomplete="off" required /></label>
      <label>本地 SOCKS5 端口 <input v-model.number="download.localPort" type="number" min="1024" max="65535" required /></label>
      <p v-if="download.error" class="notice" role="alert">{{ download.error }}</p>
      <div class="actions"><button type="submit">下载 Xray 配置</button></div>
    </form>
  </PanelDialog>
</template>
