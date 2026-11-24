<script setup lang="ts">
import { computed, ref } from 'vue'
import PanelDialog from './PanelDialog.vue'
import { destinationLabel, type Destination, type Network } from './xrayManagement'

type Protocol = '' | 'http' | 'vless' | 'vmess'
type Inbound = { port: number; protocol?: string; users: string[] }
export type PanelInboundChange = { remove: true } | {
  protocol: Protocol; username: string; credential: string; destination?: Destination
}

const props = defineProps<{
  inbounds: Inbound[]; network: Network | null; busy: boolean
  save: (port: number, change: PanelInboundChange) => Promise<void>
}>()

const protocols: { value: Protocol; label: string }[] = [
  { value: '', label: 'SOCKS5' }, { value: 'http', label: 'HTTP' },
  { value: 'vless', label: 'VLESS' }, { value: 'vmess', label: 'VMess' },
]
const form = ref<{
  port: number; editing: boolean; protocol: Protocol; username: string; credential: string; address: string; targetPort: number
} | null>(null)
const error = ref('')
const duplicate = computed(() => !!form.value && !form.value.editing && props.inbounds.some(inbound => inbound.port === form.value?.port))
const needsCredential = computed(() => {
  const draft = form.value
  const prior = draft && props.inbounds.find(inbound => inbound.port === draft.port)
  return !draft?.editing || !prior || (prior.protocol ?? '') !== draft.protocol || prior.users[0] !== draft.username
})

function protocolLabel(protocol?: string) {
  return protocols.find(option => option.value === (protocol ?? ''))?.label ?? protocol
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
    })
    form.value = null
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : '保存入站失败'
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
  </div>
  <p v-if="error && !form" class="notice" role="alert">{{ error }}</p>
  <div v-if="inbounds.length" class="table-wrap">
    <table class="data-table" aria-label="主控入站草稿">
      <thead><tr><th scope="col">监听</th><th scope="col">协议</th><th scope="col">客户端</th><th scope="col">TCP 目标</th><th scope="col">操作</th></tr></thead>
      <tbody><tr v-for="inbound in inbounds" :key="inbound.port">
        <th scope="row">127.0.0.1:{{ inbound.port }}</th>
        <td>{{ protocolLabel(inbound.protocol) }}</td>
        <td>{{ inbound.users[0] }}</td>
        <td>{{ target(inbound.port) ? destinationLabel(target(inbound.port)!) : '拒绝全部' }}</td>
        <td><div class="actions">
          <button type="button" class="outline" :disabled="busy" @click="open(inbound)">编辑</button>
          <button type="button" class="quiet" :disabled="busy" @click="remove(inbound.port)">删除</button>
        </div></td>
      </tr></tbody>
    </table>
  </div>
  <p v-else class="empty">暂无入站。</p>

  <PanelDialog v-if="form" :title="form.editing ? `编辑入站 · ${form.port}` : '添加入站'" @close="form = null">
    <form @submit.prevent="submit">
      <label>协议 <select v-model="form.protocol" @change="form.credential = ''">
        <option v-for="protocol in protocols" :key="protocol.value" :value="protocol.value">{{ protocol.label }}</option>
      </select></label>
      <label>监听端口 <input v-model.number="form.port" type="number" min="1024" max="65535" required :disabled="form.editing" /></label>
      <label>客户端用户名 <input v-model="form.username" pattern="[a-z][a-z0-9_\-]{0,23}" autocomplete="off" required /></label>
      <label>{{ form.protocol === 'vless' || form.protocol === 'vmess' ? 'UUID' : '密码' }}
        <input v-model="form.credential" autocomplete="off" :required="needsCredential" :placeholder="needsCredential ? '' : '留空保留原凭据'" />
      </label>
      <div class="actions"><button type="button" class="outline" :disabled="busy" @click="generateCredential">生成凭据</button></div>
      <p class="feedback">请在保存前复制凭据。当前监听地址为节点隔离网络的 127.0.0.1。</p>
      <label>允许的目标 IPv4 <input v-model.trim="form.address" inputmode="decimal" placeholder="留空拒绝全部" /></label>
      <label>目标 TCP 端口 <input v-model.number="form.targetPort" type="number" min="1" max="65535" :required="!!form.address" :disabled="!form.address" /></label>
      <p v-if="duplicate" class="notice" role="alert">该端口已在草稿中使用。</p>
      <p v-if="error" class="notice" role="alert">{{ error }}</p>
      <div class="actions"><button type="submit" :disabled="busy || duplicate">{{ busy ? '保存中…' : '保存' }}</button></div>
    </form>
  </PanelDialog>
</template>
