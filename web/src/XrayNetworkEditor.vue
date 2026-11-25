<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { destinationLabel, testRoute, type Destination, type Network, type Route } from './xrayManagement'

const props = defineProps<{
  tab: 'outbound' | 'routing'
  network: Network | null
  destinations: Destination[]
  inboundPorts: number[]
  disabled: boolean
  panelInbounds: boolean
  multiRoute: boolean
}>()
const emit = defineEmits<{ change: [network: Network | null] }>()
const outboundIndex = ref<number | null>(null)
const routeIndex = ref<number | null>(null)
const tag = ref('')
const destination = ref('')
const address = ref('')
const tcpPort = ref(443)
const inboundPort = ref<number | ''>('')
const outboundTag = ref('')
const testInbound = ref<number | ''>('')
const testAddress = ref('')
const testPort = ref<number | ''>('')
const testedRoute = ref<{ inbound: number; address: string; port: number } | null>(null)

const validTestAddress = computed(() => {
  const octets = testAddress.value.split('.')
  return octets.length === 4 && octets.every(octet =>
    /^(0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255,
  )
})
const canTestRoute = computed(() => props.network && testInbound.value !== '' &&
  props.inboundPorts.includes(testInbound.value) && validTestAddress.value &&
  typeof testPort.value === 'number' && Number.isInteger(testPort.value) && testPort.value >= 1 && testPort.value <= 65535)
const routeDecision = computed(() => {
  if (!props.network || !testedRoute.value) return null
  return testRoute(props.network, testedRoute.value.inbound, {
    address: testedRoute.value.address,
    port: testedRoute.value.port,
  })
})

const outbounds = computed(() => props.network?.outbounds ?? [])
const routes = computed(() => props.network?.routes ?? [])
const destinationChoices = computed(() => props.destinations.filter(target =>
  !outbounds.value.some((outbound, index) =>
    index !== outboundIndex.value && destinationLabel(outbound.destination) === destinationLabel(target)),
))
const target = computed<Destination | undefined>(() => {
  if (!props.panelInbounds) return destinationChoices.value.find(item => destinationLabel(item) === destination.value)
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(address.value) || !Number.isInteger(tcpPort.value) || tcpPort.value < 1 || tcpPort.value > 65535) return
  const octets = address.value.split('.')
  if (octets.some(octet => Number(octet) > 255 || String(Number(octet)) !== octet)) return
  const entry = { address: address.value, port: tcpPort.value }
  if (!outbounds.value.some((outbound, index) => index !== outboundIndex.value && destinationLabel(outbound.destination) === destinationLabel(entry))) return entry
})
const tagAvailable = computed(() => /^[a-z][a-z0-9_-]{0,23}$/.test(tag.value) && tag.value !== 'deny' &&
  !outbounds.value.some((outbound, index) => index !== outboundIndex.value && outbound.tag === tag.value))
const routeOutbounds = computed(() => outbounds.value.filter(outbound => !routes.value.some((route, index) =>
  index !== routeIndex.value && route.inbound_port === inboundPort.value && (!props.multiRoute || route.outbound_tag === outbound.tag),
)))
const canAddRoute = computed(() => props.inboundPorts.some(port => outbounds.value.some(outbound =>
  !routes.value.some(route => route.inbound_port === port && (!props.multiRoute || route.outbound_tag === outbound.tag)),
)))
const withdrawnDestinations = computed(() => outbounds.value.filter(outbound =>
  !props.destinations.some(target => destinationLabel(target) === destinationLabel(outbound.destination)),
).map(outbound => outbound.tag))

watch(() => props.tab, cancelEdit)
watch(() => props.network, () => {
  cancelEdit()
  testedRoute.value = null
})
watch([testInbound, testAddress, testPort], () => { testedRoute.value = null })

function cancelEdit() {
  outboundIndex.value = null
  routeIndex.value = null
}

function editOutbound(index: number) {
  outboundIndex.value = index
  const outbound = outbounds.value[index]
  tag.value = outbound?.tag ?? ''
  destination.value = outbound ? destinationLabel(outbound.destination) : ''
  address.value = outbound?.destination.address ?? ''
  tcpPort.value = outbound?.destination.port ?? 443
}

function saveOutbound() {
  if (props.disabled || !props.network || outboundIndex.value === null || !tagAvailable.value) return
  if (!target.value) return
  const previous = outbounds.value[outboundIndex.value]
  const updated = [...outbounds.value]
  updated[outboundIndex.value] = { tag: tag.value, destination: { ...target.value } }
  emit('change', {
    outbounds: updated,
    routes: routes.value.map(route => route.outbound_tag === previous?.tag ? { ...route, outbound_tag: tag.value } : route),
  })
}

function references(tag: string) {
  return routes.value.filter(route => route.outbound_tag === tag).length
}

function removeOutbound(index: number) {
  const outbound = outbounds.value[index]
  if (props.disabled || !outbound || references(outbound.tag)) return
  emit('change', { outbounds: outbounds.value.filter((_, position) => position !== index), routes: routes.value })
}

function editRoute(index: number) {
  routeIndex.value = index
  const route = routes.value[index]
  inboundPort.value = route?.inbound_port ?? ''
  outboundTag.value = route?.outbound_tag ?? ''
}

function saveRoute() {
  if (props.disabled || routeIndex.value === null || inboundPort.value === '' ||
    !props.inboundPorts.includes(inboundPort.value) || !routeOutbounds.value.some(outbound => outbound.tag === outboundTag.value)) return
  const updated = [...routes.value]
  updated[routeIndex.value] = { inbound_port: inboundPort.value, outbound_tag: outboundTag.value }
  updateRoutes(updated)
}

function updateRoutes(updated: Route[]) {
  if (!props.disabled) emit('change', { outbounds: outbounds.value, routes: updated })
}

function moveRoute(index: number, direction: number) {
  const next = index + direction
  if (next < 0 || next >= routes.value.length) return
  const updated = [...routes.value]
  const [route] = updated.splice(index, 1)
  updated.splice(next, 0, route)
  updateRoutes(updated)
}

function runRouteTest() {
  if (!canTestRoute.value || testInbound.value === '' || testPort.value === '') return
  testedRoute.value = { inbound: testInbound.value, address: testAddress.value, port: testPort.value }
}
</script>

<template>
  <p v-if="panelInbounds && !network" class="feedback">请先保存一个主控入站，再配置出站和路由。</p>
  <div v-else class="page-stack">
    <div class="actions">
      <button v-if="!network && destinations.length" type="button" :disabled="disabled"
        @click="emit('change', { outbounds: [], routes: [] })">自定义出站与路由</button>
      <button v-if="network && !panelInbounds" type="button" class="quiet" :disabled="disabled" @click="emit('change', null)">恢复节点默认路由</button>
      <button v-if="network && tab === 'outbound'" type="button" :disabled="disabled || outbounds.length >= (panelInbounds ? 4 : destinations.length) || outboundIndex !== null"
        @click="editOutbound(outbounds.length)">添加出站</button>
      <button v-if="network && tab === 'routing'" type="button" :disabled="disabled || !canAddRoute || routeIndex !== null"
        @click="editRoute(routes.length)">添加规则</button>
    </div>
    <p v-if="!network && !destinations.length" class="feedback">节点尚未批准自定义出站目标。</p>
    <p v-if="!panelInbounds && withdrawnDestinations.length" class="notice" role="status">节点已收回这些出站目标的许可。请修改目标或清除引用后删除出站。{{ withdrawnDestinations.join('、') }}</p>
    <p v-if="network && !routes.length" class="notice" role="status">草稿没有放行规则，应用后会拒绝所有业务流量。</p>
    <template v-if="tab === 'outbound'">
      <form v-if="outboundIndex !== null" class="filters" @submit.prevent="saveOutbound">
        <label>标签<input v-model.trim="tag" required maxlength="24" pattern="[a-z][a-z0-9_\-]{0,23}" :disabled="disabled" /></label>
        <template v-if="panelInbounds">
          <label>公网 IPv4 目标<input v-model.trim="address" inputmode="decimal" required :disabled="disabled" /></label>
          <label>TCP 端口<input v-model.number="tcpPort" type="number" required min="1" max="65535" :disabled="disabled" /></label>
        </template>
        <label v-else>批准的 IPv4 TCP 目标<select v-model="destination" required :disabled="disabled">
          <option value="" disabled>选择目标</option>
          <option v-for="target in destinationChoices" :key="destinationLabel(target)">{{ destinationLabel(target) }}</option>
        </select></label>
        <button type="submit" :disabled="disabled || !tagAvailable || !target">更新草稿</button>
        <button type="button" class="quiet" @click="cancelEdit">取消</button>
      </form>
      <div class="table-wrap">
        <table class="data-table" aria-label="出站">
          <thead><tr><th scope="col">标签</th><th scope="col">协议</th><th scope="col">目标</th><th scope="col">路由引用</th><th scope="col">操作</th></tr></thead>
          <tbody>
            <tr><th scope="row">deny</th><td>Blackhole</td><td>拒绝</td><td>默认出站</td><td>—</td></tr>
            <tr v-if="!network"><th scope="row">allowed</th><td>Freedom</td><td>节点默认 IPv4 TCP 目标</td><td>节点默认规则</td><td>—</td></tr>
            <tr v-for="(outbound, index) in outbounds" :key="outbound.tag">
              <th scope="row">{{ outbound.tag }}</th><td>Freedom</td><td>{{ destinationLabel(outbound.destination) }}</td>
              <td>{{ references(outbound.tag) }}</td>
              <td><div class="actions">
                <button type="button" class="outline" :disabled="disabled || outboundIndex !== null" @click="editOutbound(index)">编辑</button>
                <button type="button" class="danger" :disabled="disabled || outboundIndex !== null || !!references(outbound.tag)" @click="removeOutbound(index)">删除</button>
              </div></td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
    <template v-else>
      <form v-if="network" class="filters" @submit.prevent="runRouteTest">
        <label>测试入站<select v-model="testInbound" required>
          <option value="" disabled>选择入站</option>
          <option v-for="port in inboundPorts" :key="port" :value="port">{{ port }}</option>
        </select></label>
        <label>目标 IPv4<input v-model.trim="testAddress" inputmode="decimal" required /></label>
        <label>目标 TCP 端口<input v-model.number="testPort" type="number" min="1" max="65535" required /></label>
        <button type="submit" class="outline" :disabled="!canTestRoute">测试草稿路由</button>
      </form>
      <p v-if="testedRoute" class="feedback" role="status">
        <template v-if="routeDecision">匹配第 {{ routeDecision.ruleIndex + 1 }} 条规则，使用出站 {{ routeDecision.outbound.tag }}。</template>
        <template v-else>没有匹配的规则，使用默认拒绝出站。</template>
      </p>
      <form v-if="routeIndex !== null" class="filters" @submit.prevent="saveRoute">
        <label>入站<select v-model="inboundPort" required :disabled="disabled" @change="outboundTag = ''">
          <option value="" disabled>选择入站</option>
          <option v-for="port in inboundPorts" :key="port" :value="port">入站 {{ port }}</option>
        </select></label>
        <label>目标出站<select v-model="outboundTag" required :disabled="disabled || inboundPort === ''">
          <option value="" disabled>选择出站</option>
          <option v-for="outbound in routeOutbounds" :key="outbound.tag" :value="outbound.tag">{{ outbound.tag }} · {{ destinationLabel(outbound.destination) }}</option>
        </select></label>
        <button type="submit" :disabled="disabled || inboundPort === '' || !outboundTag">更新草稿</button>
        <button type="button" class="quiet" @click="cancelEdit">取消</button>
      </form>
      <div v-if="!network || routes.length" class="table-wrap">
        <table class="data-table" aria-label="路由规则">
          <thead><tr><th scope="col">顺序</th><th scope="col">匹配入站</th><th scope="col">TCP 目标</th><th scope="col">出站</th><th scope="col">操作</th></tr></thead>
          <tbody>
            <tr v-if="!network && inboundPorts.length"><td>1</td><td>{{ inboundPorts.join('、') }}</td><td>节点默认 IPv4 TCP 目标</td><td>allowed</td><td>—</td></tr>
            <tr v-else-if="!network"><td colspan="5">草稿没有已授权入站，默认拒绝所有业务流量。</td></tr>
            <tr v-for="(route, index) in routes" :key="`${route.inbound_port}-${route.outbound_tag}`">
              <td>{{ index + 1 }}</td><td>{{ route.inbound_port }}</td>
              <td>{{ destinationLabel(outbounds.find(outbound => outbound.tag === route.outbound_tag)!.destination) }}</td><td>{{ route.outbound_tag }}</td>
              <td><div class="actions">
                <button type="button" class="outline" :disabled="disabled || routeIndex !== null" @click="editRoute(index)">编辑</button>
                <button type="button" class="quiet" :disabled="disabled || routeIndex !== null || index === 0" @click="moveRoute(index, -1)">上移</button>
                <button type="button" class="quiet" :disabled="disabled || routeIndex !== null || index === routes.length - 1" @click="moveRoute(index, 1)">下移</button>
                <button type="button" class="danger" :disabled="disabled || routeIndex !== null" @click="updateRoutes(routes.filter((_, position) => position !== index))">删除</button>
              </div></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="network && !inboundPorts.length" class="feedback">请先在入站或客户端页为入站分配客户端。</p>
      <p v-if="network && !outbounds.length" class="feedback">请先在出站页添加目标出站。</p>
    </template>
  </div>
</template>
