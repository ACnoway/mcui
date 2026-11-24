<script setup lang="ts">
import { ref, watch } from 'vue'

const props = defineProps<{ url: string; showQr?: boolean; label?: string }>()
const linkInput = ref<HTMLInputElement | null>(null)
const canvas = ref<HTMLCanvasElement | null>(null)
const qrVisible = ref(!!props.showQr)
const copyStatus = ref('')
const qrError = ref('')

watch(() => props.url, () => { copyStatus.value = '' })
watch([() => props.url, canvas], async ([url, target], _, onCleanup) => {
  if (!target) return
  let cancelled = false
  onCleanup(() => { cancelled = true })
  qrError.value = ''
  try {
    const { default: qrcode } = await import('qrcode-generator')
    if (cancelled) return
    const code = qrcode(0, 'M')
    code.addData(url)
    code.make()
    const cell = 6
    const margin = 4
    const modules = code.getModuleCount()
    target.width = target.height = (modules + margin * 2) * cell
    const context = target.getContext('2d')
    if (!context) throw new Error('Canvas unavailable')
    context.fillStyle = '#fff'
    context.fillRect(0, 0, target.width, target.height)
    context.fillStyle = '#000'
    for (let row = 0; row < modules; row++) {
      for (let col = 0; col < modules; col++) {
        if (code.isDark(row, col)) context.fillRect((col + margin) * cell, (row + margin) * cell, cell, cell)
      }
    }
  } catch {
    if (!cancelled) qrError.value = '二维码生成失败，请复制订阅链接。'
  }
}, { flush: 'post' })

async function copyLink() {
  const url = props.url
  try {
    await navigator.clipboard.writeText(url)
    if (props.url === url) copyStatus.value = '已复制链接。'
  } catch {
    linkInput.value?.select()
    copyStatus.value = '无法访问剪贴板，已选中链接，可手动复制。'
  }
}
</script>

<template>
  <div class="link-actions">
    <label>{{ label ?? '订阅链接' }}
      <input ref="linkInput" type="text" :value="url" readonly autocomplete="off" spellcheck="false" />
    </label>
    <div class="actions">
      <button type="button" @click="copyLink">{{ label ? '复制链接' : '复制订阅' }}</button>
      <button type="button" class="outline" :aria-expanded="qrVisible" @click="qrVisible = !qrVisible">
        {{ qrVisible ? '隐藏二维码' : '显示二维码' }}
      </button>
    </div>
    <p v-if="copyStatus" role="status">{{ copyStatus }}</p>
    <canvas v-if="qrVisible" v-show="!qrError" ref="canvas" class="subscription-qr" role="img" aria-label="订阅链接二维码"></canvas>
    <p v-if="qrVisible && qrError" class="error" role="alert">{{ qrError }}</p>
  </div>
</template>
