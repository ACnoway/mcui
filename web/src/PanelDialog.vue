<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, useId } from 'vue'

defineProps<{ title: string; drawer?: boolean }>()
const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement | null>(null)
const titleId = useId()

onMounted(() => dialog.value?.showModal())
onBeforeUnmount(() => dialog.value?.close())
</script>

<template>
  <dialog ref="dialog" class="panel-dialog" :class="{ 'core-drawer': drawer }" :aria-labelledby="titleId"
    @cancel.prevent="emit('close')">
    <div class="dialog-header section-head">
      <h2 :id="titleId">{{ title }}</h2>
      <button class="quiet" type="button" @click="emit('close')">关闭</button>
    </div>
    <div class="dialog-content"><slot /></div>
  </dialog>
</template>
