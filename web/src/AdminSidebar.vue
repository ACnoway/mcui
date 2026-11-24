<script lang="ts">
export type AdminPage = 'overview' | 'nodes' | 'config' | 'subscriptions' | 'audit' | 'versions' | 'tasks' | 'admins'
</script>

<script setup lang="ts">
import { nextTick, ref } from 'vue'

defineProps<{ page: AdminPage; username: string; canManageAdmins: boolean }>()
const emit = defineEmits<{ navigate: [page: AdminPage]; logout: [] }>()
const mainItems = [
  { page: 'nodes', label: '节点列表', icon: '▤' },
  { page: 'config', label: '代理配置', icon: '⇄' },
  { page: 'subscriptions', label: '客户端订阅', icon: '↗' },
] as const
const settingsItems = [
  { page: 'audit', label: '审计日志', icon: '◷' },
  { page: 'versions', label: 'Core 版本', icon: '⬡' },
  { page: 'tasks', label: '任务', icon: '≡' },
  { page: 'admins', label: '管理员', icon: '♙' },
] as const
const settingsOpen = ref(false)
const settingsToggle = ref<HTMLButtonElement | null>(null)
const menuOpen = ref(false)
const menuToggle = ref<HTMLButtonElement | null>(null)
const sidebar = ref<HTMLElement | null>(null)

async function toggleMenu() {
  if (menuOpen.value) {
    closeMenu()
    return
  }
  menuOpen.value = true
  await nextTick()
  sidebar.value?.querySelector<HTMLButtonElement>('[aria-current="page"]')?.focus()
}

function closeMenu() {
  if (!menuOpen.value) return
  menuOpen.value = false
  menuToggle.value?.focus()
}

function closeOnEscape() {
  if (!settingsOpen.value) {
    closeMenu()
    return
  }
  settingsOpen.value = false
  settingsToggle.value?.focus()
}

function navigate(page: AdminPage) {
  emit('navigate', page)
  closeMenu()
}
</script>

<template>
  <header class="mobile-bar">
    <strong>MCUI</strong>
    <button ref="menuToggle" class="outline" type="button" :aria-expanded="menuOpen"
      aria-controls="admin-sidebar" @click="toggleMenu" @keydown.esc.stop="closeMenu">菜单</button>
  </header>
  <button v-if="menuOpen" class="menu-backdrop" type="button" tabindex="-1" aria-label="关闭菜单" @click="closeMenu"></button>
  <aside id="admin-sidebar" ref="sidebar" class="admin-sidebar" :class="{ 'is-open': menuOpen }" @keydown.esc.stop="closeOnEscape">
    <div class="brand"><span class="brand-mark" aria-hidden="true">M</span><strong>MCUI</strong></div>
    <nav aria-label="面板导航" class="side-nav">
      <button type="button" :aria-current="page === 'overview' ? 'page' : undefined" @click="navigate('overview')">
        <span class="nav-icon" aria-hidden="true">▦</span>总览
      </button>
      <p class="nav-label">节点管理</p>
      <button v-for="item in mainItems" :key="item.page" type="button"
        :aria-current="page === item.page ? 'page' : undefined" @click="navigate(item.page)">
        <span class="nav-icon" aria-hidden="true">{{ item.icon }}</span>{{ item.label }}
      </button>
      <div class="settings-nav">
        <button ref="settingsToggle" type="button" :aria-expanded="settingsOpen"
          aria-controls="settings-items" @click="settingsOpen = !settingsOpen">
          <span class="nav-icon" aria-hidden="true">⚙</span>设置
          <span class="settings-chevron" aria-hidden="true">{{ settingsOpen ? '▾' : '▴' }}</span>
        </button>
        <div v-show="settingsOpen" id="settings-items">
          <template v-for="item in settingsItems" :key="item.page">
            <button v-if="item.page !== 'admins' || canManageAdmins" type="button"
              :aria-current="page === item.page ? 'page' : undefined" @click="navigate(item.page)">
              <span class="nav-icon" aria-hidden="true">{{ item.icon }}</span>{{ item.label }}
            </button>
          </template>
        </div>
      </div>
    </nav>
    <div class="side-account">
      <strong>{{ username }}</strong>
      <button class="quiet" type="button" @click="emit('logout')">退出登录</button>
    </div>
  </aside>
</template>
