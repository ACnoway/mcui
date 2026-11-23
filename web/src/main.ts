import { createApp } from 'vue'
import App from './App.vue'
import SubscriptionView from './SubscriptionView.vue'
import './style.css'

createApp(window.location.pathname === '/subscription' ? SubscriptionView : App).mount('#app')
