import { createApp } from 'vue'
import App from './App.vue'
import SubscriptionView from './SubscriptionView.vue'
import './style.css'

const subscriptionPage = ['/subscription', '/subscription/client'].includes(window.location.pathname)
createApp(subscriptionPage ? SubscriptionView : App).mount('#app')
