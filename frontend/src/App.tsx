import { useEffect, useState } from 'react';
import { Button, ConfigProvider, Layout, Menu, Space, Spin, Tooltip, Typography, theme } from 'antd';
import {
  ApartmentOutlined,
  ClusterOutlined,
  DashboardOutlined,
  LogoutOutlined,
  MoonOutlined,
  SettingOutlined,
  SunOutlined,
  TeamOutlined,
} from '@ant-design/icons';
import { useQueryClient } from '@tanstack/react-query';
import { apiRequest, type NodeItem, type User } from './api';
import LoginView from './LoginView';
import OverviewPage from './OverviewPage';
import NodesPage from './NodesPage';
import InboundsPage from './InboundsPage';
import ClientsPage from './ClientsPage';
import SettingsPage from './SettingsPage';

type TabKey = 'overview' | 'nodes' | 'inbounds' | 'clients' | 'settings';

export default function App() {
  const qc = useQueryClient();
  const [isDark, setIsDark] = useState<boolean>(() => {
    const saved = localStorage.getItem('mcui-theme');
    if (saved) return saved === 'dark';
    return window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false;
  });
  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [user, setUser] = useState<User | null>(null);
  const [booting, setBooting] = useState(true);

  useEffect(() => {
    localStorage.setItem('mcui-theme', isDark ? 'dark' : 'light');
  }, [isDark]);

  useEffect(() => {
    apiRequest<User>('/api/auth/me')
      .then((u) => setUser(u))
      .catch(() => setUser(null))
      .finally(() => setBooting(false));

    const onUnauth = () => setUser(null);
    window.addEventListener('mcui:unauthorized', onUnauth);
    return () => window.removeEventListener('mcui:unauthorized', onUnauth);
  }, []);

  // Realtime WebSocket bridge (mirrors 3x-ui's websocketBridge.ts pattern)
  useEffect(() => {
    if (!user) return;
    let closed = false;
    let ws: WebSocket | null = null;
    let retryTimer: number | undefined;

    const connect = () => {
      if (closed) return;
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${proto}//${window.location.host}/api/ws`);
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data) as { type: string; data: NodeItem };
          if (msg.type.startsWith('node.') && msg.data?.id) {
            qc.setQueryData<NodeItem[]>(['nodes'], (prev) => {
              if (!prev) return prev;
              const idx = prev.findIndex((n) => n.id === msg.data.id);
              if (idx === -1) return [...prev, msg.data];
              const next = [...prev];
              next[idx] = msg.data;
              return next;
            });
          }
        } catch {
          // ignore non-json frames
        }
      };
      ws.onclose = () => {
        if (!closed) {
          retryTimer = window.setTimeout(connect, 3000);
        }
      };
    };

    connect();
    return () => {
      closed = true;
      if (retryTimer) window.clearTimeout(retryTimer);
      ws?.close();
    };
  }, [user, qc]);

  const handleLogout = async () => {
    await apiRequest('/api/auth/logout', { method: 'POST' }).catch(() => {});
    setUser(null);
    qc.clear();
  };

  return (
    <ConfigProvider
      theme={{
        algorithm: isDark ? theme.darkAlgorithm : theme.defaultAlgorithm,
        token: {
          colorPrimary: '#2563eb',
          borderRadius: 8,
          fontFamily: "-apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', 'PingFang SC', sans-serif",
        },
      }}
    >
      {booting ? (
        <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Spin size="large" />
        </div>
      ) : !user ? (
        <LoginView isDark={isDark} onSuccess={(u) => setUser(u)} />
      ) : (
        <Layout style={{ minHeight: '100vh' }}>
          <Layout.Sider
            width={216}
            breakpoint="lg"
            collapsedWidth={64}
            style={{
              background: isDark ? '#111622' : '#ffffff',
              borderRight: isDark ? '1px solid rgba(255,255,255,0.07)' : '1px solid rgba(15,23,42,0.06)',
            }}
          >
            <div
              style={{
                height: 56,
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '0 18px',
                borderBottom: isDark ? '1px solid rgba(255,255,255,0.06)' : '1px solid rgba(15,23,42,0.05)',
              }}
            >
              <div
                style={{
                  width: 28,
                  height: 28,
                  borderRadius: 7,
                  background: 'linear-gradient(135deg, #2563eb, #0ea5e9)',
                  color: '#fff',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >
                M
              </div>
              <Typography.Text strong style={{ fontSize: 15, letterSpacing: 0.3 }}>
                MCUI
              </Typography.Text>
            </div>

            <Menu
              mode="inline"
              selectedKeys={[activeTab]}
              onClick={(e) => setActiveTab(e.key as TabKey)}
              style={{ borderInlineEnd: 'none', background: 'transparent', paddingTop: 8 }}
              items={[
                { key: 'overview', icon: <DashboardOutlined />, label: '概览监控' },
                { key: 'nodes', icon: <ClusterOutlined />, label: '节点与内核' },
                { key: 'inbounds', icon: <ApartmentOutlined />, label: '入站管理' },
                { key: 'clients', icon: <TeamOutlined />, label: '全局客户端' },
                { key: 'settings', icon: <SettingOutlined />, label: '系统设置' },
              ]}
            />
          </Layout.Sider>

          <Layout style={{ background: isDark ? '#0b0f17' : '#f6f8fb' }}>
            <Layout.Header
              style={{
                height: 56,
                lineHeight: '56px',
                padding: '0 24px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                background: isDark ? '#111622' : '#ffffff',
                borderBottom: isDark ? '1px solid rgba(255,255,255,0.06)' : '1px solid rgba(15,23,42,0.05)',
              }}
            >
              <Typography.Text type="secondary" style={{ fontSize: 13 }}>
                分布式零端口 Agent 架构 · 首发内核 Xray
              </Typography.Text>

              <Space size={8}>
                <Tooltip title={isDark ? '切换浅色模式' : '切换深色模式'}>
                  <Button
                    type="text"
                    icon={isDark ? <SunOutlined /> : <MoonOutlined />}
                    onClick={() => setIsDark((d) => !d)}
                  />
                </Tooltip>
                <Typography.Text style={{ fontSize: 13 }}>{user.username}</Typography.Text>
                <Tooltip title="退出登录">
                  <Button type="text" icon={<LogoutOutlined />} onClick={handleLogout} />
                </Tooltip>
              </Space>
            </Layout.Header>

            <Layout.Content style={{ padding: 24, maxWidth: 1360, width: '100%', margin: '0 auto' }}>
              {activeTab === 'overview' && <OverviewPage />}
              {activeTab === 'nodes' && <NodesPage />}
              {activeTab === 'inbounds' && <InboundsPage />}
              {activeTab === 'clients' && <ClientsPage />}
              {activeTab === 'settings' && (
                <SettingsPage user={user} onPasswordChanged={() => setUser(null)} />
              )}
            </Layout.Content>
          </Layout>
        </Layout>
      )}
    </ConfigProvider>
  );
}
