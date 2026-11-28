import { useState } from 'react';
import { Button, Card, Form, Input, Typography, message } from 'antd';
import { LockOutlined, UserOutlined } from '@ant-design/icons';
import { apiRequest, type User } from './api';

interface LoginViewProps {
  isDark: boolean;
  onSuccess: (user: User) => void;
}

export default function LoginView({ isDark, onSuccess }: LoginViewProps) {
  const [loading, setLoading] = useState(false);

  const handleFinish = async (values: { username: string; password: string }) => {
    setLoading(true);
    try {
      const res = await apiRequest<{ user: User }>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify(values),
      });
      onSuccess(res.user);
    } catch (err) {
      message.error(err instanceof Error ? err.message : '登录失败');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
        background: isDark
          ? 'radial-gradient(circle at 50% 0%, #172033 0%, #0b0f17 70%)'
          : 'radial-gradient(circle at 50% 0%, #eef4ff 0%, #f7f9fc 70%)',
      }}
    >
      <Card
        style={{
          width: '100%',
          maxWidth: 380,
          borderRadius: 14,
          boxShadow: isDark ? '0 18px 48px rgba(0,0,0,0.45)' : '0 16px 40px rgba(15,23,42,0.07)',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div
            style={{
              display: 'inline-flex',
              width: 44,
              height: 44,
              borderRadius: 11,
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 700,
              fontSize: 18,
              color: '#fff',
              background: 'linear-gradient(135deg, #2563eb, #0ea5e9)',
              marginBottom: 12,
            }}
          >
            M
          </div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            MCUI 分布式面板
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            轻量化多节点 · 多内核集中控制面
          </Typography.Text>
        </div>

        <Form layout="vertical" onFinish={handleFinish} requiredMark={false}>
          <Form.Item name="username" rules={[{ required: true, message: '请输入管理员账号' }]}>
            <Input size="large" prefix={<UserOutlined />} placeholder="用户名 (默认 admin)" autoFocus />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password size="large" prefix={<LockOutlined />} placeholder="密码 (默认 admin)" />
          </Form.Item>
          <Button type="primary" htmlType="submit" size="large" block loading={loading} style={{ marginTop: 8 }}>
            登 录
          </Button>
        </Form>
      </Card>
    </div>
  );
}
