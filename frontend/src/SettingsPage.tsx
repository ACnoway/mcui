import { useState } from 'react';
import { Button, Card, Form, Input, Space, Typography, message } from 'antd';
import { apiRequest, type User } from './api';

interface SettingsPageProps {
  user: User;
  onPasswordChanged: () => void;
}

export default function SettingsPage({ user, onPasswordChanged }: SettingsPageProps) {
  const [loading, setLoading] = useState(false);
  const [form] = Form.useForm();

  const onFinish = async (values: { currentPassword: string; newUsername: string; newPassword: string }) => {
    setLoading(true);
    try {
      await apiRequest('/api/auth/password', {
        method: 'POST',
        body: JSON.stringify(values),
      });
      message.success('管理员凭据已更新，请重新登录');
      onPasswordChanged();
    } catch (e) {
      message.error(e instanceof Error ? e.message : '修改失败');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%', maxWidth: 520 }}>
      <Typography.Title level={5} style={{ margin: 0 }}>
        面板安全设置
      </Typography.Title>

      <Card size="small" title="修改管理员账号与密码">
        <Form
          form={form}
          layout="vertical"
          initialValues={{ newUsername: user.username }}
          onFinish={onFinish}
        >
          <Form.Item name="newUsername" label="管理员用户名" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="currentPassword" label="当前密码" rules={[{ required: true }]}>
            <Input.Password />
          </Form.Item>
          <Form.Item
            name="newPassword"
            label="新密码 (至少 6 位)"
            rules={[{ required: true }, { min: 6, message: '密码至少 6 位' }]}
          >
            <Input.Password />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={loading}>
            保存并吊销旧会话
          </Button>
        </Form>
      </Card>
    </Space>
  );
}
