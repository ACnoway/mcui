import { useMemo, useState } from 'react';
import {
  Button,
  Card,
  DatePicker,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Progress,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd';
import {
  CopyOutlined,
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  QrcodeOutlined,
  RetweetOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { QRCodeSVG } from 'qrcode.react';
import dayjs from 'dayjs';
import { apiRequest, formatBytes, type ClientItem, type InboundItem, type SubscriptionBundle } from './api';

interface ClientFormValues {
  email: string;
  subId: string;
  uuid: string;
  password: string;
  flow: string;
  totalGB: number;
  expiryDate?: dayjs.Dayjs | null;
  enable: boolean;
  comment: string;
  inboundIds: number[];
}

export default function ClientsPage() {
  const qc = useQueryClient();
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<ClientItem | null>(null);
  const [subModal, setSubModal] = useState<SubscriptionBundle | null>(null);
  const [form] = Form.useForm<ClientFormValues>();

  const { data: clients = [], isLoading } = useQuery({
    queryKey: ['clients'],
    queryFn: () => apiRequest<ClientItem[]>('/api/clients'),
    refetchInterval: 5000,
  });

  const { data: inbounds = [] } = useQuery({
    queryKey: ['inbounds'],
    queryFn: () => apiRequest<InboundItem[]>('/api/inbounds'),
  });

  const inboundMap = useMemo(() => {
    const m = new Map<number, InboundItem>();
    for (const ib of inbounds) m.set(ib.id, ib);
    return m;
  }, [inbounds]);

  const inboundGroupedOptions = useMemo(() => {
    const byNode = new Map<string, { label: string; value: number }[]>();
    for (const ib of inbounds) {
      const groupName = ib.nodeName || `Node #${ib.nodeId}`;
      const arr = byNode.get(groupName) ?? [];
      arr.push({
        label: `[${groupName}] ${ib.remark} (${ib.protocol.toUpperCase()} :${ib.port})`,
        value: ib.id,
      });
      byNode.set(groupName, arr);
    }
    return Array.from(byNode.entries()).map(([label, options]) => ({ label, options }));
  }, [inbounds]);

  const saveMutation = useMutation({
    mutationFn: (v: ClientFormValues) => {
      const payload = {
        email: v.email,
        subId: v.subId,
        uuid: v.uuid,
        password: v.password,
        flow: v.flow || '',
        totalBytes: v.totalGB > 0 ? Math.round(v.totalGB * 1024 * 1024 * 1024) : 0,
        expiryTime: v.expiryDate ? v.expiryDate.valueOf() : 0,
        enable: v.enable,
        comment: v.comment || '',
        inboundIds: v.inboundIds || [],
      };
      if (editing) {
        return apiRequest(`/api/clients/${editing.id}`, { method: 'PUT', body: JSON.stringify(payload) });
      }
      return apiRequest('/api/clients', { method: 'POST', body: JSON.stringify(payload) });
    },
    onSuccess: () => {
      setModalOpen(false);
      setEditing(null);
      qc.invalidateQueries({ queryKey: ['clients'] });
      qc.invalidateQueries({ queryKey: ['inbounds'] });
      message.success(editing ? '客户端配置及节点绑定已同步' : '全局客户端已创建并下发至所选节点');
    },
    onError: (e: Error) => message.error(e.message),
  });

  const resetMutation = useMutation({
    mutationFn: (id: number) => apiRequest(`/api/clients/${id}/reset-traffic`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['clients'] });
      message.success('客户端流量已清零');
    },
    onError: (e: Error) => message.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => apiRequest(`/api/clients/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['clients'] });
      qc.invalidateQueries({ queryKey: ['inbounds'] });
      message.success('客户端已从主控与所有关联节点移除');
    },
    onError: (e: Error) => message.error(e.message),
  });

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({
      email: '',
      subId: Math.random().toString(36).slice(2, 12),
      uuid: crypto.randomUUID(),
      password: Math.random().toString(36).slice(2, 14) + Math.random().toString(36).slice(2, 10),
      flow: 'xtls-rprx-vision',
      totalGB: 0,
      expiryDate: null,
      enable: true,
      inboundIds: inbounds.map((i) => i.id),
    });
    setModalOpen(true);
  };

  const openEdit = (cl: ClientItem) => {
    setEditing(cl);
    form.setFieldsValue({
      email: cl.email,
      subId: cl.subId,
      uuid: cl.uuid,
      password: cl.password,
      flow: cl.flow,
      totalGB: cl.totalBytes > 0 ? Number((cl.totalBytes / 1073741824).toFixed(2)) : 0,
      expiryDate: cl.expiryTime > 0 ? dayjs(cl.expiryTime) : null,
      enable: cl.enable,
      comment: cl.comment,
      inboundIds: cl.inboundIds ?? [],
    });
    setModalOpen(true);
  };

  const openSubModal = async (cl: ClientItem) => {
    try {
      const bundle = await apiRequest<SubscriptionBundle>(`/api/clients/${cl.id}/links`);
      setSubModal(bundle);
    } catch (e) {
      message.error(e instanceof Error ? e.message : '获取订阅链接失败');
    }
  };

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <Typography.Title level={5} style={{ margin: 0 }}>
            全局客户与跨节点入站绑定
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            客户端仅在主控定义一次，自由勾选任意节点的入站，自动聚合到同一个订阅地址
          </Typography.Text>
        </div>
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
          新建客户端
        </Button>
      </div>

      <Card size="small">
        <Table
          rowKey="id"
          size="small"
          loading={isLoading}
          dataSource={clients}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          columns={[
            {
              title: '状态',
              width: 72,
              render: (_, r) => <Tag color={r.enable ? 'success' : 'default'}>{r.enable ? '启用' : '停用'}</Tag>,
            },
            {
              title: '标识 (Email)',
              dataIndex: 'email',
              render: (v, r) => (
                <div>
                  <div style={{ fontWeight: 600 }}>{v}</div>
                  {r.comment && (
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {r.comment}
                    </Typography.Text>
                  )}
                </div>
              ),
            },
            {
              title: '已绑定节点入站',
              key: 'inbounds',
              render: (_, r) => {
                if (!r.inboundIds?.length) {
                  return <Typography.Text type="secondary">未绑定入站</Typography.Text>;
                }
                return (
                  <Space size={[4, 4]} wrap>
                    {r.inboundIds.map((id) => {
                      const ib = inboundMap.get(id);
                      return (
                        <Tag key={id} color="blue">
                          {ib ? `${ib.nodeName || `#${ib.nodeId}`} · ${ib.remark}` : `Inbound #${id}`}
                        </Tag>
                      );
                    })}
                  </Space>
                );
              },
            },
            {
              title: '已用流量 / 配额',
              width: 220,
              render: (_, r) => {
                const used = r.up + r.down;
                if (r.totalBytes <= 0) {
                  return (
                    <span className="mono" style={{ fontSize: 12.5 }}>
                      {formatBytes(used)} / 无限制
                    </span>
                  );
                }
                const pct = Math.min(100, Math.round((used / r.totalBytes) * 100));
                return (
                  <div>
                    <div className="mono" style={{ fontSize: 12 }}>
                      {formatBytes(used)} / {formatBytes(r.totalBytes)}
                    </div>
                    <Progress percent={pct} size="small" showInfo={false} />
                  </div>
                );
              },
            },
            {
              title: '到期时间',
              width: 150,
              render: (_, r) => (
                <span className="mono" style={{ fontSize: 12.5 }}>
                  {r.expiryTime > 0 ? dayjs(r.expiryTime).format('YYYY-MM-DD HH:mm') : '长期有效'}
                </span>
              ),
            },
            {
              title: '操作',
              width: 175,
              render: (_, r) => {
                const subUrl = `${window.location.origin}/sub/${r.subId}`;
                return (
                  <Space size={4}>
                    <Tooltip title="复制聚合订阅链接">
                      <Button
                        size="small"
                        type="text"
                        icon={<CopyOutlined />}
                        onClick={() => {
                          navigator.clipboard.writeText(subUrl);
                          message.success('订阅地址已复制');
                        }}
                      />
                    </Tooltip>
                    <Tooltip title="二维码与单节点链接">
                      <Button size="small" type="text" icon={<QrcodeOutlined />} onClick={() => openSubModal(r)} />
                    </Tooltip>
                    <Tooltip title="编辑与分配节点">
                      <Button size="small" type="text" icon={<EditOutlined />} onClick={() => openEdit(r)} />
                    </Tooltip>
                    <Popconfirm title="确认清零该客户端已用流量？" onConfirm={() => resetMutation.mutate(r.id)}>
                      <Button size="small" type="text" icon={<RetweetOutlined />} />
                    </Popconfirm>
                    <Popconfirm title="确认删除此客户端？" onConfirm={() => deleteMutation.mutate(r.id)}>
                      <Button size="small" type="text" danger icon={<DeleteOutlined />} />
                    </Popconfirm>
                  </Space>
                );
              },
            },
          ]}
        />
      </Card>

      <Modal
        title={editing ? `编辑客户端 — ${editing.email}` : '新建全局客户端'}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={saveMutation.isPending}
        width={620}
      >
        <Form form={form} layout="vertical" onFinish={(v) => saveMutation.mutate(v)}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 90px', gap: 12 }}>
            <Form.Item name="email" label="客户端标识 (Email / 唯一名)" rules={[{ required: true }]}>
              <Input placeholder="alice@team" />
            </Form.Item>
            <Form.Item name="subId" label="订阅 ID (SubID)" rules={[{ required: true }]}>
              <Input className="mono" />
            </Form.Item>
            <Form.Item name="enable" label="启用" valuePropName="checked">
              <Switch />
            </Form.Item>
          </div>

          <Form.Item
            name="inboundIds"
            label="绑定节点入站 (支持跨多台 Agent 节点多选)"
            extra="保存后主控会自动将该客户端下发到所选入站对应的所有在线 Agent"
          >
            <Select
              mode="multiple"
              allowClear
              placeholder="选择要开通的节点入站..."
              options={inboundGroupedOptions}
              maxTagCount="responsive"
            />
          </Form.Item>

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
            <Form.Item name="uuid" label="UUID (VLESS / VMess)">
              <Input className="mono" />
            </Form.Item>
            <Form.Item name="flow" label="VLESS Flow">
              <Select
                allowClear
                options={[
                  { label: 'xtls-rprx-vision (Reality 推荐)', value: 'xtls-rprx-vision' },
                  { label: '无 (WS / gRPC / XHTTP)', value: '' },
                ]}
              />
            </Form.Item>
          </div>

          <Form.Item name="password" label="密码 (Trojan / Shadowsocks)">
            <Input className="mono" />
          </Form.Item>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <Form.Item name="totalGB" label="总流量配额 (GB, 0 为不限)">
              <InputNumber min={0} step={10} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="expiryDate" label="到期时间 (留空长期有效)">
              <DatePicker showTime style={{ width: '100%' }} />
            </Form.Item>
          </div>

          <Form.Item name="comment" label="备注">
            <Input placeholder="选填备注" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={subModal ? `订阅与节点链接 — ${subModal.client.email}` : '订阅详情'}
        open={!!subModal}
        onCancel={() => setSubModal(null)}
        footer={null}
        width={640}
      >
        {subModal && (
          <Space orientation="vertical" size={16} style={{ width: '100%' }}>
            <div style={{ display: 'flex', gap: 20, alignItems: 'center', flexWrap: 'wrap' }}>
              <div style={{ padding: 10, background: '#fff', borderRadius: 10 }}>
                <QRCodeSVG value={`${window.location.origin}/sub/${subModal.client.subId}`} size={136} />
              </div>
              <div style={{ flex: 1, minWidth: 240 }}>
                <Typography.Text strong>聚合订阅地址 (自适应全部已绑节点):</Typography.Text>
                <div className="code-box mono" style={{ marginTop: 6, marginBottom: 8 }}>
                  {`${window.location.origin}/sub/${subModal.client.subId}`}
                </div>
                <Button
                  type="primary"
                  size="small"
                  icon={<CopyOutlined />}
                  onClick={() => {
                    navigator.clipboard.writeText(`${window.location.origin}/sub/${subModal.client.subId}`);
                    message.success('订阅链接已复制');
                  }}
                >
                  复制订阅 URL
                </Button>
              </div>
            </div>

            <div>
              <Typography.Text strong>单节点直连分享链接 ({subModal.links.length}):</Typography.Text>
              {subModal.links.length === 0 ? (
                <div style={{ marginTop: 8 }}>
                  <Typography.Text type="secondary">
                    当前无可用链接（请确认已绑定启用的入站，且对应节点已有公网 IP 或连接域名）
                  </Typography.Text>
                </div>
              ) : (
                <Space orientation="vertical" size={8} style={{ width: '100%', marginTop: 8 }}>
                  {subModal.links.map((lk, idx) => (
                    <div key={idx} className="code-box mono" style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{lk}</span>
                      <Button
                        size="small"
                        type="link"
                        icon={<CopyOutlined />}
                        onClick={() => {
                          navigator.clipboard.writeText(lk);
                          message.success('节点链接已复制');
                        }}
                      />
                    </div>
                  ))}
                </Space>
              )}
            </div>
          </Space>
        )}
      </Modal>
    </Space>
  );
}
