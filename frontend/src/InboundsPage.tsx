import { useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Segmented,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  message,
} from 'antd';
import { DeleteOutlined, EditOutlined, KeyOutlined, PlusOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiRequest, formatBytes, type InboundItem, type NodeItem, type ProtocolType } from './api';

interface InboundFormValues {
  nodeId: number;
  remark: string;
  protocol: ProtocolType;
  listen: string;
  port: number;
  enable: boolean;
  network: 'tcp' | 'ws' | 'grpc' | 'xhttp';
  security: 'none' | 'reality' | 'tls';
  ssMethod?: string;
  wsPath?: string;
  wsHost?: string;
  grpcServiceName?: string;
  xhttpPath?: string;
  tlsServerName?: string;
  tlsCertFile?: string;
  tlsKeyFile?: string;
  realityDest?: string;
  realityServerName?: string;
  realityPrivateKey?: string;
  realityPublicKey?: string;
  realityShortId?: string;
}

export default function InboundsPage() {
  const qc = useQueryClient();
  const [filterNode, setFilterNode] = useState<number>(0);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<InboundItem | null>(null);
  const [form] = Form.useForm<InboundFormValues>();

  const protocol = Form.useWatch('protocol', form) ?? 'vless';
  const network = Form.useWatch('network', form) ?? 'tcp';
  const security = Form.useWatch('security', form) ?? 'reality';

  const { data: nodes = [] } = useQuery({
    queryKey: ['nodes'],
    queryFn: () => apiRequest<NodeItem[]>('/api/nodes'),
  });

  const { data: inbounds = [], isLoading } = useQuery({
    queryKey: ['inbounds'],
    queryFn: () => apiRequest<InboundItem[]>('/api/inbounds'),
    refetchInterval: 5000,
  });

  const xrayReadyNodes = useMemo(
    () => nodes.filter((n) => n.cores?.some((c) => c.coreType === 'xray' && c.installed)),
    [nodes],
  );

  const filtered = useMemo(
    () => (filterNode === 0 ? inbounds : inbounds.filter((i) => i.nodeId === filterNode)),
    [inbounds, filterNode],
  );

  const saveMutation = useMutation({
    mutationFn: async (v: InboundFormValues) => {
      const settings: Record<string, unknown> = {};
      if (v.protocol === 'vless') {
        settings.decryption = 'none';
      } else if (v.protocol === 'shadowsocks') {
        settings.method = v.ssMethod || '2022-blake3-aes-128-gcm';
        settings.network = 'tcp,udp';
      }

      const streamSettings: Record<string, unknown> = {
        network: v.network,
        security: v.protocol === 'shadowsocks' ? 'none' : v.security,
      };
      if (v.network === 'ws') {
        streamSettings.wsSettings = {
          path: v.wsPath || '/',
          headers: v.wsHost ? { Host: v.wsHost } : {},
        };
      } else if (v.network === 'grpc') {
        streamSettings.grpcSettings = { serviceName: v.grpcServiceName || 'grpc' };
      } else if (v.network === 'xhttp') {
        streamSettings.xhttpSettings = { path: v.xhttpPath || '/' };
      }

      if (streamSettings.security === 'reality') {
        const sni = v.realityServerName || 'www.microsoft.com';
        streamSettings.realitySettings = {
          show: false,
          dest: v.realityDest || `${sni}:443`,
          xver: 0,
          serverNames: [sni],
          privateKey: v.realityPrivateKey || '',
          publicKey: v.realityPublicKey || '',
          shortIds: [v.realityShortId || ''],
          fingerprint: 'chrome',
        };
      } else if (streamSettings.security === 'tls') {
        streamSettings.tlsSettings = {
          serverName: v.tlsServerName || '',
          certificates:
            v.tlsCertFile && v.tlsKeyFile
              ? [{ certificateFile: v.tlsCertFile, keyFile: v.tlsKeyFile }]
              : [],
        };
      }

      const payload = {
        nodeId: v.nodeId,
        coreType: 'xray',
        remark: v.remark,
        enable: v.enable,
        listen: v.listen || '0.0.0.0',
        port: v.port,
        protocol: v.protocol,
        settings,
        streamSettings,
      };

      if (editing) {
        return apiRequest(`/api/inbounds/${editing.id}`, { method: 'PUT', body: JSON.stringify(payload) });
      }
      return apiRequest('/api/inbounds', { method: 'POST', body: JSON.stringify(payload) });
    },
    onSuccess: () => {
      setModalOpen(false);
      setEditing(null);
      qc.invalidateQueries({ queryKey: ['inbounds'] });
      qc.invalidateQueries({ queryKey: ['nodes'] });
      message.success(editing ? '入站已更新并下发' : '入站已创建并启动 Xray');
    },
    onError: (e: Error) => message.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => apiRequest(`/api/inbounds/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['inbounds'] });
      qc.invalidateQueries({ queryKey: ['clients'] });
      message.success('入站已删除');
    },
    onError: (e: Error) => message.error(e.message),
  });

  const fillRealityKeys = async () => {
    try {
      const kp = await apiRequest<{ privateKey: string; publicKey: string; shortId: string }>(
        '/api/xray/reality-keys',
        { method: 'POST' },
      );
      form.setFieldsValue({
        realityPrivateKey: kp.privateKey,
        realityPublicKey: kp.publicKey,
        realityShortId: kp.shortId,
      });
    } catch (e) {
      message.error(e instanceof Error ? e.message : '生成密钥失败');
    }
  };

  const openCreate = async () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({
      nodeId: xrayReadyNodes[0]?.id,
      protocol: 'vless',
      listen: '0.0.0.0',
      port: Math.floor(10000 + Math.random() * 45000),
      enable: true,
      network: 'tcp',
      security: 'reality',
      realityDest: 'www.microsoft.com:443',
      realityServerName: 'www.microsoft.com',
      ssMethod: 'chacha20-ietf-poly1305',
    });
    setModalOpen(true);
    await fillRealityKeys();
  };

  const openEdit = (ib: InboundItem) => {
    setEditing(ib);
    let stream: Record<string, any> = {};
    let settings: Record<string, any> = {};
    try {
      stream = JSON.parse(ib.streamSettings || '{}');
      settings = JSON.parse(ib.settings || '{}');
    } catch {
      // ignore malformed historical json
    }
    const r = stream.realitySettings || {};
    const tls = stream.tlsSettings || {};
    const cert = (tls.certificates && tls.certificates[0]) || {};
    form.setFieldsValue({
      nodeId: ib.nodeId,
      remark: ib.remark,
      protocol: ib.protocol,
      listen: ib.listen,
      port: ib.port,
      enable: ib.enable,
      network: stream.network || 'tcp',
      security: stream.security || 'none',
      ssMethod: settings.method || 'chacha20-ietf-poly1305',
      wsPath: stream.wsSettings?.path,
      wsHost: stream.wsSettings?.headers?.Host,
      grpcServiceName: stream.grpcSettings?.serviceName,
      xhttpPath: stream.xhttpSettings?.path,
      tlsServerName: tls.serverName,
      tlsCertFile: cert.certificateFile,
      tlsKeyFile: cert.keyFile,
      realityDest: r.dest,
      realityServerName: r.serverNames?.[0],
      realityPrivateKey: r.privateKey,
      realityPublicKey: r.publicKey,
      realityShortId: r.shortIds?.[0],
    });
    setModalOpen(true);
  };

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <Space wrap>
          <Typography.Title level={5} style={{ margin: 0 }}>
            入站列表
          </Typography.Title>
          <Segmented
            value={filterNode}
            onChange={(v) => setFilterNode(Number(v))}
            options={[
              { label: '全部节点', value: 0 },
              ...nodes.map((n) => ({ label: n.name, value: n.id })),
            ]}
          />
        </Space>
        <Button type="primary" icon={<PlusOutlined />} disabled={xrayReadyNodes.length === 0} onClick={openCreate}>
          新建入站
        </Button>
      </div>

      {xrayReadyNodes.length === 0 && (
        <Alert
          type="warning"
          showIcon
          title="尚无已安装 Xray 内核的节点。请先在「节点与内核」页面点击节点安装 Xray，安装完成后即可创建入站。"
        />
      )}

      <Card size="small">
        <Table
          rowKey="id"
          size="small"
          loading={isLoading}
          dataSource={filtered}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
          columns={[
            {
              title: '状态',
              width: 70,
              render: (_, r) => <Tag color={r.enable ? 'success' : 'default'}>{r.enable ? '启用' : '停用'}</Tag>,
            },
            {
              title: '所属节点',
              dataIndex: 'nodeName',
              render: (v, r) => <Tag color="blue">{v || `#${r.nodeId}`}</Tag>,
            },
            {
              title: '备注',
              dataIndex: 'remark',
              render: (v) => <span style={{ fontWeight: 600 }}>{v}</span>,
            },
            {
              title: '内核 / 协议',
              render: (_, r) => {
                let sec = 'none';
                let net = 'tcp';
                try {
                  const st = JSON.parse(r.streamSettings || '{}');
                  sec = st.security || 'none';
                  net = st.network || 'tcp';
                } catch {
                  // ignore
                }
                return (
                  <Space size={4}>
                    <Tag>{r.coreType.toUpperCase()}</Tag>
                    <Tag color="geekblue">{r.protocol.toUpperCase()}</Tag>
                    <Tag>{net}</Tag>
                    {sec !== 'none' && <Tag color="purple">{sec.toUpperCase()}</Tag>}
                  </Space>
                );
              },
            },
            {
              title: '监听端口',
              render: (_, r) => (
                <span className="mono">
                  {r.listen}:{r.port}
                </span>
              ),
            },
            {
              title: '绑定客户数',
              dataIndex: 'clientCount',
              render: (v) => <Tag>{v ?? 0} 人</Tag>,
            },
            {
              title: '累计流量',
              render: (_, r) => (
                <span className="mono" style={{ fontSize: 12.5 }}>
                  ↑ {formatBytes(r.up)} / ↓ {formatBytes(r.down)}
                </span>
              ),
            },
            {
              title: '操作',
              width: 110,
              render: (_, r) => (
                <Space>
                  <Button size="small" type="text" icon={<EditOutlined />} onClick={() => openEdit(r)} />
                  <Popconfirm title="确认删除此入站？" onConfirm={() => deleteMutation.mutate(r.id)}>
                    <Button size="small" type="text" danger icon={<DeleteOutlined />} />
                  </Popconfirm>
                </Space>
              ),
            },
          ]}
        />
      </Card>

      <Modal
        title={editing ? '编辑入站' : '新建 Xray 入站'}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={saveMutation.isPending}
        width={620}
      >
        <Form form={form} layout="vertical" onFinish={(v) => saveMutation.mutate(v)}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <Form.Item name="nodeId" label="目标节点 (已装 Xray)" rules={[{ required: true }]}>
              <Select
                options={xrayReadyNodes.map((n) => ({
                  label: `${n.name} (${n.publicHost || n.publicIpv4 || '无地址'})`,
                  value: n.id,
                }))}
              />
            </Form.Item>
            <Form.Item name="remark" label="入站备注" rules={[{ required: true, message: '请输入备注' }]}>
              <Input placeholder="例如: HK-Reality-主力" />
            </Form.Item>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 90px', gap: 12 }}>
            <Form.Item name="protocol" label="协议" rules={[{ required: true }]}>
              <Select
                options={[
                  { label: 'VLESS', value: 'vless' },
                  { label: 'Trojan', value: 'trojan' },
                  { label: 'VMess', value: 'vmess' },
                  { label: 'Shadowsocks', value: 'shadowsocks' },
                ]}
              />
            </Form.Item>
            <Form.Item name="listen" label="监听 IP">
              <Input placeholder="0.0.0.0" />
            </Form.Item>
            <Form.Item name="port" label="端口" rules={[{ required: true }]}>
              <InputNumber min={1} max={65535} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="enable" label="启用" valuePropName="checked">
              <Switch />
            </Form.Item>
          </div>

          {protocol === 'shadowsocks' ? (
            <Form.Item name="ssMethod" label="加密方式">
              <Select
                options={[
                  { label: 'chacha20-ietf-poly1305', value: 'chacha20-ietf-poly1305' },
                  { label: 'aes-256-gcm', value: 'aes-256-gcm' },
                  { label: 'aes-128-gcm', value: 'aes-128-gcm' },
                ]}
              />
            </Form.Item>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <Form.Item name="network" label="传输层 (Network)">
                <Select
                  options={[
                    { label: 'TCP (Raw)', value: 'tcp' },
                    { label: 'WebSocket (WS)', value: 'ws' },
                    { label: 'gRPC', value: 'grpc' },
                    { label: 'XHTTP (SplitHTTP)', value: 'xhttp' },
                  ]}
                />
              </Form.Item>
              <Form.Item name="security" label="安全层 (Security)">
                <Select
                  options={[
                    { label: 'REALITY (免证书推荐)', value: 'reality' },
                    { label: 'TLS', value: 'tls' },
                    { label: '无加密 (None)', value: 'none' },
                  ]}
                />
              </Form.Item>
            </div>
          )}

          {protocol !== 'shadowsocks' && network === 'ws' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <Form.Item name="wsPath" label="WebSocket Path">
                <Input placeholder="/ws" />
              </Form.Item>
              <Form.Item name="wsHost" label="Host Header">
                <Input placeholder="cdn.example.com" />
              </Form.Item>
            </div>
          )}

          {protocol !== 'shadowsocks' && network === 'grpc' && (
            <Form.Item name="grpcServiceName" label="gRPC ServiceName">
              <Input placeholder="grpc" />
            </Form.Item>
          )}

          {protocol !== 'shadowsocks' && network === 'xhttp' && (
            <Form.Item name="xhttpPath" label="XHTTP Path">
              <Input placeholder="/xhttp" />
            </Form.Item>
          )}

          {protocol !== 'shadowsocks' && security === 'reality' && (
            <Card
              size="small"
              title="REALITY 参数"
              extra={
                <Button size="small" icon={<KeyOutlined />} onClick={fillRealityKeys}>
                  重新生成密钥对
                </Button>
              }
            >
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <Form.Item name="realityDest" label="回落目标 (Dest)" rules={[{ required: true }]}>
                  <Input placeholder="www.microsoft.com:443" />
                </Form.Item>
                <Form.Item name="realityServerName" label="伪装域名 (SNI)" rules={[{ required: true }]}>
                  <Input placeholder="www.microsoft.com" />
                </Form.Item>
              </div>
              <Form.Item name="realityPrivateKey" label="私钥 (PrivateKey)" rules={[{ required: true }]}>
                <Input className="mono" />
              </Form.Item>
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
                <Form.Item name="realityPublicKey" label="公钥 (PublicKey — 下发给订阅)" rules={[{ required: true }]}>
                  <Input className="mono" />
                </Form.Item>
                <Form.Item name="realityShortId" label="ShortId">
                  <Input className="mono" />
                </Form.Item>
              </div>
            </Card>
          )}

          {protocol !== 'shadowsocks' && security === 'tls' && (
            <Card size="small" title="TLS 证书配置 (节点本地路径)">
              <Form.Item name="tlsServerName" label="SNI 域名">
                <Input placeholder="node.example.com" />
              </Form.Item>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <Form.Item name="tlsCertFile" label="证书路径 (fullchain.pem)">
                  <Input placeholder="/etc/ssl/certs/node.pem" />
                </Form.Item>
                <Form.Item name="tlsKeyFile" label="私钥路径 (privkey.key)">
                  <Input placeholder="/etc/ssl/private/node.key" />
                </Form.Item>
              </div>
            </Card>
          )}
        </Form>
      </Modal>
    </Space>
  );
}
