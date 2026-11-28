import { useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  Card,
  Descriptions,
  Drawer,
  Empty,
  Form,
  Input,
  Modal,
  Popconfirm,
  Progress,
  Select,
  Space,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd';
import {
  CloudDownloadOutlined,
  CodeOutlined,
  CopyOutlined,
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  PoweroffOutlined,
  ReloadOutlined,
  SyncOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiRequest, formatBytes, formatSpeed, formatUptime, type NodeItem, type NodeWithEnroll } from './api';

export default function NodesPage() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [editingNode, setEditingNode] = useState<NodeItem | null>(null);
  const [enrollModal, setEnrollModal] = useState<{ nodeName: string; token: string } | null>(null);
  const [drawerNodeId, setDrawerNodeId] = useState<number | null>(null);
  const [selectedVer, setSelectedVer] = useState<string>('');
  const [logsModal, setLogsModal] = useState<{ open: boolean; lines: string[] }>({ open: false, lines: [] });
  const [form] = Form.useForm();
  const [editForm] = Form.useForm();

  const { data: nodes = [], isLoading } = useQuery({
    queryKey: ['nodes'],
    queryFn: () => apiRequest<NodeItem[]>('/api/nodes'),
    refetchInterval: 4000,
  });

  const { data: xrayVersions = [], isFetching: loadingVers } = useQuery({
    queryKey: ['core-versions', 'xray'],
    queryFn: () => apiRequest<string[]>('/api/cores/xray/versions'),
    enabled: drawerNodeId !== null,
    staleTime: 300_000,
  });

  const activeNode = nodes.find((n) => n.id === drawerNodeId) ?? null;
  const xraySlot = activeNode?.cores?.find((c) => c.coreType === 'xray');

  const createMutation = useMutation({
    mutationFn: (values: { name: string; publicHost: string; remark: string }) =>
      apiRequest<NodeWithEnroll>('/api/nodes', { method: 'POST', body: JSON.stringify(values) }),
    onSuccess: (data) => {
      setCreateOpen(false);
      form.resetFields();
      qc.invalidateQueries({ queryKey: ['nodes'] });
      setEnrollModal({ nodeName: data.node.name, token: data.enrollToken });
    },
    onError: (e: Error) => message.error(e.message),
  });

  const updateMutation = useMutation({
    mutationFn: (payload: { id: number; name: string; publicHost: string; remark: string }) =>
      apiRequest<NodeItem>(`/api/nodes/${payload.id}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      setEditingNode(null);
      qc.invalidateQueries({ queryKey: ['nodes'] });
      message.success('节点信息已更新');
    },
    onError: (e: Error) => message.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => apiRequest(`/api/nodes/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      setDrawerNodeId(null);
      qc.invalidateQueries({ queryKey: ['nodes'] });
      qc.invalidateQueries({ queryKey: ['inbounds'] });
      message.success('节点已删除');
    },
    onError: (e: Error) => message.error(e.message),
  });

  const installCoreMutation = useMutation({
    mutationFn: ({ nodeId, version }: { nodeId: number; version: string }) =>
      apiRequest(`/api/nodes/${nodeId}/cores/install`, {
        method: 'POST',
        body: JSON.stringify({ coreType: 'xray', version }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['nodes'] });
      message.success('已向 Agent 下发 Xray 安装指令');
    },
    onError: (e: Error) => message.error(e.message),
  });

  const coreActionMutation = useMutation({
    mutationFn: ({ nodeId, action }: { nodeId: number; action: string }) =>
      apiRequest(`/api/nodes/${nodeId}/cores/action`, {
        method: 'POST',
        body: JSON.stringify({ coreType: 'xray', action }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['nodes'] });
      message.success('内核操作成功');
    },
    onError: (e: Error) => message.error(e.message),
  });

  const uninstallCoreMutation = useMutation({
    mutationFn: (nodeId: number) =>
      apiRequest(`/api/nodes/${nodeId}/cores/uninstall`, {
        method: 'POST',
        body: JSON.stringify({ coreType: 'xray' }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['nodes'] });
      message.success('Xray 内核已卸载');
    },
    onError: (e: Error) => message.error(e.message),
  });

  const rotateToken = async (node: NodeItem) => {
    try {
      const res = await apiRequest<{ enrollToken: string }>(`/api/nodes/${node.id}/enroll-token`, { method: 'POST' });
      setEnrollModal({ nodeName: node.name, token: res.enrollToken });
    } catch (e) {
      message.error(e instanceof Error ? e.message : '生成令牌失败');
    }
  };

  const openLogs = async (nodeId: number) => {
    try {
      const lines = await apiRequest<string[]>(`/api/nodes/${nodeId}/cores/xray/logs?lines=200`);
      setLogsModal({ open: true, lines: lines ?? [] });
    } catch (e) {
      message.error(e instanceof Error ? e.message : '读取日志失败');
    }
  };

  const buildInstallCmd = (token: string) => {
    const origin = window.location.origin;
    const insecure = origin.startsWith('https://') ? ' --insecure' : '';
    return `curl -fsSL ${origin}/install-agent.sh | sh -s -- --token ${token}${insecure}`;
  };

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <Typography.Title level={5} style={{ margin: 0 }}>
            节点与内核管理
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            先在节点裸装零端口 Agent，连接成功后再点击节点下发安装 Xray 内核
          </Typography.Text>
        </div>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
          添加节点
        </Button>
      </div>

      {nodes.length === 0 && !isLoading ? (
        <Card>
          <Empty description="尚未添加任何节点">
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
              创建第一台节点
            </Button>
          </Empty>
        </Card>
      ) : (
        <div className="node-grid">
          {nodes.map((n) => {
            const xray = n.cores?.find((c) => c.coreType === 'xray');
            const memPct = n.memTotal > 0 ? Math.round((n.memUsed / n.memTotal) * 100) : 0;
            return (
              <Card
                key={n.id}
                size="small"
                hoverable
                onClick={() => setDrawerNodeId(n.id)}
                title={
                  <Space>
                    <Badge status={n.online ? 'success' : 'default'} />
                    <span>{n.name}</span>
                    {n.configDirty && <Tag color="warning">待同步</Tag>}
                  </Space>
                }
                extra={
                  <Space onClick={(e) => e.stopPropagation()}>
                    <Tooltip title="获取安装命令">
                      <Button size="small" type="text" icon={<CopyOutlined />} onClick={() => rotateToken(n)} />
                    </Tooltip>
                    <Tooltip title="编辑节点">
                      <Button
                        size="small"
                        type="text"
                        icon={<EditOutlined />}
                        onClick={() => {
                          setEditingNode(n);
                          editForm.setFieldsValue({
                            name: n.name,
                            publicHost: n.publicHost,
                            remark: n.remark,
                          });
                        }}
                      />
                    </Tooltip>
                  </Space>
                }
              >
                <Space orientation="vertical" size={10} style={{ width: '100%' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5 }}>
                    <Typography.Text type="secondary">出口地址</Typography.Text>
                    <span className="mono">{n.publicHost || n.publicIpv4 || '等待上报...'}</span>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>
                      代理内核
                    </Typography.Text>
                    {!xray || !xray.installed ? (
                      <Tag color={xray?.state === 'installing' ? 'processing' : 'default'}>
                        {xray?.state === 'installing' ? `安装中 ${xray.progressPct}%` : '未安装 Core (点击安装)'}
                      </Tag>
                    ) : (
                      <Tag color={xray.state === 'running' ? 'success' : xray.state === 'error' ? 'error' : 'blue'}>
                        Xray {xray.installedVersion} · {xray.state}
                      </Tag>
                    )}
                  </div>

                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                      <Typography.Text type="secondary">CPU {n.cpuPercent.toFixed(1)}%</Typography.Text>
                      <Typography.Text type="secondary">
                        内存 {formatBytes(n.memUsed)} / {formatBytes(n.memTotal)} ({memPct}%)
                      </Typography.Text>
                    </div>
                    <Progress percent={Math.round(n.cpuPercent)} size="small" showInfo={false} />
                  </div>

                  <div
                    className="mono"
                    style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, opacity: 0.85 }}
                  >
                    <span>↑ {formatSpeed(n.netUpRate)}</span>
                    <span>↓ {formatSpeed(n.netDownRate)}</span>
                    <span>{n.online ? formatUptime(n.uptime) : '离线'}</span>
                  </div>
                </Space>
              </Card>
            );
          })}
        </div>
      )}

      {/* Create Node Modal */}
      <Modal
        title="添加 Agent 节点"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={createMutation.isPending}
      >
        <Form form={form} layout="vertical" onFinish={(v) => createMutation.mutate(v)}>
          <Form.Item name="name" label="节点名称" rules={[{ required: true, message: '请输入节点名称' }]}>
            <Input placeholder="例如: HK-BGP-01 / Tokyo-CN2" />
          </Form.Item>
          <Form.Item
            name="publicHost"
            label="客户端连接域名或公网 IP (选填)"
            extra="留空时订阅链接自动使用 Agent 探测上报的公网 IP"
          >
            <Input placeholder="例如: hk1.example.com 或 203.0.113.8" />
          </Form.Item>
          <Form.Item name="remark" label="备注">
            <Input placeholder="机房/带宽备注" />
          </Form.Item>
        </Form>
      </Modal>

      {/* Edit Node Modal */}
      <Modal
        title="编辑节点"
        open={!!editingNode}
        onCancel={() => setEditingNode(null)}
        onOk={() => editForm.submit()}
        confirmLoading={updateMutation.isPending}
      >
        <Form
          form={editForm}
          layout="vertical"
          onFinish={(v) => editingNode && updateMutation.mutate({ id: editingNode.id, ...v })}
        >
          <Form.Item name="name" label="节点名称" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="publicHost" label="连接域名 / 公网 IP">
            <Input />
          </Form.Item>
          <Form.Item name="remark" label="备注">
            <Input />
          </Form.Item>
        </Form>
      </Modal>

      {/* One-liner Enrollment Command Modal */}
      <Modal
        title={`安装裸 Agent — ${enrollModal?.nodeName ?? ''}`}
        open={!!enrollModal}
        onCancel={() => setEnrollModal(null)}
        footer={[
          <Button
            key="copy"
            type="primary"
            icon={<CopyOutlined />}
            onClick={() => {
              if (enrollModal) {
                navigator.clipboard.writeText(buildInstallCmd(enrollModal.token));
                message.success('一键安装命令已复制');
              }
            }}
          >
            复制安装命令
          </Button>,
        ]}
      >
        <Space orientation="vertical" size={12} style={{ width: '100%' }}>
          <Alert
            type="info"
            showIcon
            title="零端口反向连接模式：Agent 仅主动出站连接主控，不监听任何入站管理端口，且默认不安装任何代理内核。"
          />
          <div className="code-box mono">{enrollModal ? buildInstallCmd(enrollModal.token) : ''}</div>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            注：该注册令牌为一次性有效（24小时内），首次握手后自动换取持久化节点凭证。
          </Typography.Text>
        </Space>
      </Modal>

      {/* Node Detail & Core Slots Drawer */}
      <Drawer
        title={
          activeNode ? (
            <Space>
              <Badge status={activeNode.online ? 'success' : 'default'} />
              <span>{activeNode.name}</span>
              <Tag>{activeNode.online ? '在线' : '离线'}</Tag>
            </Space>
          ) : (
            '节点详情'
          )
        }
        size="large"
        open={!!activeNode}
        onClose={() => setDrawerNodeId(null)}
        extra={
          activeNode && (
            <Space>
              <Button
                size="small"
                icon={<SyncOutlined />}
                onClick={() =>
                  apiRequest(`/api/nodes/${activeNode.id}/reconcile`, { method: 'POST' })
                    .then(() => message.success('节点状态已同步'))
                    .catch((e: Error) => message.error(e.message))
                }
              >
                强制同步配置
              </Button>
              <Popconfirm title="确认删除该节点及其关联入站？" onConfirm={() => deleteMutation.mutate(activeNode.id)}>
                <Button size="small" danger icon={<DeleteOutlined />}>
                  删除
                </Button>
              </Popconfirm>
            </Space>
          )
        }
      >
        {activeNode && (
          <Space orientation="vertical" size={20} style={{ width: '100%' }}>
            <Descriptions size="small" bordered column={2}>
              <Descriptions.Item label="主机名">{activeNode.hostname || '-'}</Descriptions.Item>
              <Descriptions.Item label="系统架构">
                {activeNode.os ? `${activeNode.os} / ${activeNode.arch}` : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="公网 IPv4">{activeNode.publicIpv4 || '-'}</Descriptions.Item>
              <Descriptions.Item label="连接地址">{activeNode.publicHost || '自动使用公网 IP'}</Descriptions.Item>
              <Descriptions.Item label="累计上行">{formatBytes(activeNode.netUpTotal)}</Descriptions.Item>
              <Descriptions.Item label="累计下行">{formatBytes(activeNode.netDownTotal)}</Descriptions.Item>
            </Descriptions>

            <Card
              size="small"
              title="内核插槽 (Core Slots) — Xray-core"
              extra={
                xraySlot?.installed && (
                  <Button size="small" icon={<CodeOutlined />} onClick={() => openLogs(activeNode.id)}>
                    查看日志
                  </Button>
                )
              }
            >
              <Space orientation="vertical" size={14} style={{ width: '100%' }}>
                {xraySlot?.errorMsg && <Alert type="error" showIcon title={xraySlot.errorMsg} />}

                {xraySlot?.state === 'installing' && (
                  <div>
                    <Typography.Text>正在下载并校验 Xray 二进制...</Typography.Text>
                    <Progress percent={xraySlot.progressPct || 15} status="active" />
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
                  <Space>
                    <Typography.Text strong>当前状态:</Typography.Text>
                    {!xraySlot?.installed ? (
                      <Tag>未安装</Tag>
                    ) : (
                      <Tag color={xraySlot.state === 'running' ? 'success' : 'default'}>
                        {xraySlot.installedVersion} ({xraySlot.state})
                      </Tag>
                    )}
                  </Space>

                  {xraySlot?.installed && (
                    <Space>
                      <Button
                        size="small"
                        icon={<ReloadOutlined />}
                        loading={coreActionMutation.isPending}
                        onClick={() => coreActionMutation.mutate({ nodeId: activeNode.id, action: 'restart' })}
                      >
                        重启
                      </Button>
                      {xraySlot.state === 'running' && (
                        <Button
                          size="small"
                          icon={<PoweroffOutlined />}
                          onClick={() => coreActionMutation.mutate({ nodeId: activeNode.id, action: 'stop' })}
                        >
                          停止
                        </Button>
                      )}
                      <Popconfirm
                        title="确认卸载该节点上的 Xray 内核？(需先清空入站)"
                        onConfirm={() => uninstallCoreMutation.mutate(activeNode.id)}
                      >
                        <Button size="small" danger loading={uninstallCoreMutation.isPending}>
                          卸载内核
                        </Button>
                      </Popconfirm>
                    </Space>
                  )}
                </div>

                <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                  <Select
                    style={{ minWidth: 220 }}
                    loading={loadingVers}
                    placeholder="选择官方 Xray 版本 (默认最新稳定版)"
                    value={selectedVer || xrayVersions[0] || undefined}
                    onChange={setSelectedVer}
                    options={xrayVersions.map((v) => ({ label: v, value: v }))}
                  />
                  <Button
                    type="primary"
                    icon={<CloudDownloadOutlined />}
                    disabled={!activeNode.online || xraySlot?.state === 'installing'}
                    loading={installCoreMutation.isPending}
                    onClick={() =>
                      installCoreMutation.mutate({
                        nodeId: activeNode.id,
                        version: selectedVer || xrayVersions[0] || 'latest',
                      })
                    }
                  >
                    {xraySlot?.installed ? '切换 / 升级版本' : '下发安装 Xray'}
                  </Button>
                </div>
              </Space>
            </Card>
          </Space>
        )}
      </Drawer>

      <Modal
        title="Xray 运行日志"
        open={logsModal.open}
        onCancel={() => setLogsModal({ open: false, lines: [] })}
        footer={null}
        width={720}
      >
        <div className="code-box mono" style={{ maxHeight: 420, overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
          {logsModal.lines.length > 0 ? logsModal.lines.join('\n') : '暂无日志输出'}
        </div>
      </Modal>
    </Space>
  );
}
