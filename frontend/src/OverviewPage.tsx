import { Badge, Card, Progress, Space, Statistic, Table, Tag, Typography } from 'antd';
import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  ClusterOutlined,
  DeploymentUnitOutlined,
  TeamOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { apiRequest, formatBytes, formatSpeed, formatUptime, type NodeItem, type OverviewStats } from './api';

export default function OverviewPage() {
  const { data: stats } = useQuery({
    queryKey: ['overview'],
    queryFn: () => apiRequest<OverviewStats>('/api/overview'),
    refetchInterval: 4000,
  });

  const { data: nodes = [] } = useQuery({
    queryKey: ['nodes'],
    queryFn: () => apiRequest<NodeItem[]>('/api/nodes'),
    refetchInterval: 5000,
  });

  return (
    <Space orientation="vertical" size={20} style={{ width: '100%' }}>
      <div className="stat-grid">
        <Card size="small">
          <Statistic
            title="在线节点 / 总节点"
            value={stats?.onlineNodes ?? 0}
            suffix={`/ ${stats?.totalNodes ?? 0}`}
            prefix={<ClusterOutlined style={{ color: '#2563eb' }} />}
          />
        </Card>
        <Card size="small">
          <Statistic
            title="运行中内核 / 已安装"
            value={stats?.runningCores ?? 0}
            suffix={`/ ${stats?.installedCores ?? 0}`}
            prefix={<ThunderboltOutlined style={{ color: '#10b981' }} />}
          />
        </Card>
        <Card size="small">
          <Statistic
            title="入站节点 / 活跃客户"
            value={stats?.totalInbounds ?? 0}
            suffix={`入站 · ${stats?.activeClients ?? 0} 客户`}
            prefix={<DeploymentUnitOutlined style={{ color: '#8b5cf6' }} />}
          />
        </Card>
        <Card size="small">
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            全网实时吞吐 / 累计流量
          </Typography.Text>
          <div className="mono" style={{ marginTop: 8, fontSize: 15, fontWeight: 600 }}>
            <span style={{ color: '#10b981', marginRight: 12 }}>
              <ArrowUpOutlined /> {formatSpeed(stats?.netUpRate ?? 0)}
            </span>
            <span style={{ color: '#3b82f6' }}>
              <ArrowDownOutlined /> {formatSpeed(stats?.netDownRate ?? 0)}
            </span>
          </div>
          <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>
            总计: ↑ {formatBytes(stats?.totalTrafficUp ?? 0)} / ↓ {formatBytes(stats?.totalTrafficDn ?? 0)}
          </Typography.Text>
        </Card>
      </div>

      <Card
        title={
          <Space>
            <TeamOutlined />
            <span>节点实时矩阵</span>
          </Space>
        }
        size="small"
      >
        <Table
          rowKey="id"
          size="small"
          pagination={false}
          dataSource={nodes}
          locale={{ emptyText: '暂无节点，请前往「节点与内核」添加首台 Agent' }}
          columns={[
            {
              title: '节点',
              key: 'name',
              render: (_, r) => (
                <Space>
                  <Badge status={r.online ? 'success' : 'default'} />
                  <span style={{ fontWeight: 600 }}>{r.name}</span>
                  {r.publicHost || r.publicIpv4 ? (
                    <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>
                      ({r.publicHost || r.publicIpv4})
                    </Typography.Text>
                  ) : null}
                </Space>
              ),
            },
            {
              title: '内核状态',
              key: 'cores',
              render: (_, r) => {
                const xray = r.cores?.find((c) => c.coreType === 'xray');
                if (!xray || !xray.installed) {
                  return <Tag>未安装 Core</Tag>;
                }
                const color = xray.state === 'running' ? 'success' : xray.state === 'error' ? 'error' : 'default';
                return (
                  <Tag color={color}>
                    Xray {xray.installedVersion} · {xray.state}
                  </Tag>
                );
              },
            },
            {
              title: 'CPU / 内存',
              key: 'res',
              width: 220,
              render: (_, r) => {
                const memPct = r.memTotal > 0 ? Math.round((r.memUsed / r.memTotal) * 100) : 0;
                return (
                  <Space size={12} style={{ width: '100%' }}>
                    <div style={{ width: 90 }}>
                      <Typography.Text style={{ fontSize: 11 }} type="secondary">
                        CPU {r.cpuPercent.toFixed(0)}%
                      </Typography.Text>
                      <Progress percent={Math.round(r.cpuPercent)} size="small" showInfo={false} />
                    </div>
                    <div style={{ width: 90 }}>
                      <Typography.Text style={{ fontSize: 11 }} type="secondary">
                        MEM {memPct}%
                      </Typography.Text>
                      <Progress percent={memPct} size="small" showInfo={false} strokeColor="#10b981" />
                    </div>
                  </Space>
                );
              },
            },
            {
              title: '实时速率',
              key: 'rate',
              render: (_, r) => (
                <span className="mono" style={{ fontSize: 12.5 }}>
                  ↑ {formatSpeed(r.netUpRate)} / ↓ {formatSpeed(r.netDownRate)}
                </span>
              ),
            },
            {
              title: '在线时长',
              key: 'uptime',
              render: (_, r) => <span className="mono">{r.online ? formatUptime(r.uptime) : '离线'}</span>,
            },
          ]}
        />
      </Card>
    </Space>
  );
}
