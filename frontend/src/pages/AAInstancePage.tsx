import React, { useEffect, useState } from 'react';
import {
  Typography,
  Table,
  Card,
  Button,
  Space,
  Form,
  Input,
  message,
  Descriptions,
  Badge
} from 'antd';
import { SyncOutlined, SearchOutlined } from '@ant-design/icons';
import { aaInstanceApi } from '@/api';
import type { AAInstanceHeartbeat } from '@/types/api';

const { Title } = Typography;

const AAInstancePage: React.FC = () => {
  const [aaInstances, setAAInstances] = useState<AAInstanceHeartbeat[]>([]);
  const [loading, setLoading] = useState(false);
  const [form] = Form.useForm();

  useEffect(() => {
    fetchAAInstances();
    // 设置自动刷新，每30秒刷新一次
    const interval = setInterval(fetchAAInstances, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchAAInstances = async () => {
    setLoading(true);
    try {
      const response = await aaInstanceApi.listActiveInstances();
      setAAInstances(response.data.active_aa_instances || []);
    } catch (error) {
      console.error('获取实例列表失败:', error);
      message.error('获取实例列表失败');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (values: any) => {
    const { instance_id } = values;
    if (instance_id) {
      const filtered = aaInstances.filter(instance => 
        instance.instance_id.toLowerCase().includes(instance_id.toLowerCase())
      );
      setAAInstances(filtered);
    } else {
      fetchAAInstances();
    }
  };

  const getHeartbeatStatus = (lastHeartbeat: string) => {
    const now = new Date();
    const heartbeatTime = new Date(lastHeartbeat);
    const diffMinutes = (now.getTime() - heartbeatTime.getTime()) / (1000 * 60);
    
    if (diffMinutes < 10) {
      return { status: 'success', text: '活跃' };
    } else {
      return { status: 'error', text: '离线' };
    }
  };

  const columns = [
    {
      title: 'Instance ID',
      dataIndex: 'instance_id',
      key: 'instance_id',
      width: 200,
      ellipsis: true,
      render: (text: string) => (
        <span style={{ fontFamily: 'monospace' }}>{text}</span>
      ),
    },
    {
      title: 'Image ID',
      dataIndex: 'image_id',
      key: 'image_id',
      width: 150,
      ellipsis: true,
      render: (text: string) => (
        <span style={{ fontFamily: 'monospace' }}>{text}</span>
      ),
    },
    {
      title: 'Instance Name',
      dataIndex: 'instance_name',
      key: 'instance_name',
      width: 150,
      ellipsis: true,
    },
    {
      title: 'Owner Account',
      dataIndex: 'owner_account_id',
      key: 'owner_account_id',
      width: 150,
      ellipsis: true,
    },
    {
      title: 'Client IP',
      dataIndex: 'client_ip',
      key: 'client_ip',
      width: 120,
    },
    {
      title: '心跳状态',
      dataIndex: 'last_heartbeat',
      key: 'heartbeat_status',
      width: 100,
      render: (lastHeartbeat: string) => {
        const status = getHeartbeatStatus(lastHeartbeat);
        return <Badge status={status.status as any} text={status.text} />;
      },
    },
    {
      title: '最后心跳时间',
      dataIndex: 'last_heartbeat',
      key: 'last_heartbeat',
      width: 180,
      render: (text: string) => new Date(text).toLocaleString(),
    },
  ];

  return (
    <div className="aa-instance-page">
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Title level={2}>实例管理</Title>
        <Button 
          type="primary" 
          icon={<SyncOutlined />} 
          onClick={fetchAAInstances}
          loading={loading}
        >
          刷新
        </Button>
      </div>

      <Card style={{ marginBottom: 16 }}>
        <Form
          form={form}
          layout="horizontal"
          onFinish={handleSearch}
        >
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'end' }}>
            <Form.Item name="instance_id" label="Instance ID">
              <Input placeholder="搜索Instance ID" style={{ width: 250 }} />
            </Form.Item>
            <Form.Item>
              <Space>
                <Button type="primary" htmlType="submit" icon={<SearchOutlined />}>
                  搜索
                </Button>
                <Button 
                  icon={<SyncOutlined />} 
                  onClick={() => {
                    form.resetFields();
                    fetchAAInstances();
                  }}
                >
                  重置
                </Button>
              </Space>
            </Form.Item>
          </div>
        </Form>

        <Descriptions style={{ marginTop: 16 }} size="small" column={4}>
          <Descriptions.Item label="活跃实例">
            <Badge 
              count={aaInstances.filter(i => getHeartbeatStatus(i.last_heartbeat).status === 'success').length} 
              showZero 
              color="green" 
            />
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <Table
        columns={columns}
        dataSource={aaInstances}
        rowKey="ID"
        loading={loading}
        scroll={{ x: 1300 }}
        pagination={{ 
          pageSize: 20,
          showSizeChanger: true,
          showQuickJumper: true,
          showTotal: (total, range) => `第 ${range[0]}-${range[1]} 条，共 ${total} 条`
        }}
      />
    </div>
  );
};

export default AAInstancePage; 