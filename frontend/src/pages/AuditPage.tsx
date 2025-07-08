import React, { useEffect, useState } from 'react';
import {
  Typography,
  Tabs,
  Table,
  Card,
  Form,
  Input,
  DatePicker,
  Button,
  Select,
  Space,
  Modal,
  message
} from 'antd';
import { SearchOutlined, SyncOutlined, EyeOutlined } from '@ant-design/icons';
import { auditApi } from '@/api';
import type { AttestationRecord, ResourceRequest } from '@/types/api';

const { Title } = Typography;
const { RangePicker } = DatePicker;
const { Option } = Select;
const { TabPane } = Tabs;

const AuditPage: React.FC = () => {
  const [attestationRecords, setAttestationRecords] = useState<AttestationRecord[]>([]);
  const [resourceRequests, setResourceRequests] = useState<ResourceRequest[]>([]);
  const [attestationLoading, setAttestationLoading] = useState(false);
  const [resourceLoading, setResourceLoading] = useState(false);
  const [attestationForm] = Form.useForm();
  const [resourceForm] = Form.useForm();
  const [activeTab, setActiveTab] = useState('attestation');
  const [detailModalVisible, setDetailModalVisible] = useState(false);
  const [detailContent, setDetailContent] = useState('');
  const [detailTitle, setDetailTitle] = useState('');

  useEffect(() => {
    if (activeTab === 'attestation') {
      fetchAttestationRecords();
    } else {
      fetchResourceRequests();
    }
  }, [activeTab]);

  const fetchAttestationRecords = async (params?: any) => {
    setAttestationLoading(true);
    try {
      const response = await auditApi.listAttestationRecords(params);
      setAttestationRecords(response.data);
    } catch (error) {
      console.error('获取Attestation记录失败:', error);
      message.error('获取Attestation记录失败');
    } finally {
      setAttestationLoading(false);
    }
  };

  const fetchResourceRequests = async (params?: any) => {
    setResourceLoading(true);
    try {
      const response = await auditApi.listResourceRequests(params);
      setResourceRequests(response.data);
    } catch (error) {
      console.error('获取Resource请求记录失败:', error);
      message.error('获取Resource请求记录失败');
    } finally {
      setResourceLoading(false);
    }
  };

  const handleAttestationSearch = (values: any) => {
    const { session_id, source_service, successful, instance_id, time_range } = values;
    const params: any = {
      session_id,
      source_service,
      successful,
      instance_id
    };

    if (time_range && time_range.length === 2) {
      params.start_time = time_range[0].toISOString();
      params.end_time = time_range[1].toISOString();
    }

    fetchAttestationRecords(params);
  };

  const handleResourceSearch = (values: any) => {
    const { session_id, repository, type, tag, method, successful, instance_id, time_range } = values;
    const params: any = {
      session_id,
      repository,
      type,
      tag,
      method,
      successful,
      instance_id
    };

    if (time_range && time_range.length === 2) {
      params.start_time = time_range[0].toISOString();
      params.end_time = time_range[1].toISOString();
    }

    fetchResourceRequests(params);
  };

  const handleShowDetail = (content: string, title: string) => {
    try {
      // 尝试解析和格式化JSON
      const parsedContent = JSON.parse(content);
      
      // 通用处理：检测并展开任何包含JSON字符串的字段
      if (parsedContent && typeof parsedContent === 'object') {
        // 递归处理对象，查找并展开任何包含JSON的字符串字段
        const processObject = (obj: any): any => {
          if (Array.isArray(obj)) {
            return obj.map(item => processObject(item));
          } else if (obj && typeof obj === 'object') {
            const processed: any = {};
            for (const [key, value] of Object.entries(obj)) {
              if (typeof value === 'string') {
                try {
                  // 尝试解析字符串值是否为JSON
                  // 简单检查：字符串应该以 { 或 [ 开头，以 } 或 ] 结尾
                  const trimmed = value.trim();
                  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
                      (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
                    // 尝试解析为JSON
                    const parsed = JSON.parse(trimmed);
                    // 递归处理解析后的对象
                    processed[key] = processObject(parsed);
                  } else {
                    processed[key] = value;
                  }
                } catch (e) {
                  // 如果解析失败，保持原值
                  processed[key] = value;
                }
              } else {
                processed[key] = processObject(value);
              }
            }
            return processed;
          }
          return obj;
        };
        
        const processedContent = processObject(parsedContent);
        setDetailContent(JSON.stringify(processedContent, null, 2));
      } else {
        setDetailContent(JSON.stringify(parsedContent, null, 2));
      }
    } catch (e) {
      // 如果不是有效的JSON，则显示原始内容
      setDetailContent(content);
    }
    setDetailTitle(title);
    setDetailModalVisible(true);
  };

  const attestationColumns = [
    {
      title: 'ID',
      dataIndex: 'ID',
      key: 'ID',
      width: 60,
    },
    {
      title: '会话ID',
      dataIndex: 'session_id',
      key: 'session_id',
      width: 120,
    },
    {
      title: '客户端IP',
      dataIndex: 'client_ip',
      key: 'client_ip',
      width: 120,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
    },
    {
      title: '结果',
      dataIndex: 'successful',
      key: 'successful',
      width: 80,
      render: (text: boolean) => (text ? '成功' : '失败'),
    },
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 180,
      render: (text: string) => new Date(text).toLocaleString(),
    },
    {
      title: '请求服务类型',
      dataIndex: 'source_service',
      key: 'source_service',
      width: 120,
    },
    {
      title: 'Instance ID',
      dataIndex: 'instance_id',
      key: 'instance_id',
      width: 150,
      ellipsis: true,
      render: (text: string) => text ? (
        <span style={{ fontFamily: 'monospace', fontSize: '12px' }}>{text}</span>
      ) : '-',
    },
    {
      title: '操作',
      key: 'action',
      width: 120,
      render: (_: any, record: AttestationRecord) => (
        <Button
          type="primary"
          size="small"
          icon={<EyeOutlined />}
          onClick={() => handleShowDetail(record.claims, 'claims')}
        >
          详情
        </Button>
      ),
    },
  ];

  const resourceColumns = [
    {
      title: 'ID',
      dataIndex: 'ID',
      key: 'ID',
      width: 60,
    },
    {
      title: '会话ID',
      dataIndex: 'session_id',
      key: 'session_id',
      width: 120,
    },
    {
      title: '客户端IP',
      dataIndex: 'client_ip',
      key: 'client_ip',
      width: 120,
    },
    {
      title: '仓库',
      dataIndex: 'repository',
      key: 'repository',
      width: 120,
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 100,
    },
    {
      title: '标签',
      dataIndex: 'tag',
      key: 'tag',
      width: 100,
    },
    {
      title: '方法',
      dataIndex: 'method',
      key: 'method',
      width: 80,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
    },
    {
      title: '结果',
      dataIndex: 'successful',
      key: 'successful',
      width: 80,
      render: (text: boolean) => (text ? '成功' : '失败'),
    },
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 180,
      render: (text: string) => new Date(text).toLocaleString(),
    },
    {
      title: 'Instance ID',
      dataIndex: 'instance_id',
      key: 'instance_id',
      width: 150,
      ellipsis: true,
      render: (text: string) => text ? (
        <span style={{ fontFamily: 'monospace', fontSize: '12px' }}>{text}</span>
      ) : '-',
    },
    {
      title: '操作',
      key: 'action',
      width: 180,
      render: (_: any, record: ResourceRequest) =>
        record.session_id ? (
          <Button
            type="link"
            size="small"
            onClick={() => {
              if (record.session_id) {
                setActiveTab('attestation');
                attestationForm.resetFields();
                attestationForm.setFieldsValue({ session_id: record.session_id });
                attestationForm.submit();
              }
            }}
          >
            查看关联Attestation
          </Button>
        ) : null,
    },
  ];

  return (
    <div className="audit-page">
      <Title level={2}>审计查询</Title>

      <Tabs activeKey={activeTab} onChange={setActiveTab}>
        <TabPane tab="Attestation 审计" key="attestation">
          <Card style={{ marginBottom: 16 }}>
            <Form
              form={attestationForm}
              layout="horizontal"
              onFinish={handleAttestationSearch}
            >
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px' }}>
                <Form.Item name="session_id" label="会话ID">
                  <Input placeholder="输入会话ID" style={{ width: 200 }} />
                </Form.Item>

                <Form.Item name="source_service" label="请求服务类型">
                  <Select style={{ width: 120 }} allowClear>
                    <Option value="kbs">KBS</Option>
                    <Option value="attestation-service">Attestation Service</Option>
                  </Select>
                </Form.Item>

                <Form.Item name="successful" label="结果">
                  <Select style={{ width: 100 }} allowClear>
                    <Option value="true">成功</Option>
                    <Option value="false">失败</Option>
                  </Select>
                </Form.Item>

                <Form.Item name="instance_id" label="Instance ID">
                  <Input placeholder="输入Instance ID" style={{ width: 200 }} />
                </Form.Item>

                <Form.Item name="time_range" label="时间范围">
                  <RangePicker showTime />
                </Form.Item>

                <Form.Item>
                  <Space>
                    <Button type="primary" htmlType="submit" icon={<SearchOutlined />}>
                      查询
                    </Button>
                    <Button icon={<SyncOutlined />} onClick={() => attestationForm.resetFields()}>
                      重置
                    </Button>
                  </Space>
                </Form.Item>
              </div>
            </Form>
          </Card>

          <Table
            columns={attestationColumns}
            dataSource={attestationRecords}
            rowKey="ID"
            loading={attestationLoading}
            scroll={{ x: 1100 }}
            pagination={{ pageSize: 10 }}
          />
        </TabPane>

        <TabPane tab="Resource 审计" key="resource">
          <Card style={{ marginBottom: 16 }}>
            <Form
              form={resourceForm}
              layout="horizontal"
              onFinish={handleResourceSearch}
            >
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px' }}>
                <Form.Item name="session_id" label="会话ID">
                  <Input placeholder="输入会话ID" style={{ width: 200 }} />
                </Form.Item>

                <Form.Item name="repository" label="仓库">
                  <Input placeholder="输入仓库名称" style={{ width: 150 }} />
                </Form.Item>

                <Form.Item name="type" label="类型">
                  <Input placeholder="输入资源类型" style={{ width: 150 }} />
                </Form.Item>

                <Form.Item name="tag" label="标签">
                  <Input placeholder="输入资源标签" style={{ width: 150 }} />
                </Form.Item>

                <Form.Item name="method" label="方法">
                  <Select style={{ width: 100 }} allowClear>
                    <Option value="GET">GET</Option>
                    <Option value="POST">POST</Option>
                  </Select>
                </Form.Item>

                <Form.Item name="successful" label="结果">
                  <Select style={{ width: 100 }} allowClear>
                    <Option value="true">成功</Option>
                    <Option value="false">失败</Option>
                  </Select>
                </Form.Item>

                <Form.Item name="instance_id" label="Instance ID">
                  <Input placeholder="输入Instance ID" style={{ width: 200 }} />
                </Form.Item>

                <Form.Item name="time_range" label="时间范围">
                  <RangePicker showTime />
                </Form.Item>

                <Form.Item>
                  <Space>
                    <Button type="primary" htmlType="submit" icon={<SearchOutlined />}>
                      查询
                    </Button>
                    <Button icon={<SyncOutlined />} onClick={() => resourceForm.resetFields()}>
                      重置
                    </Button>
                  </Space>
                </Form.Item>
              </div>
            </Form>
          </Card>

          <Table
            columns={resourceColumns}
            dataSource={resourceRequests}
            rowKey="ID"
            loading={resourceLoading}
            scroll={{ x: 1300 }}
            pagination={{ pageSize: 10 }}
          />
        </TabPane>
      </Tabs>

      {/* 详情查看 Modal */}
      <Modal
        title={detailTitle}
        open={detailModalVisible}
        onCancel={() => setDetailModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setDetailModalVisible(false)}>
            关闭
          </Button>
        ]}
        width={800}
      >
        <pre style={{ background: '#f5f5f5', padding: 16, borderRadius: 4, maxHeight: '500px', overflow: 'auto' }}>
          {detailContent}
        </pre>
      </Modal>
    </div>
  );
};

export default AuditPage; 