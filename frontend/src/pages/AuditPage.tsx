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
    const { session_id, request_type, successful, time_range } = values;
    const params: any = {
      session_id,
      request_type,
      successful
    };

    if (time_range && time_range.length === 2) {
      params.start_time = time_range[0].toISOString();
      params.end_time = time_range[1].toISOString();
    }

    fetchAttestationRecords(params);
  };

  const handleResourceSearch = (values: any) => {
    const { session_id, repository, type, tag, method, successful, time_range } = values;
    const params: any = {
      session_id,
      repository,
      type,
      tag,
      method,
      successful
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
      const formattedContent = JSON.stringify(JSON.parse(content), null, 2);
      setDetailContent(formattedContent);
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
      title: '操作',
      key: 'action',
      width: 200,
      render: (_: any, record: AttestationRecord) => (
        <Space size="middle">
          <Button
            type="primary"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => handleShowDetail(record.request_body, 'evidence')}
          >
            evidence
          </Button>
          <Button
            type="primary"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => handleShowDetail(record.claims, 'claims')}
          >
            claims
          </Button>
        </Space>
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

                <Form.Item name="request_type" label="请求类型">
                  <Select style={{ width: 120 }} allowClear>
                    <Option value="auth">Auth</Option>
                    <Option value="attest">Attest</Option>
                  </Select>
                </Form.Item>

                <Form.Item name="successful" label="结果">
                  <Select style={{ width: 100 }} allowClear>
                    <Option value="true">成功</Option>
                    <Option value="false">失败</Option>
                  </Select>
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
            scroll={{ x: 1200 }}
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