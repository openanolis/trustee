import React, { useEffect, useState } from 'react';
import {
  Typography,
  Table,
  Button,
  Space,
  Modal,
  Form,
  Input,
  message,
  Row,
  Col,
  Card,
  Radio,
  Upload
} from 'antd';
import { PlusOutlined, SearchOutlined, UploadOutlined } from '@ant-design/icons';
import { resourceApi } from '@/api';
import type { Resource } from '@/types/api';
import type { UploadFile, UploadProps } from 'antd/es/upload/interface';

const { Title } = Typography;
const { TextArea } = Input;
interface ResourceFormValues {
  repository: string;
  type: string;
  tag: string;
  content?: string;
  file?: File;
  uploadType: 'text' | 'binary';
}

const ResourcesPage: React.FC = () => {
  const [resources, setResources] = useState<Resource[]>([]);
  const [loading, setLoading] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const [form] = Form.useForm();
  const [searchForm] = Form.useForm();
  const [currentResource, setCurrentResource] = useState<Resource | null>(null);
  const [contentModalVisible, setContentModalVisible] = useState(false);
  const [resourceContent] = useState<string>('');
  const [contentLoading] = useState(false);
  const [uploadType, setUploadType] = useState<'text' | 'binary'>('text');
  const [fileList, setFileList] = useState<UploadFile[]>([]);

  useEffect(() => {
    fetchResources();
  }, []);

  const fetchResources = async (params?: { repository?: string; type?: string }) => {
    setLoading(true);
    try {
      const response = await resourceApi.listResources(params);
      setResources(response.data);
    } catch (error) {
      console.error('获取资源列表失败:', error);
      message.error('获取资源列表失败');
    } finally {
      setLoading(false);
    }
  };

  const handleAddResource = () => {
    form.resetFields();
    setCurrentResource(null);
    setUploadType('text');
    setFileList([]);
    setModalVisible(true);
  };

  const handleSaveResource = async (values: ResourceFormValues) => {
    try {
      if (values.uploadType === 'text') {
        await resourceApi.setResource(values.repository, values.type, values.tag, values.content);
      } else {
        // 二进制文件提交
        if (fileList.length === 0) {
          message.error('请选择要上传的文件');
          return;
        }
        const file = fileList[0].originFileObj;
        if (!file) {
          message.error('文件对象不存在');
          return;
        }
        
        // 调用文件上传API
        await resourceApi.uploadResourceFile(values.repository, values.type, values.tag, file);
      }
      
      message.success('资源保存成功');
      setModalVisible(false);
      fetchResources();
    } catch (error) {
      console.error('保存资源失败:', error);
      message.error('保存资源失败');
    }
  };

  const handleSearch = (values: any) => {
    fetchResources({
      repository: values.repository,
      type: values.type
    });
  };

  const handleUploadTypeChange = (e: any) => {
    setUploadType(e.target.value);
    if (e.target.value === 'text') {
      setFileList([]);
    } else {
      form.setFieldValue('content', undefined);
    }
  };

  const uploadProps: UploadProps = {
    onRemove: () => {
      setFileList([]);
    },
    beforeUpload: (file) => {
      setFileList([
        {
          uid: '-1',
          name: file.name,
          status: 'done',
          size: file.size,
          type: file.type,
          originFileObj: file,
        }
      ]);
      return false;
    },
    fileList,
    maxCount: 1
  };

  const columns = [
    {
      title: 'ID',
      dataIndex: 'ID',
      key: 'ID',
    },
    {
      title: '仓库',
      dataIndex: 'repository',
      key: 'repository',
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
    },
    {
      title: '标签',
      dataIndex: 'tag',
      key: 'tag',
    },
    {
      title: '元数据',
      dataIndex: 'metadata',
      key: 'metadata',
    },
    {
      title: '创建时间',
      dataIndex: 'CreatedAt',
      key: 'CreatedAt',
      render: (text: string) => new Date(text).toLocaleString(),
    },
  ];

  return (
    <div className="resources-page">
      <Title level={2}>资源管理</Title>

      <Card style={{ marginBottom: 16 }}>
        <Form
          form={searchForm}
          layout="inline"
          onFinish={handleSearch}
          style={{ marginBottom: 16 }}
        >
          <Form.Item name="repository" label="仓库">
            <Input placeholder="输入仓库名称" />
          </Form.Item>
          <Form.Item name="type" label="类型">
            <Input placeholder="输入资源类型" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" icon={<SearchOutlined />}>
              查询
            </Button>
          </Form.Item>
        </Form>
      </Card>

      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'flex-end' }}>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={handleAddResource}
        >
          添加资源
        </Button>
      </div>

      <Table
        columns={columns}
        dataSource={resources}
        rowKey="ID"
        loading={loading}
      />

      {/* 添加/编辑资源 Modal */}
      <Modal
        title={currentResource ? "编辑资源" : "添加资源"}
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={null}
        width={800}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSaveResource}
          initialValues={{ uploadType: 'text' }}
        >
          <Row gutter={16}>
            <Col span={8}>
              <Form.Item
                name="repository"
                label="仓库"
                rules={[{ required: true, message: '请输入仓库名称' }]}
              >
                <Input />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="type"
                label="类型"
                rules={[{ required: true, message: '请输入资源类型' }]}
              >
                <Input />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="tag"
                label="标签"
                rules={[{ required: true, message: '请输入资源标签' }]}
              >
                <Input />
              </Form.Item>
            </Col>
          </Row>
          
          <Form.Item name="uploadType" label="上传方式">
            <Radio.Group onChange={handleUploadTypeChange} value={uploadType}>
              <Radio value="text">文本</Radio>
              <Radio value="binary">二进制文件</Radio>
            </Radio.Group>
          </Form.Item>
          
          {uploadType === 'text' && (
            <Form.Item
              name="content"
              label="资源内容"
              rules={[
                { required: uploadType === 'text', message: '请输入资源内容' },
                {
                  validator: (_, value) => {
                    if (!value && uploadType !== 'text') return Promise.resolve(); {
                      return Promise.resolve();
                    }
                  }
                }
              ]}
            >
              <TextArea rows={10} />
            </Form.Item>
          )}
          
          {uploadType === 'binary' && (
            <Form.Item 
              label="上传文件"
              rules={[{ required: uploadType === 'binary', message: '请选择文件' }]}
            >
              <Upload {...uploadProps}>
                <Button icon={<UploadOutlined />}>选择文件</Button>
              </Upload>
              <div style={{ marginTop: 8 }}>支持各种二进制文件格式</div>
            </Form.Item>
          )}
          
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">
                保存
              </Button>
              <Button onClick={() => setModalVisible(false)}>
                取消
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 资源内容查看 Modal */}
      <Modal
        title="资源内容"
        open={contentModalVisible}
        onCancel={() => setContentModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setContentModalVisible(false)}>
            关闭
          </Button>
        ]}
        width={800}
      >
        {contentLoading ? (
          <div style={{ textAlign: 'center', padding: 20 }}>加载中...</div>
        ) : (
          <pre style={{ background: '#f5f5f5', padding: 16, borderRadius: 4, maxHeight: '70vh', overflow: 'auto' }}>
            {resourceContent}
          </pre>
        )}
      </Modal>
    </div>
  );
};

export default ResourcesPage; 