import React, { useState, useEffect } from 'react';
import { Card, Tabs, Table, Button, Form, Input, Typography, message, Popconfirm } from 'antd';
import { DeleteOutlined } from '@ant-design/icons';
import { rvpsApi } from '@/api';
import type { RvpsMessage } from '@/types/api';
import { Base64 } from 'js-base64';

const { Text } = Typography;
const { TabPane } = Tabs;
const { TextArea } = Input;

const RvpsPage: React.FC = () => {
  const [queryForm] = Form.useForm();
  const [registerForm] = Form.useForm();
  const [referenceValues, setReferenceValues] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [registering, setRegistering] = useState(false);

  const fetchReferenceValues = async () => {
    try {
      setLoading(true);
      const response = await rvpsApi.queryReferenceValue();
      
      if (response.data) {
        try {          
          let tableData;
          if (typeof response.data === 'object') {
            tableData = Object.entries(response.data).map(([key, value]) => ({ key, value }));
          } else {
            const data = JSON.parse(response.data);
            tableData = Array.isArray(data) 
              ? data 
              : Object.entries(data).map(([key, value]) => ({ key, value }));
          }
          
          setReferenceValues(tableData);
        } catch (error) {
          message.error('参考值解析失败');
          console.error('解析参考值失败:', error);
          setReferenceValues([]);
        }
      } else {
        setReferenceValues([]);
      }
    } catch (error) {
      message.error('获取参考值失败');
      console.error('获取参考值失败:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (values: any) => {
    try {
      setRegistering(true);
      
      const payload = values.payload ? Base64.encode(values.payload) : '';
      
      const rvpsMessage: RvpsMessage = {
        version: values.version || '0.1.0',
        type: values.type || 'sample',
        payload
      };
      console.log(rvpsMessage);
      await rvpsApi.registerReferenceValue(rvpsMessage);
      message.success('参考值注册成功');
      registerForm.resetFields();
      
      fetchReferenceValues();
    } catch (error) {
      message.error('参考值注册失败');
      console.error('注册参考值失败:', error);
    } finally {
      setRegistering(false);
    }
  };

  const handleDelete = async (name: string) => {
    try {
      await rvpsApi.deleteReferenceValue(name);
      message.success('参考值删除成功');
      fetchReferenceValues();
    } catch (error) {
      message.error('参考值删除失败');
      console.error('删除参考值失败:', error);
    }
  };

  useEffect(() => {
    fetchReferenceValues();
  }, []);

  const columns = [
    {
      title: '键',
      dataIndex: 'key',
      key: 'key',
      width: '30%',
      ellipsis: true,
    },
    {
      title: '值',
      dataIndex: 'value',
      key: 'value',
      width: '50%',
      ellipsis: true,
      render: (text: any) => (
        <Text style={{ wordBreak: 'break-all' }}>
          {typeof text === 'object' ? JSON.stringify(text) : text}
        </Text>
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: '20%',
      render: (_, record) => (
        <Popconfirm
          title="确认删除"
          description={`确定要删除参考值 "${record.key}" 吗？`}
          onConfirm={() => handleDelete(record.key)}
          okText="确定"
          cancelText="取消"
        >
          <Button 
            type="link" 
            danger 
            icon={<DeleteOutlined />}
            size="small"
          >
            删除
          </Button>
        </Popconfirm>
      ),
    },
  ];

  return (
    <Card title="参考值提供服务 (RVPS)" bordered={false}>
      <Tabs defaultActiveKey="query">
        <TabPane tab="查询参考值" key="query">
          <Form
            form={queryForm}
            layout="inline"
            style={{ marginBottom: 16 }}
          >
            <Form.Item>
              <Button 
                type="primary" 
                onClick={fetchReferenceValues} 
                loading={loading}
              >
                刷新参考值
              </Button>
            </Form.Item>
          </Form>
          
          <Table 
            columns={columns} 
            dataSource={referenceValues} 
            rowKey="key"
            loading={loading}
            pagination={false}
            scroll={{ x: true }}
          />
        </TabPane>
        
        <TabPane tab="注册参考值" key="register">
          <Form
            form={registerForm}
            layout="vertical"
            onFinish={handleRegister}
          >
            <Form.Item
              name="version"
              label="版本"
              initialValue="0.1.0"
              rules={[{ required: true, message: '请输入版本' }]}
            >
              <Input placeholder="请输入版本，例如：0.1.0" />
            </Form.Item>
            
            <Form.Item
              name="type"
              label="类型"
              initialValue="sample"
              rules={[{ required: true, message: '请输入类型' }]}
            >
              <Input placeholder="请输入类型，例如：sample" />
            </Form.Item>
            
            <Form.Item
              name="payload"
              label="负载内容 (将自动进行Base64编码)"
              rules={[{ required: true, message: '请输入负载内容' }]}
            >
              <TextArea 
                rows={6} 
                placeholder='
{
    "test-binary-1": [
        "reference-value-1",
        "reference-value-2"
    ],
    "test-binary-2": [
        "reference-value-3",
        "reference-value-4"
    ]
}'
              />
            </Form.Item>
            
            <Form.Item>
              <Button type="primary" htmlType="submit" loading={registering}>
                注册参考值
              </Button>
            </Form.Item>
          </Form>
        </TabPane>
      </Tabs>
    </Card>
  );
};

export default RvpsPage; 