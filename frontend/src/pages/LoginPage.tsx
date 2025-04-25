import React, { useState } from 'react';
import { Button, Card, Form, Input, Typography, Upload, message } from 'antd';
import { UploadOutlined, LockOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { setAuthToken } from '@/api';

const { Title, Text } = Typography;

const LoginPage: React.FC = () => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleFileUpload = (file: File): boolean => {
    setLoading(true);
    const reader = new FileReader();
    
    reader.onload = (e) => {
      try {
        const privateKey = e.target?.result as string;
        
        if (!privateKey.trim()) {
          message.error('私钥文件内容不能为空');
          setLoading(false);
          return;
        }
        
        form.setFieldsValue({ privateKey });
        message.success('私钥文件已上传');
      } catch (error) {
        message.error('文件读取失败，请确保上传了正确的私钥文件');
      } finally {
        setLoading(false);
      }
    };
    
    reader.onerror = () => {
      message.error('文件读取失败');
      setLoading(false);
    };
    
    reader.readAsText(file);
    return false;
  };

  const handleManualInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    form.setFieldsValue({ privateKey: e.target.value });
  };

  const handleSubmit = async (values: { privateKey: string }) => {
    try {
      setLoading(true);
      const { privateKey } = values;
      
      const success = await setAuthToken(privateKey);
      
      if (success) {
        message.success('登录成功');
        navigate('/health');
      } else {
        message.error('登录失败，无法生成有效的认证token');
      }
    } catch (error) {
      message.error('登录失败，请检查私钥是否正确');
      console.error('登录失败:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ 
      display: 'flex', 
      justifyContent: 'center', 
      alignItems: 'center',
      height: '100vh',
      background: '#f0f2f5'
    }}>
      <Card style={{ width: 500, boxShadow: '0 4px 12px rgba(0,0,0,0.1)' }}>
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <Title level={2}>
            <LockOutlined style={{ marginRight: 8 }} />
            登录到 Trustee 系统
          </Title>
          <Text type="secondary">
            请上传或输入您的PEM格式Ed25519私钥以继续
          </Text>
        </div>

        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
        >
          <Form.Item
            name="privateKey"
            rules={[{ required: true, message: '请上传或输入私钥' }]}
          >
            <Input.TextArea
              rows={6}
              placeholder="请粘贴您的PEM格式Ed25519私钥内容"
              onChange={handleManualInput}
            />
          </Form.Item>

          <Form.Item>
            <Upload
              beforeUpload={handleFileUpload}
              maxCount={1}
              showUploadList={false}
            >
              <Button 
                icon={<UploadOutlined />} 
                style={{ marginBottom: 16, width: '100%' }}
              >
                上传私钥文件
              </Button>
            </Upload>
          </Form.Item>

          <Form.Item>
            <Button 
              type="primary" 
              htmlType="submit" 
              loading={loading}
              style={{ width: '100%' }}
            >
              登录
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  );
};

export default LoginPage; 