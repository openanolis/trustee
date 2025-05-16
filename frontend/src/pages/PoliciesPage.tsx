import { Base64 } from 'js-base64';
import React, { useEffect, useState } from 'react';
import { 
  Tabs, 
  Table, 
  Button, 
  Typography, 
  Space, 
  Modal, 
  Form, 
  Input, 
  message,
  Card
} from 'antd';
import { PlusOutlined, EditOutlined } from '@ant-design/icons';
import { policyApi } from '@/api';
import type { ResourcePolicy } from '@/types/api';

const { Title, Paragraph, Text } = Typography;
const { TextArea } = Input;
const { TabPane } = Tabs;

interface AttestationPolicyFormValues {
  policy_id: string;
  type: string;
  policy: string;
}

interface ResourcePolicyFormValues {
  policy: string;
}

const PoliciesPage: React.FC = () => {
  const [attestationPolicies, setAttestationPolicies] = useState<AttestationPolicyFormValues[]>([]);
  const [resourcePolicy, setResourcePolicy] = useState<ResourcePolicy | null>(null);
  const [loading, setLoading] = useState(false);
  const [attestationModalVisible, setAttestationModalVisible] = useState(false);
  const [resourceModalVisible, setResourceModalVisible] = useState(false);
  const [form] = Form.useForm();
  const [currentAttestationPolicy, setCurrentAttestationPolicy] = useState<AttestationPolicyFormValues | null>(null);

  useEffect(() => {
    fetchAttestationPolicies();
    fetchResourcePolicy();
  }, []);

  const fetchAttestationPolicies = async () => {
    setLoading(true);
    try {
      const response = await policyApi.listAttestationPolicies();
      const policiesWithContent = [];
      const policyData = response.data;
      const policyInfoArray = Object.entries(policyData)
        .map(([policy_id, policy_hash]) => ({
          policy_id,
          policy_hash: String(policy_hash)
        }));

      for (const policyInfo of policyInfoArray) {
        try {
          const policyContent = await getAttestationPolicy(policyInfo.policy_id);
          const policyContentFormValues = {
            policy_id: policyInfo.policy_id,
            type: "",
            policy: policyContent
          };
          policiesWithContent.push(policyContentFormValues);
        } catch (err) {
          console.error(`获取策略 ${policyInfo.policy_id} 内容失败:`, err);
        }
      }
      setAttestationPolicies(policiesWithContent);

    } catch (error) {
      console.error('获取Attestation策略失败:', error);
      message.error('获取Attestation策略失败');
    } finally {
      setLoading(false);
    }
  };

  const getAttestationPolicy = async (policyId: string) => {
    try {
      const response = await policyApi.getAttestationPolicy(policyId);
      return response.data;
    } catch (error) {
      console.error(`获取策略 ${policyId} 详情失败:`, error);
      throw error;
    }
  };

  const fetchResourcePolicy = async () => {
    setLoading(true);
    try {
      const response = await policyApi.getResourcePolicy();
      setResourcePolicy(response.data);
    } catch (error) {
      console.error('获取Resource策略失败:', error);
      // Resource policy 可能不存在，这里不显示错误
    } finally {
      setLoading(false);
    }
  };

  const handleAddAttestationPolicy = () => {
    form.resetFields();
    setCurrentAttestationPolicy(null);
    setAttestationModalVisible(true);
  };

  const handleEditAttestationPolicy = (record: AttestationPolicyFormValues) => {
    form.setFieldsValue({
      policy_id: record.policy_id,
      type: "rego",
      policy: Base64.decode(record.policy)
    });
    setCurrentAttestationPolicy(record);
    setAttestationModalVisible(true);
  };

  const handleEditResourcePolicy = () => {
    if (resourcePolicy) {
      form.setFieldsValue({
        policy: Base64.decode(resourcePolicy) 
      });
    } else {
      form.resetFields();
    }
    setResourceModalVisible(true);
  };

  const handleSaveAttestationPolicy = async (values: AttestationPolicyFormValues) => {
    try {
      await policyApi.setAttestationPolicy({
        policy_id: values.policy_id,
        type: values.type,
        policy: values.policy
      });
      message.success('Attestation策略保存成功');
      setAttestationModalVisible(false);
      fetchAttestationPolicies();
    } catch (error) {
      console.error('保存Attestation策略失败:', error);
      message.error('保存Attestation策略失败');
    }
  };

  const handleSaveResourcePolicy = async (values: ResourcePolicyFormValues) => {
    try {
      await policyApi.setResourcePolicy({
        policy: values.policy
      });
      message.success('Resource策略保存成功');
      setResourceModalVisible(false);
      fetchResourcePolicy();
    } catch (error) {
      console.error('保存Resource策略失败:', error);
      message.error('保存Resource策略失败');
    }
  };

  const attestationColumns = [
    {
      title: '策略ID',
      dataIndex: 'policy_id',
      key: 'policy_id',
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: AttestationPolicyFormValues) => (
        <Space size="middle">
          <Button
            type="primary"
            icon={<EditOutlined />}
            onClick={() => handleEditAttestationPolicy(record)}
          >
            编辑
          </Button>
        </Space>
      ),
    },
  ];

  return (
    <div className="policies-page">
      <Title level={2}>策略管理</Title>
      <Tabs defaultActiveKey="attestation">
        <TabPane tab="Attestation Policy" key="attestation">
          <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'flex-end' }}>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={handleAddAttestationPolicy}
            >
              添加策略
            </Button>
          </div>
          <Table
            columns={attestationColumns}
            dataSource={attestationPolicies}
            rowKey="policy_id"
            loading={loading}
          />
        </TabPane>
        <TabPane tab="Resource Policy" key="resource">
          <Card>
            {resourcePolicy ? (
              <div>
                <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'flex-end' }}>
                  <Button
                    type="primary"
                    icon={<EditOutlined />}
                    onClick={handleEditResourcePolicy}
                  >
                    编辑策略
                  </Button>
                </div>
                <Paragraph>
                  <Text strong>策略内容: </Text>
                </Paragraph>
                <pre style={{ background: '#f5f5f5', padding: 16, borderRadius: 4, overflow: 'auto' }}>
                  {resourcePolicy ? Base64.decode(resourcePolicy) : ''}
                </pre>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: 24 }}>
                <Paragraph>尚未设置Resource Policy</Paragraph>
                <Button
                  type="primary"
                  icon={<PlusOutlined />}
                  onClick={handleEditResourcePolicy}
                >
                  添加策略
                </Button>
              </div>
            )}
          </Card>
        </TabPane>
      </Tabs>

      {/* Attestation Policy Modal */}
      <Modal
        title={currentAttestationPolicy ? "编辑Attestation策略" : "添加Attestation策略"}
        open={attestationModalVisible}
        onCancel={() => setAttestationModalVisible(false)}
        footer={null}
        width={800}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSaveAttestationPolicy}
        >
          <Form.Item
            name="policy_id"
            label="策略ID"
            rules={[{ required: true, message: '请输入策略ID' }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="type"
            label="类型"
            rules={[{ required: true, message: '请输入类型' }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="policy"
            label="策略内容"
            rules={[{ required: true, message: '请输入策略内容' }]}
          >
            <TextArea rows={10} />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">
                保存
              </Button>
              <Button onClick={() => setAttestationModalVisible(false)}>
                取消
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Resource Policy Modal */}
      <Modal
        title="编辑Resource策略"
        open={resourceModalVisible}
        onCancel={() => setResourceModalVisible(false)}
        footer={null}
        width={800}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSaveResourcePolicy}
        >
          <Form.Item
            name="policy"
            label="策略内容"
            rules={[{ required: true, message: '请输入策略内容' }]}
          >
            <TextArea rows={15} />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">
                保存
              </Button>
              <Button onClick={() => setResourceModalVisible(false)}>
                取消
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default PoliciesPage; 