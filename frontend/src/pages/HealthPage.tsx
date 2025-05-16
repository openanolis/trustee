import React, { useEffect, useState } from 'react';
import { Card, Row, Col, Typography, Badge, Button, Spin, Descriptions } from 'antd';
import { SyncOutlined } from '@ant-design/icons';
import { healthApi } from '@/api';
import type { HealthStatus } from '@/types/api';

const { Title } = Typography;

const HealthPage: React.FC = () => {
  const [healthStatus, setHealthStatus] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchHealthStatus = async () => {
    setLoading(true);
    try {
      const response = await healthApi.getServicesHealth();
      setHealthStatus(response.data);
    } catch (error) {
      console.error('获取健康状态失败:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealthStatus();
  }, []);

  const renderStatusBadge = (status: string) => {
    const statusMap: Record<string, any> = {
      ok: { status: 'success', text: '正常' },
      error: { status: 'error', text: '异常' },
      warning: { status: 'warning', text: '警告' },
    };

    const statusInfo = statusMap[status.toLowerCase()] || { status: 'default', text: status };
    return <Badge status={statusInfo.status} text={statusInfo.text} />;
  };

  const renderServiceCard = (title: string, service: any) => (
    <Card 
      title={title} 
      bordered={false} 
      className="service-card"
      extra={<span>{new Date(service.timestamp).toLocaleString()}</span>}
    >
      <Descriptions column={1}>
        <Descriptions.Item label="状态">
          {renderStatusBadge(service.status)}
        </Descriptions.Item>
        {service.message && (
          <Descriptions.Item label="信息">
            {service.message}
          </Descriptions.Item>
        )}
      </Descriptions>
    </Card>
  );

  return (
    <div className="health-page">
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Title level={2}>服务健康状态</Title>
        <Button 
          type="primary" 
          icon={<SyncOutlined />} 
          onClick={fetchHealthStatus}
          loading={loading}
        >
          刷新
        </Button>
      </div>

      {loading && !healthStatus ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: '50px 0' }}>
          <Spin size="large" />
        </div>
      ) : (
        <Row gutter={[16, 16]}>
          {healthStatus && (
            <>
              <Col xs={24} sm={24} md={8}>
                {renderServiceCard('Gateway 服务', healthStatus.gateway)}
              </Col>
              <Col xs={24} sm={24} md={8}>
                {renderServiceCard('KBS 服务', healthStatus.kbs)}
              </Col>
              <Col xs={24} sm={24} md={8}>
                {renderServiceCard('RVPS 服务', healthStatus.rvps)}
              </Col>
            </>
          )}
        </Row>
      )}
    </div>
  );
};

export default HealthPage; 