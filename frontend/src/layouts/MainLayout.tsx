import React, { useState } from 'react';
import { Layout, Menu, Typography, Button } from 'antd';
import { 
  HeartFilled, 
  SecurityScanOutlined, 
  BookOutlined, 
  AuditOutlined,
  CloudServerOutlined,
  TeamOutlined,
  LogoutOutlined
} from '@ant-design/icons';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { setAuthToken } from '@/api';

const { Header, Content, Footer, Sider } = Layout;
const { Title } = Typography;

const MainLayout: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  // 根据当前路径确定选中的菜单项
  const getSelectedKey = () => {
    const path = location.pathname.split('/')[1] || 'health';
    return [path];
  };

  // 处理登出
  const handleLogout = () => {
    setAuthToken(null);
    navigate('/login');
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        collapsible
        collapsed={collapsed}
        onCollapse={(value) => setCollapsed(value)}
        theme="dark"
        width={200}
      >
        <div style={{ padding: 16, textAlign: 'center' }}>
          <Title level={4} style={{ color: 'white', margin: 0 }}>
            {collapsed ? 'TS' : 'Trustee'}
          </Title>
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={getSelectedKey()}
          items={[
            {
              key: 'health',
              icon: <HeartFilled />,
              label: <Link to="/health">系统健康</Link>,
            },
            {
              key: 'policies',
              icon: <SecurityScanOutlined />,
              label: <Link to="/policies">策略管理</Link>,
            },
            {
              key: 'resources',
              icon: <BookOutlined />,
              label: <Link to="/resources">资源管理</Link>,
            },
            {
              key: 'audit',
              icon: <AuditOutlined />,
              label: <Link to="/audit">审计日志</Link>,
            },
            {
              key: 'aa-instances',
              icon: <TeamOutlined />,
              label: <Link to="/aa-instances">实例列表</Link>,
            },
            {
              key: 'rvps',
              icon: <CloudServerOutlined />,
              label: <Link to="/rvps">参考值服务</Link>,
            },
          ]}
        />
      </Sider>
      <Layout>
        <Header style={{ 
          padding: '0 16px', 
          background: '#fff', 
          display: 'flex', 
          justifyContent: 'flex-end', 
          alignItems: 'center' 
        }}>
          <Button 
            type="text" 
            icon={<LogoutOutlined />} 
            onClick={handleLogout}
          >
            登出
          </Button>
        </Header>
        <Content style={{ margin: '16px' }}>
          <div style={{ padding: 24, minHeight: 360, background: '#fff' }}>
            <Outlet />
          </div>
        </Content>
        <Footer style={{ textAlign: 'center' }}>
          Trustee ©{new Date().getFullYear()} Created by Alibaba Cloud
        </Footer>
      </Layout>
    </Layout>
  );
};

export default MainLayout; 