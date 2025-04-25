import React, { Suspense, lazy, useEffect, useState } from 'react';
import { Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { Spin } from 'antd';
import MainLayout from './layouts/MainLayout';
import { loadAuthToken } from './api';

const HealthPage = lazy(() => import('./pages/HealthPage'));
const PoliciesPage = lazy(() => import('./pages/PoliciesPage'));
const ResourcesPage = lazy(() => import('./pages/ResourcesPage'));
const AuditPage = lazy(() => import('./pages/AuditPage'));
const RvpsPage = lazy(() => import('./pages/RvpsPage'));
const LoginPage = lazy(() => import('./pages/LoginPage'));

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const checkAuth = async () => {
      const isAuth = await loadAuthToken();
      setIsAuthenticated(isAuth);
      
      if (!isAuth && location.pathname !== '/login') {
        navigate('/login', { replace: true });
      }
    };
    
    checkAuth();
  }, [location.pathname, navigate]);

  if (isAuthenticated === null) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <Spin size="large" />
      </div>
    );
  }

  return <>{children}</>;
};

const App: React.FC = () => (
  <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}><Spin size="large" /></div>}>
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      
      <Route path="/" element={
        <ProtectedRoute>
          <MainLayout />
        </ProtectedRoute>
      }>
        <Route index element={<Navigate to="/health" replace />} />
        <Route path="health" element={<HealthPage />} />
        <Route path="policies" element={<PoliciesPage />} />
        <Route path="resources" element={<ResourcesPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="rvps" element={<RvpsPage />} />
      </Route>
      
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  </Suspense>
);

export default App; 