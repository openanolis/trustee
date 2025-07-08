import axios from 'axios';
import type { 
  AttestationPolicy, 
  AttestationPolicyList,
  ResourcePolicy, 
  Resource, 
  AttestationRecord, 
  ResourceRequest,
  HealthStatus,
  RvpsMessage,
  AAInstanceHeartbeat
} from '@/types/api';
import { createSignedToken, isTokenValid, getTokenRemainingTime } from '@/utils/auth';
import { Base64 } from 'js-base64';

const apiClient = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const setAuthToken = async (privateKey: string | null) => {
  try {
    if (privateKey) {
      const token = await createSignedToken(privateKey);
      
      apiClient.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      
      localStorage.setItem('auth_token', token);
      localStorage.setItem('private_key', privateKey);
      
      setupTokenRefresh(privateKey);
      
      return true;
    } else {
      delete apiClient.defaults.headers.common['Authorization'];
      localStorage.removeItem('auth_token');
      localStorage.removeItem('private_key');
      return false;
    }
  } catch (error) {
    console.error('设置认证token失败:', error);
    return false;
  }
};

export const loadAuthToken = async () => {
  try {
    const token = localStorage.getItem('auth_token');
    const privateKey = localStorage.getItem('private_key');
    
    if (token && privateKey) {
      if (isTokenValid(token)) {
        apiClient.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        
        setupTokenRefresh(privateKey);
        
        return true;
      } else if (privateKey) {
        return await setAuthToken(privateKey);
      }
    }
    
    return false;
  } catch (error) {
    console.error('加载认证token失败:', error);
    return false;
  }
};

const setupTokenRefresh = (privateKey: string) => {
  const checkAndRefreshToken = async () => {
    const token = localStorage.getItem('auth_token');
    
    if (token) {
      const remainingMinutes = getTokenRemainingTime(token);
      
      if (remainingMinutes < 30) {
        console.log('Token即将过期，刷新中...');
        await setAuthToken(privateKey);
      }
    }
  };
  
  const intervalId = setInterval(checkAndRefreshToken, 10 * 60 * 1000);
  
  const prevIntervalId = window.tokenRefreshInterval as unknown as number;
  if (prevIntervalId) {
    clearInterval(prevIntervalId);
  }
  
  window.tokenRefreshInterval = intervalId as unknown as number;
};

export const healthApi = {
  getHealthStatus: () => apiClient.get<{ status: string }>('/health'),
  getServicesHealth: () => apiClient.get<HealthStatus>('/services-health'),
};

export const policyApi = {
  getAttestationPolicy: (id: string) => apiClient.get<AttestationPolicy>(`/kbs/v0/attestation-policy/${id}`),
  listAttestationPolicies: () => apiClient.get<AttestationPolicyList>('/kbs/v0/attestation-policies'),
  setAttestationPolicy: (policy: { policy_id: string; type: string; policy: string }) => {
    const encodedPolicy = {
      ...policy,
      policy: Base64.encode(policy.policy, true)
    };
    return apiClient.post('/kbs/v0/attestation-policy', encodedPolicy);
  },
  
  getResourcePolicy: () => apiClient.get<ResourcePolicy>('/kbs/v0/resource-policy'),
  setResourcePolicy: (policy: { policy: string }) => {
    const encodedPolicy = {
      policy: Base64.encode(policy.policy, true)
    };
    return apiClient.post('/kbs/v0/resource-policy', encodedPolicy);
  },
};

export const resourceApi = {
  getResource: (repository: string, type: string, tag: string) => 
    apiClient.get<any>(`/kbs/v0/resource/${repository}/${type}/${tag}`),
  setResource: (repository: string, type: string, tag: string, data: any) => 
    apiClient.post(`/kbs/v0/resource/${repository}/${type}/${tag}`, data),
  listResources: (params?: { repository?: string; type?: string }) => 
    apiClient.get<Resource[]>('/kbs/v0/resources', { params }),
  uploadResourceFile: async (repository: string, type: string, tag: string, file: File) => {
    const arrayBuffer = await file.arrayBuffer();
    
    return apiClient.post(
      `/kbs/v0/resource/${repository}/${type}/${tag}`, 
      arrayBuffer, 
      {
        headers: {
          'Content-Type': 'application/octet-stream',
        },
      }
    );
  },
};

export const auditApi = {
  listAttestationRecords: (params?: {
    session_id?: string;
    source_service?: string;
    successful?: boolean;
    start_time?: string;
    end_time?: string;
    instance_id?: string;
    limit?: number;
    offset?: number;
  }) => apiClient.get<AttestationRecord[]>('/audit/attestation', { params }),
  
  listResourceRequests: (params?: {
    session_id?: string;
    repository?: string;
    type?: string;
    tag?: string;
    method?: string;
    successful?: boolean;
    start_time?: string;
    end_time?: string;
    instance_id?: string;
    limit?: number;
    offset?: number;
  }) => apiClient.get<ResourceRequest[]>('/audit/resources', { params }),
};

export const rvpsApi = {
  queryReferenceValue: () => 
    apiClient.get('/rvps/query'),
  
  registerReferenceValue: (message: RvpsMessage) => {
    const payload = {
      message: JSON.stringify({
        version: message.version,
        type: message.type,
        payload: message.payload
      })
    };
    return apiClient.post('/rvps/register', payload);
  },

  deleteReferenceValue: (name: string) => 
    apiClient.delete(`/rvps/delete/${encodeURIComponent(name)}`)
};

export const aaInstanceApi = {
  listActiveInstances: () => apiClient.get<{
    active_aa_instances: AAInstanceHeartbeat[];
    count: number;
    timestamp: string;
  }>('/aa-instance/list'),
};

declare global {
  interface Window {
    tokenRefreshInterval: number;
  }
} 