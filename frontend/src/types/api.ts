// 服务健康状态
export interface ServiceStatus {
  status: string;
  message?: string;
  timestamp: string;
}

export interface HealthStatus {
  gateway: ServiceStatus;
  kbs: ServiceStatus;
  rvps: ServiceStatus;
}

// 资源相关类型
export interface Resource {
  ID: number;
  repository: string;
  type: string;
  tag: string;
  metadata: string;
}

// 策略相关类型
export type AttestationPolicy = string;

export type AttestationPolicyList = string;

export type ResourcePolicy = string;

// 审计记录类型
export interface AttestationRecord {
  ID: number;
  client_ip: string;
  session_id: string;
  request_body: string;
  claims: string;
  status: number;
  successful: boolean;
  timestamp: string;
}

export interface ResourceRequest {
  ID: number;
  client_ip: string;
  session_id: string;
  repository: string;
  type: string;
  tag: string;
  method: string;
  status: number;
  successful: boolean;
  timestamp: string;
}

// 认证相关类型
export interface AuthState {
  isAuthenticated: boolean;
  privateKey: string | null;
}

// RVPS相关类型
export interface RvpsMessage {
  version: string;
  type: string;
  payload: string;
} 