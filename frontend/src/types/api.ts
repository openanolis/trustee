// 服务健康状态
export interface ServiceStatus {
  status: string;
  message?: string;
  timestamp: string;
}

export interface HealthStatus {
  gateway: ServiceStatus;
  kbs: ServiceStatus;
  as: ServiceStatus;
  rvps: ServiceStatus;
}

// 资源相关类型
export interface Resource {
  repository_name: string;
  resource_type: string;
  resource_tag: string;
}

// 策略相关类型
export type AttestationPolicy = string;

export type AttestationPolicyList = string;

export type ResourcePolicy = string;

// AA Instance Info相关类型
export interface InstanceInfo {
  instance_id: string;
  image_id: string;
  instance_name: string;
  owner_account_id: string;
}

// AA Instance Heartbeat相关类型
export interface AAInstanceHeartbeat {
  ID: number;
  instance_id: string;
  image_id: string;
  instance_name: string;
  owner_account_id: string;
  client_ip: string;
  last_heartbeat: string;
  CreatedAt: string;
  UpdatedAt: string;
}

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
  source_service: string;
  instance_id?: string;
  image_id?: string;
  instance_name?: string;
  owner_account_id?: string;
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
  instance_id?: string;
  image_id?: string;
  instance_name?: string;
  owner_account_id?: string;
}

// audit API的响应结构
export interface AttestationRecordsResponse {
  data: AttestationRecord[];
  total: number;
}

export interface ResourceRequestsResponse {
  data: ResourceRequest[];
  total: number;
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