// Token类型枚举
export enum TokenType {
  Simple = 'Simple',
  Ear = 'Ear'
}

// Simple Token的声明结构
export interface SimpleTokenClaims {
  customized_claims: {
    init_data: any;
    runtime_data: any;
  };
  'evaluation-reports': Array<{
    'evaluation-result': {
      allow: boolean;
    };
    'policy-hash': string;
    'policy-id': string;
  }>;
  exp: number;
  iss: string;
  jwk: {
    alg: string;
    e: string;
    kty: string;
    n: string;
  };
  nbf: number;
  'reference-data': Record<string, any>;
  'tcb-status': Record<string, string>;
  tee: string;
}

// EAR Token的信任向量结构
export interface TrustVector {
  instance_identity?: number;
  configuration?: number;
  executables?: number;
  file_system?: number;
  hardware?: number;
  runtime_opaque?: number;
  storage_opaque?: number;
  sourced_data?: number;
}

// EAR Token的声明结构
export interface EarTokenClaims {
  eat_profile: string;
  iat: number;
  'ear.verifier-id': {
    build: string;
    developer: string;
  };
  raw_evidence?: any;
  nonce?: string;
  submods: {
    [key: string]: {
      'ear.status': string;
      'ear.trustworthiness-vector': TrustVector;
      'ear.appraisal-policy-id': string;
      'ear.veraison.annotated-evidence': Record<string, any>;
    };
  };
  exp: number;
}

// 统一的Token声明接口
export interface TokenClaims {
  type: TokenType;
  claims: SimpleTokenClaims | EarTokenClaims;
}

// Token评估结果接口
export interface TokenEvaluationResult {
  type: TokenType;
  isValid: boolean;
  expirationTime: Date;
  trustStatus: {
    simple?: {
      allowed: boolean;
    };
    ear?: {
      overallStatus: string;
    };
  };
  rawClaims: any;
}