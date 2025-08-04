import {
  TokenType,
  TokenEvaluationResult,
  SimpleTokenClaims,
  EarTokenClaims
} from '@/types/token';

// 判断Token类型的辅助函数
function determineTokenType(claims: any): TokenType {
  // EAR Token特有字段
  if (claims.eat_profile && claims['ear.verifier-id'] && claims.submods) {
    return TokenType.Ear;
  }
  // Simple Token特有字段
  if (claims['evaluation-reports'] && claims['tcb-status']) {
    return TokenType.Simple;
  }
  throw new Error('Unknown token type');
}

// 解析Simple Token
function parseSimpleToken(claims: SimpleTokenClaims): TokenEvaluationResult {
  const evaluationReport = claims['evaluation-reports'][0];
  
  return {
    type: TokenType.Simple,
    isValid: evaluationReport['evaluation-result'].allow,
    expirationTime: new Date(claims.exp * 1000),
    trustStatus: {
      simple: {
        allowed: evaluationReport['evaluation-result'].allow
      }
    },
    rawClaims: claims
  };
}

// 解析EAR Token
function parseEarToken(claims: EarTokenClaims): TokenEvaluationResult {
  let overallStatus = 'valid';

  // 计算整体状态
  Object.values(claims.submods).forEach(submod => {
    if (submod['ear.status'] === 'contraindicated') {
      overallStatus = 'contraindicated';
    } else if (submod['ear.status'] === 'warning' && overallStatus !== 'contraindicated') {
      overallStatus = 'warning';
    }
  });

  return {
    type: TokenType.Ear,
    isValid: overallStatus === 'valid',
    expirationTime: new Date(claims.exp * 1000),
    trustStatus: {
      ear: {
        overallStatus
      }
    },
    rawClaims: claims
  };
}

// 统一的Token解析函数
export function parseToken(rawClaims: any): TokenEvaluationResult {
  try {
    const tokenType = determineTokenType(rawClaims);
    
    switch (tokenType) {
      case TokenType.Simple:
        return parseSimpleToken(rawClaims as SimpleTokenClaims);
      case TokenType.Ear:
        return parseEarToken(rawClaims as EarTokenClaims);
      default:
        throw new Error('Unsupported token type');
    }
  } catch (error) {
    console.error('Token parsing error:', error);
    throw error;
  }
}

// 获取Token的可读性描述
export function getTokenStatusDescription(result: TokenEvaluationResult): string {
  if (result.type === TokenType.Simple) {
    return result.trustStatus.simple?.allowed ? '验证通过' : '验证失败';
  }

  if (result.type === TokenType.Ear) {
    const { overallStatus } = result.trustStatus.ear!;
    const claims = result.rawClaims as EarTokenClaims;
    
    const descriptions = Object.entries(claims.submods).map(([key, submod]) => {
      const items: string[] = [];
      Object.entries(submod['ear.trustworthiness-vector']).forEach(([dimension, value]) => {
        if (value !== undefined) {
          items.push(`${dimension}: ${value}`);
        }
      });
      return `${key}: [${items.join(', ')}]`;
    });

    return `状态: ${overallStatus}\n${descriptions.join('\n')}`;
  }

  return '未知类型';
}

// 获取Token的有效期信息
export function getTokenExpirationInfo(result: TokenEvaluationResult): string {
  const now = new Date();
  const expTime = result.expirationTime;
  const diffInMinutes = Math.floor((expTime.getTime() - now.getTime()) / (1000 * 60));

  if (diffInMinutes < 0) {
    return '已过期';
  }
  if (diffInMinutes < 60) {
    return `${diffInMinutes}分钟后过期`;
  }
  const hours = Math.floor(diffInMinutes / 60);
  const minutes = diffInMinutes % 60;
  return `${hours}小时${minutes}分钟后过期`;
}