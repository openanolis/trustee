import { jwtDecode } from 'jwt-decode';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { Base64 } from 'js-base64';

ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));

interface Claims {
  exp: number;
  iat: number;
  sub: string;
}

function extractPrivateKeyFromPem(privateKeyPem: string): Uint8Array {
  const base64Key = privateKeyPem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');
  
  const keyBytes = Base64.toUint8Array(base64Key);

  let privateKeyStart = -1;
  
  for (let i = 0; i < keyBytes.length - 5; i++) {
    if (keyBytes[i] === 0x06 && keyBytes[i + 1] === 0x03 && 
        keyBytes[i + 2] === 0x2b && keyBytes[i + 3] === 0x65 && keyBytes[i + 4] === 0x70) {

      let pos = i + 5;
      
      while (pos < keyBytes.length - 2) {
        if (keyBytes[pos] === 0x04 && keyBytes[pos + 1] === 0x22) {
          pos += 2; // 跳过 04 22
          if (pos < keyBytes.length - 2 && keyBytes[pos] === 0x04 && keyBytes[pos + 1] === 0x20) {
            privateKeyStart = pos + 2;
            break;
          }
        }
        pos++;
      }
      break;
    }
  }
  
  if (privateKeyStart === -1) {
    throw new Error('无法在PKCS#8格式中找到Ed25519私钥数据');
  }
  
  if (privateKeyStart + 32 > keyBytes.length) {
    throw new Error('PKCS#8私钥数据长度不足');
  }
  
  return keyBytes.slice(privateKeyStart, privateKeyStart + 32);
}

function createJwtHeader(): string {
  const header = {
    alg: 'EdDSA',
    typ: 'JWT'
  };
  return Base64.encode(JSON.stringify(header), true);
}

function createJwtPayload(): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now,
    exp: now + 7200 // 2小时后过期
  };
  return Base64.encode(JSON.stringify(payload), true);
}

export const createSignedToken = async (privateKeyPem: string): Promise<string> => {
  try {
    const privateKeyBytes = extractPrivateKeyFromPem(privateKeyPem);
    
    const header = createJwtHeader();
    const payload = createJwtPayload();
    
    const message = `${header}.${payload}`;
    const messageBytes = new TextEncoder().encode(message);
    
    const signature = await ed25519.sign(messageBytes, privateKeyBytes);
    
    const signatureBase64 = Base64.fromUint8Array(signature, true);
    
    return `${message}.${signatureBase64}`;
  } catch (error) {
    console.error('创建签名token失败:', error);
    throw new Error('创建签名token失败');
  }
};

export const isTokenValid = (token: string): boolean => {
  try {
    const decoded = jwtDecode<Claims>(token);
    const now = Math.floor(Date.now() / 1000);
    
    return decoded.exp > now;
  } catch (error) {
    return false;
  }
};

export const getTokenRemainingTime = (token: string): number => {
  try {
    const decoded = jwtDecode<Claims>(token);
    const now = Math.floor(Date.now() / 1000);
    
    return Math.max(0, Math.floor((decoded.exp - now) / 60));
  } catch (error) {
    return 0;
  }
}; 