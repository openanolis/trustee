import { jwtDecode } from 'jwt-decode';
import { SignJWT, importPKCS8,  } from 'jose';

interface Claims {
  exp: number;
  iat: number;
  sub: string;
}

export const createSignedToken = async (privateKeyPem: string): Promise<string> => {
  try {
    const privateKey = await importPKCS8(privateKeyPem, 'EdDSA');
    
    const jwt = new SignJWT()
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuedAt()
      .setExpirationTime('2h')  
    
    const token = await jwt.sign(privateKey);

    return token;
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