export type User = {
    sub: string;
    nickname: string;
    name: string;
    picture: string;
    updated_at: string;
    email: string;
    email_verified: boolean;
  };
  
  export type TokenInfo = {
    accessToken: string;
    refreshToken: string;
    expiresAt: number;
    userInfo?: User;
    userInfoTimestamp?: number;
  };
  
  export type Auth0TokenResponse = {
    access_token: string;
    refresh_token?: string;
    id_token: string;
    token_type: string;
    expires_in: number;
  };
  
  export type Auth0Error = {
    error: string;
    error_description: string;
  };