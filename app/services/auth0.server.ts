import axios from 'axios';
import dotenv from 'dotenv';
import type { TokenInfo, User } from '../types/User';
import { commitSession, getSession } from './sessions.server';

// Load environment variables
dotenv.config();

// Destructure and validate required Auth0 configuration
let { AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_DOMAIN, AUTH0_CALLBACK_URL, AUTH0_AUDIENCE } = process.env;
if (!AUTH0_DOMAIN) throw new Error('Missing Auth0 domain.');
if (!AUTH0_CLIENT_ID) throw new Error('Missing Auth0 client id.');
if (!AUTH0_CLIENT_SECRET) throw new Error('Missing Auth0 client secret.');
if (!AUTH0_CALLBACK_URL) throw new Error('Missing Auth0 redirect uri.');
if (!AUTH0_AUDIENCE) throw new Error('Missing Auth0 audience.');

// Object containing Auth0 configuration values
const auth0Config = {
  clientId: AUTH0_CLIENT_ID,
  clientSecret: AUTH0_CLIENT_SECRET,
  domain: AUTH0_DOMAIN,
  callbackUrl: AUTH0_CALLBACK_URL,
  audience: AUTH0_AUDIENCE,
};

export class Auth0Service {
  // Singleton instance
  private static instance: Auth0Service;
  // Axios instance for Auth0 API communication
  private auth0Api;
  // Base URL for Auth0 endpoints
  private auth0Url;
  // In-memory cache for tokens and user information
  private tokenCache: Map<string, TokenInfo>;
  // Cache time for user information (5 minutes)
  private readonly USER_INFO_CACHE_TIME = 5 * 60 * 1000;

  /**
   * Private constructor to enforce singleton pattern
   * Initializes axios client and token cache
   */
  private constructor() {
    this.auth0Api = axios.create({
      baseURL: `https://${auth0Config.domain}`,
      headers: {
        'Content-Type': 'application/json',
      },
    });
    this.auth0Url = `https://${auth0Config.domain}`;
    this.tokenCache = new Map();
  }

  /**
   * Returns the singleton instance of Auth0Service
   * Creates it if it doesn't exist yet
   */
  static getInstance(): Auth0Service {
    if (!Auth0Service.instance) {
      Auth0Service.instance = new Auth0Service();
    }
    return Auth0Service.instance;
  }

  /**
   * Checks if cached user info has expired
   * @param timestamp - When the user info was cached
   * @returns true if expired, false otherwise
   */
  private isUserInfoExpired(timestamp?: number): boolean {
    if (!timestamp) return true;
    return Date.now() >= timestamp + this.USER_INFO_CACHE_TIME;
  }

  /**
   * Generates the URL for Auth0 login page
   * @param state - CSRF protection state parameter
   * @returns Full URL for Auth0 authorization endpoint
   */
  getLoginUrl(state: string): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: auth0Config.clientId,
      redirect_uri: auth0Config.callbackUrl,
      scope: 'openid profile email offline_access',
      state,
      audience: auth0Config.audience,
    });
    return `${this.auth0Url}/authorize?${params.toString()}`;
  }

  /**
   * Generates the URL for logging out of Auth0
   * @returns Full URL for Auth0 logout endpoint
   */
  getLogoutUrl(): string {
    const baseUrl = new URL(auth0Config.callbackUrl).origin;
    const returnTo = `${baseUrl}/auth/login`;
    const params = new URLSearchParams({
      client_id: auth0Config.clientId,
      returnTo: returnTo,
    });
    return `${this.auth0Url}/v2/logout?${params.toString()}`;
  }

  /**
   * Checks if a token is expired or about to expire (within 5 minutes)
   * @param expiresAt - Token expiration timestamp
   * @returns true if token is expired or will expire soon
   */
  private isTokenExpired(expiresAt: number): boolean {
    const now = Date.now();
    const fiveMinutes = 5 * 60 * 1000;
    return now >= expiresAt - fiveMinutes;
  }

  /**
   * Exchanges an authorization code for access and refresh tokens
   * Also fetches user information
   * @param code - Authorization code from Auth0 redirect
   * @returns Object containing tokens, user info, and expiration
   */
  async exchangeCodeForToken(code: string): Promise<{
    accessToken: string;
    userInfo: User;
    refreshToken: string;
    expiresAt: number;
  }> {
    try {
      // Request tokens from Auth0
      const { data } = await this.auth0Api.post('/oauth/token', {
        grant_type: 'authorization_code',
        client_id: auth0Config.clientId,
        client_secret: auth0Config.clientSecret,
        code,
        redirect_uri: auth0Config.callbackUrl,
      });
      // Calculate when the token will expire
      const expiresAt = Date.now() + data.expires_in * 1000;
      // Fetch user info using the access token
      const userInfo = await this.fetchUserInfo(data.access_token);
      // Cache the token information
      this.tokenCache.set(data.access_token, {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt,
        userInfo,
        userInfoTimestamp: Date.now(),
      });
      return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt,
        userInfo,
      };
    } catch (error: any) {
      const errorMessage = error.response?.data?.error_description || error.message;
      throw new Error(`Failed to exchange code for token: ${errorMessage}`);
    }
  }

  /**
   * Gets a new access token using a refresh token
   * @param refreshToken - The refresh token to use
   * @returns New token information including user details
   */
  private async refreshToken(refreshToken: string): Promise<TokenInfo> {
    try {
      // Request a new access token using the refresh token
      const { data } = await this.auth0Api.post('/oauth/token', {
        grant_type: 'refresh_token',
        client_id: auth0Config.clientId,
        client_secret: auth0Config.clientSecret,
        refresh_token: refreshToken,
      });
      // Calculate expiration time
      const expiresAt = Date.now() + data.expires_in * 1000;
      // Get user info with the new token
      const userInfo = await this.fetchUserInfo(data.access_token);
      // Create token info object
      const tokenInfo: TokenInfo = {
        accessToken: data.access_token,
        // Use the new refresh token or fall back to the old one
        refreshToken: data.refresh_token || refreshToken,
        expiresAt,
        userInfo,
        userInfoTimestamp: Date.now(),
      };
      // Cache the new token info
      this.tokenCache.set(data.access_token, tokenInfo);
      return tokenInfo;
    } catch (error: any) {
      const errorMessage = error.response?.data?.error_description || error.message;
      throw new Error(`Failed to refresh token: ${errorMessage}`);
    }
  }

  /**
   * Fetches user information from Auth0
   * @param accessToken - Token to use for authentication
   * @returns User information object
   */
  private async fetchUserInfo(accessToken: string): Promise<User> {
    try {
      // Call Auth0 userinfo endpoint
      const { data } = await this.auth0Api.get('/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      return data;
    } catch (error: any) {
      const errorMessage = error.response?.data?.error_description || error.message;
      throw new Error(`Failed to fetch user info: ${errorMessage}`);
    }
  }

  /**
   * Gets user information, using cache when possible
   * Will refresh tokens if necessary
   * @param accessToken - The access token
   * @param request - Optional request object for session handling
   * @returns User information
   */
  async getUserInfo(accessToken: string, request?: Request): Promise<User> {
    try {
      // Check in-memory cache for token information
      const cachedToken = this.tokenCache.get(accessToken);
      let sessionTokenInfo: Partial<TokenInfo> = {};
      let session;
      
      // If request is provided, try to get token info from session
      if (request) {
        session = await getSession(request.headers.get('Cookie'));
        const sessionUser = session.get('user');
        const sessionAccessToken = session.get('accessToken');
        if (sessionUser && sessionAccessToken) {
          sessionTokenInfo = {
            userInfo: sessionUser as User,
            accessToken: sessionAccessToken,
          };
        }
      }
      
      // Merge session info with cached info
      const tokenInfo = {
        ...sessionTokenInfo,
        ...(cachedToken || {}),
      };
      
      // If no token information is found, throw error
      if (!tokenInfo.accessToken && !tokenInfo.userInfo) {
        throw new Error('No token information found');
      }
      
      // Check if token or user info is expired
      const isTokenExpired = tokenInfo.expiresAt ? this.isTokenExpired(tokenInfo.expiresAt) : true;
      const isUserInfoExpired = tokenInfo.userInfoTimestamp ? this.isUserInfoExpired(tokenInfo.userInfoTimestamp) : true;
      const cachedUserInfo = tokenInfo.userInfo;
      const cachedRefreshToken = tokenInfo.refreshToken;
      
      // Return cached user info if it's still valid
      if (!isTokenExpired && !isUserInfoExpired && cachedUserInfo) {
        return cachedUserInfo;
      }
      
      // If we have a refresh token, use it to get new tokens
      if (cachedRefreshToken) {
        const newTokenInfo = await this.refreshToken(cachedRefreshToken);
        // Update session if available
        if (session && newTokenInfo.userInfo) {
          session.set('accessToken', newTokenInfo.accessToken);
          session.set('user', newTokenInfo.userInfo);
          await commitSession(session);
        }
        return newTokenInfo.userInfo || ({} as User);
      }
      
      // Fetch user info directly if no refresh token is available
      const userInfo = await this.fetchUserInfo(accessToken);
      const updatedTokenInfo = {
        ...tokenInfo,
        accessToken,
        userInfo,
        userInfoTimestamp: Date.now(),
      };
      
      // Update cache and session
      this.tokenCache.set(accessToken, updatedTokenInfo as TokenInfo);
      if (session) {
        session.set('user', userInfo);
        await commitSession(session);
      }
      return userInfo;
    } catch (error: any) {
      const errorMessage = error.response?.data?.error_description || error.message;
      throw new Error(`Failed to get user info: ${errorMessage}`);
    }
  }

  /**
   * Verifies if a session is valid
   * @param request - The request object containing session cookie
   * @returns true if session is valid, false otherwise
   */
  async verifySession(request: Request): Promise<boolean> {
    try {
      // Get session from request
      const session = await getSession(request.headers.get('Cookie'));
      const accessToken = session.get('accessToken');
      const user = session.get('user');
      
      // If no access token exists, session is invalid
      if (!accessToken) {
        return false;
      }
      
      // If we have both token and user, check/update cache
      if (accessToken && user) {
        if (!this.tokenCache.has(accessToken)) {
          // Add to cache if not present
          this.tokenCache.set(accessToken, {
            accessToken,
            userInfo: user as User,
            refreshToken: '',
            expiresAt: Date.now() + 3600 * 1000,
            userInfoTimestamp: Date.now(),
          });
        }
        return true;
      }
      
      // If we have token but no user, try to fetch user info
      try {
        const userInfo = await this.fetchUserInfo(accessToken);
        session.set('user', userInfo);
        await commitSession(session);
        return true;
      } catch (error) {
        // If fetching user info fails, session is invalid
        return false;
      }
    } catch (error) {
      return false;
    }
  }

  /**
   * Gets the access token from the session
   * @param request - The request object containing session cookie
   * @returns The access token
   * @throws Error if no access token is found
   */
  async getAccessToken(request: Request): Promise<string> {
    const session = await getSession(request.headers.get('Cookie'));
    const accessToken = session.get('accessToken');
    if (!accessToken) {
      throw new Error('No access token found');
    }
    return accessToken;
  }
}

// Export the singleton instance
export const auth0Service = Auth0Service.getInstance();