import { api } from './api';
import type { User, ApiResponse } from '@/types';

interface LoginPayload {
  email: string;
  password: string;
  tenant_id?: string;
}

interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  requires_mfa: boolean;
  mfa_session_token?: string;
}

interface MFAVerifyPayload {
  session_token: string;
  code: string;
}

interface PasswordResetRequest {
  email: string;
}

interface PasswordChangePayload {
  current_password: string;
  new_password: string;
  confirm_password: string;
}

export const authService = {
  login: (data: LoginPayload) => api.post<LoginResponse>('/auth/login', data),

  refresh: (refreshToken: string) =>
    api.post<LoginResponse>('/auth/refresh', { refresh_token: refreshToken }),

  logout: () => api.post<ApiResponse<null>>('/auth/logout'),

  getMe: () => api.get<User>('/auth/me'),

  verifyMFA: (data: MFAVerifyPayload) => api.post<LoginResponse>('/auth/mfa/verify', data),

  setupMFA: () => api.post<{ secret: string; qr_code_uri: string; backup_codes: string[] }>('/auth/mfa/setup'),

  enableMFA: (code: string) => api.post<ApiResponse<null>>('/auth/mfa/enable', { code }),

  disableMFA: (password: string) => api.post<ApiResponse<null>>('/auth/mfa/disable', { password }),

  requestPasswordReset: (data: PasswordResetRequest) =>
    api.post<ApiResponse<null>>('/auth/password/reset-request', data),

  changePassword: (data: PasswordChangePayload) =>
    api.post<ApiResponse<null>>('/auth/password/change', data),

  generateApiKey: (name: string, scopes: string[] = ['api']) =>
    api.post<{ id: string; api_key: string; prefix: string }>('/auth/api-key/generate', { name, scopes }),

  listApiKeys: () => api.get<{ id: string; name: string; prefix: string; last_used_at: string | null }[]>('/auth/api-key/list'),

  revokeApiKey: (keyId: string) => api.delete<ApiResponse<null>>(`/auth/api-key/${keyId}`),
};
