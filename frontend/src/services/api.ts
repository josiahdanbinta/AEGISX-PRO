import { useAuthStore } from '@/store/authStore';
import { useAppStore } from '@/store/appStore';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

function decodeJwtPayload(token: string): Record<string, unknown> {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(base64));
  } catch {
    return {};
  }
}

function getEffectiveTenantId(): string | null {
  const appTenant = useAppStore.getState().selectedTenantId;
  if (appTenant) return appTenant;
  const token = useAuthStore.getState().token;
  if (!token) return null;
  const payload = decodeJwtPayload(token);
  const tid = payload.tenant_id as string | undefined;
  if (tid) {
    useAppStore.getState().setSelectedTenant(tid);
    return tid;
  }
  return null;
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
  params?: Record<string, string>;
  tenantId?: string;
}

let isRefreshing = false;
let refreshSubscribers: ((token: string) => void)[] = [];

function onTokenRefreshed(token: string) {
  refreshSubscribers.forEach((cb) => cb(token));
  refreshSubscribers = [];
}

function addRefreshSubscriber(cb: (token: string) => void) {
  refreshSubscribers.push(cb);
}

async function refreshAccessToken(): Promise<string | null> {
  const { refreshToken } = useAuthStore.getState();
  if (!refreshToken) return null;

  try {
    const res = await fetch(`${BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) return null;
    const data = await res.json();
    useAuthStore.getState().setToken(data.access_token);
    return data.access_token;
  } catch {
    return null;
  }
}

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, headers = {}, params, tenantId } = options;
  const { token } = useAuthStore.getState();

  let path = `${BASE_URL}${endpoint}`;
  const qIdx = path.indexOf('?');
  const base = qIdx > -1 ? path.substring(0, qIdx) : path;
  const qs = qIdx > -1 ? path.substring(qIdx) : '';
  if (!base.endsWith('/')) path = base + '/' + qs;
  const url = new URL(path, window.location.origin);
  if (params) {
    Object.entries(params).forEach(([k, v]) => url.searchParams.append(k, v));
  }

  const reqHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    ...headers,
  };

  if (token) {
    reqHeaders['Authorization'] = `Bearer ${token}`;
  }

  const effectiveTenantId = tenantId || getEffectiveTenantId();
  if (effectiveTenantId) {
    reqHeaders['X-Tenant-ID'] = effectiveTenantId;
  }

  // For absolute URLs (Vercel -> remote backend), use the URL directly
  const isAbsolute = BASE_URL.startsWith('http');
  const fetchUrl = isAbsolute ? url.toString() : url.toString();

  const res = await fetch(fetchUrl, {
    method,
    headers: reqHeaders,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (res.status === 401 && token) {
    if (!isRefreshing) {
      isRefreshing = true;
      const newToken = await refreshAccessToken();
      isRefreshing = false;

      if (newToken) {
        onTokenRefreshed(newToken);
        reqHeaders['Authorization'] = `Bearer ${newToken}`;
        const retryRes = await fetch(fetchUrl, {
          method,
          headers: reqHeaders,
          body: body ? JSON.stringify(body) : undefined,
        });
        if (!retryRes.ok) {
          const err = await retryRes.json().catch(() => ({}));
          throw { status: retryRes.status, ...err };
        }
        return retryRes.json();
      } else {
        useAuthStore.getState().logout();
        throw { status: 401, error: { code: 'AUTH_EXPIRED', message: 'Session expired' } };
      }
    } else {
      return new Promise((resolve) => {
        addRefreshSubscriber((newToken: string) => {
          reqHeaders['Authorization'] = `Bearer ${newToken}`;
          fetch(fetchUrl, {
            method,
            headers: reqHeaders,
            body: body ? JSON.stringify(body) : undefined,
          })
            .then((r) => r.json())
            .then(resolve);
        });
      });
    }
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw { status: res.status, ...err };
  }

  if (res.status === 204) return {} as T;
  return res.json();
}

export const api = {
  get: <T>(endpoint: string, options?: RequestOptions) =>
    request<T>(endpoint, { ...options, method: 'GET' }),
  post: <T>(endpoint: string, body?: unknown, options?: RequestOptions) =>
    request<T>(endpoint, { ...options, method: 'POST', body }),
  put: <T>(endpoint: string, body?: unknown, options?: RequestOptions) =>
    request<T>(endpoint, { ...options, method: 'PUT', body }),
  patch: <T>(endpoint: string, body?: unknown, options?: RequestOptions) =>
    request<T>(endpoint, { ...options, method: 'PATCH', body }),
  delete: <T>(endpoint: string, options?: RequestOptions) =>
    request<T>(endpoint, { ...options, method: 'DELETE' }),
};
