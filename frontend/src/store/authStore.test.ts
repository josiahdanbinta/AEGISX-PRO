import { describe, it, expect, beforeEach } from 'vitest';
import { useAuthStore } from './authStore';

describe('authStore', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: null,
      token: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: true,
    });
  });

  it('starts with default values', () => {
    const state = useAuthStore.getState();
    expect(state.user).toBeNull();
    expect(state.isAuthenticated).toBe(false);
    expect(state.isLoading).toBe(true);
  });

  it('setAuth updates state', () => {
    const user = {
      id: '1',
      email: 'test@test.com',
      full_name: 'Test',
      roles: ['admin'],
      tenant_id: '1',
      status: 'active' as const,
      mfa_enabled: false,
      created_at: '2024-01-01',
      last_login_at: null,
      department: null,
      title: null,
    };
    useAuthStore.getState().setAuth(user, 'token123', 'refresh456');
    const state = useAuthStore.getState();
    expect(state.user?.email).toBe('test@test.com');
    expect(state.token).toBe('token123');
    expect(state.isAuthenticated).toBe(true);
  });

  it('logout clears state', () => {
    useAuthStore.getState().setAuth(
      { id: '1', email: 'x', full_name: 'x', roles: [], tenant_id: '1', status: 'active' as const, mfa_enabled: false, created_at: '', last_login_at: null, department: null, title: null },
      't',
      'r',
    );
    useAuthStore.getState().logout();
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
    expect(useAuthStore.getState().token).toBeNull();
  });

  it('setUser updates user only', () => {
    useAuthStore.getState().setAuth(
      { id: '1', email: 'a@b.com', full_name: 'A', roles: [], tenant_id: '1', status: 'active' as const, mfa_enabled: false, created_at: '', last_login_at: null, department: null, title: null },
      't',
      'r',
    );
    const updated = { id: '2', email: 'b@c.com', full_name: 'B', roles: ['user'], tenant_id: '2', status: 'active' as const, mfa_enabled: true, created_at: '2024-02-02', last_login_at: null, department: null, title: null };
    useAuthStore.getState().setUser(updated);
    expect(useAuthStore.getState().user?.email).toBe('b@c.com');
    expect(useAuthStore.getState().token).toBe('t');
  });

  it('setToken updates token only', () => {
    useAuthStore.getState().setToken('new-token');
    expect(useAuthStore.getState().token).toBe('new-token');
  });

  it('setLoading updates loading flag', () => {
    useAuthStore.getState().setLoading(true);
    expect(useAuthStore.getState().isLoading).toBe(true);
    useAuthStore.getState().setLoading(false);
    expect(useAuthStore.getState().isLoading).toBe(false);
  });
});
