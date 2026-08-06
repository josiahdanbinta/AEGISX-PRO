import { createContext, useContext, useEffect, type ReactNode } from 'react';
import { useAuthStore } from '@/store/authStore';
import { authService } from '@/services/auth';

interface AuthContextType {
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string, tenantId?: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const { isAuthenticated, isLoading, token, setAuth, logout: storeLogout, setLoading } =
    useAuthStore();

  useEffect(() => {
    const initAuth = async () => {
      if (token) {
        try {
          const user = await authService.getMe();
          setAuth(user, token, useAuthStore.getState().refreshToken || '');
        } catch {
          storeLogout();
        }
      }
      setLoading(false);
    };
    initAuth();
  }, []);

  const login = async (email: string, password: string, tenantId?: string) => {
    setLoading(true);
    try {
      const res = await authService.login({ email, password, tenant_id: tenantId });
      if (res.requires_mfa) {
        setLoading(false);
        throw { mfaRequired: true, mfa_session_token: res.mfa_session_token };
      }
      const user = await authService.getMe();
      setAuth(user, res.access_token, res.refresh_token);
    } catch (err) {
      setLoading(false);
      throw err;
    }
  };

  const logout = async () => {
    try {
      await authService.logout();
    } catch {
      // Continue with local logout even if API fails
    }
    storeLogout();
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, isLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
