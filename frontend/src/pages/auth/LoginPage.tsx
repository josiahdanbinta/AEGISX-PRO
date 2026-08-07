import { useState, type FormEvent } from 'react';
import { Shield, Eye, EyeOff, Sun, Moon } from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/AuthContext';
import { useTheme } from '@/contexts/ThemeContext';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import toast from 'react-hot-toast';

export function LoginPage() {
  const { login } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [tenantId, setTenantId] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      await login(email, password, tenantId || undefined);
      toast.success('Welcome back!');
    } catch (err: unknown) {
      const error = err as { mfaRequired?: boolean; error?: { message?: string } };
      if (error?.mfaRequired) {
        toast('MFA verification required', { icon: '\uD83D\uDD10' });
      } else {
        toast.error(error?.error?.message || 'Login failed. Please check your credentials.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-blue-50 to-slate-100 dark:from-slate-950 dark:via-slate-900 dark:to-slate-950 p-4">
      {/* Decorative dots */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 left-[10%] w-64 h-64 bg-brand-500/5 dark:bg-brand-500/3 rounded-full blur-3xl" />
        <div className="absolute bottom-20 right-[10%] w-96 h-96 bg-cyan-500/5 dark:bg-cyan-500/3 rounded-full blur-3xl" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md relative z-10"
      >
        {/* Logo */}
        <div className="text-center mb-8">
          <motion.div
            initial={{ scale: 0.8 }}
            animate={{ scale: 1 }}
            transition={{ duration: 0.4, delay: 0.1 }}
            className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-brand-600 to-blue-400 mb-4 shadow-lg shadow-brand-500/25"
          >
            <Shield className="w-8 h-8 text-white" />
          </motion.div>
          <h1 className="text-2xl font-bold tracking-tight">
            <span className="text-slate-900 dark:text-white">AEGIS</span>
            <span className="text-brand-600 dark:text-brand-400">X</span>
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-2">Enterprise Cybersecurity Platform</p>
        </div>

        {/* Login Card */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xl p-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-6">Sign in to your account</h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            <Input
              label="Tenant ID"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              placeholder="Optional — your tenant identifier"
            />
            <Input
              label="Email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              required
              autoComplete="username"
            />
            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  autoComplete="current-password"
                  className="w-full bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg px-3.5 py-2.5 pr-10 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 transition-all"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <Button type="submit" loading={isLoading} className="w-full">Sign In</Button>
          </form>

          <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-800">
            <p className="text-xs text-center text-slate-500">
              Forgot your password? Contact your administrator.
            </p>
          </div>
        </div>

        <p className="text-center text-xs text-slate-400 dark:text-slate-600 mt-6">
          AEGISX Platform v2.0.0 — Protected by industry-standard encryption
        </p>

        {/* Theme Toggle */}
        <div className="flex justify-center mt-4">
          <button
            onClick={toggleTheme}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 shadow-sm transition-colors"
          >
            {theme === 'light' ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4" />}
            <span className="text-xs font-medium">{theme === 'light' ? 'Dark Mode' : 'Light Mode'}</span>
          </button>
        </div>
      </motion.div>
    </div>
  );
}
