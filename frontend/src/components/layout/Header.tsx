import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search,
  Bell,
  User,
  LogOut,
  Settings,
  ChevronDown,
  Menu,
  RefreshCw,
  Sun,
  Moon,
} from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useTheme } from '@/contexts/ThemeContext';
import { useAuthStore } from '@/store/authStore';
import { useAppStore } from '@/store/appStore';

export function Header() {
  const { logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const user = useAuthStore((s) => s.user);
  const sidebarCollapsed = useAppStore((s) => s.sidebarCollapsed);

  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [notificationCount] = useState(3);

  const userMenuRef = useRef<HTMLDivElement>(null);
  const notifRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setShowUserMenu(false);
      }
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifications(false);
      }
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        const input = document.getElementById('global-search') as HTMLInputElement;
        input?.focus();
      }
    }
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  const initials = user?.full_name
    ? user.full_name
        .split(' ')
        .map((n) => n[0])
        .join('')
        .toUpperCase()
        .slice(0, 2)
    : 'UN';

  return (
    <header className="sticky top-0 z-30 h-16 bg-white/90 dark:bg-slate-950/90 backdrop-blur-xl border-b border-slate-200 dark:border-slate-800">
      <div className="flex items-center justify-between h-full px-4 lg:px-6 gap-3">
        <button
          className="p-2 rounded-lg text-slate-500 hover:text-slate-700 hover:bg-slate-100 dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-800 transition-colors lg:hidden"
          aria-label="Toggle sidebar"
        >
          <Menu className="w-5 h-5" strokeWidth={1.5} />
        </button>

        <div className="flex-1 flex justify-center lg:justify-start max-w-xl mx-auto lg:mx-0">
          <div className="relative w-full">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 dark:text-slate-500" strokeWidth={1.5} />
            <input
              id="global-search"
              type="text"
              placeholder="Search assets, incidents, threats..."
              className="w-full bg-slate-100 dark:bg-slate-800 border border-transparent rounded-xl pl-9 pr-20 py-2 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/30 focus:border-brand-500 transition-all"
            />
            <kbd className="absolute right-3 top-1/2 -translate-y-1/2 hidden sm:inline-flex items-center px-1.5 py-0.5 rounded-md text-xs font-medium text-slate-400 dark:text-slate-500 bg-slate-200 dark:bg-slate-700 border border-slate-300 dark:border-slate-600">
              Ctrl+K
            </kbd>
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button
            className="p-2 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 dark:text-slate-500 dark:hover:text-slate-300 dark:hover:bg-slate-800 transition-colors"
            aria-label="Refresh"
          >
            <RefreshCw className="w-5 h-5" strokeWidth={1.5} />
          </button>

          <div className="relative" ref={notifRef}>
            <button
              onClick={() => {
                setShowNotifications(!showNotifications);
                setShowUserMenu(false);
              }}
              className="relative p-2 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 dark:text-slate-500 dark:hover:text-slate-300 dark:hover:bg-slate-800 transition-colors"
              aria-label="Notifications"
            >
              <Bell className="w-5 h-5" strokeWidth={1.5} />
              {notificationCount > 0 && (
                <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-red-500 ring-2 ring-white dark:ring-slate-950" />
              )}
            </button>

            <AnimatePresence>
              {showNotifications && (
                <motion.div
                  initial={{ opacity: 0, y: -8, scale: 0.96 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -8, scale: 0.96 }}
                  transition={{ duration: 0.15 }}
                  className="absolute right-0 top-full mt-2 w-80 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl z-50 overflow-hidden"
                >
                  <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800">
                    <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">Notifications</span>
                  </div>
                  <div className="py-2 max-h-80 overflow-y-auto">
                    <div className="px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer transition-colors">
                      <p className="text-sm font-medium text-slate-900 dark:text-slate-100">Critical alert detected</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Suspicious login from new IP address</p>
                      <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">2 minutes ago</p>
                    </div>
                    <div className="px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer transition-colors">
                      <p className="text-sm font-medium text-slate-900 dark:text-slate-100">Scan completed</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Vulnerability scan finished for production</p>
                      <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">1 hour ago</p>
                    </div>
                    <div className="px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer transition-colors">
                      <p className="text-sm font-medium text-slate-900 dark:text-slate-100">Compliance report ready</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Monthly audit report is available for review</p>
                      <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">3 hours ago</p>
                    </div>
                  </div>
                  <div className="px-4 py-2.5 border-t border-slate-200 dark:border-slate-800">
                    <button className="text-xs font-medium text-brand-500 hover:text-brand-400 transition-colors">
                      View all notifications
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          <button
            onClick={toggleTheme}
            className="p-2 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 dark:text-slate-500 dark:hover:text-slate-300 dark:hover:bg-slate-800 transition-colors"
            aria-label="Toggle theme"
          >
            <AnimatePresence mode="wait" initial={false}>
              <motion.span
                key={theme}
                initial={{ opacity: 0, rotate: -90, scale: 0.5 }}
                animate={{ opacity: 1, rotate: 0, scale: 1 }}
                exit={{ opacity: 0, rotate: 90, scale: 0.5 }}
                transition={{ duration: 0.2 }}
                className="block"
              >
                {theme === 'dark' ? (
                  <Sun className="w-5 h-5" strokeWidth={1.5} />
                ) : (
                  <Moon className="w-5 h-5" strokeWidth={1.5} />
                )}
              </motion.span>
            </AnimatePresence>
          </button>

          <div className="relative" ref={userMenuRef}>
            <button
              onClick={() => {
                setShowUserMenu(!showUserMenu);
                setShowNotifications(false);
              }}
              className="flex items-center gap-2 p-1.5 rounded-lg text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            >
              <div className="w-8 h-8 rounded-full bg-brand-500 flex items-center justify-center text-xs font-semibold text-white flex-shrink-0">
                {initials}
              </div>
              <span className="text-sm font-medium hidden sm:block">{user?.full_name || 'User'}</span>
              <motion.span
                animate={{ rotate: showUserMenu ? 180 : 0 }}
                transition={{ duration: 0.2 }}
                className="hidden sm:block"
              >
                <ChevronDown className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" strokeWidth={1.5} />
              </motion.span>
            </button>

            <AnimatePresence>
              {showUserMenu && (
                <motion.div
                  initial={{ opacity: 0, y: -8, scale: 0.96 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -8, scale: 0.96 }}
                  transition={{ duration: 0.15 }}
                  className="absolute right-0 top-full mt-2 w-56 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl z-50 py-1.5"
                >
                  <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-800">
                    <div className="text-sm font-medium text-slate-900 dark:text-slate-100">
                      {user?.full_name || 'User'}
                    </div>
                    <div className="text-xs text-slate-500 dark:text-slate-400">{user?.email || ''}</div>
                  </div>
                  <button className="w-full flex items-center gap-2.5 px-4 py-2 text-sm text-slate-600 dark:text-slate-300 hover:text-slate-800 dark:hover:text-slate-100 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors">
                    <User className="w-4 h-4" strokeWidth={1.5} />
                    Profile
                  </button>
                  <button className="w-full flex items-center gap-2.5 px-4 py-2 text-sm text-slate-600 dark:text-slate-300 hover:text-slate-800 dark:hover:text-slate-100 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors">
                    <Settings className="w-4 h-4" strokeWidth={1.5} />
                    Settings
                  </button>
                  <div className="border-t border-slate-200 dark:border-slate-800 my-1" />
                  <button
                    onClick={() => logout()}
                    className="w-full flex items-center gap-2.5 px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors"
                  >
                    <LogOut className="w-4 h-4" strokeWidth={1.5} />
                    Sign Out
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </header>
  );
}
