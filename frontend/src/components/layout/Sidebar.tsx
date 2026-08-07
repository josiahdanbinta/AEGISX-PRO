import { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard,
  Monitor,
  Shield,
  AlertTriangle,
  Workflow,
  Globe,
  Bug,
  ClipboardCheck,
  FileText,
  Bell,
  Download,
  Users,
  Building2,
  ScrollText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Radio,
  Crosshair,
  type LucideIcon,
} from 'lucide-react';
import { useAppStore } from '@/store/appStore';
import { useAuthStore } from '@/store/authStore';

interface NavSection {
  title: string;
  items: { to: string; icon: LucideIcon; label: string }[];
}

const navSections: NavSection[] = [
  {
    title: 'MAIN',
    items: [
      { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/assets', icon: Monitor, label: 'Assets' },
      { to: '/agents', icon: Monitor, label: 'Agents' },
      { to: '/incidents', icon: Shield, label: 'Incidents' },
      { to: '/detection', icon: AlertTriangle, label: 'Detection' },
      { to: '/detection/live', icon: Radio, label: 'Live Alerts' },
      { to: '/threat-hunting', icon: Crosshair, label: 'Threat Hunting' },
      { to: '/soar', icon: Workflow, label: 'SOAR' },
    ],
  },
  {
    title: 'INTELLIGENCE',
    items: [
      { to: '/threat-intel', icon: Globe, label: 'Threat Intel' },
      { to: '/vulnerabilities', icon: Bug, label: 'Vulnerabilities' },
      { to: '/compliance', icon: ClipboardCheck, label: 'Compliance' },
    ],
  },
  {
    title: 'OPERATIONS',
    items: [
      { to: '/reports', icon: FileText, label: 'Reports' },
      { to: '/notifications', icon: Bell, label: 'Notifications' },
      { to: '/deploy', icon: Download, label: 'Deploy Agent' },
    ],
  },
  {
    title: 'ADMIN',
    items: [
      { to: '/admin/users', icon: Users, label: 'Users' },
      { to: '/admin/tenants', icon: Building2, label: 'Tenants' },
      { to: '/admin/audit', icon: ScrollText, label: 'Audit Logs' },
      { to: '/settings', icon: Settings, label: 'Settings' },
    ],
  },
];

export function Sidebar() {
  const sidebarCollapsed = useAppStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useAppStore((s) => s.toggleSidebar);
  const user = useAuthStore((s) => s.user);

  const initials = user?.full_name
    ? user.full_name
        .split(' ')
        .map((n) => n[0])
        .join('')
        .toUpperCase()
        .slice(0, 2)
    : 'UN';

  return (
    <motion.aside
      animate={{ width: sidebarCollapsed ? 80 : 256 }}
      transition={{ duration: 0.3, ease: 'easeInOut' }}
      className="fixed left-0 top-0 h-full bg-slate-900 dark:bg-slate-950 border-r border-slate-800 z-40 flex flex-col overflow-hidden"
    >
      <div className="flex items-center h-16 px-4 border-b border-slate-800">
        <AnimatePresence mode="wait">
          {!sidebarCollapsed ? (
            <motion.div
              key="expanded"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
              className="flex items-center gap-3 flex-1"
            >
              <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-brand-500 to-brand-400 flex items-center justify-center flex-shrink-0">
                <Shield className="w-5 h-5 text-white" strokeWidth={1.5} />
              </div>
              <span className="font-bold text-lg tracking-tight">
                <span className="text-white">AEGIS</span>
                <span className="text-brand-400">X</span>
              </span>
            </motion.div>
          ) : (
            <motion.div
              key="collapsed"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
              className="w-9 h-9 rounded-lg bg-gradient-to-br from-brand-500 to-brand-400 flex items-center justify-center mx-auto flex-shrink-0"
            >
              <Shield className="w-5 h-5 text-white" strokeWidth={1.5} />
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-5">
        {navSections.map((section) => (
          <div key={section.title}>
            <div
              className={`text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1.5 ${
                sidebarCollapsed ? 'text-center' : 'px-3'
              }`}
            >
              {sidebarCollapsed ? section.title.charAt(0) : section.title}
            </div>
            <div className="space-y-0.5">
              {section.items.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    aria-label={sidebarCollapsed ? item.label : undefined}
                    className={({ isActive }) =>
                      `flex items-center gap-3 rounded-lg text-sm font-medium transition-colors duration-150 relative focus:outline-none focus:ring-2 focus:ring-brand-500/40 ${
                        sidebarCollapsed ? 'justify-center px-0 py-2.5' : 'px-3 py-2.5'
                      } ${
                        isActive
                          ? 'bg-brand-600/20 text-brand-400'
                          : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                      }`
                    }
                  >
                  {({ isActive }) => (
                    <>
                      {isActive && (
                        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-6 bg-brand-500 rounded-r-full" />
                      )}
                      <item.icon className="w-5 h-5 flex-shrink-0" strokeWidth={1.5} />
                      <AnimatePresence mode="wait">
                        {!sidebarCollapsed && (
                          <motion.span
                            key="label"
                            initial={{ opacity: 0, x: -4 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: -4 }}
                            transition={{ duration: 0.15 }}
                          >
                            {item.label}
                          </motion.span>
                        )}
                      </AnimatePresence>
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="border-t border-slate-800 p-3">
        <div className={`flex items-center gap-3 ${sidebarCollapsed ? 'justify-center' : ''}`}>
          <div className="w-8 h-8 rounded-full bg-brand-500 flex items-center justify-center flex-shrink-0">
            <span className="text-xs font-semibold text-white">{initials}</span>
          </div>
          <AnimatePresence mode="wait">
            {!sidebarCollapsed && (
              <motion.div
                key="user-info"
                initial={{ opacity: 0, x: -4 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -4 }}
                transition={{ duration: 0.15 }}
                className="flex-1 min-w-0"
              >
                <p className="text-sm font-medium text-slate-200 truncate">
                  {user?.full_name || 'User'}
                </p>
                <p className="text-xs text-slate-500 truncate">{user?.email || ''}</p>
              </motion.div>
            )}
          </AnimatePresence>
          <button
            onClick={toggleSidebar}
            className="flex-shrink-0 p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <motion.span
              animate={{ rotate: sidebarCollapsed ? 180 : 0 }}
              transition={{ duration: 0.3, ease: 'easeInOut' }}
              className="block"
            >
              {sidebarCollapsed ? (
                <ChevronRight className="w-4 h-4" strokeWidth={1.5} />
              ) : (
                <ChevronLeft className="w-4 h-4" strokeWidth={1.5} />
              )}
            </motion.span>
          </button>
        </div>
      </div>
    </motion.aside>
  );
}
