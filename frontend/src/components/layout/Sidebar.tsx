import { NavLink } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard, Monitor, Shield, AlertTriangle, Workflow,
  Globe, Bug, ClipboardCheck, FileText, Download,
  Users, Building2, ScrollText, Settings, ChevronLeft, ChevronRight,
  Radio, Crosshair, Activity,
} from 'lucide-react';
import { useAppStore } from '@/store/appStore';
import { useAuthStore } from '@/store/authStore';

interface NavSection {
  title: string;
  items: { to: string; icon: any; label: string }[];
}

const navSections: NavSection[] = [
  {
    title: 'Overview',
    items: [
      { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/soc', icon: Activity, label: 'SOC Overview' },
    ],
  },
  {
    title: 'Operations',
    items: [
      { to: '/agents', icon: Monitor, label: 'Agents' },
      { to: '/incidents', icon: Shield, label: 'Incidents' },
      { to: '/detection', icon: AlertTriangle, label: 'Detection' },
      { to: '/detection/live', icon: Radio, label: 'Live Alerts' },
      { to: '/threat-hunting', icon: Crosshair, label: 'Hunting' },
      { to: '/soar', icon: Workflow, label: 'SOAR' },
    ],
  },
  {
    title: 'Intelligence',
    items: [
      { to: '/threat-intel', icon: Globe, label: 'Threat Intel' },
      { to: '/vulnerabilities', icon: Bug, label: 'Vulnerabilities' },
      { to: '/compliance', icon: ClipboardCheck, label: 'Compliance' },
    ],
  },
  {
    title: 'Admin',
    items: [
      { to: '/reports', icon: FileText, label: 'Reports' },
      { to: '/deploy', icon: Download, label: 'Deploy Agent' },
      { to: '/admin/users', icon: Users, label: 'Users' },
      { to: '/admin/tenants', icon: Building2, label: 'Tenants' },
      { to: '/admin/audit', icon: ScrollText, label: 'Audit' },
      { to: '/settings', icon: Settings, label: 'Settings' },
    ],
  },
];

export function Sidebar() {
  const sidebarCollapsed = useAppStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useAppStore((s) => s.toggleSidebar);
  const user = useAuthStore((s) => s.user);

  return (
    <motion.aside
      animate={{ width: sidebarCollapsed ? 72 : 248 }}
      transition={{ duration: 0.25, ease: 'easeInOut' }}
      className="fixed left-0 top-0 h-full border-r border-surface-border z-40 flex flex-col overflow-hidden"
      style={{ background: '#0D1217' }}
    >
      {/* Logo */}
      <div className="flex items-center h-14 px-4 border-b border-surface-border">
        <AnimatePresence mode="wait">
          {!sidebarCollapsed ? (
            <motion.div key="full" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="flex items-center gap-2.5 flex-1">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-brand-400 to-brand-600 flex items-center justify-center shadow-glow-sm">
                <Shield className="w-4.5 h-4.5 text-white" strokeWidth={1.5} />
              </div>
              <span className="font-bold text-base tracking-tight">
                <span className="text-white">AEGIS</span>
              </span>
            </motion.div>
          ) : (
            <motion.div key="mini" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="w-8 h-8 rounded-lg bg-gradient-to-br from-brand-400 to-brand-600 flex items-center justify-center mx-auto shadow-glow-sm">
              <Shield className="w-4.5 h-4.5 text-white" strokeWidth={1.5} />
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-2.5 space-y-4">
        {navSections.map((section) => (
          <div key={section.title}>
            <div className={`text-[10px] font-semibold text-gray-500 uppercase tracking-widest mb-1.5 ${sidebarCollapsed ? 'text-center' : 'px-2.5'}`}>
              {sidebarCollapsed ? section.title.charAt(0) : section.title}
            </div>
            <div className="space-y-0.5">
              {section.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                      sidebarCollapsed ? 'justify-center px-0 py-2.5' : 'px-2.5 py-2'
                    } ${
                      isActive
                        ? 'bg-brand-500/15 text-brand-400 shadow-glow-sm'
                        : 'text-gray-400 hover:text-gray-200 hover:bg-surface-hover'
                    }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      {isActive && (
                        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-brand-400 rounded-r-full animate-pulse-soft" />
                      )}
                      <item.icon className="w-4.5 h-4.5 flex-shrink-0" strokeWidth={1.5} />
                      {!sidebarCollapsed && (
                        <motion.span initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -4 }} className="truncate">
                          {item.label}
                        </motion.span>
                      )}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* User */}
      <div className="border-t border-surface-border p-2.5">
        <div className={`flex items-center gap-2.5 ${sidebarCollapsed ? 'justify-center' : ''}`}>
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-brand-400 to-brand-600 flex items-center justify-center flex-shrink-0">
            <span className="text-[10px] font-semibold text-white">
              {user?.full_name?.split(' ').map((n: string) => n[0]).join('').toUpperCase().slice(0, 2) || 'UN'}
            </span>
          </div>
          {!sidebarCollapsed && (
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-gray-200 truncate">{user?.full_name || 'User'}</p>
              <p className="text-[10px] text-gray-500 truncate">{user?.email || ''}</p>
            </div>
          )}
          <button onClick={toggleSidebar} className="p-1 rounded-lg text-gray-500 hover:text-gray-300 hover:bg-surface-hover transition-colors flex-shrink-0">
            <motion.span animate={{ rotate: sidebarCollapsed ? 180 : 0 }} className="block">
              {sidebarCollapsed ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronLeft className="w-3.5 h-3.5" />}
            </motion.span>
          </button>
        </div>
      </div>
    </motion.aside>
  );
}
