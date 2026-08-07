import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface AppState {
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  selectedTenantId: string | null;
  setSelectedTenant: (tenantId: string) => void;
}

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
      selectedTenantId: null,
      setSelectedTenant: (selectedTenantId) => set({ selectedTenantId }),
    }),
    {
      name: 'AEGIS-app',
      partialize: (state) => ({
        sidebarCollapsed: state.sidebarCollapsed,
        selectedTenantId: state.selectedTenantId,
      }),
    },
  ),
);
