import { describe, it, expect, beforeEach } from 'vitest';
import { useAppStore } from './appStore';

describe('appStore', () => {
  beforeEach(() => {
    useAppStore.setState({
      sidebarCollapsed: false,
      selectedTenantId: null,
    });
  });

  it('starts with sidebar expanded', () => {
    expect(useAppStore.getState().sidebarCollapsed).toBe(false);
  });

  it('toggleSidebar switches state', () => {
    const store = useAppStore.getState();
    store.toggleSidebar();
    expect(useAppStore.getState().sidebarCollapsed).toBe(true);
    store.toggleSidebar();
    expect(useAppStore.getState().sidebarCollapsed).toBe(false);
  });

  it('setSidebarCollapsed sets explicitly', () => {
    useAppStore.getState().setSidebarCollapsed(true);
    expect(useAppStore.getState().sidebarCollapsed).toBe(true);
  });

  it('setSelectedTenant updates tenant ID', () => {
    useAppStore.getState().setSelectedTenant('tenant-123');
    expect(useAppStore.getState().selectedTenantId).toBe('tenant-123');
  });
});
