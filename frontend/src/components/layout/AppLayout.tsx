import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';

export function AppLayout({ children }: { children?: React.ReactNode }) {
  return (
    <div className="min-h-screen" style={{ background: '#0F1419' }}>
      <Sidebar />
      <main className="pl-[248px] min-h-screen">
        <div className="p-5">
          {children || <Outlet />}
        </div>
      </main>
    </div>
  );
}
