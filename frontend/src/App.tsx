import type { ReactElement } from 'react';
import { HashRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from '@/context/AuthContext';
import { HealthProvider } from '@/context/HealthContext';
import AppBar from '@/components/AppBar';
import Landing from '@/pages/Landing';
import Auth from '@/pages/Auth';
import Setup from '@/pages/Setup';
import Scanning from '@/pages/Scanning';
import Report from '@/pages/Report';
import History from '@/pages/History';
import Profile from '@/pages/Profile';
import Pricing from '@/pages/Pricing';

function RequireAuth({ children }: { children: ReactElement }) {
  const { token } = useAuth();
  if (!token) {
    return <Navigate to="/auth?mode=signup" replace />;
  }
  return children;
}

function Layout() {
  const location = useLocation();
  const showChrome = location.pathname !== '/auth';
  return (
    <>
      {showChrome && <AppBar />}
      <main className="main">
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/auth" element={<Auth />} />
          <Route path="/setup" element={<RequireAuth><Setup /></RequireAuth>} />
          <Route path="/scan" element={<RequireAuth><Scanning /></RequireAuth>} />
          <Route path="/report" element={<Report />} />
          <Route path="/history" element={<RequireAuth><History /></RequireAuth>} />
          <Route path="/profile" element={<RequireAuth><Profile /></RequireAuth>} />
          <Route path="/pricing" element={<Pricing />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </>
  );
}

export default function App() {
  return (
    <HealthProvider>
      <AuthProvider>
        <HashRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <Layout />
        </HashRouter>
      </AuthProvider>
    </HealthProvider>
  );
}