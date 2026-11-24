import { Component, lazy, Suspense, useEffect, type ReactElement, type ReactNode } from 'react';
import { HashRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from '@/context/AuthContext';
import { HealthProvider } from '@/context/HealthContext';
import AppBar from '@/components/AppBar';

// Route splitting: each page is its own chunk, so the initial load does not download Report,
// History or Profile code. The vendor split lives in vite.config.ts.
const Landing = lazy(() => import('@/pages/Landing'));
const Auth = lazy(() => import('@/pages/Auth'));
const Setup = lazy(() => import('@/pages/Setup'));
const Scanning = lazy(() => import('@/pages/Scanning'));
const Report = lazy(() => import('@/pages/Report'));
const History = lazy(() => import('@/pages/History'));
const Profile = lazy(() => import('@/pages/Profile'));
const Pricing = lazy(() => import('@/pages/Pricing'));

function RequireAuth({ children }: { children: ReactElement }) {
  const { token } = useAuth();
  if (!token) {
    return <Navigate to="/auth?mode=signup" replace />;
  }
  return children;
}

/** Move keyboard/screen-reader focus to the new page's heading on route changes. */
function RouteFocus() {
  const location = useLocation();
  useEffect(() => {
    const root = document.querySelector('main');
    if (!root) return;
    const heading = root.querySelector<HTMLElement>('h1, h2, h3');
    if (heading) {
      heading.tabIndex = -1;
      heading.focus({ preventScroll: true });
    }
  }, [location.pathname]);
  return null;
}

/** A failed lazy chunk (usually a new deploy) should offer a reload, not a blank page. */
class RouteErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    if (this.state.failed) {
      return (
        <div className="view" id="view-route-error">
          <div className="card">
            <div className="warn-banner">
              This page failed to load. A new build may be available.{' '}
              <button className="btn btn-xs" onClick={() => window.location.reload()}>Reload</button>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function Layout() {
  const location = useLocation();
  const showChrome = location.pathname !== '/auth';
  return (
    <>
      {showChrome && <AppBar />}
      <main className="main">
        <RouteFocus />
        <Suspense
          fallback={(
            <div className="view" role="status" aria-live="polite">
              <div className="card"><div className="scope-empty">Loading…</div></div>
            </div>
          )}
        >
          <RouteErrorBoundary key={location.pathname}>
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
          </RouteErrorBoundary>
        </Suspense>
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
