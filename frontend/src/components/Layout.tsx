import { Link, Outlet, useLocation } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { docsApi } from '../services/api';
import { useBackend } from '../contexts/BackendContext';
import type { ApiMode, ApiStats } from '../types';

export default function Layout() {
  const location = useLocation();
  const { backend, setBackend, backends } = useBackend();
  const [mode, setMode] = useState<ApiMode | null>(null);
  const [stats, setStats] = useState<ApiStats | null>(null);
  const [backendStatus, setBackendStatus] = useState<'online' | 'offline' | 'checking'>('checking');

  // Check backend status and load data when backend changes
  useEffect(() => {
    setBackendStatus('checking');
    setMode(null);
    setStats(null);

    docsApi.getMode()
      .then((data) => {
        setMode(data);
        setBackendStatus('online');
      })
      .catch(() => {
        setBackendStatus('offline');
      });

    docsApi.getStats()
      .then(setStats)
      .catch(console.error);
  }, [backend]);

  const navItems = [
    { path: '/', label: 'Dashboard', icon: '📊' },
    { path: '/challenges', label: 'Challenges', icon: '🎯' },
    { path: '/console', label: 'API Console', icon: '💻' },
    { path: '/graphql', label: 'GraphQL', icon: '◈' },
  ];

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside className="w-64 bg-slate-800 border-r border-slate-700 flex flex-col">
        {/* Logo */}
        <div className="p-4 border-b border-slate-700">
          <Link to="/" className="flex items-center gap-2">
            <span className="text-2xl">🔓</span>
            <div>
              <h1 className="text-xl font-bold text-red-500">VulnAPI</h1>
              <p className="text-xs text-slate-400">Security Learning Platform</p>
            </div>
          </Link>
        </div>

        {/* Backend selector */}
        <div className="p-4 border-b border-slate-700">
          <label className="block text-xs uppercase text-slate-500 mb-2">Backend</label>
          <div className="space-y-1">
            {backends.map((b) => (
              <button
                key={b.id}
                onClick={() => setBackend(b)}
                className={`w-full flex items-center gap-2 px-3 py-2 rounded text-sm text-left transition-colors ${
                  backend.id === b.id
                    ? 'bg-red-600 text-white'
                    : 'bg-slate-700/50 text-slate-300 hover:bg-slate-700'
                }`}
              >
                <span>{b.icon}</span>
                <span className="flex-1">{b.name}</span>
                <span className="text-xs opacity-60">{b.language}</span>
              </button>
            ))}
          </div>
          {/* Status indicator */}
          <div className="mt-2 flex items-center gap-2 text-xs">
            <span className={`w-2 h-2 rounded-full ${
              backendStatus === 'online' ? 'bg-green-500' :
              backendStatus === 'offline' ? 'bg-red-500' : 'bg-yellow-500 animate-pulse'
            }`} />
            <span className="text-slate-400">
              {backendStatus === 'online' ? `Connected to ${backend.baseUrl}` :
               backendStatus === 'offline' ? 'Backend offline' : 'Connecting...'}
            </span>
          </div>
        </div>

        {/* Mode indicator */}
        {mode && (
          <div className="p-4 border-b border-slate-700">
            <div className={`px-3 py-2 rounded text-sm ${
              mode.mode === 'documentation'
                ? 'bg-green-900/50 text-green-400 border border-green-700'
                : 'bg-yellow-900/50 text-yellow-400 border border-yellow-700'
            }`}>
              <span className="font-semibold">
                {mode.mode === 'documentation' ? '📖 Docs Mode' : '🎮 Challenge Mode'}
              </span>
            </div>
          </div>
        )}

        {/* Navigation */}
        <nav className="flex-1 p-4">
          <ul className="space-y-2">
            {navItems.map((item) => (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={`flex items-center gap-3 px-3 py-2 rounded transition-colors ${
                    location.pathname === item.path
                      ? 'bg-red-600 text-white'
                      : 'text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  <span>{item.icon}</span>
                  <span>{item.label}</span>
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        {/* Stats */}
        {stats && (
          <div className="p-4 border-t border-slate-700">
            <h3 className="text-xs uppercase text-slate-500 mb-2">Statistics</h3>
            <div className="grid grid-cols-2 gap-2 text-sm">
              <div className="bg-slate-700/50 rounded p-2 text-center">
                <div className="text-xl font-bold text-red-400">{stats.total}</div>
                <div className="text-xs text-slate-400">Vulns</div>
              </div>
              <div className="bg-slate-700/50 rounded p-2 text-center">
                <div className="text-xl font-bold text-orange-400">{stats.by_severity.critical || 0}</div>
                <div className="text-xs text-slate-400">Critical</div>
              </div>
              <div className="bg-slate-700/50 rounded p-2 text-center">
                <div className="text-xl font-bold text-blue-400">{stats.rest_api}</div>
                <div className="text-xs text-slate-400">REST</div>
              </div>
              <div className="bg-slate-700/50 rounded p-2 text-center">
                <div className="text-xl font-bold text-purple-400">{stats.graphql}</div>
                <div className="text-xs text-slate-400">GraphQL</div>
              </div>
            </div>
          </div>
        )}
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
