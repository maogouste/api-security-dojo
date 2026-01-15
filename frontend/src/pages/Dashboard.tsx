import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { docsApi } from '../services/api';
import type { ApiStats, Category } from '../types';

export default function Dashboard() {
  const [stats, setStats] = useState<ApiStats | null>(null);
  const [categories, setCategories] = useState<Category[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([docsApi.getStats(), docsApi.getCategories()])
      .then(([statsData, categoriesData]) => {
        setStats(statsData);
        setCategories(categoriesData);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center">
        <div className="text-slate-400">Loading...</div>
      </div>
    );
  }

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">Welcome to VulnAPI</h1>
        <p className="text-slate-400">
          Learn API security by exploiting intentional vulnerabilities.
        </p>
      </div>

      {/* Warning banner */}
      <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 mb-8">
        <div className="flex items-center gap-3">
          <span className="text-2xl">⚠️</span>
          <div>
            <h3 className="font-bold text-red-400">Educational Purpose Only</h3>
            <p className="text-sm text-slate-300">
              This API contains intentional security vulnerabilities. Never deploy in production
              or use these techniques against systems without authorization.
            </p>
          </div>
        </div>
      </div>

      {/* Stats overview */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <div className="text-4xl font-bold text-red-500 mb-2">{stats.total}</div>
            <div className="text-slate-400">Total Vulnerabilities</div>
          </div>
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <div className="text-4xl font-bold text-orange-500 mb-2">
              {(stats.by_severity.critical || 0) + (stats.by_severity.high || 0)}
            </div>
            <div className="text-slate-400">Critical & High</div>
          </div>
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <div className="text-4xl font-bold text-blue-500 mb-2">{stats.rest_api}</div>
            <div className="text-slate-400">REST API (V01-V10)</div>
          </div>
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <div className="text-4xl font-bold text-purple-500 mb-2">{stats.graphql}</div>
            <div className="text-slate-400">GraphQL (G01-G05)</div>
          </div>
        </div>
      )}

      {/* Severity breakdown */}
      {stats && (
        <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-8">
          <h2 className="text-xl font-bold mb-4">Severity Breakdown</h2>
          <div className="flex gap-4">
            {Object.entries(stats.by_severity).map(([severity, count]) => (
              <div key={severity} className="flex items-center gap-2">
                <span
                  className={`px-3 py-1 rounded text-sm font-bold ${
                    severity === 'critical'
                      ? 'bg-red-600'
                      : severity === 'high'
                      ? 'bg-orange-500'
                      : severity === 'medium'
                      ? 'bg-yellow-500 text-black'
                      : 'bg-blue-500'
                  }`}
                >
                  {severity.toUpperCase()}
                </span>
                <span className="text-slate-300">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Categories */}
      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
        <h2 className="text-xl font-bold mb-4">Categories</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {categories.map((category) => (
            <Link
              key={category.name}
              to={`/challenges?category=${category.name}`}
              className="bg-slate-700/50 rounded-lg p-4 hover:bg-slate-700 transition-colors"
            >
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-semibold capitalize">{category.name}</h3>
                <span className="bg-slate-600 px-2 py-1 rounded text-sm">
                  {category.count}
                </span>
              </div>
              <div className="text-sm text-slate-400">
                {category.vulnerabilities.join(', ')}
              </div>
            </Link>
          ))}
        </div>
      </div>

      {/* Quick start */}
      <div className="mt-8 bg-slate-800 rounded-lg p-6 border border-slate-700">
        <h2 className="text-xl font-bold mb-4">Quick Start</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Link
            to="/challenges"
            className="bg-red-600 hover:bg-red-700 rounded-lg p-4 text-center transition-colors"
          >
            <span className="text-2xl block mb-2">🎯</span>
            <span className="font-semibold">Start Challenges</span>
          </Link>
          <Link
            to="/console"
            className="bg-blue-600 hover:bg-blue-700 rounded-lg p-4 text-center transition-colors"
          >
            <span className="text-2xl block mb-2">💻</span>
            <span className="font-semibold">API Console</span>
          </Link>
          <a
            href="/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="bg-green-600 hover:bg-green-700 rounded-lg p-4 text-center transition-colors"
          >
            <span className="text-2xl block mb-2">📚</span>
            <span className="font-semibold">Swagger Docs</span>
          </a>
        </div>
      </div>
    </div>
  );
}
