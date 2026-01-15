import { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { docsApi } from '../services/api';
import type { Vulnerability, Category } from '../types';

export default function Challenges() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState(searchParams.get('category') || '');

  useEffect(() => {
    docsApi.getCategories().then(setCategories).catch(console.error);
  }, []);

  useEffect(() => {
    setLoading(true);
    docsApi
      .getVulnerabilities(filter || undefined)
      .then(setVulnerabilities)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [filter]);

  const handleFilterChange = (category: string) => {
    setFilter(category);
    if (category) {
      setSearchParams({ category });
    } else {
      setSearchParams({});
    }
  };

  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-600';
      case 'high':
        return 'bg-orange-500';
      case 'medium':
        return 'bg-yellow-500 text-black';
      case 'low':
        return 'bg-blue-500';
      default:
        return 'bg-slate-500';
    }
  };

  const getCategoryIcon = (category: string) => {
    const icons: Record<string, string> = {
      authorization: '🔐',
      authentication: '🔑',
      data: '📊',
      injection: '💉',
      configuration: '⚙️',
      availability: '⏱️',
      inventory: '📦',
      monitoring: '📈',
      graphql: '◈',
    };
    return icons[category] || '🔒';
  };

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">Challenges</h1>
        <p className="text-slate-400">
          Explore and exploit vulnerabilities to capture flags.
        </p>
      </div>

      {/* Filters */}
      <div className="mb-6 flex flex-wrap gap-2">
        <button
          onClick={() => handleFilterChange('')}
          className={`px-4 py-2 rounded transition-colors ${
            !filter
              ? 'bg-red-600 text-white'
              : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
          }`}
        >
          All ({vulnerabilities.length})
        </button>
        {categories.map((cat) => (
          <button
            key={cat.name}
            onClick={() => handleFilterChange(cat.name)}
            className={`px-4 py-2 rounded transition-colors flex items-center gap-2 ${
              filter === cat.name
                ? 'bg-red-600 text-white'
                : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
            }`}
          >
            <span>{getCategoryIcon(cat.name)}</span>
            <span className="capitalize">{cat.name}</span>
            <span className="bg-slate-600 px-2 rounded text-sm">{cat.count}</span>
          </button>
        ))}
      </div>

      {/* Loading */}
      {loading ? (
        <div className="text-center py-12 text-slate-400">Loading challenges...</div>
      ) : (
        /* Challenges grid */
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {vulnerabilities.map((vuln) => (
            <Link
              key={vuln.id}
              to={`/challenge/${vuln.id}`}
              className="challenge-card group"
            >
              {/* Header */}
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className="text-2xl">{getCategoryIcon(vuln.category)}</span>
                  <span className="text-lg font-mono text-red-400">{vuln.id}</span>
                </div>
                <span
                  className={`px-2 py-1 rounded text-xs font-bold ${getSeverityClass(
                    vuln.severity
                  )}`}
                >
                  {vuln.severity.toUpperCase()}
                </span>
              </div>

              {/* Title */}
              <h3 className="font-bold text-lg mb-2 group-hover:text-red-400 transition-colors">
                {vuln.name}
              </h3>

              {/* Description */}
              <p className="text-sm text-slate-400 mb-3 line-clamp-2">
                {vuln.description}
              </p>

              {/* Footer */}
              <div className="flex items-center justify-between text-xs text-slate-500">
                <span className="capitalize">{vuln.category}</span>
                <div className="flex gap-2">
                  <span className="bg-slate-700 px-2 py-1 rounded">{vuln.owasp}</span>
                  <span className="bg-slate-700 px-2 py-1 rounded">{vuln.cwe}</span>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}

      {/* Empty state */}
      {!loading && vulnerabilities.length === 0 && (
        <div className="text-center py-12">
          <div className="text-4xl mb-4">🔍</div>
          <p className="text-slate-400">No vulnerabilities found for this filter.</p>
        </div>
      )}
    </div>
  );
}
