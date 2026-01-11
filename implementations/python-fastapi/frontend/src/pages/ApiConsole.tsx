import { useState } from 'react';
import { executeRequest } from '../services/api';
import type { RequestResult } from '../services/api';
import { useBackend } from '../contexts/BackendContext';

interface RequestHistory {
  id: number;
  method: string;
  url: string;
  status: number;
  timestamp: Date;
}

export default function ApiConsole() {
  const { backend } = useBackend();
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('/api/me');
  const [body, setBody] = useState('');
  const [headers, setHeaders] = useState('');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<RequestResult | null>(null);
  const [history, setHistory] = useState<RequestHistory[]>([]);
  const [token, setToken] = useState(localStorage.getItem('token') || '');

  const commonEndpoints = [
    { method: 'POST', url: '/api/login', body: '{"username": "john", "password": "password123"}' },
    { method: 'GET', url: '/api/me', body: '' },
    { method: 'GET', url: '/api/users/1', body: '' },
    { method: 'GET', url: '/api/products', body: '' },
    { method: 'GET', url: "/api/products?search=' OR '1'='1", body: '' },
    { method: 'POST', url: '/api/tools/ping', body: '{"host": "127.0.0.1"}' },
    { method: 'GET', url: '/api/v1/users', body: '' },
    { method: 'POST', url: '/graphql/', body: '{"query": "{ users { id username ssn } }"}' },
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      let parsedBody;
      if (body.trim()) {
        try {
          parsedBody = JSON.parse(body);
        } catch {
          parsedBody = body;
        }
      }

      let parsedHeaders: Record<string, string> = {};
      if (headers.trim()) {
        try {
          parsedHeaders = JSON.parse(headers);
        } catch {
          // Parse header lines
          headers.split('\n').forEach((line) => {
            const [key, ...valueParts] = line.split(':');
            if (key && valueParts.length) {
              parsedHeaders[key.trim()] = valueParts.join(':').trim();
            }
          });
        }
      }

      // Add auth header if token is set
      if (token) {
        parsedHeaders['Authorization'] = `Bearer ${token}`;
      }

      const result = await executeRequest(method, url, parsedBody, parsedHeaders);
      setResponse(result);

      // Add to history
      setHistory((prev) => [
        {
          id: Date.now(),
          method,
          url,
          status: result.status,
          timestamp: new Date(),
        },
        ...prev.slice(0, 9),
      ]);
    } catch (err) {
      setResponse({
        status: 0,
        statusText: 'Error',
        headers: {},
        data: { error: String(err) },
      });
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (preset: (typeof commonEndpoints)[0]) => {
    setMethod(preset.method);
    setUrl(preset.url);
    setBody(preset.body);
  };

  const saveToken = () => {
    localStorage.setItem('token', token);
  };

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'text-green-400';
    if (status >= 400 && status < 500) return 'text-yellow-400';
    if (status >= 500) return 'text-red-400';
    return 'text-slate-400';
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">API Console</h1>
        <p className="text-slate-400">
          Test API endpoints and explore vulnerabilities.
          <span className="ml-2 text-xs bg-slate-700 px-2 py-1 rounded">
            {backend.icon} {backend.name} - {backend.baseUrl}
          </span>
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Request panel */}
        <div className="lg:col-span-2 space-y-4">
          {/* Token input */}
          <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
            <label className="block text-sm font-semibold mb-2">Authorization Token</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Bearer token (optional)"
                className="flex-1 bg-slate-900 border border-slate-600 rounded px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
              />
              <button
                onClick={saveToken}
                className="bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded text-sm"
              >
                Save
              </button>
            </div>
          </div>

          {/* Request form */}
          <form onSubmit={handleSubmit} className="api-console">
            <div className="api-console-header">
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className="bg-slate-900 border border-slate-600 rounded px-3 py-2 font-bold"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="PATCH">PATCH</option>
              </select>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="/api/endpoint"
                className="flex-1 bg-slate-900 border border-slate-600 rounded px-3 py-2 focus:border-blue-500 focus:outline-none"
              />
              <button
                type="submit"
                disabled={loading}
                className="bg-red-600 hover:bg-red-700 disabled:bg-slate-600 px-6 py-2 rounded font-semibold"
              >
                {loading ? 'Sending...' : 'Send'}
              </button>
            </div>

            <div className="api-console-body space-y-4">
              <div>
                <label className="block text-sm font-semibold mb-2">Headers (JSON or lines)</label>
                <textarea
                  value={headers}
                  onChange={(e) => setHeaders(e.target.value)}
                  placeholder='{"Content-Type": "application/json"}'
                  rows={3}
                  className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-sm font-semibold mb-2">Body (JSON)</label>
                <textarea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  placeholder='{"key": "value"}'
                  rows={5}
                  className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none"
                />
              </div>
            </div>
          </form>

          {/* Response */}
          {response && (
            <div className="bg-slate-800 rounded-lg border border-slate-700">
              <div className="px-4 py-2 border-b border-slate-700 flex items-center gap-4">
                <span className="font-semibold">Response</span>
                <span className={`font-mono font-bold ${getStatusColor(response.status)}`}>
                  {response.status} {response.statusText}
                </span>
              </div>
              <div className="p-4">
                <pre className="bg-slate-950 rounded p-4 font-mono text-sm overflow-x-auto max-h-96">
                  {JSON.stringify(response.data, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Quick presets */}
          <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
            <h3 className="font-semibold mb-3">Quick Presets</h3>
            <div className="space-y-2">
              {commonEndpoints.map((preset, i) => (
                <button
                  key={i}
                  onClick={() => loadPreset(preset)}
                  className="w-full text-left bg-slate-700/50 hover:bg-slate-700 rounded px-3 py-2 text-sm flex items-center gap-2"
                >
                  <span
                    className={`text-xs font-bold px-2 py-0.5 rounded ${
                      preset.method === 'GET'
                        ? 'bg-green-600'
                        : preset.method === 'POST'
                        ? 'bg-blue-600'
                        : preset.method === 'PUT'
                        ? 'bg-yellow-600'
                        : 'bg-red-600'
                    }`}
                  >
                    {preset.method}
                  </span>
                  <span className="truncate font-mono text-xs">{preset.url}</span>
                </button>
              ))}
            </div>
          </div>

          {/* History */}
          {history.length > 0 && (
            <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
              <h3 className="font-semibold mb-3">History</h3>
              <div className="space-y-2">
                {history.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => {
                      setMethod(item.method);
                      setUrl(item.url);
                    }}
                    className="w-full text-left bg-slate-700/50 hover:bg-slate-700 rounded px-3 py-2 text-sm"
                  >
                    <div className="flex items-center gap-2">
                      <span className={`font-mono font-bold ${getStatusColor(item.status)}`}>
                        {item.status}
                      </span>
                      <span className="truncate font-mono text-xs">{item.url}</span>
                    </div>
                    <div className="text-xs text-slate-500">
                      {item.timestamp.toLocaleTimeString()}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Tips */}
          <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
            <h3 className="font-semibold mb-3">💡 Tips</h3>
            <ul className="text-sm text-slate-400 space-y-2">
              <li>• Try SQL injection: <code className="bg-slate-700 px-1 rounded">' OR 1=1--</code></li>
              <li>• Test BOLA: Change user IDs in URLs</li>
              <li>• Check /api/v1/ for legacy endpoints</li>
              <li>• Use GraphQL introspection</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
