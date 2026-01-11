import { useState } from 'react';
import { executeRequest } from '../services/api';
import { useBackend } from '../contexts/BackendContext';

export default function GraphQLConsole() {
  const { backend } = useBackend();
  const [query, setQuery] = useState(`{
  __schema {
    types {
      name
    }
  }
}`);
  const [variables, setVariables] = useState('');
  const [loading, setLoading] = useState(false);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [response, setResponse] = useState<Record<string, any> | null>(null);

  const presets = [
    {
      name: 'Introspection (G01)',
      query: `{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}`,
    },
    {
      name: 'List All Users (G05)',
      query: `{
  users {
    id
    username
    email
    ssn
    creditCard
    apiKey
  }
}`,
    },
    {
      name: 'Nested Query (G02)',
      query: `{
  users {
    id
    username
    orders {
      id
      status
      user {
        username
        orders {
          id
          status
        }
      }
    }
  }
}`,
    },
    {
      name: 'Field Suggestion (G04)',
      query: `{
  users {
    userna
  }
}`,
    },
    {
      name: 'Products with Internal Data',
      query: `{
  products {
    id
    name
    price
    internalNotes
    supplierCost
  }
}`,
    },
    {
      name: 'Login Mutation',
      query: `mutation {
  login(username: "john", password: "password123") {
    accessToken
    userId
    role
  }
}`,
    },
    {
      name: 'Update User Role (G05)',
      query: `mutation {
  updateUser(id: 2, input: { role: "admin" }) {
    id
    username
    role
  }
}`,
    },
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      let vars = undefined;
      if (variables.trim()) {
        try {
          vars = JSON.parse(variables);
        } catch {
          // Ignore parse errors
        }
      }

      const result = await executeRequest('POST', '/graphql/', {
        query,
        variables: vars,
      });

      setResponse(result.data as Record<string, unknown>);
    } catch (err) {
      setResponse({ error: String(err) });
    } finally {
      setLoading(false);
    }
  };

  const handleBatchAttack = async () => {
    setLoading(true);

    try {
      // G03: Batching attack - send multiple queries in one request
      const batchedQueries = [
        { query: '{ user1: user(id: 1) { username ssn } }' },
        { query: '{ user2: user(id: 2) { username ssn } }' },
        { query: '{ user3: user(id: 3) { username ssn } }' },
        { query: '{ user4: user(id: 4) { username ssn } }' },
        { query: '{ user5: user(id: 5) { username ssn } }' },
      ];

      const result = await executeRequest('POST', '/graphql/', batchedQueries);
      setResponse(result.data as Record<string, unknown>);
    } catch (err) {
      setResponse({ error: String(err) });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">GraphQL Console</h1>
        <p className="text-slate-400">
          Explore GraphQL vulnerabilities (G01-G05).
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Query panel */}
        <div className="lg:col-span-2 space-y-4">
          <form onSubmit={handleSubmit} className="bg-slate-800 rounded-lg border border-slate-700">
            <div className="px-4 py-2 border-b border-slate-700 flex items-center justify-between">
              <span className="font-semibold flex items-center gap-2">
                <span className="text-purple-400">◈</span> GraphQL Query
              </span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={handleBatchAttack}
                  className="bg-purple-600 hover:bg-purple-700 px-4 py-1 rounded text-sm"
                >
                  Batch Attack (G03)
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-red-600 hover:bg-red-700 disabled:bg-slate-600 px-4 py-1 rounded text-sm"
                >
                  {loading ? 'Running...' : 'Execute'}
                </button>
              </div>
            </div>

            <div className="p-4 space-y-4">
              <div>
                <label className="block text-sm font-semibold mb-2">Query</label>
                <textarea
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  rows={12}
                  className="w-full bg-slate-950 border border-slate-600 rounded px-4 py-3 font-mono text-sm focus:border-purple-500 focus:outline-none"
                  spellCheck={false}
                />
              </div>

              <div>
                <label className="block text-sm font-semibold mb-2">Variables (JSON)</label>
                <textarea
                  value={variables}
                  onChange={(e) => setVariables(e.target.value)}
                  rows={3}
                  placeholder='{"id": 1}'
                  className="w-full bg-slate-950 border border-slate-600 rounded px-4 py-3 font-mono text-sm focus:border-purple-500 focus:outline-none"
                />
              </div>
            </div>
          </form>

          {/* Response */}
          {response && (
            <div className="bg-slate-800 rounded-lg border border-slate-700">
              <div className="px-4 py-2 border-b border-slate-700">
                <span className="font-semibold">Response</span>
              </div>
              <div className="p-4">
                <pre className="bg-slate-950 rounded p-4 font-mono text-sm overflow-x-auto max-h-96 text-green-400">
                  {JSON.stringify(response, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Presets */}
          <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
            <h3 className="font-semibold mb-3">Query Presets</h3>
            <div className="space-y-2">
              {presets.map((preset, i) => (
                <button
                  key={i}
                  onClick={() => setQuery(preset.query)}
                  className="w-full text-left bg-slate-700/50 hover:bg-slate-700 rounded px-3 py-2 text-sm"
                >
                  {preset.name}
                </button>
              ))}
            </div>
          </div>

          {/* Vulnerabilities */}
          <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
            <h3 className="font-semibold mb-3">GraphQL Vulnerabilities</h3>
            <ul className="text-sm space-y-2">
              <li className="flex items-center gap-2">
                <span className="bg-red-600 px-2 py-0.5 rounded text-xs">G01</span>
                <span className="text-slate-300">Introspection Exposed</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="bg-red-600 px-2 py-0.5 rounded text-xs">G02</span>
                <span className="text-slate-300">Nested Queries (DoS)</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="bg-red-600 px-2 py-0.5 rounded text-xs">G03</span>
                <span className="text-slate-300">Batching Attacks</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="bg-red-600 px-2 py-0.5 rounded text-xs">G04</span>
                <span className="text-slate-300">Field Suggestions</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="bg-red-600 px-2 py-0.5 rounded text-xs">G05</span>
                <span className="text-slate-300">Authorization Bypass</span>
              </li>
            </ul>
          </div>

          {/* Link to GraphiQL */}
          <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
            <h3 className="font-semibold mb-3">External Tools</h3>
            <a
              href={`${backend.baseUrl}/graphql/`}
              target="_blank"
              rel="noopener noreferrer"
              className="block bg-purple-600 hover:bg-purple-700 text-center py-2 rounded"
            >
              Open GraphiQL →
            </a>
            <p className="text-xs text-slate-500 mt-2 text-center">
              {backend.name} ({backend.baseUrl})
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
