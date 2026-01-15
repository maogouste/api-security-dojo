import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { docsApi, flagsApi } from '../services/api';
import type { VulnerabilityDetail, Vulnerability, FlagResult } from '../types';

interface CompareData {
  id: string;
  name: string;
  vulnerable_code: string;
  secure_code: string;
  key_difference: string;
  remediation: string[];
  owasp: string;
  cwe: string;
}

export default function ChallengeDetail() {
  const { id } = useParams<{ id: string }>();
  const [vuln, setVuln] = useState<VulnerabilityDetail | Vulnerability | null>(null);
  const [compareData, setCompareData] = useState<CompareData | null>(null);
  const [isDocMode, setIsDocMode] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [flag, setFlag] = useState('');
  const [flagResult, setFlagResult] = useState<FlagResult | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!id) return;

    setLoading(true);
    setError(null);

    // Load both vulnerability info and compare data in parallel
    const loadVuln = docsApi
      .getVulnerability(id)
      .then((data) => {
        setVuln(data);
        setIsDocMode(true);
      })
      .catch(() => {
        // Fall back to basic info (challenge mode)
        return docsApi.getVulnerabilities().then((vulns) => {
          const found = vulns.find((v) => v.id === id);
          if (found) {
            setVuln(found);
            setIsDocMode(false);
          } else {
            throw new Error('Vulnerability not found');
          }
        });
      });

    // Always load compare data (works in both modes)
    const loadCompare = docsApi.getCompare(id).then(setCompareData).catch(() => null);

    Promise.all([loadVuln, loadCompare])
      .catch(() => setError('Failed to load vulnerability'))
      .finally(() => setLoading(false));
  }, [id]);

  const handleSubmitFlag = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!id || !flag.trim()) return;

    setSubmitting(true);
    setFlagResult(null);

    try {
      const result = await flagsApi.submit(flag.trim());
      setFlagResult(result);
      if (result.success) {
        setFlag('');
      }
    } catch {
      setFlagResult({ success: false, message: 'Failed to submit flag' });
    } finally {
      setSubmitting(false);
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

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center">
        <div className="text-slate-400">Loading...</div>
      </div>
    );
  }

  if (error || !vuln) {
    return (
      <div className="p-8">
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-4">
          <p className="text-red-400">{error || 'Vulnerability not found'}</p>
          <Link to="/challenges" className="text-blue-400 hover:underline mt-2 inline-block">
            ← Back to Challenges
          </Link>
        </div>
      </div>
    );
  }

  const detail = vuln as VulnerabilityDetail;

  return (
    <div className="p-8 max-w-4xl mx-auto">
      {/* Breadcrumb */}
      <div className="mb-4">
        <Link to="/challenges" className="text-slate-400 hover:text-white">
          ← Back to Challenges
        </Link>
      </div>

      {/* Header */}
      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-6">
        <div className="flex items-start justify-between mb-4">
          <div>
            <span className="text-3xl font-mono text-red-400">{vuln.id}</span>
            <span
              className={`ml-3 px-3 py-1 rounded text-sm font-bold ${getSeverityClass(
                vuln.severity
              )}`}
            >
              {vuln.severity.toUpperCase()}
            </span>
          </div>
          <div className="flex gap-2">
            <span className="bg-slate-700 px-3 py-1 rounded text-sm">{vuln.owasp}</span>
            <span className="bg-slate-700 px-3 py-1 rounded text-sm">{vuln.cwe}</span>
          </div>
        </div>
        <h1 className="text-2xl font-bold mb-2">{vuln.name}</h1>
        <p className="text-slate-400">{vuln.description}</p>
        <div className="mt-4">
          <span className="text-sm text-slate-500 capitalize">Category: {vuln.category}</span>
        </div>
      </div>

      {/* Documentation mode content */}
      {isDocMode && detail.exploitation && (
        <>
          {/* Endpoint */}
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-6">
            <h2 className="text-xl font-bold mb-3">Vulnerable Endpoint</h2>
            <code className="bg-slate-950 px-4 py-2 rounded block text-green-400">
              {detail.vulnerable_endpoint}
            </code>
          </div>

          {/* Exploitation */}
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-6">
            <h2 className="text-xl font-bold mb-3">Exploitation Steps</h2>
            <ol className="list-decimal list-inside space-y-2">
              {detail.exploitation.steps.map((step, i) => (
                <li key={i} className="text-slate-300">
                  {step}
                </li>
              ))}
            </ol>

            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-400 mb-2">Example Request</h3>
                <pre className="code-block text-xs whitespace-pre-wrap">
                  {detail.exploitation.example_request}
                </pre>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-slate-400 mb-2">Example Response</h3>
                <pre className="code-block text-xs whitespace-pre-wrap">
                  {detail.exploitation.example_response}
                </pre>
              </div>
            </div>
          </div>


          {/* Remediation */}
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-6">
            <h2 className="text-xl font-bold mb-3">Remediation</h2>
            <ul className="list-disc list-inside space-y-2">
              {detail.remediation.map((item, i) => (
                <li key={i} className="text-slate-300">
                  {item}
                </li>
              ))}
            </ul>
          </div>

          {/* References */}
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-6">
            <h2 className="text-xl font-bold mb-3">References</h2>
            <ul className="space-y-2">
              {detail.references.map((ref, i) => (
                <li key={i}>
                  <a
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:underline break-all"
                  >
                    {ref}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </>
      )}

      {/* Challenge mode notice */}
      {!isDocMode && (
        <div className="bg-yellow-900/30 border border-yellow-700 rounded-lg p-4 mb-6">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🎮</span>
            <div>
              <h3 className="font-bold text-yellow-400">Challenge Mode</h3>
              <p className="text-sm text-slate-300">
                Detailed exploitation information is hidden. Set{' '}
                <code className="bg-slate-700 px-1 rounded">DOJO_MODE=documentation</code> to see
                full details.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Code comparison - Available in BOTH modes */}
      {compareData && (
        <div className="bg-slate-800 rounded-lg p-6 border border-slate-700 mb-6">
          <h2 className="text-xl font-bold mb-2">Code Comparison</h2>
          <p className="text-sm text-slate-400 mb-4">
            <span className="text-yellow-400">💡 Key difference:</span> {compareData.key_difference}
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h3 className="text-sm font-semibold text-red-400 mb-2">❌ Vulnerable Code</h3>
              <pre className="code-block text-xs whitespace-pre-wrap text-red-300">
                {compareData.vulnerable_code}
              </pre>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-green-400 mb-2">✅ Secure Code</h3>
              <pre className="code-block text-xs whitespace-pre-wrap text-green-300">
                {compareData.secure_code}
              </pre>
            </div>
          </div>
          {compareData.remediation && compareData.remediation.length > 0 && !isDocMode && (
            <div className="mt-4 pt-4 border-t border-slate-700">
              <h3 className="text-sm font-semibold text-slate-400 mb-2">Remediation Tips</h3>
              <ul className="list-disc list-inside space-y-1 text-sm text-slate-300">
                {compareData.remediation.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Flag submission */}
      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
        <h2 className="text-xl font-bold mb-3">🚩 Submit Flag</h2>
        <form onSubmit={handleSubmitFlag} className="flex gap-4">
          <input
            type="text"
            value={flag}
            onChange={(e) => setFlag(e.target.value)}
            placeholder="VULNAPI{...}"
            className="flex-1 bg-slate-900 border border-slate-600 rounded px-4 py-2 focus:border-red-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={submitting || !flag.trim()}
            className="bg-red-600 hover:bg-red-700 disabled:bg-slate-600 disabled:cursor-not-allowed px-6 py-2 rounded font-semibold transition-colors"
          >
            {submitting ? 'Submitting...' : 'Submit'}
          </button>
        </form>

        {flagResult && (
          <div
            className={`mt-4 p-4 rounded ${
              flagResult.success
                ? 'bg-green-900/30 border border-green-700 text-green-400'
                : 'bg-red-900/30 border border-red-700 text-red-400'
            }`}
          >
            <div className="flex items-center gap-2">
              <span>{flagResult.success ? '✅' : '❌'}</span>
              <span>{flagResult.message}</span>
              {flagResult.points && (
                <span className="ml-auto font-bold">+{flagResult.points} points</span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
