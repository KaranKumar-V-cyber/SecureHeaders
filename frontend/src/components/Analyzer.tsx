'use client'

import { useState } from 'react'
import { AlertCircle, CheckCircle, Loader, Terminal, Globe, Clock, ShieldCheck } from 'lucide-react'
import { api } from '@/services/api'

interface AnalysisResult {
  scan_id: string
  target: string
  final_url?: string
  status: string
  security_score: number
  http_status?: number
  response_time_ms?: number
  server_info?: string
  response_headers: Record<string, string>
  findings: any[]
  severity_counts: Record<string, number>
}

export default function Analyzer() {
  const [url, setUrl] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'findings' | 'headers'>('findings')

  const handleAnalyze = async () => {
    if (!url) {
      setError('Please enter a URL')
      return
    }

    if (!authorized) {
      setError('You must confirm authorization to proceed')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const response = await api.post('/analyze', {
        target: url,
        authorization_confirmed: true,
      })

      setResult(response.data)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to analyze website')
    } finally {
      setLoading(false)
    }
  }

  const handleClear = () => {
    setUrl('')
    setAuthorized(false)
    setResult(null)
    setError(null)
  }

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-2">Live Website Analyzer</h1>
        <p className="text-slate-400">Perform real-time HTTP security header analysis on live websites</p>
      </div>

      <div className="card mb-8">
        <div className="mb-6">
          <label className="block text-sm font-medium mb-2">Target URL</label>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="input"
            disabled={loading}
          />
          <p className="text-xs text-slate-500 mt-2">Example: https://google.com, https://github.com, or example.com</p>
        </div>

        <div className="mb-6 p-4 bg-slate-800/50 border border-slate-700 rounded-lg">
          <label className="flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              disabled={loading}
              className="w-4 h-4 rounded"
            />
            <span className="ml-3 text-sm">
              I confirm that I own this target or have explicit authorization to test it.
            </span>
          </label>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-900/30 border border-red-800 rounded-lg flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <p className="text-red-100 text-sm">{error}</p>
          </div>
        )}

        <div className="flex gap-3">
          <button
            onClick={handleAnalyze}
            disabled={loading || !authorized}
            className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <Loader className="w-4 h-4 mr-2 animate-spin inline" />
                Analyzing Live Target...
              </>
            ) : (
              'Analyze Now'
            )}
          </button>
          <button
            onClick={handleClear}
            disabled={loading}
            className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Clear
          </button>
        </div>
      </div>

      {result && (
        <div className="space-y-6">
          <div className="card">
            <div className="flex items-start justify-between mb-4">
              <div>
                <p className="text-slate-400 text-xs">Target & Final URL</p>
                <p className="text-xl font-mono font-bold text-slate-100">{result.target}</p>
                {result.final_url && result.final_url !== result.target && (
                  <p className="text-xs text-blue-400 font-mono mt-1">↳ Resolved: {result.final_url}</p>
                )}
              </div>
              <ScoreIndicator score={result.security_score} />
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-slate-800 text-sm">
              <div>
                <p className="text-slate-400 text-xs">HTTP Status</p>
                <p className="font-semibold">{result.http_status || 'N/A'}</p>
              </div>
              <div>
                <p className="text-slate-400 text-xs">Response Time</p>
                <p className="font-semibold">{result.response_time_ms ? `${result.response_time_ms}ms` : 'N/A'}</p>
              </div>
              <div>
                <p className="text-slate-400 text-xs">Server Banner</p>
                <p className="font-semibold">{result.server_info || 'Hidden / Redacted'}</p>
              </div>
              <div>
                <p className="text-slate-400 text-xs">Total Findings</p>
                <p className="font-semibold">{result.findings.length}</p>
              </div>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex border-b border-slate-800 gap-6">
            <button
              onClick={() => setActiveTab('findings')}
              className={`pb-3 text-sm font-semibold border-b-2 transition-colors ${
                activeTab === 'findings' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Security Findings ({result.findings.length})
            </button>
            <button
              onClick={() => setActiveTab('headers')}
              className={`pb-3 text-sm font-semibold border-b-2 transition-colors flex items-center gap-2 ${
                activeTab === 'headers' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Terminal className="w-4 h-4" /> Live Raw Headers ({Object.keys(result.response_headers || {}).length})
            </button>
          </div>

          {activeTab === 'findings' ? (
            <div className="space-y-4">
              {result.findings.length === 0 ? (
                <div className="card text-center py-8 text-slate-400">
                  <ShieldCheck className="w-10 h-10 mx-auto mb-2 text-green-400" />
                  <p className="font-medium">No security issues detected!</p>
                </div>
              ) : (
                result.findings.map((finding, idx) => (
                  <FindingCard key={idx} finding={finding} />
                ))
              )}
            </div>
          ) : (
            <div className="card">
              <h3 className="text-lg font-bold mb-3 flex items-center gap-2">
                <Terminal className="w-5 h-5 text-blue-400" /> Actual HTTP Headers Received
              </h3>
              <p className="text-xs text-slate-400 mb-4">
                These are the authentic response headers fetched directly from the target server:
              </p>
              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-xs overflow-x-auto space-y-1.5">
                {Object.entries(result.response_headers || {}).map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <span className="text-blue-400 font-semibold">{k}:</span>
                    <span className="text-slate-300 break-all">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function ScoreIndicator({ score }: { score: number }) {
  const getColor = (score: number) => {
    if (score >= 80) return 'text-green-400'
    if (score >= 60) return 'text-yellow-400'
    if (score >= 40) return 'text-orange-400'
    return 'text-red-400'
  }

  return (
    <div className={`text-center ${getColor(score)}`}>
      <p className="text-xs text-slate-400">Security Score</p>
      <p className="text-4xl font-bold">{score}</p>
      <p className="text-xs text-slate-400">/100</p>
    </div>
  )
}

function FindingCard({ finding }: { finding: any }) {
  const severityColors = {
    CRITICAL: 'bg-red-900/30 border-red-800 text-red-100',
    HIGH: 'bg-orange-900/30 border-orange-800 text-orange-100',
    MEDIUM: 'bg-yellow-900/30 border-yellow-800 text-yellow-100',
    LOW: 'bg-blue-900/30 border-blue-800 text-blue-100',
    INFO: 'bg-slate-700/30 border-slate-700 text-slate-100',
  }

  const badgeClasses = {
    CRITICAL: 'badge-critical',
    HIGH: 'badge-high',
    MEDIUM: 'badge-medium',
    LOW: 'badge-low',
    INFO: 'badge-info',
  }

  return (
    <div className={`border rounded-lg p-4 ${severityColors[finding.severity as keyof typeof severityColors]}`}>
      <div className="flex items-start justify-between mb-3">
        <div>
          <h3 className="font-bold">{finding.title}</h3>
          <p className="text-xs opacity-75">{finding.category}</p>
        </div>
        <span className={`${badgeClasses[finding.severity as keyof typeof badgeClasses]} text-xs`}>
          {finding.severity}
        </span>
      </div>

      <p className="text-sm mb-3">{finding.description}</p>

      <div className="space-y-2 text-sm">
        <div>
          <p className="font-semibold opacity-75">Impact:</p>
          <p>{finding.impact}</p>
        </div>
        <div>
          <p className="font-semibold opacity-75">Remediation:</p>
          <p>{finding.remediation}</p>
        </div>
      </div>

      {finding.reference && (
        <div className="mt-3 pt-3 border-t border-current border-opacity-20">
          <a href={finding.reference} target="_blank" rel="noopener noreferrer" className="text-xs underline opacity-75">
            Learn More →
          </a>
        </div>
      )}
    </div>
  )
}
