'use client'

import { useState } from 'react'
import { AlertCircle, CheckCircle, Loader, Terminal, Globe, Clock, ShieldCheck, Copy, Check } from 'lucide-react'
import { api } from '@/services/api'

interface AnalysisResult {
  scan_id: string
  target: string
  final_url?: string
  status: string
  security_score: number
  http_status?: number
  response_time_ms?: number
  redirect_count?: number
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
  const [activeTab, setActiveTab] = useState<'findings' | 'headers' | 'verify'>('findings')
  const [copied, setCopied] = useState(false)

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

  const copyCurlCommand = (targetUrl: string) => {
    const cmd = `curl -I -L "${targetUrl.startsWith('http') ? targetUrl : 'https://' + targetUrl}"`
    navigator.clipboard.writeText(cmd)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const getGrade = (score: number) => {
    if (score >= 90) return { grade: 'A+', color: 'text-green-400 border-green-500 bg-green-950/40' }
    if (score >= 80) return { grade: 'A', color: 'text-green-400 border-green-500 bg-green-950/40' }
    if (score >= 70) return { grade: 'B', color: 'text-blue-400 border-blue-500 bg-blue-950/40' }
    if (score >= 50) return { grade: 'C', color: 'text-yellow-400 border-yellow-500 bg-yellow-950/40' }
    if (score >= 35) return { grade: 'D', color: 'text-orange-400 border-orange-500 bg-orange-950/40' }
    return { grade: 'F', color: 'text-red-400 border-red-500 bg-red-950/40' }
  }

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-2">Live HTTP Security Header Analyzer</h1>
        <p className="text-slate-400">Real-time, authentic security header inspection matching industry standards</p>
      </div>

      <div className="card mb-8">
        <div className="mb-6">
          <label className="block text-sm font-medium mb-2">Target Website URL</label>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="input text-lg"
            disabled={loading}
          />
          <p className="text-xs text-slate-500 mt-2">Try scanning: github.com (A+), google.com (D), apple.com (D/F), or your own domain</p>
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
                Fetching Live Headers...
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
          {/* Main Score Banner */}
          <div className="card flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <Globe className="w-5 h-5 text-blue-400" />
                <h2 className="text-2xl font-bold font-mono text-slate-100">{result.target}</h2>
              </div>
              {result.final_url && result.final_url !== result.target && (
                <p className="text-xs text-slate-400 font-mono">Resolved via redirects $\rightarrow$ <span className="text-blue-400">{result.final_url}</span></p>
              )}
              <div className="flex flex-wrap gap-4 mt-4 text-xs text-slate-300">
                <span className="bg-slate-800 px-2.5 py-1 rounded border border-slate-700">HTTP Status: <strong className="text-white">{result.http_status || 200}</strong></span>
                <span className="bg-slate-800 px-2.5 py-1 rounded border border-slate-700">Response Time: <strong className="text-white">{result.response_time_ms}ms</strong></span>
                <span className="bg-slate-800 px-2.5 py-1 rounded border border-slate-700">Server: <strong className="text-white">{result.server_info || 'Hidden'}</strong></span>
                <span className="bg-slate-800 px-2.5 py-1 rounded border border-slate-700">Redirects: <strong className="text-white">{result.redirect_count || 0}</strong></span>
              </div>
            </div>

            {/* Letter Grade & Score Badge */}
            <div className="flex items-center gap-4 border-l border-slate-800 pl-6">
              <div className={`w-20 h-20 rounded-2xl border-2 flex flex-col items-center justify-center font-bold shadow-lg ${getGrade(result.security_score).color}`}>
                <span className="text-3xl">{getGrade(result.security_score).grade}</span>
                <span className="text-[10px] tracking-wider uppercase opacity-80">Grade</span>
              </div>
              <div className="text-left">
                <p className="text-xs text-slate-400 uppercase font-semibold">Security Score</p>
                <p className="text-3xl font-extrabold text-white">{result.security_score}<span className="text-sm font-normal text-slate-400">/100</span></p>
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
              Audited Findings ({result.findings.length})
            </button>
            <button
              onClick={() => setActiveTab('headers')}
              className={`pb-3 text-sm font-semibold border-b-2 transition-colors flex items-center gap-2 ${
                activeTab === 'headers' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Terminal className="w-4 h-4" /> Live Raw Headers ({Object.keys(result.response_headers || {}).length})
            </button>
            <button
              onClick={() => setActiveTab('verify')}
              className={`pb-3 text-sm font-semibold border-b-2 transition-colors flex items-center gap-2 ${
                activeTab === 'verify' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <CheckCircle className="w-4 h-4" /> Live cURL Verifier
            </button>
          </div>

          {/* Tab 1: Findings */}
          {activeTab === 'findings' && (
            <div className="space-y-4">
              {result.findings.map((finding, idx) => (
                <FindingCard key={idx} finding={finding} />
              ))}
            </div>
          )}

          {/* Tab 2: Raw Headers */}
          {activeTab === 'headers' && (
            <div className="card">
              <h3 className="text-lg font-bold mb-2 flex items-center gap-2">
                <Terminal className="w-5 h-5 text-blue-400" /> Authentic HTTP Headers Received from Server
              </h3>
              <p className="text-xs text-slate-400 mb-4">
                These are the exact raw headers returned directly by {result.final_url || result.target}:
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

          {/* Tab 3: cURL Verifier */}
          {activeTab === 'verify' && (
            <div className="card">
              <h3 className="text-lg font-bold mb-2">Cross-Verify with Your Own Terminal</h3>
              <p className="text-sm text-slate-400 mb-4">
                Run this exact command in PowerShell or Terminal to see that HeaderSentinel matches the live server 100%:
              </p>
              <div className="flex items-center justify-between bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-sm mb-4">
                <code className="text-green-400">curl -I -L "{result.final_url || result.target}"</code>
                <button
                  onClick={() => copyCurlCommand(result.final_url || result.target)}
                  className="btn-secondary text-xs flex items-center gap-1.5"
                >
                  {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                  {copied ? 'Copied!' : 'Copy Command'}
                </button>
              </div>
              <p className="text-xs text-slate-500">
                Compare the headers returned in your terminal with the <strong>Live Raw Headers</strong> tab above.
              </p>
            </div>
          )}
        </div>
      )}
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
            Learn More $\rightarrow$
          </a>
        </div>
      )}
    </div>
  )
}
