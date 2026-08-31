'use client'

import { useState } from 'react'
import { AlertCircle, CheckCircle, Loader } from 'lucide-react'
import { api } from '@/services/api'

interface AnalysisResult {
  scan_id: string
  target: string
  status: string
  security_score: number
  findings: any[]
  severity_counts: Record<string, number>
}

export default function Analyzer() {
  const [url, setUrl] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)

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
        <h1 className="text-4xl font-bold mb-2">Website Analyzer</h1>
        <p className="text-slate-400">Analyze HTTP security headers of any website</p>
      </div>

      {/* Input Section */}
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
          <p className="text-xs text-slate-500 mt-2">Example: https://example.com or example.com</p>
        </div>

        {/* Authorization Confirmation */}
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
          <p className="text-xs text-slate-500 mt-2 ml-7">
            Unauthorized access to computer systems is illegal. Use this tool only on systems you own or have explicit permission to test.
          </p>
        </div>

        {/* Error Message */}
        {error && (
          <div className="mb-6 p-4 bg-red-900/30 border border-red-800 rounded-lg flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <p className="text-red-100 text-sm">{error}</p>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex gap-3">
          <button
            onClick={handleAnalyze}
            disabled={loading || !authorized}
            className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <Loader className="w-4 h-4 mr-2 animate-spin inline" />
                Analyzing...
              </>
            ) : (
              'Analyze'
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

      {/* Results */}
      {result && (
        <div className="space-y-6">
          {/* Overview Card */}
          <div className="card">
            <div className="flex items-start justify-between mb-4">
              <div>
                <p className="text-slate-400 text-sm">Target</p>
                <p className="text-xl font-mono">{result.target}</p>
              </div>
              <ScoreIndicator score={result.security_score} />
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-slate-800">
              <div>
                <p className="text-slate-400 text-xs">Status</p>
                <p className="font-semibold capitalize">{result.status}</p>
              </div>
              <div>
                <p className="text-slate-400 text-xs">Critical Findings</p>
                <p className="font-semibold text-red-400">{result.severity_counts.CRITICAL}</p>
              </div>
              <div>
                <p className="text-slate-400 text-xs">High Findings</p>
                <p className="font-semibold text-orange-400">{result.severity_counts.HIGH}</p>
              </div>
              <div>
                <p className="text-slate-400 text-xs">Medium Findings</p>
                <p className="font-semibold text-yellow-400">{result.severity_counts.MEDIUM}</p>
              </div>
            </div>
          </div>

          {/* Findings List */}
          {result.findings.length > 0 && (
            <div className="card">
              <h2 className="text-2xl font-bold mb-6">Security Findings</h2>
              <div className="space-y-4">
                {result.findings.map((finding, idx) => (
                  <FindingCard key={idx} finding={finding} />
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
      <p className="text-sm text-slate-400">Security Score</p>
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
