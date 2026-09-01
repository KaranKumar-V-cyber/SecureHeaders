'use client'

import { useState, useEffect } from 'react'
import Dashboard from '@/components/Dashboard'
import Analyzer from '@/components/Analyzer'
import Sidebar from '@/components/Sidebar'
import { api } from '@/services/api'
import { Trash2, ExternalLink, Search, Shield, RefreshCw } from 'lucide-react'

export default function Home() {
  const [currentPage, setCurrentPage] = useState<'dashboard' | 'analyzer' | 'history' | 'settings'>('dashboard')

  return (
    <div className="flex h-screen bg-slate-950">
      <Sidebar currentPage={currentPage} onPageChange={setCurrentPage} />
      
      <main className="flex-1 overflow-auto">
        {currentPage === 'dashboard' && <Dashboard onNavigate={setCurrentPage} />}
        {currentPage === 'analyzer' && <Analyzer />}
        {currentPage === 'history' && <History />}
        {currentPage === 'settings' && <Settings />}
      </main>
    </div>
  )
}

function History() {
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')

  const fetchScans = async () => {
    setLoading(true)
    try {
      const response = await api.get('/scans?limit=50')
      setScans(response.data.items || [])
    } catch (err) {
      console.error('Failed to load scans:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchScans()
  }, [])

  const handleDelete = async (scanId: string) => {
    try {
      await api.delete(`/scans/${scanId}`)
      setScans(scans.filter((s) => s.scan_id !== scanId))
    } catch (err) {
      console.error('Failed to delete scan:', err)
    }
  }

  const filteredScans = scans.filter((s) =>
    s.target.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold mb-1">Scan History</h1>
          <p className="text-slate-400 text-sm">View and manage past security header scans</p>
        </div>
        <button onClick={fetchScans} className="btn-secondary flex items-center gap-2 text-sm">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      <div className="mb-6 flex gap-4">
        <div className="relative flex-1">
          <Search className="w-5 h-5 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search scans by hostname..."
            className="input pl-10"
          />
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center p-12">
          <div className="loading-spinner" />
        </div>
      ) : filteredScans.length === 0 ? (
        <div className="card text-center py-12 text-slate-400">
          <Shield className="w-12 h-12 mx-auto mb-3 text-slate-600" />
          <p className="text-lg font-medium">No scan history found</p>
          <p className="text-sm text-slate-500 mt-1">Run an analysis in the Analyzer tab to see results here.</p>
        </div>
      ) : (
        <div className="card overflow-hidden p-0">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900 border-b border-slate-800 text-slate-400">
              <tr>
                <th className="p-4">Target</th>
                <th className="p-4">Status</th>
                <th className="p-4">Score</th>
                <th className="p-4">Findings</th>
                <th className="p-4">Date</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filteredScans.map((scan) => (
                <tr key={scan.scan_id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="p-4 font-mono font-medium">{scan.target}</td>
                  <td className="p-4">
                    <span
                      className={`px-2 py-1 rounded text-xs uppercase font-bold ${
                        scan.status === 'completed'
                          ? 'bg-green-900/40 text-green-400'
                          : 'bg-red-900/40 text-red-400'
                      }`}
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td className="p-4 font-bold">
                    {scan.security_score !== null && scan.security_score !== undefined
                      ? `${scan.security_score}/100`
                      : 'N/A'}
                  </td>
                  <td className="p-4">
                    <div className="flex gap-1 text-xs">
                      {scan.severity_counts?.CRITICAL > 0 && (
                        <span className="bg-red-900 text-red-100 px-1.5 py-0.5 rounded">
                          {scan.severity_counts.CRITICAL} Crit
                        </span>
                      )}
                      {scan.severity_counts?.HIGH > 0 && (
                        <span className="bg-orange-900 text-orange-100 px-1.5 py-0.5 rounded">
                          {scan.severity_counts.HIGH} High
                        </span>
                      )}
                      {scan.severity_counts?.MEDIUM > 0 && (
                        <span className="bg-yellow-900 text-yellow-100 px-1.5 py-0.5 rounded">
                          {scan.severity_counts.MEDIUM} Med
                        </span>
                      )}
                      {scan.severity_counts?.LOW > 0 && (
                        <span className="bg-blue-900 text-blue-100 px-1.5 py-0.5 rounded">
                          {scan.severity_counts.LOW} Low
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="p-4 text-slate-400 text-xs">
                    {new Date(scan.created_at).toLocaleString()}
                  </td>
                  <td className="p-4 text-right">
                    <button
                      onClick={() => handleDelete(scan.scan_id)}
                      className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-slate-800 rounded transition-colors"
                      title="Delete scan"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function Settings() {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

  return (
    <div className="p-8 max-w-3xl">
      <h1 className="text-3xl font-bold mb-2">Settings</h1>
      <p className="text-slate-400 mb-8 text-sm">System and analyzer configurations</p>

      <div className="space-y-6">
        <div className="card">
          <h2 className="text-lg font-bold mb-4">Backend Connection</h2>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-slate-400 block mb-1">API Base Endpoint</label>
              <input type="text" readOnly value={apiUrl} className="input font-mono text-sm opacity-80" />
            </div>
          </div>
        </div>

        <div className="card">
          <h2 className="text-lg font-bold mb-4">SSRF & Security Policies</h2>
          <div className="space-y-3 text-sm text-slate-300">
            <div className="flex items-center justify-between py-2 border-b border-slate-800">
              <div>
                <p className="font-medium">Block Private & Cloud Metadata IPs</p>
                <p className="text-xs text-slate-500">Prevents SSRF scans targeting RFC1918 and cloud metadata</p>
              </div>
              <span className="bg-green-900/50 text-green-400 text-xs px-2.5 py-1 rounded-full font-bold">
                ENFORCED
              </span>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-slate-800">
              <div>
                <p className="font-medium">Automated Sensitive Data Redaction</p>
                <p className="text-xs text-slate-500">Redacts Authorization, API Keys, and session tokens</p>
              </div>
              <span className="bg-green-900/50 text-green-400 text-xs px-2.5 py-1 rounded-full font-bold">
                ENABLED
              </span>
            </div>
            <div className="flex items-center justify-between py-2">
              <div>
                <p className="font-medium">Mandatory Authorization Check</p>
                <p className="text-xs text-slate-500">Requires affirmative user confirmation before scanning</p>
              </div>
              <span className="bg-blue-900/50 text-blue-400 text-xs px-2.5 py-1 rounded-full font-bold">
                REQUIRED
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
