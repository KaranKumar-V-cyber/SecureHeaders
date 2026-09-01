'use client'

import { useEffect, useState } from 'react'
import { AlertCircle, CheckCircle, TrendingUp } from 'lucide-react'
import { api } from '@/services/api'

interface ScanStats {
  total_scans: number
  total_websites: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  average_score: number
}

interface DashboardProps {
  onNavigate?: (page: 'dashboard' | 'analyzer' | 'history' | 'settings') => void
}

export default function Dashboard({ onNavigate }: DashboardProps) {
  const [stats, setStats] = useState<ScanStats | null>(null)
  const [recentScans, setRecentScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const loadStats = async () => {
      try {
        const response = await api.get('/scans?limit=20')
        const items = response.data.items || []
        const total = response.data.total || 0
        
        let critical = 0
        let high = 0
        let medium = 0
        let low = 0
        let totalScore = 0
        let scoredCount = 0

        items.forEach((item: any) => {
          if (item.severity_counts) {
            critical += item.severity_counts.CRITICAL || 0
            high += item.severity_counts.HIGH || 0
            medium += item.severity_counts.MEDIUM || 0
            low += item.severity_counts.LOW || 0
          }
          if (item.security_score !== null && item.security_score !== undefined) {
            totalScore += item.security_score
            scoredCount += 1
          }
        })

        setRecentScans(items.slice(0, 5))
        setStats({
          total_scans: total,
          total_websites: total,
          critical_findings: critical,
          high_findings: high,
          medium_findings: medium,
          low_findings: low,
          average_score: scoredCount > 0 ? Math.round(totalScore / scoredCount) : 100,
        })
      } catch (error) {
        console.error('Failed to load stats:', error)
      } finally {
        setLoading(false)
      }
    }

    loadStats()
  }, [])

  if (loading) {
    return (
      <div className="p-8 flex justify-center items-center h-screen">
        <div className="loading-spinner" />
      </div>
    )
  }

  return (
    <div className="p-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-4xl font-bold mb-2">Dashboard</h1>
          <p className="text-slate-400">Security header analysis overview</p>
        </div>
        {onNavigate && (
          <button
            onClick={() => onNavigate('analyzer')}
            className="btn-primary flex items-center gap-2"
          >
            New Analysis
          </button>
        )}
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard
          title="Total Scans"
          value={stats?.total_scans || 0}
          icon={<CheckCircle className="w-6 h-6" />}
          color="blue"
        />
        <StatCard
          title="Websites Analyzed"
          value={stats?.total_websites || 0}
          icon={<TrendingUp className="w-6 h-6" />}
          color="green"
        />
        <StatCard
          title="Critical Findings"
          value={stats?.critical_findings || 0}
          icon={<AlertCircle className="w-6 h-6" />}
          color="red"
        />
        <StatCard
          title="Average Score"
          value={`${stats?.average_score || 0}/100`}
          icon={<TrendingUp className="w-6 h-6" />}
          color="purple"
        />
      </div>

      {/* Findings Summary */}
      <div className="card mb-8">
        <h2 className="text-2xl font-bold mb-6">Findings Summary</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <FindingBadge severity="CRITICAL" count={stats?.critical_findings || 0} />
          <FindingBadge severity="HIGH" count={stats?.high_findings || 0} />
          <FindingBadge severity="MEDIUM" count={stats?.medium_findings || 0} />
          <FindingBadge severity="LOW" count={stats?.low_findings || 0} />
        </div>
      </div>

      {/* Recent Scans */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-bold">Recent Scans</h2>
          {onNavigate && recentScans.length > 0 && (
            <button
              onClick={() => onNavigate('history')}
              className="text-blue-400 hover:underline text-sm"
            >
              View all history →
            </button>
          )}
        </div>
        {recentScans.length === 0 ? (
          <div className="text-slate-400">No scans yet. Start analyzing websites to see results here.</div>
        ) : (
          <div className="space-y-3">
            {recentScans.map((scan) => (
              <div
                key={scan.scan_id}
                className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-800"
              >
                <div>
                  <p className="font-mono font-medium text-slate-200">{scan.target}</p>
                  <p className="text-xs text-slate-500">{new Date(scan.created_at).toLocaleString()}</p>
                </div>
                <div className="flex items-center gap-4">
                  <span className="text-sm font-bold text-slate-300">
                    {scan.security_score !== null && scan.security_score !== undefined ? `${scan.security_score}/100` : 'N/A'}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-xs uppercase font-bold ${
                      scan.status === 'completed' ? 'bg-green-900/40 text-green-400' : 'bg-red-900/40 text-red-400'
                    }`}
                  >
                    {scan.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function StatCard({
  title,
  value,
  icon,
  color,
}: {
  title: string
  value: number | string
  icon: React.ReactNode
  color: string
}) {
  const colorClasses = {
    blue: 'bg-blue-900/30 border-blue-800 text-blue-400',
    green: 'bg-green-900/30 border-green-800 text-green-400',
    red: 'bg-red-900/30 border-red-800 text-red-400',
    purple: 'bg-purple-900/30 border-purple-800 text-purple-400',
  }

  return (
    <div className={`card ${colorClasses[color as keyof typeof colorClasses]}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-slate-400 text-sm mb-2">{title}</p>
          <p className="text-3xl font-bold">{value}</p>
        </div>
        <div>{icon}</div>
      </div>
    </div>
  )
}

function FindingBadge({ severity, count }: { severity: string; count: number }) {
  const badgeClass = {
    CRITICAL: 'badge-critical',
    HIGH: 'badge-high',
    MEDIUM: 'badge-medium',
    LOW: 'badge-low',
    INFO: 'badge-info',
  }

  return (
    <div className={`${badgeClass[severity as keyof typeof badgeClass]} flex-col items-center justify-center p-3`}>
      <span className="text-lg font-bold">{count}</span>
      <span className="text-xs">{severity}</span>
    </div>
  )
}
