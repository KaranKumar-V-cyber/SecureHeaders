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

export default function Dashboard() {
  const [stats, setStats] = useState<ScanStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const loadStats = async () => {
      try {
        const response = await api.get('/scans?limit=1')
        // Calculate stats from recent scans
        setStats({
          total_scans: response.data.total || 0,
          total_websites: response.data.total || 0,
          critical_findings: 0,
          high_findings: 0,
          medium_findings: 0,
          low_findings: 0,
          average_score: 75,
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
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-2">Dashboard</h1>
        <p className="text-slate-400">Security header analysis overview</p>
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
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <FindingBadge severity="CRITICAL" count={stats?.critical_findings || 0} />
          <FindingBadge severity="HIGH" count={stats?.high_findings || 0} />
          <FindingBadge severity="MEDIUM" count={stats?.medium_findings || 0} />
          <FindingBadge severity="LOW" count={stats?.low_findings || 0} />
        </div>
      </div>

      {/* Recent Scans Placeholder */}
      <div className="card">
        <h2 className="text-2xl font-bold mb-6">Recent Scans</h2>
        <div className="text-slate-400">No scans yet. Start analyzing websites to see results here.</div>
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
