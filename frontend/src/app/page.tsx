'use client'

import { useState } from 'react'
import Dashboard from '@/components/Dashboard'
import Analyzer from '@/components/Analyzer'
import Sidebar from '@/components/Sidebar'

export default function Home() {
  const [currentPage, setCurrentPage] = useState<'dashboard' | 'analyzer' | 'history' | 'settings'>('dashboard')

  return (
    <div className="flex h-screen bg-slate-950">
      <Sidebar currentPage={currentPage} onPageChange={setCurrentPage} />
      
      <main className="flex-1 overflow-auto">
        {currentPage === 'dashboard' && <Dashboard />}
        {currentPage === 'analyzer' && <Analyzer />}
        {currentPage === 'history' && <History />}
        {currentPage === 'settings' && <Settings />}
      </main>
    </div>
  )
}

function History() {
  return (
    <div className="p-8">
      <h1 className="text-3xl font-bold mb-6">Scan History</h1>
      <p className="text-slate-400">Scan history coming soon...</p>
    </div>
  )
}

function Settings() {
  return (
    <div className="p-8">
      <h1 className="text-3xl font-bold mb-6">Settings</h1>
      <p className="text-slate-400">Settings coming soon...</p>
    </div>
  )
}
