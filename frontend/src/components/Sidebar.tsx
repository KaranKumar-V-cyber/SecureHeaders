'use client'

import { Home, Search, History, Settings, Shield } from 'lucide-react'

interface SidebarProps {
  currentPage: string
  onPageChange: (page: 'dashboard' | 'analyzer' | 'history' | 'settings') => void
}

export default function Sidebar({ currentPage, onPageChange }: SidebarProps) {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Home },
    { id: 'analyzer', label: 'Analyzer', icon: Search },
    { id: 'history', label: 'History', icon: History },
    { id: 'settings', label: 'Settings', icon: Settings },
  ]

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 p-6 flex flex-col">
      {/* Logo */}
      <div className="flex items-center gap-3 mb-8">
        <Shield className="w-8 h-8 text-blue-500" />
        <div>
          <h1 className="text-xl font-bold">HeaderSentinel</h1>
          <p className="text-xs text-slate-400">Security Header Analyzer</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-2">
        {menuItems.map((item) => {
          const Icon = item.icon
          const isActive = currentPage === item.id
          return (
            <button
              key={item.id}
              onClick={() => onPageChange(item.id as any)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors duration-200 ${
                isActive
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-300 hover:bg-slate-800'
              }`}
            >
              <Icon className="w-5 h-5" />
              <span>{item.label}</span>
            </button>
          )
        })}
      </nav>

      {/* Footer */}
      <div className="pt-4 border-t border-slate-800 text-xs text-slate-500">
        <p>v1.0.0</p>
        <p className="mt-1">For authorized security testing only</p>
      </div>
    </aside>
  )
}
