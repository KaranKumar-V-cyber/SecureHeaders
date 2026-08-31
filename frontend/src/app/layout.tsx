import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'HeaderSentinel - Web Security Header Analyzer',
  description: 'Analyze HTTP response headers and identify security misconfigurations',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="bg-slate-950 text-slate-100">{children}</body>
    </html>
  )
}
