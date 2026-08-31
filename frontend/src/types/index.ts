export interface Scan {
  scan_id: string
  target: string
  final_url?: string
  status: 'pending' | 'completed' | 'failed'
  security_score?: number
  http_status?: number
  response_time_ms?: number
  redirect_count: number
  server_info?: string
  content_type?: string
  response_headers: Record<string, string>
  findings: Finding[]
  severity_counts: SeverityCount
  created_at: string
  completed_at?: string
  error_message?: string
}

export interface Finding {
  id: string
  title: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  category: string
  description: string
  evidence: Record<string, any>
  impact: string
  remediation: string
  reference?: string
  cwe?: string
  owasp?: string
}

export interface SeverityCount {
  CRITICAL: number
  HIGH: number
  MEDIUM: number
  LOW: number
  INFO: number
}

export interface AnalyzeRequest {
  target: string
  authorization_confirmed: boolean
}
