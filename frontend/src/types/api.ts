export interface AnalyzeRequest {
  description: string
  incident_id?: string
  external_reference?: string
  metadata?: Record<string, unknown>
}

export interface MitreTechniqueResponse {
  technique_id: string
  name: string
  tactic: string | null
  url: string | null
}

export interface AttackMatchResponse {
  attack_id: string
  name: string
  semantic_score: number
  keyword_score: number
  hybrid_score: number
  mitre_techniques: MitreTechniqueResponse[]
}

export interface ResponsePlaybookResponse {
  containment: string[]
  investigation: string[]
  recovery: string[]
  prevention: string[]
  detection_rules: string[]
}

export interface AnalyzeResponse {
  analysis_id: string
  incident_id: string
  primary_match: AttackMatchResponse
  alternatives: AttackMatchResponse[]
  severity: string
  novelty_status: string
  confidence: number
  playbook: ResponsePlaybookResponse
  explanation: string[]
  requires_review: boolean
  model_version: string
  review_status: string
  created_at: string
}

export interface ApiErrorResponse {
  error: {
    code: string
    message: string
    details: Array<Record<string, unknown>>
  }
  request_id: string
}
