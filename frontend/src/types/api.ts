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

export interface EvidenceItem {
  id: string
  text: string
  type: "supporting" | "contradicting" | "missing"
  source: string
  strength: number
}

export interface Hypothesis {
  id: string
  name: string
  category: string
  score: number
  status: "supported" | "possible" | "weak" | "contradicted"
  supporting: string[]
  contradicting: string[]
  missing: string[]
  techniques: MitreTechniqueResponse[]
}

export interface SourceVerification {
  source: string
  status: "verified" | "partial" | "unavailable"
  version?: string
  details: string
  url: string
}

export interface InvestigationStep {
  order: number
  title: string
  action: string
  whatToLookFor: string
  supports: string[]
  contradicts: string[]
}

export interface IncidentIdentity {
  name: string
  attack_family: string
  stage: string
  confidence: number
  description: string
}

export interface NoveltyAssessment {
  score: number
  status: "KNOWN_PATTERN" | "NOVEL_BEHAVIOR" | "NOVEL_COMBINATION" | "INSUFFICIENT_EVIDENCE"
  known_similarity: number
  behavior_coverage: number
  unseen_signal_ratio: number
  combination_novelty: number
  reasons: string[]
}

export interface ResearchEvaluation {
  feature_vector: string[]
  matched_pattern_ids: string[]
  unmatched_features: string[]
  hypothesis_count: number
  technique_count: number
  reproducible: boolean
  evaluation_version: string
}

export interface InvestigationAssessment {
  detectionState: "alert-present" | "no-alert-supplied" | "unknown"
  securityState: "malicious" | "benign" | "undetermined"
  verdict: "TRUE POSITIVE" | "FALSE POSITIVE" | "TRUE NEGATIVE" | "FALSE NEGATIVE" | "UNDETERMINED"
  rationale: string
}

export interface AnalyzeResponse {
  analysis_id: string
  incident_id: string
  primary_match: AttackMatchResponse
  incident: IncidentIdentity
  novelty: NoveltyAssessment
  research: ResearchEvaluation
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
  evidence: EvidenceItem[]
  hypotheses: Hypothesis[]
  verification: SourceVerification[]
  investigation: InvestigationStep[]
  assessment: InvestigationAssessment
  next_evidence: string[]
  beginner_summary: string[]
}

export interface ResponsePlaybookResponse {
  containment: string[]
  investigation: string[]
  recovery: string[]
  prevention: string[]
  detection_rules: string[]
}

export interface ApiErrorResponse {
  error: {
    code: string
    message: string
    details: Array<Record<string, unknown>>
  }
  request_id: string
}
