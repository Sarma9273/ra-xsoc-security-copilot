import type { AnalyzeRequest, AnalyzeResponse, AttackMatchResponse } from "../types/api";

const mitre = {
  phishing: [
    { technique_id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access", url: "https://attack.mitre.org/techniques/T1566/002/" },
    { technique_id: "T1078", name: "Valid Accounts", tactic: "Initial Access / Persistence", url: "https://attack.mitre.org/techniques/T1078/" },
  ],
  malware: [
    { technique_id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution", url: "https://attack.mitre.org/techniques/T1204/002/" },
    { technique_id: "T1059.001", name: "PowerShell", tactic: "Execution", url: "https://attack.mitre.org/techniques/T1059/001/" },
  ],
  lateral: [
    { technique_id: "T1021", name: "Remote Services", tactic: "Lateral Movement", url: "https://attack.mitre.org/techniques/T1021/" },
    { technique_id: "T1078", name: "Valid Accounts", tactic: "Initial Access / Persistence", url: "https://attack.mitre.org/techniques/T1078/" },
  ],
};

function match(id: string, name: string, score: number, techniques: AttackMatchResponse["mitre_techniques"]): AttackMatchResponse {
  return {
    attack_id: id,
    name,
    semantic_score: Math.max(0, score - 0.04),
    keyword_score: Math.max(0, score - 0.01),
    hybrid_score: score,
    mitre_techniques: techniques,
  };
}

export function analyzeInBrowser(request: AnalyzeRequest): AnalyzeResponse {
  const text = request.description.toLowerCase();
  const now = new Date().toISOString();
  let primary: AttackMatchResponse;
  let alternatives: AttackMatchResponse[];
  let severity = "medium";
  let explanation: string[];
  let playbook: AnalyzeResponse["playbook"];

  if (/phish|credential|login link|spoof|email/.test(text)) {
    primary = match("phishing", "Phishing", 0.91, mitre.phishing);
    alternatives = [match("account_takeover", "Account Takeover", 0.63, mitre.phishing.slice(1)), match("business_email_compromise", "Business Email Compromise", 0.48, mitre.phishing)];
    severity = "high";
    explanation = [
      "Suspicious email and credential-request indicators were identified.",
      "The incident is consistent with a phishing-led credential compromise path.",
      "ATT&CK mappings are attached to the evidence-supported hypothesis.",
    ];
    playbook = {
      containment: ["Disable or challenge the affected account if compromise is confirmed.", "Invalidate active sessions and tokens."],
      investigation: ["Inspect the original email headers and URL destination.", "Review authentication events around the reported timestamp.", "Check endpoint and mailbox activity for follow-on access."],
      recovery: ["Reset exposed credentials and require MFA reauthentication.", "Remove malicious messages from affected mailboxes."],
      prevention: ["Strengthen phishing-resistant MFA and mail filtering.", "Add confirmed indicators to approved detection controls."],
      detection_rules: ["Alert on suspicious login geography or impossible-travel patterns.", "Correlate credential submission with subsequent authentication anomalies."],
    };
  } else if (/powershell|malware|ransomware|payload|executable|trojan/.test(text)) {
    primary = match("malware", "Malware", 0.88, mitre.malware);
    alternatives = [match("ransomware", "Ransomware", 0.57, mitre.malware), match("web_shell", "Web Shell", 0.41, mitre.malware)];
    severity = "critical";
    explanation = [
      "Execution-oriented indicators were identified in the supplied incident description.",
      "The evidence is consistent with malicious code execution and possible follow-on activity.",
      "Endpoint telemetry should be acquired before treating the hypothesis as confirmed.",
    ];
    playbook = {
      containment: ["Isolate the affected endpoint using an approved EDR workflow.", "Preserve volatile and relevant endpoint evidence."],
      investigation: ["Collect process creation and PowerShell telemetry.", "Inspect parent-child process relationships and network destinations.", "Search for persistence and lateral movement indicators."],
      recovery: ["Remove confirmed malicious artifacts through approved response procedures.", "Restore affected systems from trusted recovery points where required."],
      prevention: ["Constrain unnecessary scripting and execution paths.", "Harden endpoint application controls."],
      detection_rules: ["Monitor suspicious PowerShell execution chains.", "Correlate unsigned binaries with unusual outbound connections."],
    };
  } else if (/lateral|remote desktop|rdp|smb|internal host|remote service/.test(text)) {
    primary = match("lateral_movement", "Lateral Movement", 0.86, mitre.lateral);
    alternatives = [match("active_directory_compromise", "Active Directory Compromise", 0.61, mitre.lateral), match("account_takeover", "Account Takeover", 0.45, mitre.lateral)];
    severity = "high";
    explanation = [
      "Internal remote-access indicators suggest possible movement between hosts.",
      "Valid-account or remote-service abuse should be investigated as competing hypotheses.",
      "Authentication and endpoint evidence are required to confirm the attack path.",
    ];
    playbook = {
      containment: ["Restrict suspicious remote sessions using approved controls.", "Protect affected privileged accounts."],
      investigation: ["Correlate source and destination authentication events.", "Inspect remote-service activity and endpoint process telemetry.", "Map the observed path between hosts and identities."],
      recovery: ["Rotate compromised credentials and review privileged access.", "Remove unauthorized persistence identified during investigation."],
      prevention: ["Reduce unnecessary remote-service exposure.", "Apply least privilege and stronger authentication controls."],
      detection_rules: ["Alert on unusual east-west authentication patterns.", "Correlate new remote sessions with privilege changes."],
    };
  } else {
    primary = match("incident_analysis", "Security Incident", 0.55, []);
    alternatives = [match("phishing", "Phishing", 0.39, mitre.phishing), match("malware", "Malware", 0.36, mitre.malware)];
    explanation = [
      "The supplied description does not contain enough evidence for a high-confidence classification.",
      "The browser demo keeps multiple hypotheses rather than forcing a single conclusion.",
      "Add concrete email, authentication, endpoint, network, or IOC evidence for a stronger result.",
    ];
    playbook = {
      containment: ["Preserve evidence before making disruptive changes.", "Apply only approved containment actions supported by confirmed evidence."],
      investigation: ["Collect the earliest known event and relevant surrounding telemetry.", "Identify affected identities, hosts, indicators, and timestamps."],
      recovery: ["Recover only after the root cause and scope are established."],
      prevention: ["Document confirmed control gaps after investigation."],
      detection_rules: ["Create detections only from validated indicators and behavior."],
    };
  }

  return {
    analysis_id: `demo-${Date.now()}`,
    incident_id: request.incident_id ?? `demo-incident-${Date.now()}`,
    primary_match: primary,
    alternatives,
    severity,
    novelty_status: "known-pattern",
    confidence: primary.hybrid_score,
    playbook,
    explanation,
    requires_review: true,
    model_version: "ra-xsoc-x-browser-demo-1.0",
    review_status: "PENDING_HUMAN_REVIEW",
    created_at: now,
  };
}
