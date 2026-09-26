import { semanticRank, semanticModel } from "./semantic";
import { RETRIEVAL_CORPUS } from "../data/retrievalCorpus";
import type {
  AnalyzeRequest, AnalyzeResponse, AttackMatchResponse, EvidenceItem,
  Hypothesis, InvestigationStep, MitreTechniqueResponse, SourceVerification
} from "../types/api";

type Candidate = {
  id: string
  name: string
  category: string
  keywords: string[]
  techniques: MitreTechniqueResponse[]
  playbook: {
    investigation: string[]
    containment: string[]
    recovery: string[]
    prevention: string[]
    detection_rules: string[]
  }
  beginner: string[]
}

const technique = (id: string, name: string, tactic: string): MitreTechniqueResponse => ({
  technique_id: id,
  name,
  tactic,
  url: `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`
})

const CANDIDATES: Candidate[] = [
  { id:"phishing", name:"Phishing", category:"Initial Access", keywords:["phishing","phish","spoofed email","credential link","login link","malicious link","spearphishing"], techniques:[technique("T1566","Phishing","Initial Access"),technique("T1566.002","Phishing: Spearphishing Link","Initial Access")], playbook:{investigation:["Inspect original headers and sender infrastructure.","Extract every URL and follow redirects in a safe analysis environment.","Correlate the recipient's authentication and mailbox activity."],containment:["Quarantine the message and preserve the original.","Protect or challenge affected accounts if compromise is supported."],recovery:["Reset confirmed exposed credentials and revoke active sessions."],prevention:["Strengthen mail filtering and phishing-resistant MFA."],detection_rules:["Correlate suspicious messages with subsequent anomalous authentication."]}, beginner:["Check the original email, not a screenshot.","Inspect sender, Reply-To, URLs and redirects.","Check whether the user entered credentials.","Correlate the timestamp with sign-in logs."] },
  { id:"brute_force", name:"Brute-Force Authentication Attack", category:"Credential Access", keywords:["brute force","brute-force","multiple login attempts","repeated login attempts","repeated failed login","failed login attempts","many failed logins","password guessing","credential guessing","login attempts","unknown ip","unknown ip address","authentication attempts","authentication failures"], techniques:[technique("T1110","Brute Force","Credential Access"),technique("T1110.001","Password Guessing","Credential Access")], playbook:{investigation:["Count failed and successful authentication attempts over time.","Identify source IPs, targeted accounts, geography, device and MFA outcomes.","Determine whether one account, many accounts, or one source was targeted.","Correlate successful authentication with activity immediately afterward."],containment:["Apply approved authentication protections such as rate limiting or account protection.","Protect confirmed affected accounts and preserve authentication telemetry."],recovery:["Reset confirmed compromised credentials and revoke suspicious sessions."],prevention:["Use phishing-resistant MFA, rate limiting and password protection controls."],detection_rules:["Detect repeated authentication failures followed by a successful login from the same or related source."]}, beginner:["Count the failed login attempts and time window.","Identify the source IP and targeted account(s).","Check whether a login eventually succeeded.","Review MFA and post-login activity."] },
  { id:"valid_accounts", name:"Valid Accounts / Account Compromise", category:"Credential Access", keywords:["stolen credential","compromised account","valid account","password spray","credential reuse","impossible travel","unusual login","login from","successful login"], techniques:[technique("T1078","Valid Accounts","Defense Evasion / Persistence / Privilege Escalation / Initial Access")], playbook:{investigation:["Review sign-in history, source IP, device, MFA and geography.","Compare the activity with the user's normal baseline.","Trace actions performed after authentication."],containment:["Protect the affected identity using approved account controls.","Revoke suspicious sessions and tokens when compromise is confirmed."],recovery:["Reset credentials and review MFA registrations."],prevention:["Use phishing-resistant MFA and conditional access."],detection_rules:["Detect anomalous authentication and impossible-travel sequences."]}, beginner:["Identify the account and source IP.","Check whether the device and location are normal.","Check MFA result.","Review activity immediately after login."] },
  { id:"execution", name:"Command and Script Execution", category:"Execution", keywords:["powershell","cmd.exe","command prompt","wscript","cscript","bash","script","encoded command","execution"], techniques:[technique("T1059","Command and Scripting Interpreter","Execution"),technique("T1059.001","PowerShell","Execution")], playbook:{investigation:["Capture the exact command line and parent process.","Inspect script contents, downloaded files and destinations.","Check persistence and follow-on process activity."],containment:["Isolate an affected endpoint only under approved IR procedure."],recovery:["Remove confirmed malicious artifacts and restore from trusted state."],prevention:["Constrain unnecessary scripting and administrative execution."],detection_rules:["Alert on suspicious parent-child process chains and encoded commands."]}, beginner:["Copy the exact command line.","Find the parent process.","Determine what the command downloaded or changed.","Check the same user and host for follow-on events."] },
  { id:"malware", name:"Malware / Malicious File", category:"Execution", keywords:["malware","trojan","payload","malicious file","exe","dll","ransomware","backdoor","dropper","virus"], techniques:[technique("T1204.002","User Execution: Malicious File","Execution"),technique("T1105","Ingress Tool Transfer","Command and Control")], playbook:{investigation:["Hash and safely identify the file.","Inspect process tree, persistence and network destinations.","Search for the same hash or behavior across hosts."],containment:["Isolate affected hosts through approved EDR workflow."],recovery:["Remove confirmed malware and restore affected systems as required."],prevention:["Harden application control and endpoint protection."],detection_rules:["Correlate new executable creation with unusual outbound traffic."]}, beginner:["Record the file hash.","Find the process that launched it.","Check network connections.","Search whether other hosts have the same indicator."] },
  { id:"persistence", name:"Persistence", category:"Persistence", keywords:["scheduled task","startup","run key","registry run","service created","persistence","cron","autorun"], techniques:[technique("T1053","Scheduled Task/Job","Persistence"),technique("T1547","Boot or Logon Autostart Execution","Persistence")], playbook:{investigation:["Enumerate the persistence mechanism and creator.","Identify the account, parent process and creation time.","Trace the payload launched by the persistence mechanism."],containment:["Disable only confirmed malicious persistence using approved procedure."],recovery:["Remove persistence and verify it does not recreate."],prevention:["Monitor new services, scheduled tasks and autostart locations."],detection_rules:["Alert on unusual persistence creation by non-administrative processes."]}, beginner:["Identify exactly what starts automatically.","Find who created it and when.","Inspect the program or command it launches.","Check whether it recreates after removal."] },
  { id:"privilege_escalation", name:"Privilege Escalation", category:"Privilege Escalation", keywords:["privilege escalation","admin rights","elevated","uac bypass","sudo","root","administrator","system account"], techniques:[technique("T1548","Abuse Elevation Control Mechanism","Privilege Escalation")], playbook:{investigation:["Determine the privilege transition and initiating process.","Review token, group membership and elevation events.","Identify the resource accessed after elevation."],containment:["Protect affected privileged identities and systems."],recovery:["Remove unauthorized privilege changes and rotate compromised credentials."],prevention:["Apply least privilege and monitor elevation events."],detection_rules:["Correlate elevation events with unusual process creation."]}, beginner:["Identify the original user.","Determine when privileges changed.","Find the process that requested elevation.","Check what happened immediately after elevation."] },
  { id:"defense_evasion", name:"Defense Evasion", category:"Defense Evasion", keywords:["disable defender","disable antivirus","tamper","clear logs","delete logs","obfuscated","encoded","bypass detection","security tool disabled"], techniques:[technique("T1562.001","Impair Defenses: Disable or Modify Tools","Defense Evasion"),technique("T1070","Indicator Removal","Defense Evasion")], playbook:{investigation:["Determine what security control changed and by which process.","Preserve available telemetry before further destructive changes.","Trace the activity before and after the evasion event."],containment:["Protect affected security controls and endpoints."],recovery:["Restore security tooling and investigate preceding activity."],prevention:["Restrict security-control modification privileges."],detection_rules:["Alert on security-tool tampering and unexpected log clearing."]}, beginner:["Record exactly which control changed.","Find who or what changed it.","Check events immediately before the change.","Look for payload execution or persistence after it."] },
  { id:"discovery", name:"Discovery", category:"Discovery", keywords:["network scan","nmap","whoami","ipconfig","systeminfo","net user","net group","discovery","enumeration","directory listing"], techniques:[technique("T1046","Network Service Scanning","Discovery"),technique("T1087","Account Discovery","Discovery")], playbook:{investigation:["Identify the command, source host and target range.","Determine whether the activity matches an approved administrative scan.","Correlate discovery with subsequent access attempts."],containment:["Restrict suspicious scanning where approved."],recovery:["Review exposed services and credentials if compromise is established."],prevention:["Limit unnecessary network exposure and monitor reconnaissance."],detection_rules:["Correlate discovery commands with later authentication or exploitation."]}, beginner:["Find who ran the scan.","Identify the source and targets.","Check whether it is approved.","Look for what happened after discovery."] },
  { id:"lateral_movement", name:"Lateral Movement", category:"Lateral Movement", keywords:["lateral movement","rdp","remote desktop","smb","psexec","winrm","ssh","remote service","internal host","east-west"], techniques:[technique("T1021","Remote Services","Lateral Movement"),technique("T1021.001","Remote Services: RDP","Lateral Movement")], playbook:{investigation:["Map source host, destination host and identity.","Review authentication and remote-service telemetry.","Trace the path across hosts and privileged accounts."],containment:["Restrict confirmed suspicious remote sessions under approved controls."],recovery:["Rotate compromised credentials and remove unauthorized persistence."],prevention:["Reduce remote-service exposure and enforce strong authentication."],detection_rules:["Correlate unusual east-west authentication with process activity."]}, beginner:["Write down source and destination.","Identify the account used.","Check whether the connection was expected.","Follow the same account across other hosts."] },
  { id:"command_control", name:"Command and Control", category:"Command and Control", keywords:["c2","command and control","beacon","beaconing","callback","dns tunnel","reverse shell","cobalt","external connection","periodic connection"], techniques:[technique("T1071","Application Layer Protocol","Command and Control"),technique("T1105","Ingress Tool Transfer","Command and Control")], playbook:{investigation:["Analyze destination, timing, protocol and process ownership.","Look for periodic or unusual outbound communication.","Correlate network activity with endpoint execution."],containment:["Restrict confirmed malicious destinations using approved controls."],recovery:["Remove the communicating payload after evidence preservation."],prevention:["Improve egress controls and network analytics."],detection_rules:["Detect periodic outbound connections correlated with suspicious processes."]}, beginner:["Identify the process making the connection.","Record destination and port.","Check whether the traffic repeats.","Look for the process that created the connection."] },
  { id:"collection", name:"Collection", category:"Collection", keywords:["collect files","archive","zip","screenshot","clipboard","keylogging","staging","sensitive files","data collection"], techniques:[technique("T1114","Email Collection","Collection"),technique("T1113","Screen Capture","Collection")], playbook:{investigation:["Identify what data was accessed or staged.","Determine the account, host and collection mechanism.","Look for subsequent transfer or exfiltration."],containment:["Protect affected data stores and identities."],recovery:["Assess accessed data and required recovery actions."],prevention:["Apply least privilege and monitor sensitive-data access."],detection_rules:["Correlate bulk access or staging with unusual outbound activity."]}, beginner:["Identify what data was accessed.","Find the user and host.","Check whether files were staged or archived.","Look for transfer activity afterward."] },
  { id:"exfiltration", name:"Exfiltration", category:"Exfiltration", keywords:["exfiltration","data theft","upload","uploaded data","large outbound","cloud storage","stolen data","transfer data"], techniques:[technique("T1041","Exfiltration Over C2 Channel","Exfiltration"),technique("T1567","Exfiltration Over Web Service","Exfiltration")], playbook:{investigation:["Quantify the data transferred and destination.","Identify the source process and account.","Determine whether the transfer was authorized."],containment:["Restrict confirmed malicious transfer paths using approved controls."],recovery:["Assess exposed information and affected identities."],prevention:["Strengthen egress controls and sensitive-data monitoring."],detection_rules:["Detect unusual outbound volume and sensitive-data staging."]}, beginner:["Find the destination.","Measure the amount of data.","Identify the process and account.","Check whether the transfer was authorized."] },
  { id:"impact", name:"Impact / Ransomware", category:"Impact", keywords:["ransomware","encrypted files","file encryption","data destruction","wiper","service stopped","impact","denial of service"], techniques:[technique("T1486","Data Encrypted for Impact","Impact"),technique("T1490","Inhibit System Recovery","Impact")], playbook:{investigation:["Determine affected systems and scope.","Preserve evidence and identify the initiating account/process.","Check backup and recovery integrity."],containment:["Follow approved incident containment and isolation procedures."],recovery:["Recover from trusted backups after root cause and persistence are addressed."],prevention:["Protect backups and restrict high-impact administrative actions."],detection_rules:["Correlate mass file changes with suspicious process execution."]}, beginner:["Determine what is affected.","Find the first affected host.","Identify the process and account responsible.","Protect evidence and escalate immediately."] },
  { id:"web_attack", name:"Web Application Attack", category:"Initial Access / Execution", keywords:["sql injection","sqli","xss","web shell","command injection","path traversal","web application","http exploit","upload shell"], techniques:[technique("T1190","Exploit Public-Facing Application","Initial Access")], playbook:{investigation:["Inspect HTTP requests, response codes and application logs.","Identify the vulnerable endpoint and payload.","Check for shell execution, persistence and follow-on access."],containment:["Protect the affected application through approved controls."],recovery:["Patch or mitigate the exploited condition after evidence preservation."],prevention:["Harden input validation, authentication and exposed services."],detection_rules:["Correlate exploit-like requests with process or file creation."]}, beginner:["Find the request that triggered the alert.","Check the application response.","Inspect server-side process/file changes.","Look for a follow-on shell or outbound connection."] },
  { id:"credential_access", name:"Credential Access", category:"Credential Access", keywords:["credential dumping","lsass","mimikatz","password dump","hash dump","token theft","credential access","ntds"], techniques:[technique("T1003","OS Credential Dumping","Credential Access"),technique("T1555","Credentials from Password Stores","Credential Access")], playbook:{investigation:["Identify the credential source and process.","Check access to credential stores and privileged processes.","Trace use of recovered credentials."],containment:["Protect affected accounts and hosts."],recovery:["Rotate potentially exposed credentials and revoke tokens."],prevention:["Protect credential stores and enforce privileged-access controls."],detection_rules:["Monitor access to credential stores by unusual processes."]}, beginner:["Identify what credential store was accessed.","Find the process and account.","Check whether credentials were actually obtained.","Trace subsequent authentication using them."] },
  { id:"benign_admin", name:"Authorized / Benign Administrative Activity", category:"Benign", keywords:["approved change","maintenance","administrator","scheduled maintenance","backup job","patching","monitoring","deployment","automation"], techniques:[], playbook:{investigation:["Verify the change ticket, owner, time window and expected host scope.","Correlate process and authentication activity with the approved task.","Look for unexplained actions outside the change."],containment:[],recovery:["No recovery action if activity is verified as authorized."],prevention:["Document approved administrative baselines where appropriate."],detection_rules:["Tune detections using validated benign context rather than simply suppressing alerts."]}, beginner:["Find the change ticket or approval.","Verify user, host and time window.","Check that the observed commands match the approved work.","Look for anything outside the approved scope."] }
];

const lower = (s:string) => s.toLowerCase();
function lexicalScoreCandidate(c:Candidate, text:string): number {
  const hits = c.keywords.filter(k => text.includes(k)).length;
  if (!hits) return 0;
  const unique = new Set(c.keywords.filter(k => text.includes(k)));
  const density = Math.min(unique.size / 5, 1);
  return Math.min(0.18 + hits * 0.095 + density * 0.42, 0.97);
}

function candidateText(c: Candidate): string {
  const d = RETRIEVAL_CORPUS.find(x => String(x.id).toLowerCase().includes(c.id.toLowerCase()) || String(x.text).toLowerCase().includes(c.name.toLowerCase()));
  return d?.text ?? `${c.name} ${c.category} ${c.keywords.join(" ")} ${c.playbook.investigation.join(" ")}`;
}

async function rankCandidates(text: string): Promise<Array<{c:Candidate; score:number; semantic:number; lexical:number}>> {
  const semantic = await semanticRank(text, CANDIDATES.map(c => ({id:c.id,text:candidateText(c)})));
  return CANDIDATES.map(c => {
    const lexical=lexicalScoreCandidate(c,text);
    const semanticScore=Math.max(0,semantic.get(c.id) ?? 0);
    const score=Math.min(0.97, semanticScore*0.62 + lexical*0.38);
    return {c,score,semantic:semanticScore,lexical};
  }).sort((a,b)=>b.score-a.score);
}

function evidenceFor(c:Candidate, text:string): EvidenceItem[] {
  const items:EvidenceItem[] = [];
  c.keywords.filter(k=>text.includes(k)).slice(0,5).forEach((k,i)=>items.push({
    id:`${c.id}-support-${i}`, text:`Observed indicator: "${k}"`, type:"supporting", source:"user-supplied activity", strength:0.55+i*0.06
  }));
  if (!items.length) items.push({id:`${c.id}-missing`,text:"No direct indicator for this hypothesis was supplied.",type:"missing",source:"user-supplied activity",strength:0});
  return items;
}

function buildHypothesis(c:Candidate, score:number, text:string): Hypothesis {
  const ev=evidenceFor(c,text);
  const support=ev.filter(x=>x.type==="supporting").map(x=>x.text);
  const missing:string[]=[];
  if(c.id!=="benign_admin") missing.push("Authorization/baseline evidence", "Correlated endpoint or network telemetry");
  if(c.id==="benign_admin") missing.push("Change ticket or administrator confirmation");
  const status = score>=0.7 ? "supported" : score>=0.45 ? "possible" : score>=0.2 ? "weak" : "contradicted";
  return {id:c.id,name:c.name,category:c.category,score,status,supporting:support,contradicting:[],missing,techniques:c.techniques};
}

function playbookFor(c:Candidate, top:Candidate[]) {
  const investigation=[...c.playbook.investigation];
  top.slice(1,3).forEach(x=>investigation.push(`Differentiate from ${x.name} using identity, endpoint and network evidence.`));
  return {...c.playbook,investigation};
}

function buildSteps(): InvestigationStep[] {
  const steps:InvestigationStep[]=[
    {order:1,title:"Preserve the original activity",action:"Record the exact alert/log/email/command and timestamp before changing anything.",whatToLookFor:"Original event, user, host, source/destination, timestamp and alert context.",supports:["A reproducible event exists."],contradicts:["The alert cannot be reproduced or source data is invalid."]},
    {order:2,title:"Identify the identity and asset",action:"Determine who performed the activity and which host, application or account was involved.",whatToLookFor:"Username, device, IP, process, application and asset owner.",supports:["Known affected identity/asset."],contradicts:["Identity or asset attribution is inconsistent."]},
    {order:3,title:"Check authorization and baseline",action:"Determine whether the activity was expected, approved or normal for this user/host.",whatToLookFor:"Change ticket, maintenance window, known automation, normal source and device.",supports:["Approved and expected activity supports benign hypothesis."],contradicts:["No authorization or clear deviation from baseline."]},
    {order:4,title:"Correlate surrounding telemetry",action:"Review events immediately before and after the activity.",whatToLookFor:"Authentication, process tree, network connections, mailbox, file and privilege events.",supports:["Coherent malicious sequence supports a security hypothesis."],contradicts:["Independent benign explanation with no suspicious follow-on activity."]},
    {order:5,title:"Verify the leading hypotheses",action:"Test the strongest and competing hypotheses against supporting and contradicting evidence.",whatToLookFor:"Evidence that distinguishes phishing, malware, credential abuse, lateral movement, benign administration and other candidates.",supports:["One hypothesis explains the evidence with few contradictions."],contradicts:["A competing hypothesis explains the evidence better."]},
    {order:6,title:"Determine impact and scope",action:"Identify affected accounts, hosts, data and follow-on actions.",whatToLookFor:"Additional victims, persistence, privilege changes, data access or transfer.",supports:["Broader correlated impact increases incident confidence."],contradicts:["No impact and verified benign scope."]},
    {order:7,title:"Record verdict and next action",action:"Assign TP/FP/TN/FN only when alert state and investigated security state are supported by evidence.",whatToLookFor:"Alert presence plus verified malicious/benign outcome.",supports:["Evidence supports a defensible verdict."],contradicts:["Evidence is insufficient; keep UNDETERMINED and escalate."]}
  ];
  return steps;
}

async function verifyMitre(candidates:Candidate[]): Promise<SourceVerification[]> {
  const url="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
  try {
    const cached=sessionStorage.getItem("ra-xsoc-mitre-enterprise");
    const raw: { objects?: Array<{ type?: string; revoked?: boolean; x_mitre_deprecated?: boolean; external_references?: Array<{ source_name?: string; external_id?: string }> }> } = cached ? JSON.parse(cached) : await (await fetch(url,{cache:"force-cache"})).json();
    if(!cached) sessionStorage.setItem("ra-xsoc-mitre-enterprise",JSON.stringify(raw));
    const ids=new Set<string>();
    for(const o of raw.objects ?? []) if(o.type==="attack-pattern" && !o.revoked && !o.x_mitre_deprecated) { const id=o.external_references?.find(r=>r.source_name==="mitre-attack")?.external_id; if(id) ids.add(id); }
    const wanted=candidates.flatMap(c=>c.techniques.map(t=>t.technique_id));
    const verified=wanted.filter(id=>ids.has(id));
    return [{source:"MITRE ATT&CK Enterprise STIX",status:verified.length?"verified":"partial",version:"current Enterprise STIX release",details:`${verified.length}/${wanted.length || 1} candidate technique mappings verified against the machine-readable ATT&CK dataset.`,url:"https://attack.mitre.org/"}];
  } catch {
    return [{source:"MITRE ATT&CK Enterprise STIX",status:"unavailable",details:"Live verification was unavailable in this browser session; local technique mappings are retained and human review is required.",url:"https://attack.mitre.org/"}];
  }
}

export async function analyzeInBrowser(request: AnalyzeRequest): Promise<AnalyzeResponse> {
  const text=lower(request.description);
  const scored=await rankCandidates(text);
  const nonzero=scored.filter(x=>x.score>0);
  const top=(nonzero.length?nonzero:scored.slice(0,6)).slice(0,8);
  const primary=top[0];
  const alternatives=top.slice(1).map(x=>toMatch(x.c,x.score,x.semantic,x.lexical));
  const hypotheses=top.map(x=>buildHypothesis(x.c,x.score,text));
  const attackSignals = [
    "multiple login attempts","repeated login attempts","failed login attempts","password guessing",
    "credential guessing","brute force","brute-force","authentication failures","successful login",
    "phishing","malicious link","powershell","ransomware","lateral movement","rdp","psexec"
  ];
  const matchedSignals=attackSignals.filter(s=>text.includes(s));
  const unmatchedFeatures = text.split(/[^a-z0-9.-]+/).filter(x=>x.length>4 && !CANDIDATES.some(c=>c.keywords.includes(x))).slice(0,12);
  const primaryScore=Math.max(primary.score,0.01);
  const knownSimilarity=Math.min(primaryScore,0.97);
  const behaviorCoverage=Math.min(matchedSignals.length/4,1);
  const unseenSignalRatio=matchedSignals.length ? Math.min(unmatchedFeatures.length/Math.max(matchedSignals.length,1),1) : 0;
  const combinationNovelty = top.length>=3 && matchedSignals.length>=3 ? Math.min(0.25 + matchedSignals.length*0.08,0.8) : 0;
  const noveltyScore=Math.min(1,Math.max(0,(1-knownSimilarity)*0.55 + unseenSignalRatio*0.25 + combinationNovelty*0.20));
  const noveltyStatus: "KNOWN_PATTERN"|"NOVEL_BEHAVIOR"|"NOVEL_COMBINATION"|"INSUFFICIENT_EVIDENCE" =
    matchedSignals.length===0 ? "INSUFFICIENT_EVIDENCE" :
    noveltyScore>=0.72 ? "NOVEL_BEHAVIOR" :
    combinationNovelty>=0.45 ? "NOVEL_COMBINATION" :
    knownSimilarity>=0.70 ? "KNOWN_PATTERN" : "INSUFFICIENT_EVIDENCE";
  const incident = {
    name: primary.c.name,
    attack_family: primary.c.category,
    stage: primary.c.techniques[0]?.tactic ?? primary.c.category,
    confidence: primaryScore,
    description: `${primary.c.name} suspected from observed behavior: ${request.description.trim()}`
  };
  const novelty = {
    score: noveltyScore,
    status: noveltyStatus,
    known_similarity: knownSimilarity,
    behavior_coverage: behaviorCoverage,
    unseen_signal_ratio: unseenSignalRatio,
    combination_novelty: combinationNovelty,
    reasons: [
      `Known-pattern similarity: ${(knownSimilarity*100).toFixed(0)}%.`,
      `Recognized behavior signals: ${matchedSignals.length}.`,
      unseenSignalRatio>0 ? `${unmatchedFeatures.length} input features were not directly represented by the local attack vocabulary.` : "Observed features map to existing attack vocabulary.",
      combinationNovelty>0 ? "Multiple behavior signals form a combined pattern that should be evaluated against prior incidents." : "No strong novel combination signal was detected."
    ]
  };
  const research = {
    feature_vector: matchedSignals,
    matched_pattern_ids: top.map(x=>x.c.id),
    unmatched_features: unmatchedFeatures,
    hypothesis_count: hypotheses.length,
    technique_count: new Set(top.flatMap(x=>x.c.techniques.map(t=>t.technique_id))).size,
    reproducible: true,
    evaluation_version: "RA-XSOC-X-EVAL-1.0"
  };
  const verification=await verifyMitre(top.map(x=>x.c));
  const alertPresent=/alert|alerted|detection|siem|edr|ids|wazuh|splunk|sentinel|rule fired|blocked/.test(text);
  const benignScore=top.find(x=>x.c.id==="benign_admin")?.score ?? 0;
  const maliciousScore=Math.max(...top.filter(x=>x.c.id!=="benign_admin").map(x=>x.score),0);
  const securityState: "malicious"|"benign"|"undetermined" = maliciousScore>=0.72 && maliciousScore>benignScore+0.12 ? "malicious" : benignScore>=0.72 && benignScore>maliciousScore+0.12 ? "benign" : "undetermined";
  const detectionState=alertPresent?"alert-present":"no-alert-supplied";
  let verdict: "TRUE POSITIVE"|"FALSE POSITIVE"|"TRUE NEGATIVE"|"FALSE NEGATIVE"|"UNDETERMINED"="UNDETERMINED";
  if(securityState==="malicious") verdict=alertPresent?"TRUE POSITIVE":"FALSE NEGATIVE";
  else if(securityState==="benign") verdict=alertPresent?"FALSE POSITIVE":"TRUE NEGATIVE";
  const severity=securityState==="malicious"?(maliciousScore>=0.85?"critical":"high"):"medium";
  const steps=buildSteps();
  const candidateList=top.map(x=>x.c.name).join(", ");
  const explanation=[
    `The engine evaluated ${CANDIDATES.length} behavior hypotheses instead of selecting one attack type up front.`,
    `Leading candidates: ${candidateList}.`,
    `MITRE verification: ${verification[0]?.status ?? "unavailable"}. The verifier is independent of the keyword ranking.`,
    securityState==="undetermined" ? "The supplied activity is insufficient to establish the real security state; collect the next evidence before assigning TP/FP/TN/FN." : `Evidence currently supports a ${securityState} security state.`
  ];
  const nextEvidence=["Original alert/rule context","Identity + source/destination IP/device","Authentication and MFA events","Endpoint process tree or application logs","Authorization/change-ticket context"];
  const primaryMatch=toMatch(primary.c,Math.max(primary.score,0.01),primary.semantic,primary.lexical);
  const now=new Date().toISOString();
  return {
    analysis_id:`rx-x-${Date.now()}`,incident_id:request.incident_id??`incident-${Date.now()}`,
    primary_match:primaryMatch,incident,novelty,research,alternatives,severity,novelty_status:novelty.status,confidence:Math.max(0.35,Math.min(primary.score,0.97)),
    playbook:playbookFor(primary.c,top.map(x=>x.c)),explanation,requires_review:true,model_version:`ra-xsoc-x-investigation-engine-1.1-browser-${semanticModel}`,
    review_status:"PENDING_HUMAN_REVIEW",created_at:now,evidence:evidenceFor(primary.c,text),hypotheses,verification,investigation:steps,
    assessment:{detectionState,securityState,verdict,rationale:verdict==="UNDETERMINED"?"Do not force a verdict until the missing evidence is collected.":`Current evidence supports ${verdict}.`},
    next_evidence:nextEvidence,beginner_summary:primary.c.beginner
  };
}

function toMatch(c:Candidate,score:number):AttackMatchResponse {
  return {attack_id:c.id,name:c.name,semantic_score:Math.max(0,score-0.05),keyword_score:Math.max(0,score-0.01),hybrid_score:score,mitre_techniques:c.techniques};
}
