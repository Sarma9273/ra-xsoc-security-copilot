export type InvestigationQuestion = { id:string; question:string; evidenceType:string; informationGain:number; distinguishes:string[] };

type Candidate = {id:string;name:string;keywords:string[]};

export function planInvestigation(candidates:Candidate[], observed:string[]): InvestigationQuestion[] {
  const signals=new Set(observed);
  const questions=[
    {id:"auth",question:"Was there an authentication event, and was it successful or failed?",evidenceType:"authentication",tests:["brute_force","valid_accounts","password_spraying","credential_stuffing"]},
    {id:"process",question:"Which process or command produced the activity, and what was its parent process?",evidenceType:"endpoint process",tests:["execution","malware","persistence","web_attack"]},
    {id:"network",question:"Which source and destination communicated, over which protocol and port?",evidenceType:"network",tests:["command_control","lateral_movement","exfiltration","discovery"]},
    {id:"authorization",question:"Was the activity explicitly authorized by a user, change ticket, automation or maintenance window?",evidenceType:"authorization",tests:["benign_admin"]},
    {id:"scope",question:"Did the same behavior occur on other accounts, hosts or applications?",evidenceType:"scope correlation",tests:["lateral_movement","credential_stuffing","password_spraying","ransomware"]},
    {id:"impact",question:"Was sensitive data accessed, changed, encrypted, transferred or destroyed?",evidenceType:"impact",tests:["collection","exfiltration","impact"]},
    {id:"email",question:"Was there an original email, sender infrastructure, URL, attachment or credential-entry event?",evidenceType:"email evidence",tests:["phishing","business_email_compromise"]}
  ];
  return questions.map(q=>({...q,informationGain:Math.min(1,q.tests.filter(t=>candidates.some(c=>c.id===t)).length*0.2+q.tests.filter(t=>!signals.has(t)).length*0.1),distinguishes:q.tests.filter(t=>candidates.some(c=>c.id===t))})).sort((a,b)=>b.informationGain-a.informationGain).slice(0,5);
}
