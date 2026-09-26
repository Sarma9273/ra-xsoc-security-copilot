export type AnalystFeedback = {
  analysis_id:string;
  predicted_attack_id:string;
  action:"ACCEPTED"|"REJECTED"|"CORRECTED";
  corrected_attack_id?:string;
  timestamp:string;
};
const KEY="ra-xsoc-x-experience-memory-v1";
export function getExperienceMemory(): AnalystFeedback[] { try{return JSON.parse(localStorage.getItem(KEY)||"[]") as AnalystFeedback[];}catch{return [];} }
export function recordFeedback(item:AnalystFeedback): void { const all=getExperienceMemory(); all.push(item); localStorage.setItem(KEY,JSON.stringify(all.slice(-500))); }
export function experienceAdjustment(attackId:string): number { const rows=getExperienceMemory(); const accepted=rows.filter(x=>x.action==="ACCEPTED"&&x.predicted_attack_id===attackId).length; const corrected=rows.filter(x=>x.action==="CORRECTED"&&x.corrected_attack_id===attackId).length; const rejected=rows.filter(x=>x.action==="REJECTED"&&x.predicted_attack_id===attackId).length; return Math.max(-0.12,Math.min(0.12,(accepted+corrected)*0.02-rejected*0.03)); }
