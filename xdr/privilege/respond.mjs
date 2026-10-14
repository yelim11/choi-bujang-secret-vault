import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const TTL_MS=15*60*1000;
const safeId=value=>typeof value==='string'&&/^[a-z0-9][a-z0-9_.-]{0,79}$/iu.test(value)?value:null;
const safeText=value=>typeof value==='string'
  ?value.replace(/[\r\n]+/gu,' ').replace(/(?:Bearer\s+)?eyJ[A-Za-z0-9_.-]+/gu,'[REDACTED]').slice(0,300)
  :'';
const sessionKey=alert=>String(alert?.data?.srcip??'')+'\u0000'+String(alert?.data?.srcuser??'');
const privilegeTechnique=alert=>{
  const ids=Array.isArray(alert?.rule?.mitre)?alert.rule.mitre.map(String):[];
  return ids.some(id=>id==='T1068'||id.startsWith('T1068.')||id==='T1078'||id.startsWith('T1078.'));
};
const expiryFor=timestamp=>{
  const at=Date.parse(timestamp);
  return Number.isFinite(at)?new Date(at+TTL_MS).toISOString():null;
};
const existingLog=async path=>{
  try{return await readFile(path,'utf8')}catch(error){if(error?.code==='ENOENT')return '';throw error}
};

export function buildDenyRules(alerts,decisions){
  const byId=new Map(alerts.map(alert=>[alert?.id,alert]));
  const normalSessions=new Set(
    decisions.filter(decision=>decision?.action==='record')
      .map(decision=>sessionKey(byId.get(decision.alertId)))
  );
  const grouped=new Map();
  for(const decision of decisions){
    if(decision?.action!=='block'||decision.confidence<0.85)continue;
    const alert=byId.get(decision.alertId);
    const sourceAddress=alert?.data?.srcip;
    const account=alert?.data?.srcuser;
    const key=sessionKey(alert);
    if(!privilegeTechnique(alert)
      ||typeof sourceAddress!=='string'||!sourceAddress
      ||typeof account!=='string'||!account
      ||normalSessions.has(key))continue;
    const expiresAt=expiryFor(alert.timestamp);
    if(!expiresAt)continue;
    const current=grouped.get(key)??{
      ruleId:'xdr.privilege.session-'+sourceAddress.replaceAll('.','-')+'-'+account.replace(/[^A-Za-z0-9_-]/gu,'-').slice(0,32),
      action:'deny',
      match:{sourceAddress,account},
      expiresAt,
      evidenceAlertIds:[],
    };
    if(Date.parse(expiresAt)>Date.parse(current.expiresAt))current.expiresAt=expiresAt;
    const id=safeId(alert.id);
    if(id)current.evidenceAlertIds.push(id);
    grouped.set(key,current);
  }
  return [...grouped.values()].map(rule=>({...rule,evidenceAlertIds:[...new Set(rule.evidenceAlertIds)].sort()}));
}

export async function respond({root,fixture,result}){
  const rules=buildDenyRules(fixture.alerts,result.decisions);
  await writeFile(join(root,'xdr','privilege','deny-rules.json'),JSON.stringify({
    schema:'aleph.xdr.ztna-deny-rules.v1',
    moduleKey:'privilege',
    note:'고확신도 권한 가로채기 세션만 회수 후보로 연결하며 기존 판정기 규칙은 수정하지 않습니다.',
    rules,
  },null,2)+'\n','utf8');

  const byId=new Map(fixture.alerts.map(alert=>[alert?.id,alert]));
  const logPath=join(root,'xdr','alerts.log');
  const previous=(await existingLog(logPath)).split(/\r?\n/u).filter(Boolean);
  const preserved=previous.filter(line=>{
    try{return JSON.parse(line)?.moduleKey!=='privilege'}catch{return true}
  });
  const current=result.decisions.filter(decision=>decision.action==='block'||decision.action==='alert').map(decision=>{
    const alert=byId.get(decision.alertId)??{};
    return JSON.stringify({
      moduleKey:'privilege',
      alertId:safeId(decision.alertId)??'unknown',
      action:decision.action,
      confidence:decision.confidence,
      timestamp:safeText(alert.timestamp),
      sourceAddress:safeText(alert?.data?.srcip),
      account:safeText(alert?.data?.srcuser),
      reason:safeText(decision.reason),
    });
  });
  await writeFile(logPath,[...preserved,...current].join('\n')+'\n','utf8');

  const ruleSessions=new Set(rules.map(rule=>rule.match.sourceAddress+'\u0000'+rule.match.account));
  const normalEventsBlocked=result.decisions
    .filter(decision=>decision.action==='record')
    .filter(decision=>ruleSessions.has(sessionKey(byId.get(decision.alertId)))).length;

  await writeFile(join(root,'xdr','privilege','verification.json'),JSON.stringify({
    schema:'aleph.xdr.verification.v1',
    moduleKey:'privilege',
    alertsRead:fixture.alerts.length,
    blockCandidates:rules.length,
    normalEventsBlocked,
    baseDeciderModified:false,
  },null,2)+'\n','utf8');
  return {rules:rules.length,normalEventsBlocked};
}
