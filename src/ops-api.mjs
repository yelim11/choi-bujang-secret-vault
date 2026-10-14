import { RULE_IDS } from './decider.mjs';
import { collectAttackChecks, summarizeAttempts } from './attack-check.mjs';
import { currentPolicy, diffPolicy, verifySnapshot } from './policy-diff.mjs';
import { verifyNoteSnapshot } from './note-backup.mjs';

export function recoverySummary({policy,notes,config}){
  const out={
    policy:{valid:false,version:null,changes:null},
    notes:{valid:false,version:null,entries:null},
  };
  try{
    verifySnapshot(policy);
    const diff=diffPolicy(policy,currentPolicy(config));
    out.policy={valid:true,version:diff.restoreVersion,changes:diff.changed};
  }catch{}
  try{
    if(verifyNoteSnapshot(notes)===null){
      out.notes={valid:true,version:notes.version,entries:notes.notes.length};
    }
  }catch{}
  return out;
}

export function logLineOf({summary,rules,recovery,commit}){
  const safe=value=>String(value??'na').replace(/\s+/gu,'_').slice(0,40);
  return [
    'ops_view',
    'commit='+safe(commit),
    'total='+summary.total,
    'blocked='+summary.blocked,
    'failed='+summary.failed,
    'not_run='+summary.notRun,
    'rules='+rules.count,
    'policy_valid='+recovery.policy.valid,
    'policy_version='+safe(recovery.policy.version),
    'notes_valid='+recovery.notes.valid,
    'notes_version='+safe(recovery.notes.version),
  ].join(' ');
}

export function createOpsApi({config,policy,notes,now=()=>new Date(),commit=null,collect=collectAttackChecks}){
  return async function ops(request,response){
    response.setHeader('Content-Type','application/json; charset=utf-8');
    response.setHeader('Cache-Control','no-store');
    response.setHeader('X-Content-Type-Options','nosniff');
    response.setHeader('X-Resource-Id','ops.public');
    if(request.method!=='GET'){
      response.setHeader('Allow','GET');
      return response.status(405).json({error:'METHOD_NOT_ALLOWED'});
    }
    try{
      const items=await collect(config,{now});
      const summary=summarizeAttempts(items);
      const rules={count:RULE_IDS.length,ids:[...RULE_IDS]};
      const recovery=recoverySummary({policy,notes,config});
      const logLine=logLineOf({summary,rules,recovery,commit});
      try{console.log(logLine)}catch{}
      return response.status(200).json({
        schema:'aleph.ops.v1',
        checkedAt:now().toISOString(),
        commit,
        rules,
        recovery,
        summary,
        items,
        logLine,
      });
    }catch{
      return response.status(503).json({error:'OPS_UNAVAILABLE'});
    }
  };
}
