import { collectAttackChecks, summarizeAttempts } from './attack-check.mjs';
import { runRuleCheck } from './rule-check.mjs';

export function createChecksApi({config,now=()=>new Date(),commit=null}){
  return async function checks(request,response){
    response.setHeader('Content-Type','application/json; charset=utf-8');
    response.setHeader('Cache-Control','no-store');
    response.setHeader('X-Content-Type-Options','nosniff');
    response.setHeader('X-Resource-Id','checks.public');
    if(request.method!=='GET'){
      response.setHeader('Allow','GET');
      return response.status(405).json({error:'METHOD_NOT_ALLOWED'});
    }
    try{
      if(request.query?.case!==undefined){
        const result=await runRuleCheck(request.query.case);
        return result?response.status(200).json(result):response.status(400).json({error:'UNKNOWN_CHECK'});
      }
      const items=await collectAttackChecks(config,{now});
      return response.status(200).json({
        checkedAt:now().toISOString(),commit,...summarizeAttempts(items)
      });
    }catch{
      return response.status(503).json({error:'CHECKS_UNAVAILABLE'});
    }
  };
}
