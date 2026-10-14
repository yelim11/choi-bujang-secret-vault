import config from '../aleph.config.json' with { type:'json' };
import policy from '../backup/policy.v1.json' with { type:'json' };
import notes from '../backup/note.v1.json' with { type:'json' };
import { createOpsApi } from '../src/ops-api.mjs';
import { runRuleCheck } from '../src/rule-check.mjs';

let handler;
export default async function ops(request,response){
  if(request.query?.case!==undefined){
    response.setHeader('Content-Type','application/json; charset=utf-8');
    response.setHeader('Cache-Control','no-store');
    response.setHeader('X-Content-Type-Options','nosniff');
    response.setHeader('X-Resource-Id','checks.public');
    if(request.method!=='GET'){
      response.setHeader('Allow','GET');
      return response.status(405).json({error:'METHOD_NOT_ALLOWED'});
    }
    const result=await runRuleCheck(request.query.case);
    return result
      ?response.status(200).json(result)
      :response.status(400).json({error:'UNKNOWN_CHECK'});
  }

  if(!handler){
    handler=createOpsApi({
      config,policy,notes,
      commit:(process.env.VERCEL_GIT_COMMIT_SHA??'').slice(0,12)||null,
    });
  }
  return handler(request,response);
}
