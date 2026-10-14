import config from '../aleph.config.json' with { type:'json' };
import policy from '../backup/policy.v1.json' with { type:'json' };
import notes from '../backup/note.v1.json' with { type:'json' };
import { createOpsApi } from '../src/ops-api.mjs';

let handler;
export default function ops(request,response){
  if(!handler){
    handler=createOpsApi({
      config,policy,notes,
      commit:(process.env.VERCEL_GIT_COMMIT_SHA??'').slice(0,12)||null,
    });
  }
  return handler(request,response);
}
