import config from '../aleph.config.json' with { type:'json' };
import { createChecksApi } from '../src/checks-api.mjs';

let handler;
export default function checks(request,response){
  if(!handler){
    handler=createChecksApi({
      config,
      commit:(process.env.VERCEL_GIT_COMMIT_SHA??'').slice(0,12)||null,
    });
  }
  return handler(request,response);
}
