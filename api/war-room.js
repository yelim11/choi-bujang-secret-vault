import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import policy from '../backup/policy.v1.json' with { type: 'json' };
import notes from '../backup/note.v1.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { deviceGate } from '../src/device-session.mjs';
import { handleWarRoom } from '../src/war-room.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
let runtime;

function noStore(response){
  response.setHeader('Cache-Control','no-store');
  response.setHeader('CDN-Cache-Control','no-store');
  response.setHeader('Vercel-CDN-Cache-Control','no-store');
  response.setHeader('X-Content-Type-Options','nosniff');
  response.setHeader('X-Resource-Id','warroom.own');
}
function getRuntime(){
  if(runtime)return runtime;
  const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;
  if(!url||!key)return null;
  const db=createClient(url,key,{auth:{autoRefreshToken:false,persistSession:false,detectSessionInUrl:false}});
  runtime={db,verifyLogin:createLoginVerifier({config,supabaseClient:db})};
  return runtime;
}

export async function handleWarRoomRequest(request,response,current=getRuntime()){
  noStore(response);
  if(request.method!=='GET'){
    response.setHeader('Allow','GET');
    return response.status(405).json({error:'METHOD_NOT_ALLOWED'});
  }
  if(!current)return response.status(503).json({error:'WAR_ROOM_BACKEND_NOT_CONFIGURED'});
  const user=await current.verifyLogin(request.headers?.authorization);
  if(!user){
    response.setHeader('WWW-Authenticate','Bearer');
    return response.status(401).json({error:'UNAUTHORIZED'});
  }
  if(user.kind!=='student'||typeof user.sessionId!=='string'||!UUID.test(user.sessionId))
    return response.status(403).json({error:'STUDENT_LOGIN_REQUIRED'});
  const blocked=await deviceGate(user,current.db);
  if(blocked)return response.status(blocked.status).json({error:blocked.error});
  return handleWarRoom({user,db:current.db},response,{policy,notes,config});
}
export default async function handler(request,response){
  return handleWarRoomRequest(request,response);
}
