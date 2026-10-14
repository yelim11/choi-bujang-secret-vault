import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { restoreNote } from '../src/restore-note.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
function noStore(res){for(const [k,v] of [['Cache-Control','no-store'],['CDN-Cache-Control','no-store'],['Vercel-CDN-Cache-Control','no-store'],['X-Content-Type-Options','nosniff']])res.setHeader(k,v);}
function readBody(req){
  if(req.body===undefined||req.body===null||req.body==='') return {};
  if(req.body&&typeof req.body==='object'&&!Array.isArray(req.body)) return req.body;
  if(typeof req.body==='string'&&req.body.length<=1024){try{const x=JSON.parse(req.body);return x&&typeof x==='object'&&!Array.isArray(x)?x:null;}catch{return null;}}
  return null;
}
let runtime;
function getRuntime(){
  if(runtime)return runtime;const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;if(!url||!key)return null;
  const supabase=createClient(url,key,{auth:{autoRefreshToken:false,persistSession:false,detectSessionInUrl:false}});
  runtime={supabase,verifyLogin:createLoginVerifier({config,supabaseClient:supabase})};return runtime;
}
export async function handleRestoreRequest(req,res,current){
  noStore(res);if(!current)return res.status(503).json({error:'RESTORE_BACKEND_NOT_CONFIGURED'});
  const identity=await current.verifyLogin(req.headers?.authorization);
  if(!identity){res.setHeader('WWW-Authenticate','Bearer');return res.status(401).json({error:'UNAUTHORIZED'});}
  if(req.method!=='POST'){res.setHeader('Allow','POST');return res.status(405).json({error:'METHOD_NOT_ALLOWED'});}
  const body=readBody(req);
  if(!body||!Object.keys(body).every(k=>k==='dryRun')||(Object.hasOwn(body,'dryRun')&&typeof body.dryRun!=='boolean'))
    return res.status(400).json({error:'INVALID_RESTORE_REQUEST'});
  const id=typeof req.query?.id==='string'?req.query.id:'';if(!UUID.test(id))return res.status(400).json({error:'INVALID_NOTE_ID'});
  const result=await restoreNote({supabase:current.supabase,ownerId:identity.userId,noteId:id,dryRun:body.dryRun===true});
  return res.status(result.status).json(result.body);
}
export default async function handler(req,res){return handleRestoreRequest(req,res,getRuntime());}
