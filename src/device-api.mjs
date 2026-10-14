import{createClient}from'@supabase/supabase-js';import config from'../aleph.config.json'with{type:'json'};import{createLoginVerifier}from'./verify-login.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;let runtime;
function getRuntime(){if(runtime)return runtime;const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;if(!url||!key)return null;
 const db=createClient(url,key,{auth:{autoRefreshToken:false,persistSession:false,detectSessionInUrl:false}});runtime={db,verifyLogin:createLoginVerifier({config,supabaseClient:db})};return runtime;}
export function noStore(res){res.setHeader('Cache-Control','no-store');res.setHeader('CDN-Cache-Control','no-store');res.setHeader('Vercel-CDN-Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Resource-Id','devices.own');}
export async function deviceContext(req,res,method){noStore(res);if(req.method!==method){res.setHeader('Allow',method);res.status(405).json({error:'METHOD_NOT_ALLOWED'});return null;}
 const current=getRuntime();if(!current){res.status(503).json({error:'DEVICE_BACKEND_NOT_CONFIGURED'});return null;}
 const user=await current.verifyLogin(req.headers?.authorization);if(!user){res.setHeader('WWW-Authenticate','Bearer');res.status(401).json({error:'UNAUTHORIZED'});return null;}
 if(user.kind!=='student'||typeof user.sessionId!=='string'||!UUID.test(user.sessionId)){res.status(403).json({error:'STUDENT_LOGIN_REQUIRED'});return null;}
 return{user,db:current.db};}
