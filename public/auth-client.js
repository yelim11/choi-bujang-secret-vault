let sessionState=null;const listeners=new Set();
function publish(session){sessionState=session;const out=session?{access_token:session.accessToken}:null;for(const listener of listeners)listener(out);}
async function authRequest(payload){const response=await fetch('/api/auth',{method:'POST',headers:{Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify(payload),cache:'no-store',credentials:'omit',redirect:'error'});const data=await response.json().catch(()=>null);return{response,data};}
async function ensureSession(){if(!sessionState)return null;const now=Math.floor(Date.now()/1000);if(Number.isFinite(sessionState.expiresAt)&&sessionState.expiresAt-now>60)return sessionState;
 const {response,data}=await authRequest({action:'refresh',refreshToken:sessionState.refreshToken});if(!response.ok||!data?.session){publish(null);return null;}publish(data.session);return data.session;}
export async function signIn(email,password){const {response,data}=await authRequest({action:'login',email,password});if(!response.ok||!data?.session)return{data:{session:null},error:new Error(data?.error||'로그인에 실패했습니다.')};publish(data.session);return{data:{session:{access_token:data.session.accessToken}},error:null};}
export async function signOut(){if(sessionState)await authRequest({action:'logout'}).catch(()=>{});publish(null);return{error:null};}
export async function currentSession(){try{const session=await ensureSession();return{session:session?{access_token:session.accessToken}:null,error:null};}catch{publish(null);return{session:null,error:new Error('로그인 상태를 확인할 수 없습니다.')}}}
export function onAuthChange(callback){listeners.add(callback);return()=>listeners.delete(callback);}
export async function apiRequest(path,init={}){const session=await ensureSession();if(!session?.accessToken)throw new Error('로그인이 필요합니다.');const headers=new Headers(init.headers||{});
 headers.set('Accept','application/json');headers.set('Authorization',`Bearer ${session.accessToken}`);if(init.body)headers.set('Content-Type','application/json');
 const response=await fetch(path,{...init,headers,cache:'no-store',credentials:'omit',redirect:'error'});if(response.status===401)publish(null);return response;}
