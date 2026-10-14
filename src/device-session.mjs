export const DEVICE_SESSION_SECONDS=3600;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
export const sameUser=(ownerId,user)=>typeof ownerId==='string'&&ownerId.toLowerCase()===String(user?.userId).toLowerCase();
export async function readDeviceSession(db,user,now=Date.now()){
  const sessionId=user?.sessionId;
  if(typeof sessionId!=='string'||!UUID.test(sessionId))return{reason:'device_not_verified',expiresAt:null};
  const {data:session,error}=await db.from('device_sessions').select('owner_id,device_id,verified_at,expires_at').eq('session_id',sessionId).maybeSingle();
  if(error)return{reason:'device_check_failed',expiresAt:null};
  if(!session||!sameUser(session.owner_id,user)||!session.device_id||!session.verified_at||!(Date.parse(session.expires_at)>now))
    return{reason:'device_not_verified',expiresAt:null};
  const {data:device,error:deviceError}=await db.from('devices').select('owner_id,status').eq('id',session.device_id).maybeSingle();
  if(deviceError)return{reason:'device_check_failed',expiresAt:null};
  if(!device||!sameUser(device.owner_id,user)||device.status!=='approved')return{reason:'device_not_approved',expiresAt:null};
  return{reason:null,expiresAt:session.expires_at};
}
export async function deviceGate(user,db){
  if(user?.kind==='judge')return null;
  let result;try{result=await readDeviceSession(db,user);}catch{result={reason:'device_check_failed'};}
  if(!result.reason)return null;
  return result.reason==='device_check_failed'
    ?{status:503,error:'DEVICE_CHECK_UNAVAILABLE',reason:result.reason}
    :{status:403,error:'DEVICE_NOT_APPROVED',reason:result.reason};
}
