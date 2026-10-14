import{generateAuthenticationOptions,generateRegistrationOptions,verifyAuthenticationResponse,verifyRegistrationResponse}from'@simplewebauthn/server';
import{isoBase64URL,isoUint8Array}from'@simplewebauthn/server/helpers';
import config from'../aleph.config.json'with{type:'json'};
import{DEVICE_SESSION_SECONDS,readDeviceSession,sameUser}from'./device-session.mjs';
const APP=new URL(config.publicAppUrl),RP_NAME='BYTE BACK 내 자료실',ALGORITHMS=[-7,-257],CHALLENGE_SECONDS=300,CEREMONY_TIMEOUT_MS=120000;
export const RP_ID=APP.hostname,EXPECTED_ORIGIN=APP.origin;
const LABEL=/^[^\p{Cc}\p{Cf}]{1,40}$/u,CREDENTIAL_ID=/^[A-Za-z0-9_-]{16,1400}$/u;
const plain=v=>v!==null&&typeof v==='object'&&!Array.isArray(v),onlyKeys=(v,keys)=>plain(v)&&Object.keys(v).every(k=>keys.includes(k)),reply=(status,body)=>({status,body});
const publicDevice=row=>({code:String(row.id).slice(0,8),label:row.label,status:row.status,synced:row.synced===true,createdAt:row.created_at});
export async function deviceStatus({user,db},now=Date.now()){
  const {data,error}=await db.from('devices').select('id,owner_id,label,status,synced,created_at').eq('owner_id',user.userId).order('created_at',{ascending:true});
  if(error)return reply(502,{error:'DB_READ_FAILED'});
  const session=await readDeviceSession(db,user,now);if(session.reason==='device_check_failed')return reply(502,{error:'DB_READ_FAILED'});
  return reply(200,{sessionVerified:session.reason===null,expiresAt:session.expiresAt,devices:(data??[]).filter(r=>sameUser(r.owner_id,user)).map(publicDevice)});
}
export async function deviceChallenge({user,db},input,now=Date.now()){
  if(!onlyKeys(input,['purpose'])||!['register','verify'].includes(input.purpose))return reply(400,{error:'INVALID_REQUEST'});
  const {data,error}=await db.from('devices').select('owner_id,credential_id,status').eq('owner_id',user.userId);if(error)return reply(502,{error:'DB_READ_FAILED'});
  const mine=(data??[]).filter(r=>sameUser(r.owner_id,user));let options;
  if(input.purpose==='register'){
    options=await generateRegistrationOptions({rpName:RP_NAME,rpID:RP_ID,userName:`byteback-${user.userId.slice(0,8)}`,userDisplayName:RP_NAME,
      userID:isoUint8Array.fromHex(user.userId.replaceAll('-','').toLowerCase()),attestationType:'none',timeout:CEREMONY_TIMEOUT_MS,supportedAlgorithmIDs:ALGORITHMS,
      excludeCredentials:mine.filter(r=>r.status!=='revoked').map(r=>({id:r.credential_id})),
      authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'preferred',userVerification:'required'}});
  }else{
    const approved=mine.filter(r=>r.status==='approved');if(!approved.length)return reply(409,{error:'NO_APPROVED_DEVICE'});
    options=await generateAuthenticationOptions({rpID:RP_ID,timeout:CEREMONY_TIMEOUT_MS,userVerification:'required',allowCredentials:approved.map(r=>({id:r.credential_id}))});
  }
  const {error:saveError}=await db.from('device_sessions').upsert({session_id:user.sessionId,owner_id:user.userId,challenge:options.challenge,
    challenge_purpose:input.purpose,challenge_expires_at:new Date(now+CHALLENGE_SECONDS*1000).toISOString(),updated_at:new Date(now).toISOString()},{onConflict:'session_id'});
  if(saveError)return reply(502,{error:'DB_WRITE_FAILED'});return reply(200,options);
}
async function takeChallenge(db,user,purpose,now){
  const {data:row,error}=await db.from('device_sessions').select('owner_id,challenge,challenge_purpose,challenge_expires_at').eq('session_id',user.sessionId).maybeSingle();
  if(error)return{status:502,error:'DB_READ_FAILED'};
  if(!row||!sameUser(row.owner_id,user)||row.challenge_purpose!==purpose||typeof row.challenge!=='string'||!(Date.parse(row.challenge_expires_at)>now))
    return{status:400,error:'CHALLENGE_INVALID'};
  const {data:taken,error:takeError}=await db.from('device_sessions').update({challenge:null,challenge_purpose:null,challenge_expires_at:null,updated_at:new Date(now).toISOString()})
    .eq('session_id',user.sessionId).eq('challenge',row.challenge).select('session_id').maybeSingle();
  if(takeError)return{status:502,error:'DB_WRITE_FAILED'};if(!taken)return{status:400,error:'CHALLENGE_INVALID'};return{value:row.challenge};
}
export async function deviceRegister({user,db},input,now=Date.now()){
  const label=typeof input?.label==='string'?input.label.trim():'';
  if(!onlyKeys(input,['label','credential'])||!LABEL.test(label)||!plain(input.credential))return reply(400,{error:'INVALID_REQUEST'});
  const challenge=await takeChallenge(db,user,'register',now);if(challenge.error)return reply(challenge.status,{error:challenge.error});
  let result=null;try{result=await verifyRegistrationResponse({response:input.credential,expectedChallenge:challenge.value,expectedOrigin:EXPECTED_ORIGIN,expectedRPID:RP_ID,requireUserVerification:true,supportedAlgorithmIDs:ALGORITHMS});}catch{result=null;}
  if(!result?.verified)return reply(400,{error:'DEVICE_PROOF_INVALID'});
  const {credential,credentialDeviceType}=result.registrationInfo;
  const {data,error}=await db.from('devices').insert({owner_id:user.userId,label,credential_id:credential.id,public_key:isoBase64URL.fromBuffer(credential.publicKey),
    sign_count:credential.counter,synced:credentialDeviceType==='multiDevice',status:'pending'}).select('id,owner_id,label,status,synced,created_at').single();
  if(error?.code==='23505')return reply(409,{error:'DEVICE_EXISTS'});if(error)return reply(502,{error:'DB_WRITE_FAILED'});return reply(201,{device:publicDevice(data)});
}
export async function deviceVerify({user,db},input,now=Date.now()){
  if(!onlyKeys(input,['credential'])||!plain(input.credential)||typeof input.credential.id!=='string'||!CREDENTIAL_ID.test(input.credential.id))return reply(400,{error:'INVALID_REQUEST'});
  const challenge=await takeChallenge(db,user,'verify',now);if(challenge.error)return reply(challenge.status,{error:challenge.error});
  const {data:device,error}=await db.from('devices').select('id,owner_id,credential_id,public_key,sign_count,status').eq('credential_id',input.credential.id).maybeSingle();
  if(error)return reply(502,{error:'DB_READ_FAILED'});if(!device||!sameUser(device.owner_id,user))return reply(404,{error:'DEVICE_NOT_FOUND'});
  if(device.status!=='approved')return reply(403,{error:'DEVICE_NOT_APPROVED'});
  let result=null;try{result=await verifyAuthenticationResponse({response:input.credential,expectedChallenge:challenge.value,expectedOrigin:EXPECTED_ORIGIN,expectedRPID:RP_ID,
    credential:{id:device.credential_id,publicKey:isoBase64URL.toBuffer(device.public_key),counter:Number(device.sign_count)},requireUserVerification:true});}catch{result=null;}
  if(!result?.verified)return reply(400,{error:'DEVICE_PROOF_INVALID'});
  const {data:counted,error:countError}=await db.from('devices').update({sign_count:result.authenticationInfo.newCounter}).eq('id',device.id).eq('owner_id',user.userId).eq('status','approved').select('id').maybeSingle();
  if(countError)return reply(502,{error:'DB_WRITE_FAILED'});if(!counted)return reply(403,{error:'DEVICE_NOT_APPROVED'});
  const expiresAt=new Date(now+DEVICE_SESSION_SECONDS*1000).toISOString();
  const {data:saved,error:saveError}=await db.from('device_sessions').update({device_id:device.id,verified_at:new Date(now).toISOString(),expires_at:expiresAt,updated_at:new Date(now).toISOString()})
    .eq('session_id',user.sessionId).eq('owner_id',user.userId).select('session_id').maybeSingle();
  if(saveError||!saved)return reply(502,{error:'DB_WRITE_FAILED'});return reply(200,{sessionVerified:true,expiresAt});
}
