import { appendAudit,contentSha256,latestBackup,verifyBackup } from './note-backup.mjs';
export async function restoreNote({supabase,ownerId,noteId,dryRun=false}){
  const reply=(status,body)=>({status,body});
  if(typeof ownerId!=='string'||!ownerId||typeof noteId!=='string'||!noteId) return reply(400,{error:'INVALID_RESTORE_TARGET'});
  const {backup,error:backupError}=await latestBackup(supabase,noteId);
  if(backupError) return reply(503,{error:'BACKUP_UNAVAILABLE'});
  const problem=verifyBackup(backup,noteId,ownerId);
  if(problem==='backup_not_found') return reply(404,{error:'BACKUP_NOT_FOUND'});
  if(problem) return reply(409,{error:'BACKUP_UNVERIFIED'});
  const {data:current,error:currentError}=await supabase.from('notes').select('id,owner_id,title,content').eq('id',noteId).maybeSingle();
  if(currentError) return reply(502,{error:'NOTES_BACKEND_ERROR'});
  if(current&&current.owner_id!==ownerId) return reply(409,{error:'OWNER_CONFLICT'});
  const currentSha256=current?contentSha256(current.title,current.content):null;
  const changes=!current?['recreate']:[current.title!==backup.title?'title':null,current.content!==backup.content?'body':null].filter(Boolean);
  const plan={id:noteId,backupVersion:backup.version,backupCapturedAt:backup.captured_at,backupSha256:backup.content_sha256,currentSha256,changes};
  if(dryRun) return reply(200,{dryRun:true,plan});
  if(!changes.length) return reply(200,{restored:false,reason:'ALREADY_MATCHES_BACKUP',...plan,idMatches:true,ownerMatches:true});
  const audited=await appendAudit(supabase,{action:'restore',noteId,ownerId,actorId:ownerId,
    beforeSha256:currentSha256,afterSha256:backup.content_sha256,backupVersion:backup.version});
  if(!audited) return reply(503,{error:'AUDIT_UNAVAILABLE'});
  const write=current?await supabase.from('notes').update({title:backup.title,content:backup.content}).eq('id',noteId).eq('owner_id',ownerId)
    :await supabase.from('notes').insert({id:noteId,owner_id:ownerId,title:backup.title,content:backup.content});
  if(write.error) return reply(502,{error:'RESTORE_FAILED'});
  const {data:after,error:afterError}=await supabase.from('notes').select('id,owner_id,title,content').eq('id',noteId).eq('owner_id',ownerId).maybeSingle();
  if(afterError||!after) return reply(502,{error:'RESTORE_UNVERIFIED'});
  const restoredSha256=contentSha256(after.title,after.content);
  if(after.id!==noteId||after.owner_id!==ownerId||restoredSha256!==backup.content_sha256) return reply(500,{error:'RESTORE_MISMATCH'});
  return reply(200,{restored:true,...plan,restoredSha256,idMatches:true,ownerMatches:true,audit:'recorded'});
}
