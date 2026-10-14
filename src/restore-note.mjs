import { appendAudit,contentSha256,latestBackup,verifyBackup } from './note-backup.mjs';

const readVerifiedBackup=async(supabase,noteId,ownerId)=>{
  const {backup,error}=await latestBackup(supabase,noteId);
  if(error) return {error:{status:503,body:{error:'BACKUP_UNAVAILABLE'}}};
  const problem=verifyBackup(backup,noteId,ownerId);
  if(problem==='backup_not_found') return {error:{status:404,body:{error:'BACKUP_NOT_FOUND'}}};
  if(problem) return {error:{status:409,body:{error:'BACKUP_UNVERIFIED'}}};
  return {backup};
};

const sameVerifiedBackup=(first,second)=>
  first.note_id===second.note_id
  && first.owner_id===second.owner_id
  && first.version===second.version
  && first.content_sha256===second.content_sha256
  && first.captured_at===second.captured_at;

export async function restoreNote({supabase,ownerId,noteId,dryRun=false}){
  const reply=(status,body)=>({status,body});
  if(typeof ownerId!=='string'||!ownerId||typeof noteId!=='string'||!noteId)
    return reply(400,{error:'INVALID_RESTORE_TARGET'});

  // 실행 계획을 만들기 전에 안전 사본을 DB에서 다시 읽고 ID·소유자·내용 해시를 검증합니다.
  const firstRead=await readVerifiedBackup(supabase,noteId,ownerId);
  if(firstRead.error) return firstRead.error;
  const firstBackup=firstRead.backup;

  const {data:current,error:currentError}=await supabase.from('notes')
    .select('id,owner_id,title,content').eq('id',noteId).maybeSingle();
  if(currentError) return reply(502,{error:'NOTES_BACKEND_ERROR'});
  if(current&&current.owner_id!==ownerId) return reply(409,{error:'OWNER_CONFLICT'});

  const currentSha256=current?contentSha256(current.title,current.content):null;
  const changes=!current?['recreate']:[
    current.title!==firstBackup.title?'title':null,
    current.content!==firstBackup.content?'body':null,
  ].filter(Boolean);
  const plan={
    id:noteId,
    backupVersion:firstBackup.version,
    backupCapturedAt:firstBackup.captured_at,
    backupSha256:firstBackup.content_sha256,
    currentSha256,
    changes,
  };

  if(dryRun) return reply(200,{dryRun:true,backupVerified:true,plan});
  if(!changes.length) return reply(200,{restored:false,reason:'ALREADY_MATCHES_BACKUP',
    backupVerified:true,...plan,idMatches:true,ownerMatches:true});

  // 실제 쓰기 직전에 같은 사본을 다시 읽어 재검증합니다.
  // 사본이 사라지거나 해시 검증에 실패하거나 첫 검증 뒤 버전/해시가 달라졌으면 복원하지 않습니다.
  const secondRead=await readVerifiedBackup(supabase,noteId,ownerId);
  if(secondRead.error) return secondRead.error;
  const backup=secondRead.backup;
  if(!sameVerifiedBackup(firstBackup,backup))
    return reply(409,{error:'BACKUP_CHANGED_BEFORE_RESTORE'});

  // 재검증이 끝난 뒤에만 감사 기록과 복구 쓰기를 시작합니다.
  const audited=await appendAudit(supabase,{action:'restore',noteId,ownerId,actorId:ownerId,
    beforeSha256:currentSha256,afterSha256:backup.content_sha256,backupVersion:backup.version});
  if(!audited) return reply(503,{error:'AUDIT_UNAVAILABLE'});

  const write=current
    ? await supabase.from('notes').update({title:backup.title,content:backup.content})
        .eq('id',noteId).eq('owner_id',ownerId)
    : await supabase.from('notes').insert({id:noteId,owner_id:ownerId,title:backup.title,content:backup.content});
  if(write.error) return reply(502,{error:'RESTORE_FAILED'});

  const {data:after,error:afterError}=await supabase.from('notes')
    .select('id,owner_id,title,content').eq('id',noteId).eq('owner_id',ownerId).maybeSingle();
  if(afterError||!after) return reply(502,{error:'RESTORE_UNVERIFIED'});
  const restoredSha256=contentSha256(after.title,after.content);
  if(after.id!==noteId||after.owner_id!==ownerId||restoredSha256!==backup.content_sha256)
    return reply(500,{error:'RESTORE_MISMATCH'});

  return reply(200,{restored:true,backupVerified:true,...plan,restoredSha256,
    idMatches:true,ownerMatches:true,audit:'recorded'});
}
