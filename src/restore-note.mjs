import {
  appendAudit,contentSha256,latestBackup,snapshotEntry,verifyBackup,verifyNoteSnapshot,
} from './note-backup.mjs';

const fail=(status,error)=>({status,body:{error}});

async function readVerifiedBackup(supabase,noteId,ownerId,snapshot){
  const snapshotProblem=verifyNoteSnapshot(snapshot);
  if(snapshotProblem) return {error:fail(503,'BACKUP_SNAPSHOT_INVALID')};

  const manifest=snapshotEntry(snapshot,noteId,ownerId);
  if(manifest.problem==='snapshot_not_found') return {error:fail(404,'BACKUP_NOT_FOUND')};
  if(manifest.problem) return {error:fail(503,'BACKUP_SNAPSHOT_INVALID')};

  const {backup,error}=await latestBackup(supabase,noteId);
  if(error) return {error:fail(503,'BACKUP_UNAVAILABLE')};
  const problem=verifyBackup(backup,noteId,ownerId,manifest.entry);
  if(problem==='backup_not_found') return {error:fail(404,'BACKUP_NOT_FOUND')};
  if(problem) return {error:fail(409,'BACKUP_UNVERIFIED')};
  return {backup,manifest};
}

const sameBackup=(first,second)=>
  first.note_id===second.note_id
  && first.owner_id===second.owner_id
  && first.version===second.version
  && first.content_sha256===second.content_sha256
  && first.captured_at===second.captured_at;

export async function restoreNote({supabase,ownerId,noteId,snapshot,dryRun=false}){
  if(typeof ownerId!=='string'||!ownerId||typeof noteId!=='string'||!noteId)
    return fail(400,'INVALID_RESTORE_TARGET');

  // 1) Git에 남긴 침해 전 스냅숏 자체의 형식·버전·전체 SHA-256을 검증하고,
  // 2) 그 스냅숏의 ID·소유자 해시·내용 해시와 비공개 DB 백업을 다시 대조합니다.
  const first=await readVerifiedBackup(supabase,noteId,ownerId,snapshot);
  if(first.error) return first.error;

  const {data:current,error:currentError}=await supabase.from('notes')
    .select('id,owner_id,title,content').eq('id',noteId).maybeSingle();
  if(currentError) return fail(502,'NOTES_BACKEND_ERROR');
  if(current&&current.owner_id!==ownerId) return fail(409,'OWNER_CONFLICT');

  const currentSha256=current?contentSha256(current.title,current.content):null;
  const changes=!current?['recreate']:[
    current.title!==first.backup.title?'title':null,
    current.content!==first.backup.content?'body':null,
  ].filter(Boolean);

  const plan={
    id:noteId,
    snapshotVersion:first.manifest.version,
    snapshotSha256:first.manifest.sha256,
    backupVersion:first.backup.version,
    backupCapturedAt:first.backup.captured_at,
    backupSha256:first.backup.content_sha256,
    currentSha256,
    changes,
  };

  if(dryRun) return {status:200,body:{dryRun:true,backupVerified:true,plan}};
  if(!changes.length) return {status:200,body:{
    restored:false,backupVerified:true,reason:'ALREADY_MATCHES_BACKUP',
    ...plan,idMatches:true,ownerMatches:true,
  }};

  // 실제 쓰기 직전에 사본 전체 SHA-256과 DB 백업을 다시 검증합니다.
  const second=await readVerifiedBackup(supabase,noteId,ownerId,snapshot);
  if(second.error) return second.error;
  if(second.manifest.sha256!==first.manifest.sha256
      ||second.manifest.version!==first.manifest.version
      ||!sameBackup(first.backup,second.backup))
    return fail(409,'BACKUP_CHANGED_BEFORE_RESTORE');

  const backup=second.backup;

  // 두 번째 검증 전에는 감사 기록이나 메모 쓰기를 시작하지 않습니다.
  const audited=await appendAudit(supabase,{
    action:'restore',noteId,ownerId,actorId:ownerId,
    beforeSha256:currentSha256,afterSha256:backup.content_sha256,
    backupVersion:backup.version,
  });
  if(!audited) return fail(503,'AUDIT_UNAVAILABLE');

  const write=current
    ? await supabase.from('notes').update({title:backup.title,content:backup.content})
        .eq('id',noteId).eq('owner_id',ownerId)
    : await supabase.from('notes').insert({
        id:noteId,owner_id:ownerId,title:backup.title,content:backup.content,
      });
  if(write.error) return fail(502,'RESTORE_FAILED');

  const {data:after,error:afterError}=await supabase.from('notes')
    .select('id,owner_id,title,content')
    .eq('id',noteId).eq('owner_id',ownerId).maybeSingle();
  if(afterError||!after) return fail(502,'RESTORE_UNVERIFIED');

  const restoredSha256=contentSha256(after.title,after.content);
  if(after.id!==noteId||after.owner_id!==ownerId
      ||restoredSha256!==first.manifest.entry.contentSha256)
    return fail(500,'RESTORE_MISMATCH');

  return {status:200,body:{
    restored:true,backupVerified:true,...plan,restoredSha256,
    idMatches:true,ownerMatches:true,audit:'recorded',
  }};
}
