import { createHash } from 'node:crypto';
export const contentSha256=(title,content)=>createHash('sha256').update(`${title}\n${content}`,'utf8').digest('hex');
export async function latestBackup(db,noteId){
  const {data,error}=await db.from('note_backups').select('note_id,owner_id,version,title,content,content_sha256,captured_at')
    .eq('note_id',noteId).order('version',{ascending:false}).limit(1).maybeSingle();
  return {backup:data??null,error:error??null};
}
export function verifyBackup(backup,noteId,ownerId){
  if(!backup||typeof backup!=='object'||backup.note_id!==noteId||backup.owner_id!==ownerId) return 'backup_not_found';
  if(typeof backup.title!=='string'||typeof backup.content!=='string'||typeof backup.content_sha256!=='string') return 'backup_unverified';
  return contentSha256(backup.title,backup.content)===backup.content_sha256?null:'backup_unverified';
}
export async function appendAudit(db,entry){
  try{const {error}=await db.from('note_audit').insert({action:entry.action,note_id:entry.noteId,
    owner_id:entry.ownerId??null,actor_id:entry.actorId??null,before_sha256:entry.beforeSha256??null,
    after_sha256:entry.afterSha256??null,backup_version:entry.backupVersion??null});return !error;}catch{return false;}
}
export async function ensureBackup(db,note){
  try{
    const {backup,error}=await latestBackup(db,note.id);if(error||backup) return false;
    const sha=contentSha256(note.title,note.content);
    const {error:insertError}=await db.from('note_backups').insert({note_id:note.id,owner_id:note.owner_id,
      version:1,title:note.title,content:note.content,content_sha256:sha});
    if(insertError) return false;
    await appendAudit(db,{action:'backup',noteId:note.id,ownerId:note.owner_id,afterSha256:sha,backupVersion:1});
    return true;
  }catch{return false;}
}
