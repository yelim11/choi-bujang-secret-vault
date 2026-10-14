import { createHash } from 'node:crypto';

const SHA256=/^[0-9a-f]{64}$/u;
const SNAPSHOT_SCHEMA='aleph.note.snapshot.v1';
const sha256=text=>createHash('sha256').update(text,'utf8').digest('hex');

export const contentSha256=(title,content)=>sha256(`${title}\n${content}`);
export const ownerSha256=ownerId=>sha256(String(ownerId).toLowerCase());

const snapshotHash=notes=>sha256(JSON.stringify(
  notes.map(({id,ownerSha256,contentSha256})=>({id,ownerSha256,contentSha256}))
));

export function buildNoteSnapshot(version,notes){
  return {schema:SNAPSHOT_SCHEMA,version,notes,sha256:snapshotHash(notes)};
}

export function verifyNoteSnapshot(snapshot){
  if(!snapshot||typeof snapshot!=='object'||Array.isArray(snapshot)) return 'snapshot_shape';
  if(snapshot.schema!==SNAPSHOT_SCHEMA) return 'snapshot_schema';
  if(typeof snapshot.version!=='string'||!snapshot.version) return 'snapshot_version';
  if(!Array.isArray(snapshot.notes)||typeof snapshot.sha256!=='string'||!SHA256.test(snapshot.sha256))
    return 'snapshot_shape';
  const ids=new Set();
  for(const note of snapshot.notes){
    if(!note||typeof note.id!=='string'||!note.id
        ||typeof note.ownerSha256!=='string'||!SHA256.test(note.ownerSha256)
        ||typeof note.contentSha256!=='string'||!SHA256.test(note.contentSha256)
        ||ids.has(note.id)) return 'snapshot_entry';
    ids.add(note.id);
  }
  return snapshotHash(snapshot.notes)===snapshot.sha256?null:'snapshot_hash';
}

export function snapshotEntry(snapshot,noteId,ownerId){
  const problem=verifyNoteSnapshot(snapshot);
  if(problem) return {problem};
  const entry=snapshot.notes.find(note=>note.id===noteId);
  if(!entry||entry.ownerSha256!==ownerSha256(ownerId)) return {problem:'snapshot_not_found'};
  return {entry,version:snapshot.version,sha256:snapshot.sha256};
}

export async function latestBackup(db,noteId){
  const {data,error}=await db.from('note_backups')
    .select('note_id,owner_id,version,title,content,content_sha256,captured_at')
    .eq('note_id',noteId).order('version',{ascending:false}).limit(1).maybeSingle();
  return {backup:data??null,error:error??null};
}

export function verifyBackup(backup,noteId,ownerId,entry=null){
  if(!backup||typeof backup!=='object'||backup.note_id!==noteId||backup.owner_id!==ownerId)
    return 'backup_not_found';
  if(typeof backup.title!=='string'||typeof backup.content!=='string'
      ||typeof backup.content_sha256!=='string') return 'backup_unverified';
  const actual=contentSha256(backup.title,backup.content);
  if(actual!==backup.content_sha256) return 'backup_unverified';
  if(entry&&entry.contentSha256!==actual) return 'backup_snapshot_mismatch';
  return null;
}

export async function appendAudit(db,entry){
  try{
    const {error}=await db.from('note_audit').insert({
      action:entry.action,note_id:entry.noteId,owner_id:entry.ownerId??null,
      actor_id:entry.actorId??null,before_sha256:entry.beforeSha256??null,
      after_sha256:entry.afterSha256??null,backup_version:entry.backupVersion??null,
    });
    return !error;
  }catch{return false;}
}

export async function ensureBackup(db,note){
  try{
    const {backup,error}=await latestBackup(db,note.id);
    if(error||backup) return false;
    const hash=contentSha256(note.title,note.content);
    const {error:insertError}=await db.from('note_backups').insert({
      note_id:note.id,owner_id:note.owner_id,version:1,title:note.title,
      content:note.content,content_sha256:hash,
    });
    if(insertError) return false;
    await appendAudit(db,{action:'backup',noteId:note.id,ownerId:note.owner_id,
      afterSha256:hash,backupVersion:1});
    return true;
  }catch{return false;}
}
