import {
  buildNoteSnapshot,contentSha256,ensureBackup,ownerSha256,
} from '../src/note-backup.mjs';
import { restoreNote } from '../src/restore-note.mjs';

function db(){
  const t={notes:[],note_backups:[],note_audit:[]};
  let backupReadHook=null,backupReads=0;
  return {
    tables:t,
    setBackupReadHook(hook){backupReadHook=hook;backupReads=0;},
    from(n){
      const f=[];let op='select',p=null,o=null,l=null;
      const rows=()=>t[n].filter(r=>f.every(([k,v])=>r[k]===v));
      const run=()=>{
        if(op==='insert'){
          for(const r of(Array.isArray(p)?p:[p]))
            t[n].push({...r,...(n==='note_backups'?{captured_at:r.captured_at??new Date().toISOString()}:{})});
          return {data:p,error:null};
        }
        if(op==='update'){for(const r of rows())Object.assign(r,p);return {data:rows(),error:null};}
        let x=rows();
        if(o)x=[...x].sort((a,b)=>(a[o.k]>b[o.k]?1:a[o.k]<b[o.k]?-1:0)*(o.a?1:-1));
        if(l!==null)x=x.slice(0,l);
        return {data:x,error:null};
      };
      const b={
        select(){return b},insert(v){op='insert';p=v;return b},update(v){op='update';p=v;return b},
        eq(k,v){f.push([k,v]);return b},order(k,z){o={k,a:z?.ascending!==false};return b},
        limit(v){l=v;return b},
        async maybeSingle(){
          if(n==='note_backups'){backupReads+=1;if(backupReadHook)backupReadHook(backupReads,t);}
          const x=run(),row=x.data?.[0]??null;
          return {data:row?{...row}:null,error:x.error??null};
        },
        then(a,c){return Promise.resolve(run()).then(a,c);}
      };
      return b;
    },
  };
}

const A='11111111-1111-4111-8111-111111111111';
const B='22222222-2222-4222-8222-222222222222';
const N='33333333-3333-4333-8333-333333333333';
const O='44444444-4444-4444-8444-444444444444';
const d=db();
d.tables.notes.push({id:N,owner_id:B,title:'B',content:'safe'},{id:O,owner_id:B,title:'O',content:'keep'});
for(const note of[...d.tables.notes])await ensureBackup(d,note);

const snapshot=buildNoteSnapshot('fixture-safe',[
  {id:N,ownerSha256:ownerSha256(B),contentSha256:contentSha256('B','safe')},
  {id:O,ownerSha256:ownerSha256(B),contentSha256:contentSha256('O','keep')},
]);

const expected=contentSha256('B','safe');
const other=JSON.stringify(d.tables.notes.find(x=>x.id===O));
const checks=[];
const ok=(name,value)=>checks.push([name,Boolean(value)]);

d.tables.notes.find(x=>x.id===N).content='bad';
const dry=await restoreNote({supabase:d,ownerId:B,noteId:N,snapshot,dryRun:true});
ok('실행 전 사본 버전·해시·변경 범위 표시',
  dry.status===200&&dry.body.backupVerified===true
  &&dry.body.plan.snapshotVersion==='fixture-safe'
  &&dry.body.plan.changes.join()==='body');

const fixed=await restoreNote({supabase:d,ownerId:B,noteId:N,snapshot});
ok('변조 복구',fixed.status===200&&fixed.body.restoredSha256===expected);
ok('다른 메모 보존',JSON.stringify(d.tables.notes.find(x=>x.id===O))===other);

d.tables.notes.splice(d.tables.notes.findIndex(x=>x.id===N),1);
ok('삭제 복구',(await restoreNote({supabase:d,ownerId:B,noteId:N,snapshot})).body.changes.join()==='recreate');
ok('타인 거부',(await restoreNote({supabase:d,ownerId:A,noteId:N,snapshot})).status===404);

const brokenSnapshot=structuredClone(snapshot);
brokenSnapshot.notes[0].contentSha256='0'.repeat(64);
const auditBeforeBroken=d.tables.note_audit.length;
ok('스냅숏 전체 해시 불일치면 복원 전 중단',
  (await restoreNote({supabase:d,ownerId:B,noteId:N,snapshot:brokenSnapshot})).status===503
  &&d.tables.note_audit.length===auditBeforeBroken);

d.tables.notes.find(x=>x.id===N).content='bad-again';
const auditBefore=d.tables.note_audit.length;
d.setBackupReadHook((reads,tables)=>{
  if(reads===2){
    const backup=tables.note_backups.find(x=>x.note_id===N);
    backup.content='changed-between-checks';
    backup.content_sha256=contentSha256(backup.title,backup.content);
    backup.version=2;
  }
});
const raced=await restoreNote({supabase:d,ownerId:B,noteId:N,snapshot});
ok('쓰기 직전 DB 백업 재검증에서 변경 감지',
  raced.status===409&&['BACKUP_UNVERIFIED','BACKUP_CHANGED_BEFORE_RESTORE'].includes(raced.body.error));
ok('재검증 실패 시 감사·메모 쓰기 없음',
  d.tables.note_audit.length===auditBefore&&d.tables.notes.find(x=>x.id===N).content==='bad-again');

for(const[name,value]of checks) console.log(`${value?'통과':'확인 필요'} · ${name}`);
if(checks.some(x=>!x[1])) process.exitCode=1;
