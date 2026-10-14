import { contentSha256,ensureBackup } from '../src/note-backup.mjs';
import { restoreNote } from '../src/restore-note.mjs';

function db(){
  const t={notes:[],note_backups:[],note_audit:[]};
  let backupReadHook=null;
  let backupReads=0;
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
        eq(k,v){f.push([k,v]);return b},order(k,z){o={k,a:z?.ascending!==false};return b},limit(v){l=v;return b},
        async maybeSingle(){
          if(n==='note_backups'){backupReads+=1;if(backupReadHook)backupReadHook(backupReads,t);}
          const x=run();const row=x.data?.[0]??null;
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
for(const n of[...d.tables.notes])await ensureBackup(d,n);

const h=contentSha256('B','safe'),other=JSON.stringify(d.tables.notes.find(x=>x.id===O)),c=[];
const ok=(n,v)=>c.push([n,!!v]);

d.tables.notes.find(x=>x.id===N).content='bad';
const dry=await restoreNote({supabase:d,ownerId:B,noteId:N,dryRun:true});
ok('dryRun에서 검증 버전과 변경 범위 표시',
  dry.status===200&&dry.body.backupVerified===true&&dry.body.plan.changes.join()==='body');

const fixed=await restoreNote({supabase:d,ownerId:B,noteId:N});
ok('변조 복구',fixed.status===200&&fixed.body.backupVerified===true&&fixed.body.restoredSha256===h);
ok('다른 메모 보존',JSON.stringify(d.tables.notes.find(x=>x.id===O))===other);

d.tables.notes.splice(d.tables.notes.findIndex(x=>x.id===N),1);
const recreated=await restoreNote({supabase:d,ownerId:B,noteId:N});
ok('삭제 복구',recreated.status===200&&recreated.body.changes.join()==='recreate');

ok('타인 거부',(await restoreNote({supabase:d,ownerId:A,noteId:N})).status===404);

d.tables.note_backups.find(x=>x.note_id===N).content='broken';
ok('사본 해시 변조 즉시 중단',(await restoreNote({supabase:d,ownerId:B,noteId:N})).status===409);

d.tables.note_backups.find(x=>x.note_id===N).content='safe';
d.tables.note_backups.find(x=>x.note_id===N).content_sha256=h;
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
const raced=await restoreNote({supabase:d,ownerId:B,noteId:N});
ok('복원 직전 사본 재조회에서 변경 감지 후 중단',
  raced.status===409&&raced.body.error==='BACKUP_CHANGED_BEFORE_RESTORE');
ok('재검증 실패 시 감사 기록과 메모 쓰기 없음',
  d.tables.note_audit.length===auditBefore&&d.tables.notes.find(x=>x.id===N).content==='bad-again');

for(const[n,v]of c)console.log(`${v?'통과':'확인 필요'} · ${n}`);
if(c.some(x=>!x[1]))process.exitCode=1;
