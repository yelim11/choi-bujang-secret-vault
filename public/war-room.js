const room=document.querySelector('#war-room');
const workspace=document.querySelector('#workspace');
const refresh=document.querySelector('#war-room-refresh');
const statusRoot=document.querySelector('#war-room-status');
const rulesRoot=document.querySelector('#war-room-rules');
const detectRoot=document.querySelector('#war-room-detect');
const revokeRoot=document.querySelector('#war-room-revocation');
const recoveryRoot=document.querySelector('#war-room-recovery');
const assaultRoot=document.querySelector('#war-room-assault');
const logRoot=document.querySelector('#war-room-log');

const clear=()=>{
  for(const el of[rulesRoot,detectRoot,revokeRoot,recoveryRoot,assaultRoot])el.textContent='미확인';
  logRoot.textContent='';
};

async function load(){
  if(workspace.hidden){
    room.hidden=true;
    clear();
    return;
  }
  room.hidden=false;
  statusRoot.textContent='실제 API 점검 기록을 읽는 중…';
  try{
    const response=await fetch('/api/ops',{cache:'no-store'});
    const data=await response.json().catch(()=>null);
    if(!response.ok||data?.schema!=='aleph.ops.v1'){
      clear();
      statusRoot.textContent='서버 기록을 읽지 못했습니다. 수치를 표시하지 않습니다.';
      return;
    }
    const stage9=(data.items??[]).filter(item=>item.stage===9);
    rulesRoot.textContent='코드 목록 · '+(data.rules?.count??'-')+'개 · '+(data.rules?.ids??[]).join(', ');
    detectRoot.textContent=stage9.length
      ?'실제 점검 '+stage9.length+'건 · '+stage9.map(item=>item.result).join(', ')
      :'미실행';
    const summary=data.summary??{};
    revokeRoot.textContent='전체 점검 기준 기대와 일치 '+(summary.blocked??'-')+
      ' · 다름 '+(summary.failed??'-')+' · 미실행 '+(summary.notRun??'-');
    const recovery=data.recovery??{};
    recoveryRoot.textContent='정책 '+(recovery.policy?.valid?'검증됨':'검증 실패')+
      ' ('+(recovery.policy?.version??'-')+', 차이 '+(recovery.policy?.changes??'-')+') · 메모 '+
      (recovery.notes?.valid?'검증됨':'검증 실패')+
      ' ('+(recovery.notes?.version??'-')+', 항목 '+(recovery.notes?.entries??'-')+')';
    assaultRoot.textContent='미실행 · 41종 총공세는 ALEPH 심판 결과 전 통과로 표시하지 않음';
    statusRoot.textContent='확인 시각 '+(data.checkedAt??'-')+' · 검사 커밋 '+(data.commit??'-');
    logRoot.textContent=typeof data.logLine==='string'?data.logLine:'기록 없음';
  }catch{
    clear();
    statusRoot.textContent='서버에 연결하지 못했습니다. 수치를 표시하지 않습니다.';
  }
}

refresh.addEventListener('click',()=>void load());
new MutationObserver(()=>void load()).observe(workspace,{attributes:true,attributeFilter:['hidden']});
void load();
