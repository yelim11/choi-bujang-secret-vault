import { apiRequest } from './auth-client.js';

const room=document.querySelector('#war-room');
const workspace=document.querySelector('#workspace');
const refreshButton=document.querySelector('#war-room-refresh');
const statusRoot=document.querySelector('#war-room-status');
const rulesRoot=document.querySelector('#war-room-rules');
const detectRoot=document.querySelector('#war-room-detect');
const revokeRoot=document.querySelector('#war-room-revocation');
const recoveryRoot=document.querySelector('#war-room-recovery');
const assaultRoot=document.querySelector('#war-room-assault');
const logRoot=document.querySelector('#war-room-log');

const statusName=value=>value==='confirmed'?'실제 서버 확인':value==='listed'?'코드 목록 · 실행 결과 아님':'미실행';
const clear=()=>{
  for(const element of[rulesRoot,detectRoot,revokeRoot,recoveryRoot,assaultRoot])element.textContent='미확인';
  logRoot.textContent='';
};

async function refreshWarRoom(){
  if(workspace.hidden){room.hidden=true;clear();return;}
  room.hidden=false;
  statusRoot.textContent='실제 API 응답을 확인하는 중…';
  try{
    const response=await apiRequest('/api/war-room');
    const data=await response.json().catch(()=>null);
    if(!response.ok||!data){
      clear();
      statusRoot.textContent=`작전실 API를 확인하지 못했습니다 (HTTP ${response.status}).`;
      if(response.status===401||response.status===403)room.hidden=true;
      return;
    }
    const ids=Array.isArray(data.decider?.ruleIds)?data.decider.ruleIds.join(', '):'목록 없음';
    rulesRoot.textContent=`${statusName(data.decider?.status)} · ${data.decider?.ruleCount??'?'}개 · ${ids}`;

    detectRoot.textContent=data.detect?.status==='not_run'
      ? '미실행/미연결 · 사건 수를 0으로 간주하지 않음'
      : `${statusName(data.detect?.status)} · 사건 ${data.detect?.events??'?'}건 · 회수 제안 ${data.detect?.proposals??'?'}건`;

    revokeRoot.textContent=`${statusName(data.revocation?.status)} · 승인 ${data.revocation?.approved??'?'} · 대기 ${data.revocation?.pending??'?'} · 회수 ${data.revocation?.revoked??'?'}`;

    const policy=data.recovery?.policy??{},notes=data.recovery?.notes??{};
    recoveryRoot.textContent=`${statusName(data.recovery?.status)} · 정책 ${policy.verified?'검증됨':'검증 실패'} (${policy.version??'버전 없음'}, 차이 ${policy.changed??'미확인'}) · 메모 사본 ${notes.verified?'검증됨':'검증 실패'} (${notes.version??'버전 없음'}, 항목 ${notes.entries??'미확인'})`;

    assaultRoot.textContent=data.totalAssault?.status==='not_run'
      ? `미실행 · ALEPH 총공세 ${data.totalAssault?.expectedAttackTypes??41}종은 심판 실행 전 통과로 표시하지 않음`
      : `${statusName(data.totalAssault?.status)} · ${data.totalAssault?.completedAttackTypes??'?'}종 확인`;

    statusRoot.textContent=`API 확인 시각 ${data.checkedAt??'미확인'} · 요청 ID ${data.requestId??'없음'}`;
    logRoot.textContent=typeof data.logLine==='string'?data.logLine:'가린 서버 기록 없음';
  }catch(error){
    clear();
    statusRoot.textContent=error instanceof Error?error.message:'작전실 API 확인 실패';
  }
}

refreshButton.addEventListener('click',()=>void refreshWarRoom());
new MutationObserver(()=>{void refreshWarRoom();}).observe(workspace,{attributes:true,attributeFilter:['hidden']});
void refreshWarRoom();
