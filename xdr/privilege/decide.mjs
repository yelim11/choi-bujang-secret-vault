// privilege standalone evaluator. PATTERNS is copied from patterns.json; no imports or I/O.
const PATTERNS=Object.freeze([
  {
    "id": "high-severity",
    "name": "높은 위험도의 권한 상승 경보",
    "when": {
      "minLevel": 10
    },
    "evidence": "Wazuh 위험도 10 이상의 계정·그룹 변경 및 관리자 권한 사용 경보는 명확한 권한 가로채기로 봅니다.",
    "confidence": 0.9
  },
  {
    "id": "admin-group-added",
    "name": "관리자 그룹 추가",
    "when": {
      "textAny": [
        "관리자 그룹에 추가",
        "관리자 그룹에 들어가",
        "관리자 그룹에 들어왔",
        "관리자 그룹 추가",
        "관리자로 들어왔"
      ]
    },
    "evidence": "평범한 계정이 관리자 그룹에 추가되거나 다시 들어오면 정상 계정 도용(T1078)으로 권한을 키우는 전형입니다.",
    "confidence": 0.95
  },
  {
    "id": "fresh-admin-activity",
    "name": "방금 관리자가 된 계정의 활동",
    "when": {
      "textAny": [
        "방금 관리자가 된",
        "곧바로 권한 명령을 실행",
        "관리자 권한으로 바뀌었"
      ]
    },
    "evidence": "관리자가 된 직후 곧바로 관리자 명령을 실행하거나 세션이 관리자 권한으로 바뀌면 권한 상승 악용(T1068)의 전형입니다.",
    "confidence": 0.93
  },
  {
    "id": "off-hours-admin-use",
    "name": "업무 시간 밖의 관리자 권한 사용",
    "when": {
      "textAny": [
        "수업 시간 밖",
        "업무처럼 보이지 않는 시각",
        "업무 시간 밖"
      ]
    },
    "evidence": "평소 일하지 않는 시각의 관리자 명령이나 그룹 변경은 계정을 도용한 사용일 가능성이 높습니다.",
    "confidence": 0.93
  },
  {
    "id": "unfamiliar-source-admin",
    "name": "처음 보는 주소의 관리자 권한 사용",
    "when": {
      "textAny": [
        "처음 보는 주소에서 관리자",
        "주소는 처음 봅니다"
      ]
    },
    "evidence": "처음 보는 주소에서 관리자 명령을 실행하거나 관리자 세션이 열리면 다른 사람이 계정을 쓰고 있을 가능성이 높습니다.",
    "confidence": 0.93
  },
  {
    "id": "borrowed-credentials",
    "name": "다른 계정의 권한 사용",
    "when": {
      "textAny": [
        "다른 계정의 권한으로"
      ]
    },
    "evidence": "다른 계정의 권한으로 관리자 명령을 실행하면 정상 계정을 도용한 권한 상승입니다.",
    "confidence": 0.93
  },
  {
    "id": "admin-activity-mention",
    "name": "관리자 권한 관련 활동",
    "when": {
      "textAny": [
        "관리자 명령",
        "권한 상승",
        "관리자 그룹",
        "관리자 권한"
      ]
    },
    "evidence": "관리자 권한이 언급되지만 평소와 다르다는 근거가 없으면 단정하기 어려워 사람이 확인합니다.",
    "confidence": 0.6
  },
  {
    "id": "admin-group-field",
    "name": "관리자 그룹이 걸린 경보",
    "when": {
      "groupIn": "admin"
    },
    "evidence": "경보의 그룹 필드가 관리자 그룹이면 어떤 변경인지 사람이 확인합니다.",
    "confidence": 0.6
  },
  {
    "id": "mid-severity",
    "name": "중간 위험도 경보",
    "when": {
      "minLevel": 5
    },
    "evidence": "위험도 5~9 경보는 권한 가로채기라 단정하기 어려워 사람이 확인합니다.",
    "confidence": 0.55
  }
].map(pattern=>Object.freeze(pattern)));
const BLOCK_AT=0.85;
const ALERT_AT=0.5;
const ADMIN_GROUP=/^(?:administrators?|admins?|domain admins|wheel|sudo|관리자)$/iu;
const GROUP_KEY=/group/iu;

function fieldsOf(alert){
  const out=[];
  const walk=(value,key,depth)=>{
    if(typeof value==='string')out.push([key,value]);
    else if(depth<3&&value&&typeof value==='object'&&!Array.isArray(value)){
      for(const [childKey,child] of Object.entries(value))walk(child,childKey,depth+1);
    }
  };
  if(alert&&typeof alert==='object')walk(alert.data,'',0);
  return out;
}
function featuresOf(alert){
  const description=typeof alert?.rule?.description==='string'?alert.rule.description:'';
  const level=Number(alert?.rule?.level)||0;
  const groupKinds=new Set();
  for(const [key,text] of fieldsOf(alert)){
    if(GROUP_KEY.test(key)&&ADMIN_GROUP.test(text.trim()))groupKinds.add('admin');
  }
  return {level,description,groupKinds};
}
function matches(when,features){
  if(when.minLevel!==undefined&&!(features.level>=when.minLevel))return false;
  if(when.textAny&&!when.textAny.some(text=>features.description.includes(text)))return false;
  if(when.groupIn!==undefined&&!features.groupKinds.has(when.groupIn))return false;
  return true;
}
function toAction(confidence){
  if(confidence>=BLOCK_AT)return 'block';
  if(confidence>=ALERT_AT)return 'alert';
  return 'record';
}
export function decide(alert){
  const features=featuresOf(alert);
  const hits=PATTERNS.filter(pattern=>matches(pattern.when,features)).sort((a,b)=>b.confidence-a.confidence);
  if(hits.length===0)return {action:'record',confidence:0.05,reason:'위험도가 낮고 권한 가로채기 형태 없음'};
  let confidence=hits[0].confidence;
  const strong=hits.filter(pattern=>pattern.confidence>=BLOCK_AT&&pattern.id!=='high-severity').length;
  if(strong>1&&confidence<0.99)confidence=Math.min(0.99,confidence+0.02);
  return {action:toAction(confidence),confidence:Number(confidence.toFixed(2)),reason:hits[0].name};
}
