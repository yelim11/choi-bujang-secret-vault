// Standalone offline evaluator. PATTERNS is copied from patterns.json; this file imports nothing.
const PATTERNS=Object.freeze([
  {
    "name": "log4shell-header-jndi",
    "condition": "요청 머리글에 ${jndi:<원격 프로토콜>://...} 형태의 완전한 원격 조회 구문이 있다.",
    "evidence": "CVE-2021-44228 및 MITRE ATT&CK T1190: 외부 입력이 Log4j JNDI 원격 조회로 이어지는 명확한 악용 형태."
  },
  {
    "name": "log4shell-argument-jndi",
    "condition": "URL·검색어·요청 인자에 ${jndi:<원격 프로토콜>://...} 형태의 완전한 원격 조회 구문이 있다.",
    "evidence": "CVE-2021-44228 및 MITRE ATT&CK T1190: 요청 인자에 삽입된 JNDI 원격 조회는 공개 애플리케이션 취약점 악용 형태."
  },
  {
    "name": "known-cve-probe-trace",
    "condition": "완전한 JNDI 구문은 없지만 T1190 경보 수준 5 이상에서 CVE·JNDI·취약점 점검·라이브러리 흔적이 관측된다.",
    "evidence": "MITRE ATT&CK T1190: 알려진 취약점 탐색·점검 흔적은 악용 성공과 구분해 중간 신뢰 알림으로 다룬다."
  },
  {
    "name": "normal-event",
    "condition": "T1190 악용 구문이나 알려진 취약점 점검 흔적이 없는 낮은 수준 정상 이벤트다.",
    "evidence": "MITRE ATT&CK T1190 악용 증거가 없는 정상 접속은 차단하지 않고 기록만 남긴다."
  }
].map(pattern=>Object.freeze(pattern)));
const BLOCK_AT=0.85;
const ALERT_AT=0.5;
const HEADER_KEYS=/user-?agent|referer|referrer|header|cookie|accept|authorization|x-[a-z-]+/iu;
const JNDI=/\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|nis|corba)\s*:\/\/[^\s{}]+\}/iu;
const PROBE_TRACE=/CVE-2021-44228|\bjndi\b|\blog4j\b|\blog4shell\b|취약점|점검\s*도구|라이브러리|조회\s*(?:구문|형태)|중괄호/iu;
function fieldsOf(alert){const out=[];const walk=(value,key,depth)=>{if(typeof value==='string')out.push([key,value]);else if(depth<3&&value&&typeof value==='object'&&!Array.isArray(value)){for(const [childKey,child] of Object.entries(value))walk(child,childKey,depth+1)}};if(alert&&typeof alert==='object')walk(alert.data,'',0);return out}
function actionOf(confidence){if(confidence>=BLOCK_AT)return 'block';if(confidence>=ALERT_AT)return 'alert';return 'record'}
export function decide(alert){
  const description=typeof alert?.rule?.description==='string'?alert.rule.description:'';
  const level=Number(alert?.rule?.level)||0;
  const mitre=Array.isArray(alert?.rule?.mitre)?alert.rule.mitre.map(String):[];
  const fields=fieldsOf(alert);
  let inHeader=false,inArgument=false;
  for(const [key,text] of fields){if(!JNDI.test(text))continue;if(HEADER_KEYS.test(key))inHeader=true;else inArgument=true}
  if(inHeader||inArgument){const confidence=inHeader&&inArgument?0.99:inHeader?0.97:0.95;const reason=inHeader?PATTERNS[0].name:PATTERNS[1].name;return {action:actionOf(confidence),confidence,reason}}
  const evidenceText=[description,...fields.map(([,text])=>text)].join(' ');
  if(level>=5&&mitre.some(id=>id==='T1190'||id.startsWith('T1190.'))&&PROBE_TRACE.test(evidenceText)){const confidence=0.55;return {action:actionOf(confidence),confidence,reason:PATTERNS[2].name}}
  return {action:'record',confidence:0.05,reason:PATTERNS[3].name};
}
