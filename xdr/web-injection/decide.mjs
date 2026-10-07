// Standalone for isolated evaluation. No request payload is executed or logged.
export async function decide(alert, options={}) {
  const safe=value=>typeof value==='string'?value.replace(/(?:Bearer\s+)?eyJ[A-Za-z0-9_.-]+|sb_(?:secret|publishable)_[A-Za-z0-9_-]+/g,'[redacted]').replace(/((?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*)[^\s,;]+/gi,'$1[redacted]').replace(/[\r\n]+/g,' ').slice(0,500):'';
  const description=safe(alert?.rule?.description);
  const level=Number(alert?.rule?.level)||0;
  const source=safe(alert?.data?.srcip);
  const count=Number(alert?.data?.count)||Number(description.match(/(\d+)(?:번|건)/)?.[1])||0;
  let url=String(alert?.data?.url||'').slice(0,2000);
  try {url=decodeURIComponent(url);}catch{}
  const path=/\.\.\//.test(url)||/경로.*(?:이탈|거슬러)/.test(description);
  const script=/<script\b|on(?:error|load)\s*=/i.test(url)||/스크립트.*(?:삽입|표식|표기)/.test(description);
  const query=/union\s+select|\bor\s+['"\d]+\s*=|;\s*(?:cat|ls|whoami)|select\s+.*\s+from/i.test(url)||/SQL.*(?:구문|표식)|명령 구분자|데이터베이스 조회.*이어/.test(description);
  const pattern=path?'path-traversal':script?'script-injection':'query-expression-injection';
  if(source && level>=10 && count>=2 && (path||script||query))return {action:'block',confidence:0.95,reason:pattern};
  if(level<=3)return {action:'record',confidence:0.1,reason:'normal-event'};
  const askJev=options.askJev||(async()=>null);
  let timer;
  try {
    const response=await Promise.race([askJev({pattern,alert:{timestamp:safe(alert?.timestamp),source,account:safe(alert?.data?.srcuser),level,description}}),new Promise(resolve=>{timer=setTimeout(()=>resolve(null),options.timeoutMs??1000);})]);
    const confidence=response?.confidence;
    if(typeof confidence!=='number'||!Number.isFinite(confidence)||confidence<0||confidence>1)return {action:'alert',confidence:0.5,reason:`${pattern}: Jev unavailable`};
    return {action:confidence>=0.85?'block':confidence>=0.5?'alert':'record',confidence,reason:pattern};
  }catch{return {action:'alert',confidence:0.5,reason:`${pattern}: Jev unavailable`};}
  finally{clearTimeout(timer);}
}
