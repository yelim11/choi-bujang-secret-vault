import { readFile } from 'node:fs/promises';

const DEFAULT_FIXTURE=new URL('../fixtures/known-cve.json',import.meta.url);
const SECRET_LIKE=[
  /\bBearer\s+[A-Za-z0-9._~+/-]{12,}/giu,
  /\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]+/giu,
  /\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\b/gu,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu,
];

const safeText=value=>{
  let text=typeof value==='string'?value:'';
  for(const pattern of SECRET_LIKE)text=text.replace(pattern,'[REDACTED]');
  return text.replace(/[\r\n]+/gu,' ').slice(0,500);
};

export async function readAlerts(source=DEFAULT_FIXTURE){
  const fixture=typeof source==='object'&&source!==null&&!(source instanceof URL)&&!Array.isArray(source)
    ?source
    :JSON.parse(await readFile(source,'utf8'));
  if(fixture?.schema!=='aleph.xdr.fixture.v1'||fixture.moduleKey!=='known-cve'||!Array.isArray(fixture.alerts)){
    throw new TypeError('invalid_known_cve_fixture');
  }
  return fixture.alerts.map(alert=>({
    timestamp:safeText(alert?.timestamp),
    sourceAddress:safeText(alert?.data?.srcip),
    account:safeText(alert?.data?.srcuser),
    ruleLevel:Number.isFinite(Number(alert?.rule?.level))?Number(alert.rule.level):0,
    description:safeText(alert?.rule?.description),
  }));
}
