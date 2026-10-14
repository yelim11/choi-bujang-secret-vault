import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { RULE_IDS } from './decider.mjs';

const SNAPSHOT_SCHEMA='aleph.policy.snapshot.v1';
const SNAPSHOT_URL=new URL('../backup/policy.v1.json',import.meta.url);
const CONFIG_URL=new URL('../aleph.config.json',import.meta.url);

export class PolicyCopyError extends Error {}

const strings=value=>Array.isArray(value)&&value.every(item=>typeof item==='string'&&item.length>0);
const routeName=route=>typeof route==='string'?route:
  route&&typeof route.method==='string'&&typeof route.pathPattern==='string'
    ? `${route.method.toUpperCase()} ${route.pathPattern}`:null;
const canonical=policy=>JSON.stringify({rules:policy.rules,allowedRoutes:policy.allowedRoutes});
export const hashPolicy=policy=>createHash('sha256').update(canonical(policy),'utf8').digest('hex');

export const currentPolicy=config=>({
  rules:[...RULE_IDS],
  allowedRoutes:(config?.allowedRoutes??[]).map(routeName).filter(Boolean),
});

export const verifySnapshot=snapshot=>{
  if(!snapshot||typeof snapshot!=='object'||Array.isArray(snapshot))
    throw new PolicyCopyError('정책 사본 모양이 틀립니다');
  if(snapshot.schema!==SNAPSHOT_SCHEMA) throw new PolicyCopyError('정책 사본 schema가 다릅니다');
  if(typeof snapshot.version!=='string'||!snapshot.version) throw new PolicyCopyError('정책 사본 버전이 없습니다');
  if(!snapshot.policy||!strings(snapshot.policy.rules)||!strings(snapshot.policy.allowedRoutes))
    throw new PolicyCopyError('정책 사본 항목이 틀립니다');
  if(typeof snapshot.sha256!=='string'||snapshot.sha256!==hashPolicy(snapshot.policy))
    throw new PolicyCopyError('정책 사본 해시가 내용과 다릅니다');
  return snapshot;
};

export const loadSnapshot=(url=SNAPSHOT_URL)=>{
  let text;
  try{text=readFileSync(url,'utf8');}catch{throw new PolicyCopyError('정책 사본이 없습니다');}
  let parsed;
  try{parsed=JSON.parse(text);}catch{throw new PolicyCopyError('정책 사본 JSON을 읽을 수 없습니다');}
  return verifySnapshot(parsed);
};

const delta=(saved,now)=>({
  removedNow:saved.filter(item=>!now.includes(item)),
  addedNow:now.filter(item=>!saved.includes(item)),
});

export const diffPolicy=(snapshot,current)=>{
  verifySnapshot(snapshot);
  const rules=delta(snapshot.policy.rules,current.rules);
  const routes=delta(snapshot.policy.allowedRoutes,current.allowedRoutes);
  return {
    restoreVersion:snapshot.version,sha256:snapshot.sha256,rules,routes,
    changed:rules.removedNow.length+rules.addedNow.length
      +routes.removedNow.length+routes.addedNow.length,
  };
};

export const formatDiff=diff=>{
  const lines=[
    `복원할 버전: ${diff.restoreVersion} (사본 해시 ${diff.sha256.slice(0,12)}…, 검증 통과)`,
    '변경 범위: 판정 규칙 이름과 허용 경로만 비교합니다. 운영 정책·다른 서비스·감사 기록은 건드리지 않습니다.',
  ];
  if(diff.changed===0) return [...lines,'차이 없음: 현재 시험 정책이 검증 사본과 같습니다.'].join('\n');
  const show=(label,value)=>[
    ...value.removedNow.map(item=>`  - ${label} 사본에만 있음: ${item}`),
    ...value.addedNow.map(item=>`  + ${label} 현재에만 있음: ${item}`),
  ];
  return [...lines,`차이 ${diff.changed}건:`,...show('규칙',diff.rules),...show('경로',diff.routes)].join('\n');
};

if(process.argv[1]===fileURLToPath(import.meta.url)){
  try{
    const snapshot=loadSnapshot();
    const config=JSON.parse(readFileSync(CONFIG_URL,'utf8'));
    console.log(formatDiff(diffPolicy(snapshot,currentPolicy(config))));
  }catch(error){
    console.error(`중단: ${error instanceof PolicyCopyError?error.message:'현재 정책을 읽을 수 없습니다'}`);
    process.exitCode=1;
  }
}
