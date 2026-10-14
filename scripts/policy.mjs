import { resolve } from 'node:path';import { pathToFileURL } from 'node:url';import { applyRestore,planRestore } from '../src/policy-restore.mjs';
const root=resolve(import.meta.dirname,'..'),safePath=resolve(root,'policy','safe-policy.json'),testPath=resolve(root,'policy','test-policy.json');
const[cmd='diff',...flags]=process.argv.slice(2),out=x=>process.stdout.write(`${x}\n`);
try{if(!['diff','restore'].includes(cmd))throw new Error('policy command');
 const p=planRestore({safePath,testPath});if(!p.ok){out(`중단: ${p.error}`);process.exitCode=1;}else{
 out(`복원할 버전: ${p.version} (규칙 해시 ${p.safe.rulesSha256.slice(0,12)})`);out(p.changes.length?`바뀔 항목 ${p.changes.length}개:`:'바뀔 항목 없음');
 for(const x of p.changes)out(`  - ${x.id}: ${x.change}`);
 const{RULE_IDS}=await import(pathToFileURL(resolve(root,'src','decider.mjs')).href),ids=p.safe.rules.filter(r=>r.layer==='decider').map(r=>r.id).sort();
 out(ids.join(',')===[...RULE_IDS].sort().join(',')?'운영 판정기 규칙 이름: 사본과 같음(읽기만 함)':'운영 판정기 규칙 이름: 사본과 다름(자동 수정 안 함)');
 if(cmd==='restore'){const r=applyRestore({safePath,testPath,confirm:flags.includes('--yes')});if(r.error){out(`중단: ${r.error}`);process.exitCode=1;}
 else if(r.applied)out('시험 정책만 안전 사본으로 복원했습니다. 다른 서비스와 감사 이력은 보존했습니다.');
 else if(r.reason==='confirmation_required')out('아직 변경하지 않았습니다. diff 확인 뒤 --yes로 실행합니다.');else out('바꿀 것이 없어 그대로 두었습니다.');}}}
catch(e){out(`정책 대조 첫 오류: ${e.message}`);process.exitCode=1;}
