import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import config from '../aleph.config.json' with { type:'json' };
import { collectAttackChecks, summarizeAttempts } from '../src/attack-check.mjs';

const ROOT=resolve(import.meta.dirname,'..');
const clean=value=>String(value).replace(/\|/gu,'\\|').replace(/\r?\n/gu,' ');
const currentCommit=()=>{
  try{return execFileSync('git',['-C',ROOT,'rev-parse','HEAD'],{encoding:'utf8',timeout:3000}).trim()}
  catch{return '현재 작업 트리'}
};

const items=await collectAttackChecks(config);
const summary=summarizeAttempts(items);
const kind={live_api:'실제 API',not_run:'미실행'};
const result={blocked:'기대와 일치',breached:'기대와 다름',not_run:'미실행'};

const lines=[
  '# BYTE BACK · 1~11단계 재검증 표',
  '',
  '검사 커밋: '+currentCommit(),
  '요약: 전체 '+summary.total+' · 기대와 일치 '+summary.blocked+' · 다름 '+summary.failed+' · 미실행 '+summary.notRun,
  '',
  '| 단계 | 종류 | 요청 | 기대 | 실제 | 요청 ID | 확인 시각 | 결과 |',
  '| ---: | --- | --- | --- | --- | --- | --- | --- |',
  ...items.map(item=>'| '+item.stage+' | '+(kind[item.kind]??item.kind)+' | '+clean(item.request)+' | '+clean(item.expected)+' | '+clean(item.observed)+' | '+clean(item.requestId??'-')+' | '+clean(item.checkedAt)+' | '+(result[item.result]??item.result)+' |'),
  '',
  '> 실제로 보내지 않은 요청은 미실행이며, 41종 총공세는 ALEPH 심판 실행 전에는 이 표에서 통과로 계산하지 않습니다.',
];

mkdirSync(join(ROOT,'artifacts'),{recursive:true});
writeFileSync(join(ROOT,'artifacts','recon-table.md'),lines.join('\n')+'\n','utf8');
console.log(lines.join('\n'));
if(summary.failed>0)process.exitCode=1;
