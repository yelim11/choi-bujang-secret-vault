import { createHash } from 'node:crypto';import { existsSync,readFileSync,writeFileSync } from 'node:fs';
export function canonical(v){if(Array.isArray(v))return`[${v.map(canonical).join(',')}]`;if(v&&typeof v==='object')return`{${Object.keys(v).sort().map(k=>`${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;return JSON.stringify(v);}
export const rulesSha256=rules=>createHash('sha256').update(canonical(rules),'utf8').digest('hex');
const readJson=p=>{if(!existsSync(p))return{error:'missing'};try{return{value:JSON.parse(readFileSync(p,'utf8'))}}catch{return{error:'invalid_json'}}};
export function loadSafePolicy(p){const{value,error}=readJson(p);if(error)return{error:`safe_policy_${error}`};
 if(value?.schema!=='aleph.safe-policy.v1'||typeof value.version!=='string'||!Array.isArray(value.rules)||typeof value.rulesSha256!=='string')return{error:'safe_policy_invalid'};
 if(rulesSha256(value.rules)!==value.rulesSha256)return{error:'safe_policy_unverified'};return{safe:value};}
export function loadTestPolicy(p){const{value,error}=readJson(p);if(error)return{error:`test_policy_${error}`};
 return value?.schema==='aleph.test-policy.v1'&&Array.isArray(value.rules)?{test:value}:{error:'test_policy_invalid'};}
export function diffRules(a,b){const m=x=>new Map(x.map(r=>[r.id,r])),sa=m(a),te=m(b),c=[];
 for(const[id,r]of sa){if(!te.has(id))c.push({id,change:'missing_in_test'});else if(canonical(r)!==canonical(te.get(id)))c.push({id,change:'modified'});}
 for(const id of te.keys())if(!sa.has(id))c.push({id,change:'extra_in_test'});return c;}
export function planRestore({safePath,testPath}){const{safe,error:s}=loadSafePolicy(safePath);if(s)return{ok:false,error:s};
 const{test,error:t}=loadTestPolicy(testPath);if(t)return{ok:false,error:t};return{ok:true,safe,test,version:safe.version,changes:diffRules(safe.rules,test.rules)};}
export function applyRestore({safePath,testPath,confirm,now=new Date()}){const p=planRestore({safePath,testPath});if(!p.ok)return p;
 if(!p.changes.length)return{...p,applied:false,reason:'already_matches'};if(confirm!==true)return{...p,applied:false,reason:'confirmation_required'};
 const audit=Array.isArray(p.test.audit)?p.test.audit:[];const next={...p.test,rules:p.safe.rules,restoredFrom:{version:p.safe.version,rulesSha256:p.safe.rulesSha256},
 audit:[...audit,{at:now.toISOString(),action:'restore_policy',version:p.safe.version,beforeSha256:rulesSha256(p.test.rules),afterSha256:p.safe.rulesSha256,changed:p.changes.map(x=>`${x.id}:${x.change}`)}]};
 writeFileSync(testPath,`${JSON.stringify(next,null,2)}\n`,'utf8');const v=planRestore({safePath,testPath});
 return !v.ok||v.changes.length?{...p,applied:false,error:'restore_unverified'}:{...p,applied:true};}
