import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));

if (config.step !== 2) {
  throw new Error('현재 저장점 설정과 배포 식별 단계가 맞지 않습니다.');
}

await mkdir(resolve(root, 'public'), { recursive: true });
await writeFile(
  resolve(root, 'public', 'data.json'),
  `${JSON.stringify({ notes: [] }, null, 2)}\n`,
  'utf8',
);
console.log('2단계 공개 정적 data.json은 메모와 1단계 확인 표시 없이 생성했습니다.');

if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(
    resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`,
    'utf8',
  );
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
