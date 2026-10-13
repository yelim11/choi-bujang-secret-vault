# BYTE BACK 방어전 · 8단계 저장점

현재 단계는 **8단계 「자료마다 갈 수 있는 구역을 나눕니다」**입니다. 1~5단계 배포 앱의 기능과 경로는 보존합니다.

브라우저의 메모 CRUD는 모두 Vercel 서버 함수만 호출합니다. 로그인 요청도 `/api/auth` 서버 함수로 보내므로 현재 브라우저 정적 코드에는 Supabase publishable/anon 키를 넣지 않습니다. 4단계의 로그인 토큰 검증과 owner 검사는 그대로 유지합니다.

## 현재 경로

메모 API:

- `GET /api/notes`
- `POST /api/notes`
- `GET /api/notes/:id`
- `PUT /api/notes/:id`
- `DELETE /api/notes/:id`

로그인·세션:

- `POST /api/auth`

브라우저 메모 코드는 Supabase Data API를 직접 호출하지 않습니다.

## 원본 자료 API

`aleph.config.json.originalApiUrl`:

`https://naukmhaknwezkbxvkylc.supabase.co/rest/v1/notes`

query나 키·토큰이 없는 원본 자료 경로입니다.

## 직접 권한 회수

`supabase/step5_revoke_direct_access.sql`의 내용을 실제 DB에 적용했습니다.

확인 결과:

- anon: SELECT/INSERT/UPDATE/DELETE 모두 false
- authenticated: SELECT/INSERT/UPDATE/DELETE 모두 false
- service_role: SELECT/INSERT/UPDATE/DELETE 모두 true

따라서 브라우저 공개 키와 로그인 사용자 토큰으로 원본 Data API를 직접 읽거나 수정하는 테이블 권한은 없고, Vercel 서버 함수의 정상 CRUD는 유지됩니다.

## 100점 조건

1. `/aleph.json.allowedRoutes`에 허용 경로를 기록
2. 첫 화면에 `X-Content-Type-Options: nosniff`
3. 현재 화면 코드에서 Supabase publishable/anon 키 제거

오래된 브라우저 캐시에 이전 JS가 남지 않도록 첫 화면, `auth-client.js`, `app.js`에는 `Cache-Control: no-store`도 적용합니다.

## 보너스 XDR · 무차별 로그인 공격

기존 `src/decider.mjs` 규칙은 변경하지 않고 `xdr/brute-force` 부품을 추가했습니다.

- `read-alerts.mjs`: Wazuh 경보에서 시각·출발 주소·계정·규칙 수준·설명만 안전하게 추출
- `patterns.json`: MITRE ATT&CK T1110 기반 `rapid-same-source-failures`, `password-spray` 패턴
- `decide.mjs`: 명확한 공격은 `block`, 애매한 건 Jev 보조 판정, 정상 이벤트는 `record`
- `bridge.mjs`: 고확신도 T1110 차단 후보만 만료 시각·근거 경보 번호를 붙여 `deny-rules.json`으로 연결
- `alerts.log`: block/alert 이벤트를 한 줄 JSON으로 기록

재실행:

```bash
npm run xdr:run -- brute-force
```

현재 시험 경보 결과는 `block 10 / alert 9 / record 9`이며, 정상 이벤트를 block 한 경우는 0건입니다. 이 결과는 수업용 fixture를 로컬 실행한 자기점검 결과이며 운영 심판 판정을 뜻하지 않습니다.

## 직접 확인

- A 로그인 후 자기 메모 CRUD가 유지되는지 확인
- B의 타인 자료 접근이 계속 거부되는지 확인
- 무로그인 요청이 거부되는지 확인
- 원본 Supabase Data API 직접 접근이 거부되는지 확인
- 현재 배포 정적 코드에 Supabase 공개 키가 없는지 확인


## 6단계 기기 등록 판정기

- 요청 계약: `docs/DECIDER_REQUEST.md` (`aleph.decision.v1`).
- 운영 엔진이 검증해 전달한 `request.subjectId`는 가명 사용자 주체이며 `request.deviceId`는 확인된 기기 ID입니다.
- `request.deviceRegistered === true`이면 `allow / approved`, 그 외(`false` 또는 누락)는 `deny / device_not_registered`입니다.
- 구현 규칙 ID: `device_registered`. 판정기 응답은 계약의 다섯 항목만 반환합니다.
- 인증서 검증, mTLS 통로 접근, 사용자 토큰과 등록 기기 바인딩은 운영 엔진의 사전 검증 책임이며, 이 로컬 규칙만으로 해당 공격을 실증했다고 해석하지 않습니다.
- 신규 인증서, CA, 개인키, 접속 프로그램은 설치하거나 저장하지 않았습니다.

### 로컬 확인 순서

```bash
npm run decider:test
```

예상 결과:

```text
통과 · 등록 기기의 정상 요청
통과 · 미등록 기기의 가상 요청
이 명령은 가상 요청으로 연습하며 심판 통과 증거가 아닙니다.
```

두 번째 항목은 `deny`와 `device_not_registered`를 확인하는 테스트입니다. 위 내용은 저장소의 판정기·시험 스크립트를 별도 Node.js 폴더에 재현하여 확인한 출력입니다. 저장소 전체에서 `npm run decider:test`를 실행하거나 운영 심판 판정을 받은 것은 아닙니다. 최종 심판 판정은 제출 후 별도로 확인해야 합니다.

## 7단계 복합 접속 이상과 추가 본인 확인

- 계약: `docs/DECIDER_REQUEST.md`의 `aleph.decision.v1`. 6단계 `device_registered`를 유지하며, `step_up_required` 규칙을 추가했습니다.
- 운영 엔진이 신원·기기·경로를 검증한 요청만 판정합니다. `request.signals.source === 'judge_fixture'`인 가상 사건에서만 이상 신호를 결합합니다.
- `signals.hour`가 0~5시 또는 23시이고 `signals.network === 'unusual'`이며, `recentEvents`의 최근 300초 내 `risk_signal` 횟수가 10 이상인 경우를 복합 이상 접속으로 분류합니다. `region`만 바뀐 경우에는 차단하지 않습니다.
- 기기가 미등록이면 기존처럼 `deny / device_not_registered`로 거부합니다. 등록된 기기의 복합 이상 접속은 `step_up / step_up_required`로 재확인을 요청하고, 해당 요청에 엔진이 검증해 제공한 `stepUp.verified === true`와 계약상 유효한 인증 나이(0~900초)가 있으면 `allow / approved`합니다.
- 운영 접속의 `signals.source: 'none'`, 누락되거나 출처가 불명확한 신호는 임의로 정상 지역·시각·네트워크 정보로 보정하지 않습니다. 가상 사건 신호를 실제 위치 증거로 취급하지 않습니다.
- 제공된 계약에서 `stepUp` 필드가 확인되지만, 이 코드의 로컬 시험만으로 실제 로그인 재요청 UI 또는 실제 자료 차단을 확인할 수는 없습니다. 운영 연결 실측은 **미실행**입니다. 토큰 원문은 로그·저장소에 기록하지 않습니다.

### 재실행 및 자체 검증

```bash
npm run decider:test
npm run fixture:7
```

`decider:test`는 등록 기기 허용, 미등록 기기 거부, 복합 이상 접속 `step_up`, 재확인 후 `allow`를 점검합니다. `fixture:7`는 정상 사건 `allow`와 복합 이상 사건 `step_up`을 비교합니다. 모두 가상 요청 연습으로 운영 심판 통과 증거가 아닙니다.

별도 Node.js 재현 환경에서 정상·미등록·복합 이상·재확인·지역 단독 변화·신호 출처 불분명·인증 시간 초과·기기 거부 우선 8개 시나리오를 통과했습니다. 저장소 전체 npm 스크립트 및 실제 운영 로그인 확인 전 자료 차단은 미실행이며, 심판 또는 엔진이 연결된 환경에서 별도 시험해야 합니다.

## 8단계 자료 구역 (검증 가능한 최소 권한)

- 기존 메모 구역: `notes`, 개별 자원 ID: 저장된 `notes.id`(UUID), API: `/api/notes`, `/api/notes/:id`. 기존 URL/화면을 바꾸지 않습니다.
- 강사 공지 구역: `notices` (별도 자원 네임스페이스 예약). **현재 저장소에는 공지 저장 테이블, 운영 엔진의 검증된 강사 역할/소유권 정보, 공지 수정 API가 없습니다.** 강사 공지 수정은 허용하지 않으며 실제 공지 편집 기능이 구현되었다고 주장하지 않습니다.
- 판정기 `resource_boundary` 규칙은 엔진의 `service`, `method`, `route`, `path`를 모두 대조합니다. 정해진 메모 경로만 허용 후보이며, 임의 구역·`/notes/export`·메서드 불일치는 `deny / resource_not_allowed` 처리합니다. 실제 사용 시 새 reasonCode의 운영 등록부 허용 여부 확인이 필요합니다. 등록되지 않은 거부 코드는 엔진의 기본 거부로 처리될 수 있습니다.
- 6단계 기기 확인과 7단계 추가 인증 규칙은 유지합니다. 쿼리나 브라우저 본문의 `role`, `owner_id`를 판정 권한으로 사용하지 않습니다.
- 자료 API는 이미 `createLoginVerifier`로 로그인 증명을 검증하며, 목록은 검증된 `userId`로 필터링합니다. 단건 GET/PUT/DELETE는 저장된 `owner_id`와 검증된 `userId`를 대조하고, 수정/삭제 시 DB 쿼리에도 `owner_id` 조건을 재사용합니다. 타인 자료는 `NOTE_NOT_FOUND`로 처리해 존재 여부를 노출하지 않습니다.
- **한계:** 현재 `aleph.decision.v1` 판정 요청에는 소유자/강사 권한에 대한 검증 필드가 없습니다. 판정기만으로 A 메모와 B 메모의 권한을 구분했다고 말할 수 없습니다. 이 부분은 최종 API의 저장된 소유자 검사에 의존하며, 강사 공지 권한 시나리오는 검증된 엔진 계약이 추가되기 전까지 미구현/미실행입니다.
- 기존 `scripts/build-public.mjs` 및 `deployment-identity.mjs`의 단계 제한을 8단계까지 호환시켜, 배포 식별 정보가 누락되지 않도록 했습니다.

### 8단계 시험 순서

```bash
npm run decider:test
npm run fixture:7
npm run test:r5
npm run build
npm run bundle
```

로컬 가상 판정기에서 정상 요청 허용, 미등록 기기 거부, 이상 접속 추가 확인, 미지 구역/기능 경로 거부를 확인합니다. `npm run build`는 Vercel 배포 메타데이터 환경변수가 있는 환경에서 실행합니다(로컬 점검에는 `node scripts/build-public.mjs --local` 사용). `npm run bundle`은 Git 작업 디렉터리가 깨끗하고 로컬의 Git 제외 `bundle-notes.json` 세 줄 설명이 있어야 하며 실제 배포 자기점검을 수행합니다. 실행 전에는 결과를 성공이라고 적지 않습니다.

**직접 확인할 것:** A의 정상 목록·단건 요청 유지, B의 A 메모 목록/조회/수정 거부, 학생의 공지 수정 거부, 등록되지 않은 경로 거부. 심판의 실제 결과는 별도 확인해야 합니다.

### 8단계 심판 실패 S08_OTHER_ZONE_ALLOWED 대응

- 8단계 최초 판정(커밋 `83c854439190`)에서 `S08_OTHER_ZONE_ALLOWED`, 36/100점을 확인했습니다. 원인은 `/notes/:id`의 ID를 임의 문자열로 인정하여 다른 구역 이름이 개별 메모로 분류될 수 있는 점입니다.
- 판정기의 메모 ID를 API와 동일한 UUID 형식으로 제한했습니다. 가상 테스트의 `/notes/demo`는 엔진이 검증한 테스트 반/프로젝트/주체/사건 출처 조합에서만 예외입니다.
- `/notes/other`, `/notes/other-user-note`, `/notes/export`는 `deny / resource_not_allowed`를 기대하도록 회귀 시험을 추가했습니다.
- **남은 한계:** UUID의 실제 소유자는 판정 요청 계약에 제공되지 않습니다. API의 DB `owner_id` 확인이 최종 권한 경계이며, 이번 변경만으로 심판 재통과를 주장하지 않습니다.

### S08 2차 실패 후 DB 소유권 조건 강화

- 커밋 `76939c4f3b1b` 심판 재판정에서도 `S08_OTHER_ZONE_ALLOWED`가 반복되어 **UUID 형식 검사만으로 해결되지 않았음**을 확인했습니다.
- `api/notes.js`의 `ownedNote` 단건 조회에 `.eq('owner_id', userId)`를 추가해, 서버에서 검증된 사용자와 DB 소유자가 다른 행은 조회 단계에서 제외합니다. 기존 조회 결과 검사·PUT/DELETE 소유권 조건·목록 소유자 필터는 유지합니다.
- 이는 실제 API의 소유권 검증을 강화하는 최소 변경이며, 판정기에 소유자 정보가 전달되지 않는 `aleph.decision.v1` 계약의 한계는 그대로입니다. 심판 재통과와 본인/타인 계정 실측은 **미확인**입니다. 네트워크 DNS 제한으로 전체 저장소 git clone 및 npm 실행도 미실행입니다.

## 제출

로컬에 Git에 올리지 않는 `bundle-notes.json`을 준비한 뒤 `npm run bundle`을 실행해야 합니다. 제출 묶음은 실제 명령이 성공한 경우에만 생성 완료로 기록합니다.


`npm run bundle`은 학생 자기점검이며 실제 심판 판정 자체는 아닙니다. `bundle-notes.json`과 `artifacts/submission.json`은 Git에 커밋하지 않습니다.

