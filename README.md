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

## 8단계 · 자료마다 다른 신뢰 구역

이번 구현은 **SDP 엔진의 가명 ID**와 **실제 데이터베이스의 로그인 사용자 ID**를 무조건 같다고 가정하지 않습니다. 소유권을 증명할 수 없으면 거부합니다.

### 자료 구역과 기존 호환성

| 영역 | 서비스 | 주소 | 권한 확인 |
| --- | --- | --- | --- |
| 자기 메모 | `notes` | `/api/notes`, `/api/notes/:id` | 검증된 로그인 `userId`와 DB `owner_id` 일치 |
| 강사 공지 열람 | `notices` | `/api/notices`, `/api/notices/:id` | 로그인 인증 |
| 강사 공지 생성·수정·삭제 | `notices` | `POST /api/notices`, `PUT/DELETE /api/notices/:id` | 서버가 관리자 Auth `app_metadata`에서 강사 역할 확인 + 저장된 소유자 확인 |

각 요청은 서버 내부에서 `notes:<uuid>` 또는 `notices:<uuid>`로 구별됩니다. 목록에는 `notes:own-list` / `notices:own-list`를 사용합니다. 기존 메모 테이블과 화면, 기존 `{id,title,body}` 응답은 변경하지 않았습니다.

`src/resource-policy.mjs`가 정확한 경로/메서드/`id`를 검사하고, 중복 `id`, 다른 ID의 경로/쿼리 혼용, `export` 같은 인접 기능 경로와 권한 관련 쿼리를 거부합니다. 요청 본문의 `role`, `owner_id`, 쿠키/헤더의 임의 사용자 정보는 권한 근거로 사용하지 않습니다.

### 6~8단계 판정기

`src/decider.mjs` 응답은 기존 `aleph.decision.v1`의 다섯 필드만 사용하며, `RULE_IDS`는 `device_registered`, `step_up_required`, `resource_zone`입니다.

- 미등록 기기: `deny / device_not_registered`
- 등록된 기기의 복합 가상 이상 접속: 재인증 전 `step_up / step_up_required`
- 정해진 연습용 A 메모 조회·수정 및 등록된 강사 주체·기기의 공지 수정: `allow`
- 다른 주체/기기/반/프로젝트, 임의 UUID, 인접 기능 경로: `deny / route_not_allowed`

공식 가상 사건용 권한은 `class_fixture/project_fixture`와 정확한 가명 주체·기기·경로까지 대조하는 **연습용 등록 항목**으로만 존재합니다. 실제 사용자와 연결된다는 주장은 하지 않습니다.

### 실제 SDP 가명 사용자와 DB 소유자 연결

판정 요청 v1에는 `owner_id`나 `role`이 없습니다. 이를 임의 요청 필드로 추가하는 대신 다음과 같이 **서버 전용 등록부를 추가**했습니다.

1. 운영자가 신원을 검증하고 `sdp_principal_bindings`에 반·프로젝트·가명 주체·등록 기기와 실제 Supabase 사용자 ID를 연결합니다.
2. `src/engine-resource-access.mjs`가 서버 비밀키로 활성화·만료 여부를 확인하고, 개별 메모는 해당 DB `owner_id`와 실제로 일치할 때만 통과시킵니다.
3. 강사 공지 쓰기는 추가로 `auth.admin.getUserById`가 반환한 서버 관리 `app_metadata.role/roles`을 확인합니다. 공지 수정·삭제 시 저장된 `owner_id`를 다시 검사합니다.
4. 이 연결이 없거나 만료되었거나 DB 연결이 실패하면 **기본 거부**합니다. 브라우저에서 가명-실사용자 연결을 등록하는 API는 만들지 않았습니다.

`supabase/step8_resource_authorization.sql`에 새 `notices` 및 `sdp_principal_bindings` 테이블과 RLS/서비스 역할 전용 접근을 준비했습니다. **2026-10-13 점검 시 Supabase 관리 SQL 연결이 반복해서 시간 초과되어 실제 DB에 적용하지 못했습니다.** 기존 notes 데이터는 수정하지 않았습니다. 따라서 새로운 공지 CRUD 및 실사용 SDP 바인딩은 SQL 적용과 운영자의 실제 등록 전에는 **미실행**이며, 배포된 서버는 해당 기능을 실패 시 거부합니다.

### 자동 검증

```bash
npm run decider:test
npm run fixture:7
npm run test:r5
npm run test:zone
node scripts/build-public.mjs --local
npm run bundle
```

`test:zone`은 가상 DB에 A/B 사용자·각 메모·강사 공지를 넣고 자기 메모 허용, B의 A 메모 거부, 기기/구역 변경 거부, 학생의 강사 행세 차단, 강사의 자기 공지 수정과 다른 소유자 공지 거부를 확인합니다. 실제 사용자 비밀번호/토큰/메모 내용은 테스트에 사용하지 않습니다.

`npm run bundle`은 배포 완료·정상 Git 작업 디렉터리·Git 제외 `bundle-notes.json` 3줄 설명이 필요하며 자체점검이지 심판 판정이 아닙니다.

### 이전 심판 판정과 남은 운영 검증

- 기존 `51421bd67371` 커밋 기준 **48/100점**, 실패 코드 `S08_OTHER_ZONE_ALLOWED`를 확인했습니다.
- 뒤이은 `e608ff24182a` 수정과 이번 서버 연결·강사 권한 구현의 **공식 심판 결과는 아직 확인되지 않았습니다**.
- 운영 엔진 가명 주체의 실제 발급·등록부 연결과 실사용자 정상 단건 조회, 강사 계정/공지 DB E2E는 운영 데이터와 등록을 갖춘 뒤 검증해야 합니다.
- 사용자 제공 엔진 계약 자체를 수정하거나 운영 서버가 소유권 필드를 전달한다고 가정하지 않았습니다.

## 제출

로컬에 Git에 올리지 않는 `bundle-notes.json`을 준비한 뒤 `npm run bundle`을 실행해야 합니다. 제출 묶음은 실제 명령이 성공한 경우에만 생성 완료로 기록합니다.


`npm run bundle`은 학생 자기점검이며 실제 심판 판정 자체는 아닙니다. `bundle-notes.json`과 `artifacts/submission.json`은 Git에 커밋하지 않습니다.

