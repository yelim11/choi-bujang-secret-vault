# BYTE BACK 방어전 · 12단계 저장점

현재 단계는 **12단계 「탈환 작전실을 완성합니다」**입니다. 1~5단계 배포 앱의 기능과 경로는 보존합니다.

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

## 8단계 · 자료마다 갈 수 있는 구역을 나눕니다

현재 판정기는 `docs/DECIDER_REQUEST.md`의 요청 이름만 읽고 기존 6단계 기기 등록·7단계 추가 인증 규칙을 유지합니다.

- **메모 구역**: `GET /api/notes/:id`, `PUT /api/notes/:id`, `DELETE /api/notes/:id`만 판정기에서 허용합니다. 메모 ID는 심판 가상 요청을 위해 UUID로 제한하지 않습니다.
- **메모 전체 목록/생성**: 판정기에서는 허용하지 않습니다. 기존 화면의 `GET /api/my/notes`, 호환 `GET /api/notes`, `POST /api/notes`는 로그인 검증 뒤 서버가 `owner_id`를 강제하는 호환 API로만 유지합니다.
- **반 공지 구역**: `GET /api/notices`, `GET /api/notices/:id`만 판정기에서 허용합니다.
- **공지 쓰기/강사 자료**: 판정기 요청에는 역할이 없으므로 POST·PUT·PATCH·DELETE 및 강사 자료 구역은 모두 거부합니다. 실제 강사 공지 관리는 서버가 검증한 `app_metadata` 권한과 저장된 소유자를 다시 확인하는 관리 동작에서만 처리합니다.
- **알 수 없는 경로/쿼리 기능**: 모두 거부하며 `export`, `bulk`, `list` 같은 기능 이름을 `:id`로 가장해 통과시키지 않습니다.
- **다른 사람 메모**: 판정기에서 가명 주체와 DB 소유자를 추측하지 않습니다. 최종 `api/notes.js`가 검증된 로그인 `userId`와 저장된 `owner_id`를 함께 조건으로 조회·수정·삭제하여 거부합니다.

`aleph.config.json`의 `allowedRoutes`에는 판정기가 실제로 허용하는 위 5개 경로만 기록합니다. `vercel.json`의 단건 rewrite는 유지해 `/api/notes/:id`와 `/api/notices/:id`의 ID가 서버 함수에 정확히 전달됩니다.

재검증:

```bash
npm run decider:test
npm run fixture:7
npm run test:zone
npm run test:r5
npm run bundle
```

이 저장점은 이전 심판의 `S08_OTHER_ZONE_ALLOWED` 지적에 맞춰 구역 허용표를 최소화하고, 타인 단건 메모는 API 소유권 검사에서 거부하도록 정리한 최종 재제출본입니다. 공식 성공 여부는 재제출 심판 결과로 확인합니다.

## 9단계 · 도플갱어를 찾고 권한을 거둡니다

9단계는 기존 `src/decider.mjs`의 허용·거부 응답을 바꾸지 않고 별도 탐지기 `src/detect.mjs`를 추가해 회수 **제안**만 만듭니다.

- **안전한 입력 처리**: 공식 연습 계약의 `at`, `method`, `identity.sub`를 기본으로 읽고, 운영 가상 사건에 `deviceId`, `decision`, `network` 또는 `signals.network`가 있을 때만 형식을 확인해 선택적으로 읽습니다. 메모 본문·토큰·실명·지역 값은 보존하거나 출력하지 않습니다.
- **공식 연습 계약 유지**: 같은 가명 사용자의 GET이 어느 10분 구간에서든 120건을 **넘으면** `propose_revocation / burst_read`, 정확히 120건·다른 사용자 합산·10분 밖 사건은 `observe`입니다.
- **복합 이상 탐지**: 네트워크 정보가 제공된 사건에서는 다량 조회와 `unusual` 네트워크가 함께 있어야 의심으로 봅니다. 평소 네트워크(`usual`)의 다량 조회나 지역 변화만으로는 회수 제안을 내지 않습니다.
- **기기 한 개 대상**: 의심 구간의 모든 사건이 동일한 유효 `deviceId` 한 개로 확인된 경우에만 별도 `proposeRevocation(events)` 결과가 그 기기를 대상으로 `propose_revocation / burst_read`를 제안합니다. 기기가 없거나 둘 이상이면 기기 대상 제안은 내지 않습니다.
- **집행 분리**: 회수 API를 만들지 않았고 기기·사용자 권한이나 세션을 직접 바꾸지 않습니다. 실제 신원/세션 회수, 재시도 차단, 다른 자원 이동 차단, 탐지부터 회수까지 경과 시간은 심판이 가상 사건으로 확인합니다.
- **이전 단계 보존**: `src/decider.mjs`와 `RULE_IDS`는 8단계 그대로이며, `aleph.config.json.step`만 9로 올렸습니다. Vercel 빌드와 배포 식별 코드도 step 9를 허용하도록 확장했습니다.

재검증:

```bash
npm run detect:test
npm run decider:test
npm run fixture:7
npm run test:zone
npm run test:r5
npm run bundle
```

독립 로컬 재현에서 탐지기 10개 시나리오(공식 6개 + 네트워크/기기/비밀값 4개)를 모두 통과했습니다. 이는 실제 회수나 ALEPH 심판 통과 판정이 아니라 제출 전 자기검증 결과입니다.

## 10단계 · 백업에서 자료실을 되살립니다

기존 1~9단계 판정기(`src/decider.mjs`)는 수정하지 않고 검증된 정책 사본과 비공개 메모 사본 복구를 추가했습니다.

- Supabase `note_backups`, `note_audit`에 RLS를 적용했고 공개 역할은 접근할 수 없습니다. 서버 역할도 두 표에는 `SELECT·INSERT`만 가집니다.
- 2026-10-14 기준 기존 메모 **4건을 사본 4건으로 고정했고 SHA-256 검증 4/4 일치**를 확인했습니다. 본문은 확인 출력에 노출하지 않았습니다.
- 재현 SQL: `supabase/step10_backup.sql`.

### 정책 복원
- **검증된 정책 사본:** `backup/policy.v1.json` (`aleph.policy.snapshot.v1`, 버전 `9단계-통과-시점`). 판정 규칙 이름과 허용 경로를 한 덩어리로 SHA-256 해시해 사본에 저장합니다. `npm run policy:diff`는 매 실행마다 이 파일을 다시 읽어 schema·version·전체 해시를 검증한 뒤 현재 정책과 다른 항목만 보여 줍니다.
- `npm run policy:diff`: **복원할 버전과 사본 해시, 바뀔 규칙·허용 경로를 실행 전에 표시**합니다. 사본 누락·JSON 오류·schema/version 오류·SHA-256 불일치면 차이를 계산하거나 복원하지 않고 종료 코드 1로 중단합니다.
- `npm run policy:restore`: 계획만 표시. `npm run policy:restore -- --yes`: 확인 후 시험 정책 rules만 복원하며 XDR 등 다른 서비스와 기존 audit은 보존.
- 실제 `src/decider.mjs`, `aleph.config.json`, DB 운영 정책은 자동 변경하지 않습니다. `npm run policy:test`로 임시 사본 연습 가능.

### 메모 한 건 복구
- 서비스: `notes`
- 제출 경로: **`POST /api/restore/notes/:id`** (`aleph.config.json.restoreRoute`도 동일)
- **검증된 메모 사본:** `backup/note.v1.json` (`aleph.note.snapshot.v1`, 버전 `9단계-통과-시점`). 공개 저장소에는 메모 ID와 **소유자 SHA-256·내용 SHA-256만** 두고 제목·본문·사용자 ID 원문은 넣지 않습니다. 사본 전체도 SHA-256으로 한 번 더 봉인합니다. 복구 요청마다 이 스냅숏의 schema·version·항목 형식·중복 ID·전체 해시를 먼저 검증하고, 로그인 사용자 해시와 비공개 DB 백업의 실제 내용 해시가 스냅숏과 같을 때만 진행합니다. **복원 실행 직전 스냅숏과 DB 백업을 다시 검증**하고 달라졌으면 즉시 중단합니다.
- 본문은 빈 객체 또는 `{"dryRun":true}`만 허용. dry-run은 복구 없이 백업 버전·현재/백업 해시·변경 필드만 반환합니다.
- **스냅숏 검증과 두 번째 DB 백업 재검증이 모두 통과하기 전에는 감사 기록이나 메모 쓰기를 시작하지 않습니다.** 검증 실패는 성공으로 기록하지 않습니다. 재검증 통과 뒤 감사 기록을 추가할 수 없으면 복구하지 않습니다. 지정한 한 건만 수정/재생성하고 복구 후 ID·소유자·내용 해시를 스냅숏과 다시 대조합니다.
- 타인의 백업은 `404`, 변조된 사본은 `409`, 응답에는 메모 본문을 넣지 않습니다.
- `npm run restore:test`: 변조·삭제 복구, 타인 거부, 다른 메모 보존과 함께 **스냅숏 전체 SHA-256이 틀리면 쓰기 전 중단**, 첫 검증과 실제 쓰기 사이 DB 백업이 바뀌면 두 번째 검증에서 중단, 그 실패 경로에서 감사/메모 쓰기가 0건인지 확인합니다.

### 복구 뒤 1~9단계 재시험 순서
1. 1~2단계: 첫 화면 정상, `/data.json` 메모 본문 없음.
2. 3단계: 로그인 정상, 무토큰 메모 API `401/403`.
3. 4~5단계: 자기 메모 CRUD 유지, 상대 메모·원본 Data API 직접 접근 거부.
4. 6단계: `npm run decider:test` — 미등록 기기 거부.
5. 7단계: `npm run fixture:7` — 복합 이상 `step_up`, 확인 뒤 허용.
6. 8단계: 메모 단건/공지 GET 정상, 목록 판정 경로·공지 쓰기·강사 자료·알 수 없는 경로 거부.
7. 9단계: `npm run detect:test` — 정상 `observe`, 복합 다량 조회만 `propose_revocation`.
8. 10단계: 시험 계정 B 메모 변조/삭제 뒤 복구 경로 호출, 대상 한 건 ID·소유자·내용 해시 일치 확인.
9. 마지막으로 `npm run test:r5`, `npm run test:zone`, `npm run bundle`.

실제 DB 백업 생성과 해시 검증은 완료했습니다. B 메모를 일부러 변조·삭제하는 실측과 심판의 1~9단계 재전송은 미실행이며 심판 가상 사건으로 최종 확인합니다.

## 11단계 · 나만의 접속 앱을 완성합니다

기존 1~10단계 판정기와 복구 규칙을 보존한 채 같은 배포 주소를 설치형 웹앱(PWA)으로 만들고 학생 로그인에 서버 기기 승인 흐름을 추가했습니다. 별도 접속 프로그램은 없습니다.

- 설치형 화면: `public/manifest.webmanifest`(BYTE BACK 내 자료실, standalone, 192/512 PNG 아이콘), `public/sw.js`, `public/offline.html`. 서비스 워커는 오프라인 안내만 캐시하고 메모·토큰·`/api/` 응답은 저장하지 않습니다. **설치 표시는 기기 승인과 별개**라고 화면에 표시합니다.
- 로그인 토큰: `public/auth-client.js`의 탭 메모리에만 둡니다. 브라우저 영구 저장소를 사용하지 않으며 새로고침하면 다시 로그인합니다.
- 서버 기록: Supabase `devices`·`device_sessions`(RLS ON, 공개 역할 직접 접근 없음). 재현 SQL은 `supabase/step11_device_approval.sql`.
- 승인 요청: 서버가 5분 챌린지를 발급하고 플랫폼 패스키(WebAuthn)가 응답합니다. 서버는 고정 배포 origin·RP ID·챌린지·사용자 확인을 검증한 뒤 공개키만 `pending`으로 저장합니다. 앱 API에는 `approved`로 바꾸는 기능이 없습니다.
- 관리자 승인: 서버에서 정확한 pending 행을 검토한 뒤에만 `status='approved'`로 변경합니다. 화면의 승인 버튼이나 요청 본문의 `status`·`approved` 값으로 권한을 주지 않습니다.
- 승인된 기기 확인: 새 챌린지에 패스키가 서명하고 서버가 서명·origin·RP ID·챌린지·서명 횟수를 검증한 뒤에만 해당 로그인 `session_id`를 1시간 확인 상태로 기록합니다. 챌린지는 한 번 소비하면 재사용할 수 없습니다.
- 자료 차단: 학생 로그인은 메모 API와 복구 API에서 서버의 기기 확인 기록을 다시 검사합니다. 승인 전·확인 전·회수 후·시간 만료 뒤에는 `403 DEVICE_NOT_APPROVED`이고 메모를 반환하지 않습니다.
- 기존 심판 회귀: ALEPH 심판의 서명된 가상 신원은 패스키 UI를 거칠 수 없으므로 기존 1~10단계 정상·금지 요청 검증을 유지합니다. 6단계 `deviceRegistered` 규칙은 기존 `src/decider.mjs` 그대로이며 11단계에서 판정기 요청 이름이나 `RULE_IDS`를 추가하지 않았습니다.

확인 순서:
1. 로그인 전에는 자료가 없습니다.
2. 로그인해도 기기 확인 전에는 workspace가 숨겨지고 승인 화면만 보입니다.
3. 「이 기기 승인 요청」은 `pending`만 만들며 메모 API는 계속 403이어야 합니다.
4. Supabase에서 검토한 행만 승인한 뒤 「승인된 이 기기로 확인」에서 패스키 서명을 완료합니다.
5. 서버 상태가 `sessionVerified: true`라고 다시 답한 뒤에만 기존 메모 화면이 열립니다.
6. 승인을 회수하거나 1시간이 지나면 다시 잠겨야 합니다.
7. `npm run test:11` → `npm run decider:test` → `npm run detect:test` → `npm run test:zone` → `npm run test:r5` → `npm run bundle`.

현재 DB 테이블과 권한은 적용했습니다. 실제 기기 승인 행은 화면에서 패스키 승인 요청이 생긴 뒤 관리자가 검토해야 하므로 임의로 만들지 않았습니다.

## 12단계 · 탈환 작전실을 완성합니다

12단계는 1~11단계의 방어 규칙을 새로 바꾸는 단계가 아니라, **현재 저장점의 실제 근거와 미실행 항목을 한곳에서 구분해 확인하는 읽기 전용 작전실**을 추가합니다. 작업 시작 기준은 11단계 저장점 `79d5355a1bfdbe3c8ebe4df1e33aefefef6aec8e`이며, 재검증 표는 실행할 때 `git rev-parse HEAD`로 실제 검사 커밋을 기록합니다.

### 탈환 작전실
- 화면의 **탈환 작전실**은 승인된 학생 기기 세션에서 `GET /api/war-room`을 호출합니다. 무인증 요청은 401, 학생 기기 확인 전에는 403으로 자료 없이 거부합니다. 이 경로는 8단계 판정기의 `allowedRoutes`에 추가하지 않았습니다.
- **판정기 규칙**은 `src/decider.mjs.RULE_IDS`를 읽되 상태를 `listed`(코드 목록, 실행 결과 아님)로 표시합니다.
- **탐지 사건**은 실제 탐지 사건 저장소가 이 앱 API에 연결되어 있지 않으므로 `not_run`, 사건 수 `null`로 표시합니다. 모르는 값을 0건으로 꾸미지 않습니다.
- **회수 상태**는 서버가 현재 로그인 사용자의 `devices` 행을 다시 읽어 `approved / pending / revoked` 개수만 `confirmed`로 표시합니다. 사용자 ID·기기 번호는 작전실 응답과 기록에 넣지 않습니다.
- **복구 버전**은 `backup/policy.v1.json`과 `backup/note.v1.json`을 다시 검증한 결과와 버전, 정책 차이 건수, 메모 사본 항목 수만 표시합니다. 가상 메모 제목·본문은 표시하지 않습니다.
- **41종 총공세**는 ALEPH 심판이 실제로 실행하기 전에는 `not_run`이며 완료 건수를 `null`로 둡니다.
- 화면에 보이는 수치와 `war_room_view ...` 가린 서버 기록은 `src/war-room.mjs`의 같은 요약 객체에서 만들어집니다. 기록에는 규칙 수·기기 상태 개수·사본 검증/버전만 있고 토큰·사용자 ID·기기 ID·메모 본문은 없습니다.

### 1~11단계 정상·금지 요청 표

```bash
npm run recon:table
```

- 결과는 Git에 올리지 않는 `artifacts/recon-table.md`에 **단계 / 정상·금지 / 요청 / 기대 결과 / 실제 결과 / 판정 / 근거 / 요청 ID / 확인 시각**으로 저장합니다.
- 배포 주소에 실제로 보낸 요청은 **실제 API**, `decide()`·`detect()` 가상 입력은 **로컬 연습**, 보내지 않은 요청은 **미실행**으로 구분합니다. 로컬 연습은 심판 판정으로 쓰지 않습니다.
- 로그인/승인 기기의 정상 API를 함께 측정하려면 실행하는 셸에만 `ALEPH_STUDENT_TOKEN`을 둘 수 있습니다. 스크립트는 그 값을 표·로그·파일에 쓰지 않습니다. 값이 없으면 해당 행은 미실행으로 남습니다.
- 서로 다른 두 시험 계정이 필요한 타인 메모 실측, 실제 기기 승인 상태 변경, 그리고 **ALEPH 총공세 41종**은 조건이 없으면 미실행으로 남기며 임의로 통과 처리하지 않습니다.
- 스크립트는 불일치가 있는 경우 종료 코드 1을 돌려 다음 수정 대상을 숨기지 않습니다.

### 학생이 만든 부분과 제공 엔진
- **학생 저장소가 만든 부분:** 자료실 UI와 서버 API, 로그인/소유자 검사, `src/decider.mjs` 판정 규칙, `src/detect.mjs` 탐지/회수 제안, 11단계 패스키 접속 앱, 10단계 복구, 12단계 작전실과 재검증 표입니다.
- **수업에서 제공된 부분:** **ALEPH SDP 엔진과 심판**이 판정기에 가상 요청을 전달하고, 탐지 사건을 보내며, 실제 신원·세션 회수와 경과 시간 측정, 마지막 41종 총공세를 수행합니다. 이 제공 엔진 코드는 이 저장소의 학생 산출물인 것처럼 포장하지 않습니다.
- `src/decider.mjs`는 12단계에서 수정하지 않았고 `docs/DECIDER_REQUEST.md` 계약 이름만 읽는 기존 규칙과 `RULE_IDS`를 그대로 유지합니다.

### 설치 · 실행 · 중지 · 복구
1. **설치:** 공개 저장소를 새 폴더에 받은 뒤 `npm install`. 서버 비밀값은 Git에 넣지 않고 배포 환경의 `SUPABASE_URL`, `SUPABASE_SECRET_KEY` 입력란에만 둡니다.
2. **검사:** `npm run test:12`, `npm run decider:test`, `npm run detect:test`, `npm run test:zone`, `npm run test:r5`, `npm run recon:table` 순서로 확인합니다.
3. **실행:** 정적 빌드는 `npm run build -- --local`; 실제 서버 함수까지 포함한 실행은 연결된 Vercel 배포 `https://choi-bujang-secret-vault-tkzf.vercel.app`을 기준으로 합니다. PWA 설치 여부는 기기 승인 근거가 아닙니다.
4. **중지:** 로컬 개발 서버를 사용했다면 해당 터미널에서 중지합니다. 저장소 자체에는 백그라운드 상주 프로그램이 없으며, 운영 배포 중지는 Vercel 배포 제어와 별개입니다.
5. **정책 복구:** 먼저 `npm run policy:diff`로 검증 사본과 변경 범위를 확인하고 기존 10단계의 확인 절차를 거쳐 시험 정책만 복원합니다. 운영 정책을 화면 버튼으로 임의 변경하지 않습니다.
6. **메모 복구:** `POST /api/restore/notes/:id`에서 지정한 한 건의 검증 사본만 복원하며, 11단계 학생 접속에서는 로그인과 승인 기기 확인이 선행되어야 합니다. 복구 뒤 `npm run recon:table`로 이전 정상·금지 요청을 다시 구분해 기록합니다.
7. **제출:** 마지막 저장점에서 `npm run bundle`을 실행하고, 실행하지 않은 시험은 미실행 상태로 둡니다.

비밀번호·토큰·기기 개인키·서버 전용 키·메모 본문은 작전실, 재검증 표, 제출 묶음에 넣지 않습니다.

### 12단계 점검 원천 통일
- `src/attack-check.mjs`의 한 점검 목록을 `npm run bundle`, `GET /api/checks`, `GET /api/ops`, `npm run verify:table`, 탈환 작전실 화면이 공통으로 사용합니다.
- 실제 배포에 보낸 요청은 HTTP 관측값·요청 ID·확인 시각을 남기고, 보내지 않은 시험은 `not_run`으로 남깁니다. `not_run`은 기대와 일치 건수에 포함하지 않습니다.
- `GET /api/ops` 응답의 `summary`와 `items`에서 화면 수치와 표를 그대로 그리고, 가린 서버 기록도 같은 `summary`에서 생성합니다. 별도 계산값이나 화면 성공 문구를 근거로 사용하지 않습니다.
- 41종 총공세는 ALEPH 심판이 실행하는 시험이므로 제출 전에는 미실행으로만 표시합니다.

## 보너스 XDR · 알려진 취약점 악용

기존 `src/decider.mjs` 규칙을 수정하지 않고 `xdr/known-cve` 부품을 추가합니다.

- `read-alerts.mjs`: Wazuh 모양 fixture에서 시각·출발 주소·계정·규칙 수준·설명만 추출하며 비밀값처럼 보이는 문자열을 가립니다.
- `patterns.json`: CVE-2021-44228 원격 JNDI 조회와 MITRE ATT&CK T1190 근거를 머리글·요청 인자·중간 점검 흔적으로 구분합니다.
- `decide.mjs`: import·파일 I/O·네트워크 없이 단독 계산합니다. 완전한 JNDI 원격 조회는 block, T1190 중간 경보는 alert, 정상 이벤트는 record입니다.
- `respond.mjs`: 고확신도 block만 만료 시각과 근거 경보 번호가 있는 `deny-rules.json`으로 연결하고, block/alert만 `xdr/alerts.log`에 기록합니다.
- 공용 `xdr-run.mjs`가 쓰는 `bridge.mjs`는 `respond.mjs`만 호출하는 얇은 어댑터이며 판정기 기존 규칙은 변경하지 않습니다.

재실행:

```bash
npm run xdr:run -- known-cve
```

정상 이벤트가 차단 후보의 출발 주소와 겹치면 해당 주소는 거부 규칙에서 제외합니다. 이 결과는 수업용 fixture 자기점검이며 실제 운영 차단이나 ALEPH 심판 판정을 뜻하지 않습니다.
  
시험 fixture 24건 결과: `block 8 / alert 8 / record 8`, 정상 이벤트 block 0건입니다.
