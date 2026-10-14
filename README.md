# BYTE BACK 방어전 · 9단계 저장점

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
