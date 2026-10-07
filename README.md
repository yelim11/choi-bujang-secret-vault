# BYTE BACK 방어전 · 5단계 저장점

현재 단계는 **5단계 「자료 요청을 서버 한곳으로 모읍니다」**입니다.

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

## 제출

`npm run bundle`은 학생 자기점검이며 실제 심판 판정 자체는 아닙니다. `bundle-notes.json`과 `artifacts/submission.json`은 Git에 커밋하지 않습니다.
