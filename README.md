# BYTE BACK 방어전 · 3단계 저장점

현재 단계는 **3단계 「진짜 로그인을 붙입니다」**입니다. 2단계의 서버 DB 구조를 유지하면서 Supabase Auth 이메일·비밀번호 로그인/로그아웃을 붙였고, Vercel 자료 API가 틀의 `src/verify-login.mjs`로 로그인 토큰을 검증합니다.

## 현재 구현

- 브라우저: Supabase 공식 SDK로 이메일·비밀번호 로그인/로그아웃
- 공개 설정: Project URL과 publishable key만 브라우저에 사용
- 서버 설정: `SUPABASE_SECRET_KEY`는 Vercel Production 환경변수에만 존재
- 서버 인증: `src/verify-login.mjs`는 수정하지 않고 그대로 사용
- 메모 DB: `public.notes`, `id uuid`, `owner_id uuid`, RLS 활성화
- 직접 DB 권한: `anon`·`authenticated`는 읽기/CRUD 불가, 서버 역할만 CRUD
- 정적 `data.json`: 메모 없음

## 로그인 발급자

`aleph.config.json.identityProvider`:

- issuer: `https://naukmhaknwezkbxvkylc.supabase.co/auth/v1`
- audience: `authenticated`
- JWKS: issuer의 `/.well-known/jwks.json`

서버는 브라우저가 보내는 `userId`나 `role`을 권한 판단에 사용하지 않고 검증된 토큰의 사용자 ID만 사용합니다.

## API 계약

`aleph.config.json.allowedRoutes`:

- `/api/notes`
- `/api/notes/:id`

동작:

- `GET /api/notes`: 로그인 사용자의 `owner_id`에 해당하는 메모 배열
- `POST /api/notes`: `{id,title,body}`, id 생략 시 서버가 UUID 생성 후 `{id}` 반환
- `GET /api/notes/:id`: `{id,title,body}`
- `PUT /api/notes/:id`: 제목·본문 수정
- `DELETE /api/notes/:id`: 삭제, 이후 같은 id GET은 404

POST의 `owner_id`는 서버가 확인한 사용자 ID로만 저장합니다. **3단계에서는 한 건 GET/PUT/DELETE의 owner 검사를 아직 하지 않습니다.** 따라서 로그인한 B가 A의 메모 id를 알면 접근할 수 있는 BOLA 약점은 4단계에서 막습니다.

## 100점 조건 점검

현재 Production에서 직접 확인한 결과:

1. 무로그인 `GET /api/notes` → **HTTP 401 + JSON `{"error":"UNAUTHORIZED"}`**
2. `/aleph.json` → **HTTP 200, step 3 배포 식별 정보 확인**
3. 첫 화면 `/` → **`X-Content-Type-Options: nosniff` 확인**

추가로 무로그인 `POST /api/notes`와 무로그인 `GET /api/notes/:id`도 JSON 401로 거부됨을 확인했습니다.

## DB 마이그레이션

재실행 기록은 `supabase/step3_auth_crud.sql`에 있습니다. 기존 가상 메모 본문은 Git에 넣지 않고 DB에만 유지합니다.

## 아직 직접 확인하지 못한 것

현재 Supabase Auth 사용자 수가 0명이므로 실제 A 이메일·비밀번호 로그인 후 브라우저 CRUD E2E는 아직 실행하지 않았습니다. A 계정은 Supabase Dashboard의 Authentication → Users에서 직접 만들고, 비밀번호는 채팅이나 Git에 남기지 않습니다.

A 계정이 준비되면 다음 순서로 확인합니다.

1. 시크릿 창에서 무로그인 상태로 자료가 보이지 않는지 확인
2. A 로그인
3. 가상 메모 추가
4. 같은 메모 수정
5. 삭제
6. 로그아웃 후 다시 자료가 보이지 않는지 확인

## 실행 및 제출

```bash
npm run build -- --local
npm run test:r5
npm run bundle
```

`bundle-notes.json`과 `artifacts/submission.json`은 Git에 커밋하지 않습니다. `npm run bundle`은 자기점검이며 운영 심판의 판정 자체는 아닙니다.

다음 4단계에서는 현재 의도적으로 남겨 둔 로그인 사용자 간 메모 소유자 검사를 추가합니다.
