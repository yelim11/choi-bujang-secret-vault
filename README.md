# BYTE BACK 방어전 · 4단계 저장점

현재 단계는 **4단계 「로그인해도 내 자료만 보이게 합니다」**입니다. 3단계의 Supabase Auth와 서버 토큰 검증을 유지하면서, Vercel 자료 API와 Supabase RLS가 모두 메모 소유자를 확인하도록 변경했습니다.

## 현재 구현

- 서버는 기존 `src/verify-login.mjs`가 검증한 사용자 ID만 신뢰합니다.
- URL·JSON 본문의 `userId`, `role`, `owner_id`는 권한 근거로 사용하지 않습니다.
- 목록 GET은 `owner_id = 검증된 userId`인 메모만 반환합니다.
- POST는 검증된 userId를 서버가 `owner_id`에 저장합니다.
- 한 건 GET·PUT·DELETE는 기존 DB 행의 `owner_id`와 검증된 userId를 비교하고, 다르면 404로 기본 거부합니다.
- PUT은 `{title,body}`만 허용하며 저장되는 `owner_id`는 다시 검증된 userId로 고정합니다.

## API 계약

`aleph.config.json.allowedRoutes`에는 실제 메서드와 경로를 기록합니다.

- `GET /api/notes`
- `POST /api/notes`
- `GET /api/notes/:id`
- `PUT /api/notes/:id`
- `DELETE /api/notes/:id`

응답 형식:

- 목록 GET → `[{id,title,body}, ...]`
- POST `{id?,title,body}` → `{id}`
- 한 건 GET → `{id,title,body}`
- PUT body → `{title,body}`
- DELETE → `{id}`
- 없는 메모와 타인 메모는 모두 404로 처리합니다.

## A/B 시험 자료

실제 DB에는 시험 계정 두 개와 가상 메모 4건을 연결했습니다.

- A 소유 메모: 3건
- B 소유 메모: 1건
- `owner_id IS NULL`: 0건

실제 이메일 값은 Git에 저장하지 않습니다. 재실행용 템플릿은 `supabase/step4_assign_owners.sql`이며 실행 직전에 placeholder만 시험 계정 이메일로 바꿉니다.

## RLS와 최소 권한

`supabase/step4_owner_rls.sql`을 실제 DB에 적용했습니다.

권한 확인 결과:

- `anon`: SELECT/INSERT/UPDATE/DELETE 모두 false
- `authenticated`: SELECT/INSERT/UPDATE/DELETE만 true

정책:

- SELECT → `USING (auth.uid() = owner_id)`
- INSERT → `WITH CHECK (auth.uid() = owner_id)`
- UPDATE → `USING`과 `WITH CHECK` 모두 `auth.uid() = owner_id`
- DELETE → `USING (auth.uid() = owner_id)`

다른 테이블은 건드리지 않았습니다.

## 100점 조건

4단계에서도 다음 세 조건을 유지합니다.

1. 무로그인 `GET /api/notes` → JSON 오류와 HTTP 401/403
2. 배포 주소의 `/aleph.json` → 현재 step 4 배포 식별 정보
3. 첫 화면 `/` → `X-Content-Type-Options: nosniff`

## 직접 확인

- A 로그인 → A 메모만 보이는지 확인
- B 로그인 → B 메모만 보이고 A 메모는 보이지 않는지 확인
- 각 계정에서 자기 메모 추가·수정·삭제 확인
- 상대 메모 UUID로 GET·PUT·DELETE 시 404 확인
- POST/PUT 본문에 `owner_id`를 추가하면 허용 계약이 아니므로 400 확인

## 실행 및 제출

```bash
npm run build -- --local
npm run test:r5
npm run bundle
```

`bundle-notes.json`과 `artifacts/submission.json`은 Git에 커밋하지 않습니다. `npm run bundle`은 자기점검이며 심판 판정 자체는 아닙니다.
