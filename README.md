# BYTE BACK 방어전 시작 틀 R5

## 현재 상태 · 2단계 제작 2

1단계에서 공개되던 가상 메모 네 건을 학습용 Supabase DB로 옮겼습니다. 최신 정적 `data.json`과 `public/data.json`에는 메모 본문을 두지 않습니다.

화면은 Vercel 서버 함수 `/api/notes`를 호출하고, 서버 함수만 Supabase의 `notes` 테이블을 읽습니다. 서버 함수는 다음 두 값을 Vercel 환경변수에서 읽습니다.

- `SUPABASE_URL`
- `SUPABASE_SECRET_KEY`

실제 URL 값이나 서버 전용 키는 GitHub 코드, 브라우저 파일, API 응답, 로그, 제출 묶음에 넣지 않습니다. 환경변수는 Vercel 프로젝트의 공식 설정 화면에서 직접 입력합니다.

### 현재 남아 있는 약점

2단계에서는 자료 위치만 코드 밖의 서버 DB로 옮겼습니다. `/api/notes` 자체에는 아직 로그인 검사가 없으므로 주소를 아는 누구나 호출할 수 있습니다. 이것은 3단계에서 인증을 붙이기 전까지 의도적으로 남아 있는 약점입니다.

또한 이전 공개 커밋이나 이전 배포에 포함됐던 가상 메모의 과거 노출 기록은 이번 변경만으로 사라졌다고 볼 수 없습니다.

## 실행 구조

- `/`: 정적 화면. 메모를 직접 포함하지 않고 `/api/notes`를 호출합니다.
- `/data.json`: 메모가 없는 공개 정적 확인 파일입니다.
- `/api/notes`: Supabase에서 `title`, `content`만 읽어 반환하는 Vercel 서버 함수입니다.
- `public/aleph.json`: Vercel 빌드 시 저장소·커밋·배포 주소를 기록합니다.

`@supabase/supabase-js`는 기존 의존성을 그대로 사용합니다. 실제 학생 자료, 토큰, 서버 전용 키를 코드나 Git 기록에 넣지 않습니다.

## Vercel 환경변수 설정

Vercel 프로젝트의 Settings → Environment Variables에서 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 Production 환경에 등록한 뒤 다시 배포합니다. 값 자체를 README나 커밋 메시지에 적지 않습니다.

정상 배포 후 화면에는 가상 메모 네 카드가 보여야 하고, `/data.json`의 `notes`는 빈 배열이어야 합니다. 반면 `/api/notes`는 아직 인증 없이 호출 가능한 상태여야 합니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽고 한 번에 한 제작 단위만 변경합니다. 비밀번호, 토큰, 서버 전용 키, 실제 개인정보를 코드·로그·답변·Git·제출 묶음에 넣지 않습니다. 3단계에서는 현재 공개된 서버 API 앞에 로그인 검사를 추가해야 합니다.
