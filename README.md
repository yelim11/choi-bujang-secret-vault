# BYTE BACK 방어전 시작 틀 R5

## 현재 상태 · 2단계 저장점

2단계 저장점 기준으로 1단계에서 공개되던 가상 메모 네 건을 학습용 Supabase DB로 옮겼습니다. 최신 정적 `data.json`과 `public/data.json`에는 메모 본문을 두지 않습니다.

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



## 2단계 제작 3 · 최신 파일 노출 확인 절차

가상 메모의 실제 문장을 README나 스크립트에 다시 적으면 최신 저장소에 같은 문장이 남게 되므로, 검색할 문장은 Supabase의 학습용 가상 자료에서 확인한 뒤 **로컬 셸 변수에만 잠깐 넣고 커밋하지 않습니다.**

현재 GitHub 최신 커밋에서 확인할 때는 가상 메모 문장 하나씩 아래처럼 검사합니다.

```bash
PATTERN='여기에 확인할 가상 메모 문장을 로컬에서만 입력'
git grep -n -F -- "$PATTERN" HEAD -- .
unset PATTERN
```

정상 결과는 **출력 없음**입니다. 같은 방법으로 가상 메모 네 문장을 각각 확인합니다. 서버 전용 키도 값 자체를 저장하지 않고, 비밀키 접두어를 셸에서 조합해 최신 커밋을 확인할 수 있습니다.

```bash
SECRET_PREFIX="sb_""secret_"
git grep -n -F -- "$SECRET_PREFIX" HEAD -- .
git grep -n -F -- 'SUPABASE_SECRET_KEY=' HEAD -- .
unset SECRET_PREFIX
```

정상 결과는 두 검색 모두 **출력 없음**입니다.

현재 Production의 공개 정적 파일도 배포 주소를 로컬 변수로 두고 확인합니다.

```bash
APP='https://choi-bujang-secret-vault-tkzf.vercel.app'
curl -fsS "$APP/" -o /tmp/step2-index.html
curl -fsS "$APP/data.json" -o /tmp/step2-data.json

PATTERN='여기에 확인할 가상 메모 문장을 로컬에서만 입력'
grep -n -F -- "$PATTERN" /tmp/step2-index.html /tmp/step2-data.json
unset PATTERN
```

가상 메모 네 문장에 대해 반복했을 때 정상 결과는 **출력 없음**입니다. `/data.json`의 `notes`는 빈 배열이어야 합니다. 화면에서 보이는 네 카드의 내용은 정적 파일에 들어 있는 것이 아니라 공개 서버 API에서 실행 중에 받아오는 값입니다.

### 현재 확인 기록

- 최신 GitHub에서 가상 메모 문장 네 건을 각각 검색한 결과: 모두 0건.
- 최신 GitHub에서 서버용 비밀키 형태 및 직접 대입 흔적을 검색한 결과: 0건.
- Production 환경변수에는 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`가 등록되어 있으며, Secret 값 자체는 코드나 README에 기록하지 않음.
- 현재 화면은 가상 메모 네 카드를 표시하고 `/data.json`은 메모가 없는 상태임.
- `GET /api/notes`는 **아직 인증 없이 호출 가능**하며 가상 메모 네 건을 반환함. 이것은 3단계에서 막아야 할 남은 약점임.

### 과거 노출에 대한 한계

이번 단계는 **현재 최신 저장소와 현재 배포에서 정적 메모 시드와 서버 비밀값을 제거하는 작업**입니다. 1단계에서 이미 공개된 과거 Git 커밋과 과거 Vercel 배포 이력은 이 변경만으로 삭제되지 않습니다. 따라서 과거 노출까지 해소되었다고 표현하지 않습니다.



## 2단계 저장점

- 단계: `2`
- 저장소: `https://github.com/yelim11/choi-bujang-secret-vault`
- Production: `https://choi-bujang-secret-vault-tkzf.vercel.app`
- 정상 확인: 화면에는 가상 메모 네 카드가 보이고 `/data.json`은 빈 배열임.
- 남은 약점: `GET /api/notes`는 아직 비로그인으로 호출 가능함.

다시 확인할 때는 Production의 `/`, `/data.json`, `/api/notes` 세 경로를 확인합니다. 실제 서버 비밀값은 출력하거나 저장소에 기록하지 않습니다.



## 2단계 완결성 가점 보강

필수 방어 성공 뒤 제출 완결성을 높이기 위해 현재 Production의 공개 JSON 응답도 캐시되지 않도록 고정합니다.

- `/data.json`: `notes: []`만 반환하며 `Cache-Control: no-store`
- `/aleph.json`: 현재 2단계 배포 식별 정보만 반환하며 `Cache-Control: no-store`
- `/api/notes`: 서버 함수 응답에 브라우저/CDN 캐시 방지 헤더와 `X-Content-Type-Options: nosniff` 적용
- 화면의 서버 API 요청은 자격증명 없이, 리다이렉트를 허용하지 않고 JSON 응답만 요청

### 제출 묶음 설명

`bundle-notes.json`은 Git에 커밋하지 않고 제출 직전에만 만듭니다. 2단계의 `explanation`은 빈 줄을 제외하고 **정확히 세 줄**이며 다음 네 사실을 모두 포함해야 합니다.

1. 정적 자료를 Supabase/DB로 이동함.
2. 화면은 `/api/notes` Vercel 서버 함수를 사용하고 서버 전용 secret은 브라우저에 두지 않음.
3. `/api/notes`는 아직 비로그인 공개라는 남은 약점.
4. 과거 Git 커밋과 이전 Vercel 배포의 노출은 해소되지 않았음.

예시:

```json
{
  "explanation": "정적 data.json의 자료 본문을 코드 밖 Supabase DB로 이동했습니다.\n브라우저는 /api/notes Vercel 서버 함수만 호출하고 SUPABASE_SECRET_KEY는 서버 전용으로 사용합니다.\n/api/notes는 아직 비로그인 공개이며 과거 Git 커밋과 이전 Vercel 배포의 노출도 해소되지 않고 남아 있습니다."
}
```

`npm run bundle`은 위 형식과 필수 의미를 제출 전에 검사합니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽고 한 번에 한 제작 단위만 변경합니다. 비밀번호, 토큰, 서버 전용 키, 실제 개인정보를 코드·로그·답변·Git·제출 묶음에 넣지 않습니다. 3단계에서는 현재 공개된 서버 API 앞에 로그인 검사를 추가해야 합니다.
