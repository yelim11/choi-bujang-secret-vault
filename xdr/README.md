# XDR 보너스 경보

이 폴더는 보너스 작전의 Wazuh 모양 연습 경보를 처리합니다. 경보는 수업용 가상 데이터이며 실제 로그가 아닙니다.

## brute-force

`xdr/fixtures/brute-force.json`을 읽어 MITRE ATT&CK T1110 기반으로 다음처럼 처리합니다.

- 명확한 무차별 대입·password spraying: `block`
- 애매한 로그인 실패: Jev 보조 판단, 응답이 없으면 `alert`
- 정상 로그인·세션 이벤트: `record`

`xdr/brute-force/read-alerts.mjs`는 시각·출발 주소·계정·규칙 수준·설명만 추출하고 비밀값처럼 보이는 문자열을 가립니다.
`xdr/brute-force/bridge.mjs`는 고확신도 차단 후보만 만료 시각과 근거 경보 번호가 붙은 `deny-rules.json`으로 만들며, 기존 `src/decider.mjs` 규칙은 수정하지 않습니다.
알림은 `xdr/alerts.log`에 JSON 한 줄씩 기록합니다.

## 실행

```bash
npm run xdr:run -- brute-force
```

결과는 `xdr/brute-force/result.json`에 저장됩니다. 실행기는 네트워크를 사용하지 않으며 `decide(alert)`의 반환 형식을 확인합니다.


## web-injection

`xdr/fixtures/web-injection.json`의 26개 가상 Wazuh 경보를 MITRE ATT&CK T1190 기반으로 판정합니다.

- 같은 주소에서 반복되는 명확한 SQL/명령 구문, 스크립트 삽입, 경로 순회: `block`
- 일회성이거나 애매한 주입 의심 이벤트: Jev 보조 판단, 응답이 없으면 `alert`
- 낮은 수준의 정상 웹 요청: `record`

`xdr/web-injection/decide.mjs`는 심판의 격리 실행에서도 동작하도록 형제 파일 import 없이 standalone으로 구성했습니다.
`xdr/web-injection/bridge.mjs`는 고확신도 T1190 반복 공격만 만료 시각과 근거 경보 번호가 붙은 거부 규칙으로 연결하며 기존 `src/decider.mjs` 규칙은 수정하지 않습니다.

실행 명령:

```bash
npm run xdr:run -- web-injection
```

시험 결과: `block 8 / alert 9 / record 9`, 정상 이벤트 오차단 0건.

## known-cve

`xdr/fixtures/known-cve.json`의 24개 가상 Wazuh 경보를 CVE-2021-44228 및 MITRE ATT&CK T1190 근거로 분류합니다.

- 완전한 JNDI 원격 조회 구문: `block`
- 완전한 악용 구문은 없지만 T1190 중간 경보: `alert`
- 공격 근거가 없는 낮은 수준 정상 이벤트: `record`

`decide.mjs`는 다른 파일이나 패키지를 import하지 않는 standalone 판단기입니다. `respond.mjs`는 고확신도 block만 `deny-rules.json`으로 연결하고 기존 `src/decider.mjs`는 수정하지 않습니다.

```bash
npm run xdr:run -- known-cve
```
  
시험 fixture 24건 결과: `block 8 / alert 8 / record 8`, 정상 이벤트 block 0건입니다.

## persistence

`xdr/fixtures/persistence.json`의 24개 가상 Wazuh 경보를 MITRE ATT&CK T1543·T1053 근거로 판정합니다.

- 서명 없는 새 서비스·낯선 예약 작업·시작 폴더의 미등록 프로그램처럼 명확한 지속성 징후: `block`
- 서명 미확인, 서비스 설명 변경, 단독 임시 파일 등 증거가 부족한 변경: `alert`
- 기존 서명 서비스·정상 예약 작업·목록 읽기·로그인 등 정상 이벤트: `record`

`decide.mjs`는 다른 파일이나 패키지를 import하지 않는 standalone 판단기입니다. `respond.mjs`는 고확신도 block만 `deny-rules.json`으로 연결하고 기존 `src/decider.mjs`는 수정하지 않습니다.

```bash
npm run xdr:run -- persistence
```

fixture 24건 결과: `block 8 / alert 8 / record 8`, 정상 이벤트 block 0건.
