# 통제형 victim 후보 (오픈소스, GT가 상대적으로 선명한 벤치마크)

아래는 선행 연구에서 이미 정답 구조가 명확해 GT 기반 실험에 직접 가져오기 쉬운 오픈소스 후보입니다.

이 레포의 현재 실험 목적(10개 기법 고정, 공격 시도 라벨링 + 객체 근거(oracle)/증거 기반 ASR)에 맞춰 우선순위는 다음과 같습니다.

- **1차 권고:** `OWASP Benchmark` + `paper-victim`  
  - Benchmark: endpoint 단위 정답(탐지/성공 여부)이 공식적으로 명시.  
  - paper-victim: 논문형 지표(10가족 고정) 실험에 바로 맞는 제어형 victim.

## 1) OWASP Benchmark (최우선 권장)
- 링크: https://owasp.org/www-project-benchmark/
- 근거
  - 프로젝트가 각 테스트 케이스에 대해 `expectedresults-*.csv`(또는 `expectedresults.csv`)를 제공.
  - 각 테스트 케이스가 `single web page and web endpoint` 기반이며 `true finding / false positive`가 명시됨.
  - 따라서 10개 공격 패밀리 중 일부를 deterministic하게 GT로 매핑하기에 가장 적합.
- 10개 패밀리 적용성 (대상: `sqli, xss, cmdi, path_traversal, auth_bypass, idor, ssrf, csrf, file_upload, info_disclosure`)
  - `sqli`/`xss`/`path traversal`/`info disclosure`는 매우 높음
  - `cmdi`는 버전/테스트 세트에 따라 존재 여부 확인 필요
  - `idor, csrf, auth_bypass, file_upload, ssrf`는 CVE/Benchmark version별 포함 여부를 매핑표로 고정 후 사용
- 권장 활용
  - 본 레포의 `attack_label(family)` 분류 규칙은 그대로 유지하고, GT는 Benchmark expectedresults를 라벨별 ground truth로 주입.

## 1-1) WAVSEP (Web Application Vulnerability Scanner Evaluation Project, 보조 후보)
- 링크: https://github.com/sectooladdict/wavsep
- 근거
  - OWASP/기반 스캐너 평가 목적으로 만든 취약 웹앱 모음형 벤치마크입니다.
  - 레포 자체 소개 문구에서 자동화 평가 목적을 명시하며, 다수의 고유 취약 페이지를 포함합니다.
  - 다만 공식 파일 수준의 per-test GT(예: expected-results CSV)가 본 프로젝트에 바로 노출되어 있지 않아, GT 정합도를 독립 검증해야 합니다.
- 10개 패밀리 적용성
  - SQLi, XSS, Path Traversal, command/원격입력 계열 취약점 페이지가 포함된 버전이 존재.
  - `auth_bypass`/`idor`/`csrf`/`file_upload`는 버전별 편차가 있어 별도 매핑 테이블이 필요.
- 권장 활용
  - 논문/보고서에서 **주요 GT 중심 비교군(OWASP Benchmark)** 보조로 쓰기 적합.

## 2) OWASP Juice Shop (강력한 보조 벤치마크)
- 링크: https://owasp.org/www-project-juice-shop/
- 근거
  - 공식 문서에서 “Challenge tracking” 및 “Challenge declaration file”(`data/static/challenges.yml`)를 단일 소스 오브 트루스로 사용함을 설명.
  - `/api/Challenges` 엔드포인트가 각 챌린지의 `solved` 상태를 반환(정답 여부가 트랙 가능한 형태).
  - `challenges` webhook/API로 이벤트 기반 판정도 가능.
- 10개 패밀리 적용성
  - `sqli`, `xss`, `csrf`, `idor`(접근제어 계열), `file_upload`, `info_disclosure`, `path_traversal` 계열, 일부 `ssrf`/`cmdi` 계열 케이스는 버전별 존재 여부 점검 필요
  - `auth_bypass`는 난수/권한 체인 공격으로 검증 가능한 챌린지가 존재하는지 버전별 점검 필요
- 권장 활용
  - `solved` 필드와 챌린지 키를 GT로 사용. challenge-key 기준으로 10개 패밀리 매핑 테이블을 별도 정리.

## 3) OWASP crAPI (API 중심 통제형, 10개 중 일부에 특히 강함)
- 링크: https://owasp.org/www-project-crapi/
- 근거
  - OWASP Top10 API 취약점 기반으로 BOLA, 인증/권한, 과도한 노출, SSRF, NoSQLi 등 명시적 챌린지 목록 제공.
  - `docs/challenges.md`의 챌린지 설명 자체가 오라클 없이도 ‘무엇이 성공 조건인지’ 판별 가능한 수준으로 명시됨.
- 10개 패밀리 적용성
  - `idor`(BOLA), `auth_bypass`(Broken User Authentication), `info_disclosure`(Excessive Data Exposure), `ssrf`, `cmdi`(직접 포함은 약함), `file_upload`(거의 없음), `xss`(거의 없음)
  - 즉 10개 전부 커버하려면 단독 사용보다 `paper-victim`/Benchmark류와 병행 추천.
- 권장 활용
  - API 전용 패밀리(특히 `idor`, `auth_bypass`, `ssrf`, `info_disclosure`) 중심의 라벨링/성공 판정 실험에 사용.

## 4) CVE-Bench (현실적 웹 취약점 집합, 자동 평가기 제공)
- 링크: https://github.com/uiuc-kang-lab/cve-bench
- 근거
  - 40개 치명적 CVE 태스크와 태스크별 메타데이터, reference exploit/평가 오라클 형태 결과 클래스(예: file access, db access, unauthorized admin login, outbound service, privilege escalation 등) 제공.
  - 자동 실행/평가 스크립트(`run eval`, `test-solution`)로 결과 판정 체인을 재현하기 쉬움.
- 10개 패밀리 적용성
  - `sqli`, `auth_bypass`, `idor`/권한우회, `ssrf`, `info_disclosure` 계열과 정합성 높음
  - `xss`, `csrf`, `file_upload`, `cmdi`, `path_traversal`은 CVE 특성에 따라 케이스별 선별 필요
- 권장 활용
  - 벤치마크 자체는 “현실형 결과 클래스”가 강점. 10개 분류를 억지로 넣기보다, 가족별 성능 비교의 별도 하네스로 사용하는 게 정확도 높음.

## 5) 후보 보조: OWASP WebGoat + WebWolf (보조)
- 링크: https://owasp.org/www-project-webgoat/
- 근거
  - 교재형 레슨 기반과 도전 과제 수행 이력/진행 콘셉트가 존재.
  - 다만 공식 문서에서 “solved/체크 상태”를 직접 수치형으로 추출하는 API/스키마가 명확히 문서화되어 있지 않아, CVE/Benchmark류보다 GT 신뢰도는 다소 낮음.

## 적용 우선순위 (이 레포 10개 패밀리 정책에 맞춘 채택안)
1. `OWASP Benchmark`를 참조 GT로 채택 + `paper-victim`은 실험 엔진/측정 파이프라인용 통제형 victim로 사용.
2. `OWASP Juice Shop`은 Web 공격군(특히 XSS/CSRF/Upload/Info Disclosure/Injection) 교차 검증용으로 보조 사용.
3. `OWASP crAPI`는 API 계열(`idor`/`auth_bypass`/`ssrf`/`info_disclosure`) 보강용으로 보조 사용.
4. `CVE-Bench`는 현실형 CVE 태스크와 강건성 확인용으로 보조 사용.
