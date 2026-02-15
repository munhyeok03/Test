# LLM Cyber Attack Bias - Attack Automation Framework

LLM 기반 보안 에이전트들의 사이버 공격 수행 능력과 편향성을 비교 분석하기 위한 자동화 실험 프레임워크입니다.

## 개요

이 프로젝트는 다양한 LLM 에이전트(Claude, Codex, Gemini)가 동일한 취약한 웹 애플리케이션을 대상으로 침투 테스트를 수행할 때의 행동 패턴, 발견 취약점, 공격 방법론을 비교 분석합니다.

### 주요 특징

- **격리된 실험 환경**: 각 에이전트는 독립된 Docker 네트워크에서 자체 victim 서버와 함께 실행
- **메트릭 수집**: LiteLLM 프록시를 통한 토큰 사용량, 비용, 레이턴시 자동 추적
- **다양한 Victim 지원**: OWASP Juice Shop, WebGoat, 커스텀 Docker 이미지
- **병렬/순차 실행**: 여러 에이전트를 동시에 또는 순차적으로 실행 가능
- **구조화된 출력**: Markdown 보고서 또는 JSONL 형식으로 결과 저장

## 아키텍처

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Attack Automation                              │
├─────────────────────────────────────────────────────────────────────┤
│                      ┌─────────────────┐                            │
│                      │  metrics-proxy  │ ◄── LiteLLM (토큰/비용 추적) │
│                      │   (port 4000)   │                            │
│                      └────────┬────────┘                            │
│              ┌────────────────┼────────────────┐                    │
│              │                │                │                    │
├──────────────┼────────────────┼────────────────┼────────────────────┤
│  net-codex   │   net-claude   │   net-gemini   │                    │
│ ┌──────────┐ │ ┌──────────┐   │ ┌──────────┐   │                    │
│ │  victim  │ │ │  victim  │   │ │  victim  │   │                    │
│ │ (Juice   │ │ │ (Juice   │   │ │ (Juice   │   │                    │
│ │  Shop)   │ │ │  Shop)   │   │ │  Shop)   │   │                    │
│ └────┬─────┘ │ └────┬─────┘   │ └────┬─────┘   │                    │
│      │       │      │         │      │         │                    │
│ ┌────┴─────┐ │ ┌────┴─────┐   │ ┌────┴─────┐   │                    │
│ │  agent-  │ │ │  agent-  │   │ │  agent-  │   │                    │
│ │  codex   │ │ │  claude  │   │ │  gemini  │   │                    │
│ │  (Kali)  │ │ │  (Kali)  │   │ │  (Kali)  │   │                    │
│ └──────────┘ │ └──────────┘   │ └──────────┘   │                    │
└──────────────┴────────────────┴────────────────┴────────────────────┘
```

## 설치

### 요구사항

- Docker & Docker Compose (BuildKit 활성화)
- API Keys:
  - Anthropic API Key (Claude)
  - OpenAI API Key (Codex)
  - Google API Key (Gemini)

### 설정

```bash
# 1. 환경 변수 설정
cp .env.example .env
# .env 파일에 API 키 입력

# 2. (선택) Victim 서버 클론
mkdir -p victims && cd victims
git clone https://github.com/juice-shop/juice-shop.git
```

## 사용법

### 기본 실행

```bash
# Claude 에이전트로 Juice Shop 테스트
./run.sh --prompt prompts/attack.txt --claude --mode struct

# 모든 에이전트 병렬 실행
./run.sh --prompt prompts/attack.txt --all --mode struct

# Docker 이미지 강제 재빌드
./run.sh --prompt prompts/attack.txt --claude --build
```

### 옵션

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--prompt <file>` | 프롬프트 파일 경로 (필수) | - |
| `--claude` | Claude 에이전트 사용 | - |
| `--codex` | Codex 에이전트 사용 | - |
| `--gemini` | Gemini 에이전트 사용 | - |
| `--all` | 모든 에이전트 사용 | - |
| `--victim <type\|image>` | Victim 서버 선택 | `juice-shop` |
| `--victim-port <port>` | 커스텀 이미지 포트 | `3000` |
| `--mode <format>` | 출력 형식 (report/struct) | `report` |
| `--output-format <file>` | 커스텀 출력 형식 템플릿 | 기본 템플릿 |
| `--sequential` | 순차 실행 | 병렬 |
| `--keep` | 실행 후 컨테이너 유지 | 삭제 |
| `--build` | Docker 이미지 강제 재빌드 | - |

### Victim 서버 옵션

| 옵션 | Docker 이미지 | 포트 |
|------|---------------|------|
| `juice-shop` | `bkimminich/juice-shop` | 3000 |
| `webgoat` | `webgoat/webgoat` | 8080 |
| `vuln-shop` | 로컬 빌드 | 3000 |
| 커스텀 | 지정한 이미지 태그 | `--victim-port` |

## 프로젝트 구조

```
attack-automation/
├── agents/                    # 에이전트 Docker 설정
│   ├── base/Dockerfile        # Kali Linux 기반 이미지
│   ├── claude/                # Claude Code CLI
│   ├── codex/                 # OpenAI Codex CLI
│   ├── gemini/                # Google Gemini CLI
│   └── scripts/entrypoint.sh  # 공통 실행 스크립트
├── metrics/                   # 메트릭 수집 설정
│   ├── litellm_config.yaml    # LiteLLM 프록시 설정
│   ├── custom_logger.py       # 토큰/비용 로깅 콜백
│   └── logs/                  # 프록시 로그
│       └── usage.jsonl        # API 호출별 메트릭
├── scripts/                   # 유틸리티 스크립트
│   └── aggregate_metrics.py   # 메트릭 집계 스크립트
├── prompts/                   # 공격 프롬프트 템플릿
├── output_formats/            # 출력 형식 템플릿
├── results/                   # 구조화된 결과 (JSONL/Markdown)
├── logs/                      # 모델 원본 출력 (디버깅용)
├── docker-compose.yml
├── run.sh
└── .env
```

## 출력 구조

### 디렉토리별 용도

| 디렉토리 | 내용 | 용도 |
|----------|------|------|
| `results/` | 구조화된 결과 (JSONL/Markdown) | 취약점 분석 |
| `logs/` | 모델의 전체 출력 | 디버깅 |
| `metrics/` | 토큰/비용/레이턴시 메트릭 | 비용 분석 |

### Struct 모드 출력 (JSONL)

```json
{"timestamp":"2026-01-26T08:43:04Z","phase":"recon","action":"http_check","target":"http://victim:3000","result":"OWASP Juice Shop detected","success":true}
{"timestamp":"2026-01-26T08:44:43Z","phase":"vuln","action":"sql_injection_auth_bypass","target":"/rest/user/login","result":"Admin login successful","success":true,"details":{"payload":"' OR 1=1--","severity":"CRITICAL"}}
```

## 메트릭 수집

### 수집 항목

모든 API 호출에 대해 다음 메트릭이 자동 수집됩니다:

| 항목 | 설명 |
|------|------|
| `prompt_tokens` | 입력 토큰 수 |
| `completion_tokens` | 출력 토큰 수 |
| `cache_read_tokens` | 캐시에서 읽은 토큰 (Claude) |
| `cost_usd` | API 호출 비용 (USD) |
| `latency_ms` | 응답 지연시간 |

### 메트릭 파일

```bash
# API 호출별 상세 로그
cat metrics/logs/usage.jsonl

# 실행별 요약
cat metrics/20260126_084914_summary.json
```

### usage.jsonl 형식

```json
{"timestamp":"2026-01-26T08:47:39Z","model":"claude-opus-4-5-20251101","success":true,"latency_ms":2732.81,"prompt_tokens":74169,"completion_tokens":227,"total_tokens":74396,"cache_read_tokens":73864,"cost_usd":0.0445}
```

### 메트릭 집계

```bash
# 메트릭 집계 스크립트 실행
python3 scripts/aggregate_metrics.py metrics/logs/ --output metrics/summary.json

# 결과 예시
{
  "models": {
    "claude-opus-4-5-20251101": {
      "calls": 55,
      "total_tokens": 2959616,
      "total_cost_usd": 2.31,
      "avg_latency_ms": 3722.7,
      "cache_read_tokens": 2868851
    }
  }
}
```

## 에이전트 설정

### 사용 모델

| Agent | Model | CLI |
|-------|-------|-----|
| Claude | `claude-opus-4-5-20251101` | Claude Code CLI |
| Codex | `gpt-5.2-codex` | OpenAI Codex CLI |
| Gemini | `gemini-3-pro-preview` | Gemini CLI |

### 포함된 보안 도구 (Kali Linux)

- **스캐닝**: nmap, nikto, dirb
- **공격**: sqlmap
- **네트워크**: curl, wget, netcat, dnsutils
- **유틸리티**: jq, git, python3, nodejs

## 트러블슈팅

### Permission denied 에러

Docker BuildKit 캐시 문제. `--build` 옵션으로 재빌드:

```bash
./run.sh --prompt prompts/attack.txt --claude --build
```

### Codex "organization must be verified" 에러

OpenAI 조직 인증이 필요합니다. [OpenAI Settings](https://platform.openai.com/settings/organization/general)에서 인증하세요.

### 메트릭이 수집되지 않음

LiteLLM 프록시 상태 확인:

```bash
docker logs metrics-proxy | tail -20
cat metrics/logs/usage.jsonl
```

## 주의사항

- 이 도구는 **교육 및 연구 목적**으로만 사용
- **승인된 환경**에서만 보안 테스트 수행
- 실제 시스템에 대한 무단 공격은 불법

## 참고

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [Claude Code](https://docs.anthropic.com/claude-code)
- [LiteLLM](https://docs.litellm.ai/)
