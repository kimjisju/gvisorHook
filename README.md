# gvisorHook

`gvisorHook`는 Codex, Gemini, Claude CLI 같은 로컬 AI agent를 patched gVisor `runsc` 안에서 실행하고, agent의 시스템 호출과 LLM 통신을 데이터셋으로 수집하는 도구다.

핵심 목적은 세 가지다.

- agent가 수행하려는 주요 시스템 호출을 gVisor 안에서 감지한다.
- 브라우저 승인 UI에서 syscall을 허용하거나 거부한다.
- agent 터미널 입출력, LLM HTTP/WebSocket 트래픽, syscall 이벤트, reason pipeline 결과를 세션 단위로 저장한다.

## 주요 기능

- `--agent-cmd`로 전달한 임의 CLI를 sandbox 안에서 실행
- Node 기반 CLI의 symlink, shebang, `node_modules`, sibling chunk 파일 구조 보존
- `~/.codex`, `~/.gemini`, `~/.config/<agent>` 같은 agent config 자동 mount
- `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`를 통한 외부 통신 capture
- mitmproxy CA를 sandbox에 신뢰시켜 HTTPS 요청 본문 저장
- 성공 응답 중심의 LLM request/response artifact 저장
- gzip body 압축 해제, SSE `data:` chunk JSON 배열화, WebSocket turn 단위 저장
- syscall approval UI와 AutoAccept 토글 제공
- syscall event마다 reason pipeline 실행
- 기존 세션의 reason pipeline event를 result로 재처리하는 replay 명령 제공

## 저장소 구조

```text
gvisor_hook/                 Python launcher, broker, bundle, dataset, proxy glue
third_party/gvisor/          syscall approval patch가 들어간 vendored gVisor
third_party/reason_pipeline/ LLM request/response + syscall 정규화 pipeline
scripts/build_runsc.sh       patched runsc 빌드 스크립트
scripts/format_gvisor_go.sh  gVisor Go patch formatting helper
tests/                       Python regression tests
```

## 준비

Python 가상환경을 사용한다.

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -U pip
python -m pip install aiohttp mitmproxy
```

reason pipeline에서 parser 생성 모델을 사용하려면 추가 패키지가 필요하다.

```bash
python -m pip install torch llama-cpp-python huggingface-hub
```

현재 reason pipeline의 로컬 생성 모델은 다음 GGUF를 사용한다.

```text
unsloth/Qwen3.5-2B-GGUF
*Q4_K_M.gguf
```

## runsc 빌드

patched gVisor runtime을 빌드한다.

```bash
./scripts/build_runsc.sh
```

스크립트는 실행 전에 필요한 system/Python package를 확인한다. Docker, mitmproxy, Python venv dependency가 없으면 설치 안내를 출력하고 중단한다.

Go patch formatting이 필요하면:

```bash
./scripts/format_gvisor_go.sh
```

## 실행

기본 형태:

```bash
python3 -m gvisor_hook launch \
  --agent-cmd codex \
  --workdir /home/tmdgusebbu/workspace/gvisorHook \
  --web-port 8080
```

실행 후 브라우저에서 아래 주소를 연다.

```text
http://127.0.0.1:8080
```

Gemini 예:

```bash
python3 -m gvisor_hook launch \
  --agent-cmd gemini \
  --workdir /home/tmdgusebbu/workspace/gvisorHook \
  --web-port 8080
```

agent 명령에 인자가 필요하면 문자열로 넘길 수 있다.

```bash
python3 -m gvisor_hook launch \
  --agent-cmd "codex exec --json \"README 찾아줘\"" \
  --workdir /home/tmdgusebbu/workspace/gvisorHook
```

Codex non-interactive 편의 모드:

```bash
python3 -m gvisor_hook launch \
  --prompt "README 파일을 찾아줘" \
  --codex-model gpt-5.5 \
  --workdir /home/tmdgusebbu/workspace/gvisorHook
```

## 주요 옵션

```text
--agent-cmd <cmd>              sandbox 안에서 실행할 agent command
--workdir <path>               sandbox에 read-write로 mount할 작업 디렉터리
--web-port <port>              승인 UI 포트
--decision-timeout <seconds>   syscall 승인 대기 시간
--runsc-bin <path>             사용할 runsc binary 지정
--runsc-strace                 runsc debug log에 syscall trace 기록
--runsc-strace-syscalls <csv>  trace 대상 syscall 목록
--dataset-root <path>          dataset 저장 루트 변경
--proxy-mode all|off           mitmproxy capture 사용 여부
--no-reason-pipeline           syscall마다 reason pipeline 실행하지 않음
--reason-pipeline-dir <path>   reason_pipeline 위치 override
```

## Syscall Approval UI

브라우저 UI는 다음 정보를 보여준다.

- pending syscall 목록
- syscall log
- LLM traffic log
- request/response artifact path
- AutoAccept 토글

수동 승인:

- `Allow`
- `Deny`
- keyboard shortcut `y`, `n`

AutoAccept를 켜면 현재 pending syscall과 이후 syscall을 자동으로 `allow` 처리한다.

## 수집되는 syscall 범위

현재 patched gVisor는 host 영향 가능성이 있는 주요 syscall을 broker로 보낸다.

- `open`, `openat`, `creat` 중 write intent가 있는 호출
- `write`, `writev`, `pwrite64`
- `mkdir`, `mkdirat`
- `unlink`, `unlinkat`
- `rmdir`
- `rename`, `renameat`, `renameat2`
- `execve`, `execveat`

거부되거나 timeout되면 sandbox 쪽 syscall은 `EPERM`으로 실패한다.

## Dataset 구조

기본 dataset root:

```text
datasets/raw-response-dataset/
```

각 실행은 session 디렉터리를 만든다.

```text
datasets/raw-response-dataset/sessions/<timestamp>-<agent>-<pid>/
```

주요 파일:

```text
manifest.json                         세션 메타데이터
index.ndjson                          세션 index event log
broker.log                            broker log
mitmproxy.log                         mitmproxy log
agent/stdin.bin                       agent stdin 원본
agent/stdout.bin                      agent stdout 원본
agent/terminal.ndjson                 터미널 chunk log
llm/ui.ndjson                         UI에 표시되는 LLM exchange log
llm/<number>_<flow-id>/meta.json       LLM flow metadata
llm/<number>_<flow-id>/request_headers.raw
llm/<number>_<flow-id>/request_body.json
llm/<number>_<flow-id>/response_headers.raw
llm/<number>_<flow-id>/response_body.json
runsc-logs/                           runsc debug/user logs
reason-pipeline-events/               pipeline 입력 event JSON
reason-pipeline-results/              pipeline 결과 JSON
reason-pipeline.ndjson                실시간 pipeline 실행 log
reason-pipeline-replay.ndjson         replay 실행 log
reason-pipeline.db                    syscall mapping/parser cache DB
```

LLM artifact directory는 요청 순서가 앞에 붙는다.

```text
llm/000001_<flow-id>/
llm/000002_<flow-id>/
```

## LLM Traffic 저장

proxy mode가 `all`이면 sandbox agent에는 proxy env가 주입된다.

```text
HTTP_PROXY
HTTPS_PROXY
ALL_PROXY
```

HTTPS 본문을 읽기 위해 mitmproxy CA도 sandbox에 mount하고, 여러 runtime용 CA env를 설정한다.

```text
NODE_EXTRA_CA_CERTS
REQUESTS_CA_BUNDLE
SSL_CERT_FILE
CURL_CA_BUNDLE
GIT_SSL_CAINFO
GRPC_DEFAULT_SSL_ROOTS_FILE_PATH
```

저장 정책:

- 2xx 성공 응답 중 본문이 있는 flow 중심으로 저장
- 3xx, 4xx, 5xx, 204 응답은 저장 대상에서 제외
- request body에 `tools`, `role`, `systemInstruction` 등 LLM 입력 신호가 있는 flow를 capture 대상으로 표시
- gzip body는 압축 해제 후 JSON으로 저장
- SSE `data: {...}` stream은 JSON object 배열로 저장
- WebSocket은 client frame부터 다음 client frame 전까지 server frame들을 하나의 turn으로 묶어 저장
- 원본 headers는 `.raw`로 저장

## Reason Pipeline

`third_party/reason_pipeline`이 있으면 syscall event마다 pipeline이 백그라운드로 실행된다.

입력 event:

```text
<session>/reason-pipeline-events/<syscall-event-id>.json
```

결과 JSON:

```text
<session>/reason-pipeline-results/<result-event-id>.json
```

결과 JSON은 현재 다음 필드를 중심으로 저장한다.

```json
{
  "event_id": "claude-1778332858-2",
  "agent_name": "claude",
  "syscall": "write",
  "summary": "write 20 bytes",
  "path": "/tmp/workspace/.git/index.lock",
  "argv": null,
  "affects_host_os": 1,
  "syscall_category": "file",
  "reason": "can affect host-visible files",
  "syscall_mapping_source": "mapping_table",
  "is_known_syscall": true,
  "prompt_text": "[user] #0\n\nreadme 파일을 찾아줘.",
  "reasoning_text": "Bash: {\"command\": \"find ...\"}",
  "created_at": "2026-05-09T00:00:00+00:00"
}
```

정규화 특징:

- request/response/syscall 원본 payload는 result JSON에 넣지 않는다.
- syscall 정보는 동적 parser를 쓰지 않고 gVisor event의 `syscall`, `summary`, `path`, `argv`를 그대로 저장한다.
- `prompt_text`가 이전 결과보다 1000자 이상 급증하면 정제한다.
- `<system-reminder>`, `<local-command-caveat>`, `<command-name>`, `<local-command-stdout>` 같은 agent 내부 메타데이터는 prompt contamination으로 보고 제거한다.
- Claude stream response의 `message_start` 메타데이터가 reasoning으로 잡히는 경우를 보정하고, tool call delta를 이어붙여 `reasoning_text`를 복원한다.

## 기존 세션 재처리

기존 session의 `reason-pipeline-events`를 순서대로 다시 `reason-pipeline-results`로 변환할 수 있다.

```bash
python3 -m gvisor_hook replay-reason-pipeline <session-path>
```

기존 result JSON을 지우고 다시 만들려면:

```bash
python3 -m gvisor_hook replay-reason-pipeline <session-path> --clear-results
```

예:

```bash
python3 -m gvisor_hook replay-reason-pipeline \
  datasets/raw-response-dataset/sessions/20260509T140805.861275Z-claude-1778335685 \
  --clear-results
```

replay는 `...-1`, `...-2`, `...-10`처럼 파일명 끝 숫자를 기준으로 정렬해 순차 처리한다.

## Agent 실행 resolver 원칙

`--agent-cmd`는 사용자가 입력한 command 이름을 신뢰한다.

- 실행 파일은 `PATH`에서 resolve한다.
- config mount 탐색은 사용자가 입력한 command 이름 기준으로 한다.
- 예: `--agent-cmd gemini`가 내부적으로 `gemini-js`로 resolve되어도 config 후보는 `~/.gemini`, `~/gemini`, `~/.config/gemini`이다.
- Node CLI는 shebang과 symlink를 분석해 필요한 `node`, package root, sibling JS chunk, `node_modules`를 함께 mount한다.
- 특정 provider, URL, agent 이름을 launcher에 특별 대우로 박지 않는다.

## 다른 프록시/게이트웨이 사용

agent가 별도 LLM gateway를 사용해야 하면 host env에 그대로 설정한 뒤 launch하면 된다.

```bash
export OPENAI_API_KEY=YOUR_API_KEY
export OPENAI_BASE_URL=https://factchat-cloud.mindlogic.ai/v1/gateway

python3 -m gvisor_hook launch \
  --agent-cmd codex \
  --workdir /home/tmdgusebbu/workspace/gvisorHook
```

`gvisorHook`의 mitmproxy는 network path에 들어가지만, agent가 바라보는 upstream base URL은 env 그대로 유지된다.

## 테스트

```bash
./venv/bin/python -m unittest discover tests
```

특정 테스트만 실행:

```bash
./venv/bin/python -m unittest tests.test_reason_pipeline
./venv/bin/python -m unittest tests.test_launcher
```

## 자주 보는 문제

### `ModuleNotFoundError: aiohttp`

프로젝트 venv를 활성화하지 않은 상태일 수 있다.

```bash
source venv/bin/activate
python -m pip install aiohttp
```

### `PermissionError: [Errno 13] Permission denied: '.'`

과거에는 `mitmdump`를 찾지 못했을 때 현재 디렉터리 `.`를 실행하려는 문제가 있었다. 현재 코드는 실제 실행 가능한 `mitmdump`만 후보로 사용한다.

### HTTPS 인증 실패

예:

```text
self-signed certificate in certificate chain
```

mitmproxy CA가 아직 생성되지 않았거나 sandbox에 mount되지 않은 상태일 수 있다. 한 번 mitmproxy를 실행해 CA를 생성한 뒤 다시 launch한다.

### Codex optional dependency 누락

Node CLI를 평평한 `/tmp/agent/bin/*.js`로 실행하면 nested `node_modules`를 못 찾을 수 있다. 현재 resolver는 package 구조를 보존해 mount한다.

## 라이선스와 vendored 코드

`third_party/gvisor`와 `third_party/reason_pipeline`은 각각의 upstream 코드와 라이선스를 따른다. 이 저장소의 변경은 gVisor syscall approval hook, launcher, dataset capture, reason pipeline integration에 집중되어 있다.
