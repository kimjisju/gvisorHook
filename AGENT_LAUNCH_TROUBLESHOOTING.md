# Agent Launch Troubleshooting Notes

이 문서는 gvisorHook에서 `--agent-cmd gemini`, `--agent-cmd codex`를 실행하면서 발견한 문제와 해결 내용을 정리한다.

## 핵심 원칙

- `--agent-cmd`는 사용자가 입력한 command 이름을 신뢰한다.
- PATH resolve 결과로 나온 내부 구현 파일명은 실행에는 사용할 수 있지만, config 탐색 이름으로 쓰지 않는다.
- 특정 agent, provider, URL을 launcher에 하드코딩하지 않는다.
- Node 기반 CLI는 실행 파일 하나만 mount하면 부족하다. shebang, symlink, `node_modules` 구조를 보존해야 한다.
- 프록시는 모든 외부 트래픽을 통과시키고, dataset에도 기본적으로 모든 captured flow를 저장한다.

## Gemini 실행 문제

### 1. Config mount 이름 문제

증상:

```text
Config directory for 'gemini-js' was not found automatically.
```

원인:

- 사용자는 `--agent-cmd gemini`를 입력했다.
- PATH에서 실제 실행 파일이 `gemini-js` 같은 내부 구현 파일로 resolve됐다.
- config mount 자동 탐색도 실제 파일명 기준으로 돌아가 `~/.gemini`를 찾지 못했다.

해결:

- 실행 파일 resolve 이름과 config 탐색 이름을 분리했다.
- 실행은 `shutil.which(args.agent_cmd)` 결과를 사용한다.
- config mount는 `Path(args.agent_cmd).name` 기준으로 탐색한다.
- 따라서 `--agent-cmd gemini`는 항상 아래 후보를 본다.

```text
~/.gemini
~/gemini
~/.config/gemini
```

### 2. Node interpreter 누락

증상:

```text
/usr/bin/env: 'node': No such file or directory
```

원인:

- Gemini CLI는 JS entrypoint이고 shebang이 `#!/usr/bin/env node`였다.
- sandbox 안에는 host의 nvm `node`가 없었다.

해결:

- shebang을 파싱한다.
- `env node`를 감지하면 host PATH에서 실제 `node` 실행 파일을 찾는다.
- 찾은 `node`를 `/tmp/agent/bin/node`로 mount한다.
- sandbox PATH는 `/tmp/agent/bin`을 앞에 둔다.

### 3. JS bundle chunk 누락

증상:

```text
Error [ERR_MODULE_NOT_FOUND]: Cannot find module '/tmp/agent/bin/gemini-....js'
```

원인:

- Gemini entry JS만 bind mount했다.
- 같은 디렉터리에 있는 chunk 파일들이 sandbox에 없었다.

해결:

- shebang이 있는 script는 파일 하나가 아니라 parent directory 전체를 `/tmp/agent/bin`에 mount한다.
- JS bundle의 sibling chunk 파일들이 함께 보인다.

### 4. Config mount 권한 문제

증상:

```text
Permission denied
```

원인:

- config를 sandbox의 runtime home 바깥 위치에 mount하려 했다.
- sandbox rootfs와 `/home` mount 구조 때문에 권한/경로가 어긋났다.

해결:

- runtime home을 `/tmp/agent-home`으로 고정했다.
- config mount 목적지도 `/tmp/agent-home/.gemini`처럼 runtime home 아래로 보낸다.

## Codex 실행 문제

### 1. `--agent-cmd codex` 하드코딩 문제

증상:

```text
running container: creating container: cannot create sandbox: cannot read client sync file: waiting for sandbox to start: EOF
```

debug log의 실제 원인:

```text
error setting up FS: opening /usr/bin/node: open /usr/bin/node: no such file or directory
```

원인:

- `--agent-cmd codex`를 줬는데 launcher가 이를 강제로 아래 argv로 바꿨다.

```text
/usr/bin/node /usr/local/lib/node_modules/@openai/codex/bin/codex.js
```

- 현재 환경의 실제 Codex와 Node는 nvm 아래에 있었다.

```text
<user-home>/.nvm/versions/node/<node-version>/bin/node
<user-home>/.nvm/versions/node/<node-version>/bin/codex
```

해결:

- `--agent-cmd`에 대한 Codex 전용 변환을 제거했다.
- `--agent-cmd codex`는 그대로 두고, 범용 resolver가 PATH 기준으로 실제 command를 찾게 했다.
- `--prompt` 편의 모드도 hardcoded path 대신 `codex exec ...`로 시작한다.

### 2. nvm symlink와 sibling `node`

증상:

- host shell에서는 `command -v node`, `command -v codex`가 nvm 경로로 잘 나왔다.
- 하지만 sandbox config에는 여전히 `/usr/bin/node`가 들어갔다.

원인:

- nvm의 `bin/codex`는 symlink다.
- resolver가 symlink를 따라가면 실제 JS 위치는 다음처럼 바뀐다.

```text
.../lib/node_modules/@openai/codex/bin/codex.js
```

- `node`는 원래 호출된 symlink의 sibling인 nvm `bin/node`에 있다.
- 최종 JS 파일의 parent directory에는 `node`가 없다.

해결:

- resolver가 `resolved_command.parent`를 preferred interpreter directory로 기억한다.
- shebang interpreter를 찾을 때 이 directory의 `node`를 PATH보다 먼저 본다.
- 실제 파일이고 실행 가능할 때만 mount한다.
- 깨진 `/usr/bin/node` 같은 path는 mount하지 않는다.

### 3. `@openai/codex-linux-x64` optional dependency 누락처럼 보인 문제

증상:

```text
Error: Missing optional dependency @openai/codex-linux-x64.
Reinstall Codex: npm install -g @openai/codex@latest
```

원인:

- host에는 optional dependency가 실제로 있었다.

```text
.../lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64
```

- 하지만 launcher가 `codex.js`를 `/tmp/agent/bin/codex.js`로 평평하게 실행했다.
- Node의 `require.resolve()` 기준 위치가 바뀌면서 nested `node_modules`를 못 찾았다.

해결:

- `node_modules` 안에 설치된 CLI는 원래 상대 구조를 보존해 실행한다.

```text
/tmp/agent/node_modules/@openai/codex/bin/codex.js
```

- host의 nvm global `node_modules` 전체를 아래에 mount한다.

```text
/tmp/agent/node_modules
```

- 이렇게 하면 Codex 내부의 `require.resolve("@openai/codex-linux-x64/package.json")`가 정상 동작한다.

최종 Codex resolver 결과 예:

```text
argv:
  /tmp/agent/node_modules/@openai/codex/bin/codex.js

mounts:
  /tmp/agent/node_modules -> <user-home>/.nvm/versions/node/<node-version>/lib/node_modules
  /tmp/agent/bin/node     -> <user-home>/.nvm/versions/node/<node-version>/bin/node
  /tmp/agent-home/.codex  -> <user-home>/.codex
```

## mitmdump 실행 문제

증상:

```text
PermissionError: [Errno 13] Permission denied: '.'
```

원인:

- `shutil.which("mitmdump")`가 실패했을 때 `Path("")`가 후보에 들어갔다.
- `Path("")`는 현재 디렉터리 `.`로 해석된다.
- subprocess가 `.`를 실행하려다 permission error가 났다.

해결:

- `find_mitmdump_binary()`가 실제 실행 가능한 file만 반환하게 했다.
- PATH에 없으면 `Path("")`를 후보에 넣지 않는다.
- `/usr/bin/mitmdump`가 Python 버전 문제로 실패하는 환경을 위해 Python fallback command를 검사한다.

## 프록시와 인증서

### 모든 외부 통신 프록시

- sandbox process에는 `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`를 주입한다.
- uppercase/lowercase variant를 모두 설정한다.
- 기본 `NO_PROXY`는 local host만 둔다.

```text
127.0.0.1
localhost
```

### mitmproxy CA 신뢰

문제:

- 인증 요청이나 HTTPS API 요청이 mitmproxy를 통과하면 self-signed certificate chain 오류가 날 수 있다.

해결:

- host의 mitmproxy CA cert를 runtime staging directory에 복사한다.
- sandbox에는 `/tmp/mitmproxy/mitmproxy-ca-cert.pem`로 mount한다.
- 여러 runtime이 읽는 CA env를 설정한다.

```text
NODE_EXTRA_CA_CERTS
REQUESTS_CA_BUNDLE
SSL_CERT_FILE
CURL_CA_BUNDLE
GIT_SSL_CAINFO
GRPC_DEFAULT_SSL_ROOTS_FILE_PATH
```

## Dataset 저장 범위

프록시는 모든 외부 트래픽을 통과시킨다.
현재 dataset에는 response status가 저장 대상인 captured flow만 저장한다.
또한 request body가 LLM 입력처럼 보이는 marker를 포함해야 저장한다.

session id는 실행 command 이름을 prefix로 사용한다.
예를 들어 `--agent-cmd codex`는 `...-codex-<timestamp>` 형태가 되고, `--agent-cmd gemini`는 `...-gemini-<timestamp>` 형태가 된다.

request body marker:

- `tools`
- `role`
- `systemInstruction`

marker 비교는 JSON key 기준으로 수행하며, key의 대소문자와 공백 차이를 무시한다.
예를 들어 `numAllowedTools`, `mcpToolsCount`, `deferred_tools_delta`처럼 marker가 다른 이름 안에 섞인 telemetry field/value는 저장 조건으로 보지 않는다.

저장 대상:

- `2xx` 응답
- 단, `204 No Content`는 제외

저장하지 않는 대상:

- `3xx`
- `4xx`
- `5xx`
- `204`
- network error처럼 response status가 없는 flow
- marker가 없는 request body

host 제한이 필요하면 다음 env를 사용한다.

```bash
export GVISOR_HOOK_LLM_TARGET_HOSTS="api.example.com,api2.example.com"
```

이 경우 request host가 target host 목록에 있는 flow만 저장한다.

저장되는 LLM artifact id와 디렉터리는 저장 순서 번호를 prefix로 붙인다.
예:

```text
000001_<mitm-flow-id>
000002_<websocket-flow-id>-websocket-turn-000001
```

헤더는 HTTP start line과 header block을 그대로 `.raw` 파일에 저장한다.
본문은 `.json` 파일에 저장한다.
`Content-Encoding: gzip` 본문은 압축을 해제한 뒤 JSON으로 저장한다.
SSE 형식의 `data: {...}` 스트림은 각 `data:` JSON payload를 배열 원소로 파싱해서 저장한다.
`data: [DONE]`은 종료 신호라 저장 배열에서는 제외한다.

### WebSocket 기반 추론 요청

Codex의 일부 추론 요청은 일반 HTTP response body가 아니라 WebSocket으로 흐른다.

mitmproxy log 예:

```text
GET https://chatgpt.com/backend-api/codex/responses
<< 101 Switching Protocols
-> WebSocket 1 message -> chatgpt.com:443/backend-api/codex/responses
<- WebSocket 1 message <- chatgpt.com:443/backend-api/codex/responses
```

이 경우 `101 Switching Protocols` handshake는 HTTP 저장 대상이 아니지만, 실제 추론 입력/출력은 그 뒤의 WebSocket frame에 있다.
따라서 dataset 저장은 `websocket_message` hook에서 WebSocket turn 단위로 누적 저장한다.
turn 경계는 client frame이다.
하나의 client frame과 다음 client frame 전까지 이어지는 server frame들을 하나의 묶음으로 본다.

저장 방식:

- UI/index에는 turn당 하나의 `WEBSOCKET_TURN` exchange를 upsert
- client frame 원문은 `request_body.json`에 JSON 배열로 저장
- 해당 client 이후 server frame 원문들은 `response_body.json`에 JSON 배열로 누적 저장
- client/server 순서가 섞인 읽기용 turn transcript는 `websocket_transcript.txt`에 저장
- frame별 구조화 원문은 `websocket_transcript.ndjson`에 저장
- WebSocket 원문 저장은 preview truncation을 거치지 않는다
- turn의 client frame에 request body marker가 있어야 저장
- `is_stream: true`
- 기존 HTTP host filter인 `GVISOR_HOOK_LLM_TARGET_HOSTS`는 WebSocket에도 동일하게 적용

## 외부 OpenAI-compatible gateway 사용

예:

```bash
export OPENAI_API_KEY=YOUR_API_KEY
export OPENAI_BASE_URL=https://factchat-cloud.mindlogic.ai/v1/gateway
```

주의:

- `OPENAI_BASE_URL`은 HTTP proxy가 아니다.
- Codex/OpenAI SDK가 호출할 API endpoint다.
- gvisorHook의 mitmproxy는 여전히 `HTTP_PROXY`/`HTTPS_PROXY`로 network path에 들어간다.
- request destination은 `OPENAI_BASE_URL`의 gateway가 된다.

현재 env 전달은 provider prefix 하드코딩 대신 suffix allowlist를 사용한다.

```text
_API_KEY
_API_BASE
_ACCESS_TOKEN
_AUTH_TOKEN
_BASE_URL
_BEARER_TOKEN
_CREDENTIALS
_CREDENTIALS_FILE
_ENDPOINT
```

따라서 `OPENAI_API_KEY`, `OPENAI_BASE_URL`은 sandbox env로 전달된다.

## Debugging Checklist

## Reason Pipeline

`reason_pipeline`은 `third_party/reason_pipeline`에 둔다.
기본 실행에서는 이 경로가 있으면 syscall event가 발생할 때마다 reason pipeline을 백그라운드로 실행한다.

입력 event 파일은 dataset session 아래에 저장한다.

```text
<session>/reason-pipeline-events/<syscall-event-id>.json
```

실행 결과 로그는 다음 파일에 저장한다.

```text
<session>/reason-pipeline.ndjson
```

정규화된 결과 JSON은 다음 디렉터리에 이벤트별 파일로 저장한다.

```text
<session>/reason-pipeline-results/<result-event-id>.json
```

기존 세션의 입력 event들을 순서대로 다시 result로 변환하려면 다음 명령을 사용한다.

```bash
python3 -m gvisor_hook replay-reason-pipeline <session>
```

기존 result JSON을 지우고 다시 만들려면:

```bash
python3 -m gvisor_hook replay-reason-pipeline <session> --clear-results
```

pipeline DB는 session별로 분리한다.

```text
<session>/reason-pipeline.db
```

비활성화:

```bash
python3 -m gvisor_hook launch ... --no-reason-pipeline
```

경로를 직접 지정:

```bash
python3 -m gvisor_hook launch ... --reason-pipeline-dir /path/to/reason_pipeline
```

### 1. 실제 command 확인

```bash
command -v node
command -v codex
command -v gemini
```

Windows 경로(`/mnt/c/...`)가 잡히면 WSL/gVisor 안에서 깨질 가능성이 높다.

### 2. runsc EOF 원인 확인

`EOF`는 보통 겉증상이다. 실제 원인은 debug log에 있다.

```bash
tail -n 200 <session>/runsc-logs/debug
```

자주 볼 수 있는 원인:

```text
opening /usr/bin/node: no such file or directory
Error reading mounts file
Missing optional dependency ...
```

### 3. 생성된 OCI config 확인

```bash
python3 - <<'PY'
import json
from pathlib import Path
p = sorted(Path(".gvisor-hook").glob("run-*/bundle/config.json"), key=lambda x: x.stat().st_mtime)[-1]
data = json.loads(p.read_text())
print(p)
print(data["process"]["args"])
for mount in data["mounts"]:
    if "agent" in mount.get("destination", ""):
        print(mount)
PY
```

확인할 것:

- argv가 hardcoded `/usr/bin/node`를 쓰지 않는가
- `node` source가 실제 nvm node인가
- Node CLI가 `node_modules` 안에 있으면 `/tmp/agent/node_modules/...` 경로로 실행되는가
- config mount가 `/tmp/agent-home/...` 아래인가

### 4. Tests

주요 회귀 테스트:

```bash
./venv/bin/python -m unittest discover tests
```

관련 테스트 파일:

```text
tests/test_launcher.py
tests/test_mitm_addon.py
tests/test_dataset.py
```
