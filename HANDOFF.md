# gVisor Hook MVP Handoff

작성일: 2026-04-05  
대상: 이 프로젝트를 이어받아 디버깅/구현을 계속할 다른 AI Agent 또는 개발자

## 1. 프로젝트 목적

이 프로젝트의 목표는 `Open Interpreter` 바이너리(`/home/kimjisu/.local/bin/interpreter`)를 수정하지 않고 그대로 사용하면서, gVisor sandbox 안에서 실행되는 AI Agent의 주요 시스템 호출을 가로채고, 별도 웹 UI에서 사용자 승인(`allow`) 또는 거부(`deny`)를 받을 수 있게 하는 것이다.

사용자 요구사항은 다음과 같다.

- AI Agent는 gVisor 가상 커널에서 실행되어야 한다.
- 사용자는 기존 Open Interpreter의 CLI 화면을 그대로 사용해야 한다.
- 후킹 시스템은 백그라운드에서 동작해야 한다.
- 웹 UI는 실시간 syscall 로그를 보여주고, syscall마다 `y/n` 또는 `allow/deny`를 선택할 수 있어야 한다.
- 거부 시 syscall은 실패해야 하며, MVP에서는 `EPERM`을 반환하는 방향으로 설계했다.
- Open Interpreter 소스 코드는 수정하지 않아야 한다.

## 2. 현재 아키텍처

현재 구현은 크게 3개 층으로 나뉜다.

### 2.1 런처 / 샌드박스 실행

- `python3 -m gvisor_hook launch ...` 가 엔트리포인트다.
- 런처는 런타임 디렉터리 `.gvisor-hook/run-*` 를 만들고, 거기에 다음을 생성한다.
  - OCI `bundle/config.json`
  - 네트워크 설정 파일
  - bootstrap Python 파일
  - `runsc` 로그 디렉터리
- 이후 패치된 `runsc-hook`를 사용해 Open Interpreter를 gVisor 안에서 실행한다.
- PTY는 `--console-socket`으로 전달받아 현재 터미널에 relay 한다. 그래서 사용자는 원래 CLI와 거의 같은 화면을 본다.

### 2.2 승인 브로커 / 웹 UI

- `gvisor_hook/broker.py` 에 `aiohttp` 기반 브로커와 웹 UI가 구현되어 있다.
- 브로커 역할:
  - 승인 요청 수신
  - 웹소켓 및 `/api/events` snapshot 제공
  - `POST /api/events/{id}/decision` 로 allow/deny 처리
  - OpenAI reverse proxy 제공
- 웹 UI는 터미널 출력과 혼동을 줄이기 위해 “터미널은 실제 agent 대화, 웹은 syscall 승인 전용” 배너를 표시한다.

### 2.3 gVisor 후킹

- `third_party/gvisor/pkg/sentry/syscalls/linux/approval.go` 가 핵심 승인 게이트다.
- 파일/실행 관련 syscall 진입점에서 `requestApproval(...)`를 호출하도록 패치했다.
- 승인 전까지 syscall을 block 하고, 허용 시 계속 진행, 거부 시 `EPERM`을 반환하도록 설계했다.

## 3. 현재 주요 파일

### Python 쪽

- `gvisor_hook/launcher.py`
  - 브로커 시작
  - 런타임 디렉터리 생성
  - bundle 생성
  - `runsc-hook` 실행
  - PTY relay
- `gvisor_hook/bundle.py`
  - OCI `config.json` 생성
  - Open Interpreter 실행 인자와 env 구성
- `gvisor_hook/broker.py`
  - 승인 브로커
  - 웹 UI
  - REST/WebSocket
  - OpenAI reverse proxy
- `gvisor_hook/models.py`
  - 이벤트 모델
- `gvisor_hook/cli.py`
  - `launch`, `serve` CLI
- `tests/test_broker.py`
  - 브로커 승인 round-trip / timeout / file-backend 테스트

### gVisor 쪽

- `third_party/gvisor/pkg/sentry/syscalls/linux/approval.go`
  - 승인 설정 로드
  - path 필터링
  - warmup
  - socket / file backend 처리
  - 디버깅 로그
- `third_party/gvisor/pkg/sentry/syscalls/linux/sys_file.go`
- `third_party/gvisor/pkg/sentry/syscalls/linux/sys_read_write.go`
- `third_party/gvisor/pkg/sentry/syscalls/linux/sys_thread.go`
  - 실제 syscall hook 호출 지점
- `third_party/gvisor/runsc/boot/filter/config/extra_filters_hostinet.go`
  - approval IPC에 필요한 seccomp 예외 규칙 추가
- `third_party/gvisor/runsc/boot/filter/filter.go`
  - seccomp debug 모드 토글

### 스크립트

- `scripts/build_runsc.sh`
  - 패치된 `runsc-hook` 빌드

## 4. 현재 후킹 대상 범위

MVP 기준으로 다음 syscall 계열을 대상으로 설계되어 있다.

- 파일 변경 관련
  - `open/openat/openat2/creat` 중 write intent가 있는 경우
  - `write/pwrite64/writev`
  - `rename/renameat/renameat2`
  - `unlink/unlinkat`
  - `mkdir/mkdirat`
  - `rmdir`
- 프로세스 실행 관련
  - `execve/execveat`

노이즈 감소를 위해 모든 syscall을 다 노출하지는 않으며, path 필터도 들어가 있다.

## 5. 현재까지 해결된 문제들

아래는 이미 한번 이상 해결하거나 우회한 문제들이다.

- Docker 권한 문제
- Bazel image 문제
- gVisor 빌드에 필요한 시스템 패키지 누락
  - `clang`
  - `libbpf-dev`
  - ARM64 cross toolchain
  - `libc6-dev-i386`
  - 기타 빌드 의존성
- `runsc` 빌드 후 산출물 경로 처리 문제
- rootless/cgroup 관련 시작 실패
- 초기 workdir 권한 문제
- WSL/gVisor 환경에서 Open Interpreter 네트워크/DNS 문제
- OpenAI API 연결을 위해 host 브로커 reverse proxy 추가
- 웹 로그와 agent CLI 출력이 섞이는 문제를 일부 완화

현재 `scripts/build_runsc.sh` 로 `third_party/gvisor/bin/runsc-hook` 생성 자체는 가능한 상태다.

## 6. 현재까지 검증된 것

완전히 끝난 것은 아니지만, 다음은 실제로 검증했다.

### 6.1 Open Interpreter가 sandbox 안에서 실행됨

- `python3 -m gvisor_hook launch --workdir /home/kimjisu/gvisorHook --web-port 8080`
- 위 명령으로 Open Interpreter 프롬프트가 뜨는 상태까지는 반복적으로 확인했다.

### 6.2 웹 승인 UI 자체는 동작함

- `http://127.0.0.1:8080`
- WebSocket과 `/api/events` snapshot polling fallback이 있다.
- 이벤트가 들어오면 pending 목록과 event log에 표시되도록 되어 있다.

### 6.3 브로커 단위 테스트는 통과함

다음은 통과한 상태다.

```bash
python3 -m py_compile gvisor_hook/*.py
python3 -m unittest tests/test_broker.py
```

### 6.4 승인 UI와 execve 이벤트 round-trip 검증

Open Interpreter 전체 경로는 아니지만, `runsc exec` 를 이용한 별도 검증에서 다음을 확인했다.

- execve 이벤트가 브로커까지 도달함
- 웹/REST snapshot에서 pending 이벤트를 확인할 수 있음
- `allow` 처리 시 `uname` 실행이 성공적으로 끝남
- `deny` 처리 시 이벤트 상태가 `denied`, `errno=EPERM` 으로 업데이트됨

즉, “승인 이벤트 생성 -> 브로커 수신 -> 사용자 결정 -> 상태 업데이트” 자체는 일부 경로에서 동작이 확인되었다.

## 7. 현재까지 확인된 중요한 디버깅 사실

### 7.1 seccomp 때문에 승인 IPC가 막히는 문제가 있었다

초기에는 approval IPC를 위해 sentry가 여는 socket syscall이 seccomp에 막혀서 죽었다.

이 문제를 해결하기 위해 `third_party/gvisor/runsc/boot/filter/config/extra_filters_hostinet.go` 에 다음 계열 socket 허용 규칙을 추가했다.

- `AF_INET`, `SOCK_STREAM | NONBLOCK | CLOEXEC`, protocol `0`
- `AF_INET6`, 동일
- `AF_UNIX`, 동일

이 변경 이후, 적어도 seccomp 때문에 approval IPC가 즉시 죽는 문제는 넘겼다.

### 7.2 TCP approval backend는 WSL/rootless 조합에서 불안정했다

이전에는 approval backend를 `tcp://127.0.0.1:<port>` 로 열어 sentry가 브로커에 붙게 했는데, 다음 문제가 있었다.

- sentry가 TCP socket을 열 수는 있어도
- `connect` 단계에서 `network is unreachable`가 발생하는 경우가 있었다

그래서 이후에는 Unix socket과 file backend를 같이 실험했다.

### 7.3 Unix socket backend는 일부 경로에서 실제로 동작했다

seccomp 예외와 함께 UDS를 허용한 뒤, 다음 패턴의 로그를 실제로 확인했다.

- `gvisor-hook: enabled network="unix" ...`
- `gvisor-hook: connected ...`
- `gvisor-hook: sent ... waiting-for-decision`
- deny 시 `gvisor-hook: denied ... errno=EPERM`

즉, UDS 경로 자체는 완전히 허상은 아니고 실제로 살아본 적이 있다.

### 7.4 최신 실패에서는 실제 실행 경로가 다시 TCP로 돌아간 흔적이 있다

최신 실패 런인 `.gvisor-hook/run-lvs9xpkr` 기준으로, `debug` 로그에는 다음이 찍혀 있다.

- `gvisor-hook: enabled network="tcp" address="127.0.0.1:38481" ...`

그리고 같은 런의 `bundle/config.json` 에도 실제로 아래 env가 들어 있다.

- `GVISOR_HOOK_ADDR=127.0.0.1:38481`
- `GVISOR_HOOK_SOCKET=.../broker.sock`
- `GVISOR_HOOK_EVENT_LOG=.../events.ndjson`
- `GVISOR_HOOK_DECISION_DIR=.../decisions`

즉, 최신 런타임은 “socket만 쓰는 구조”가 아니라 TCP와 UDS와 file backend를 동시에 싣고 있었고, `approval.go` 의 우선순위상 `address != ""` 이면 TCP를 먼저 사용한다.

이건 매우 중요하다. 현재 소스 일부를 보면 socket-only 로 보이는데, 실제 생성된 bundle은 아직 `GVISOR_HOOK_ADDR` 를 포함한다. 다음 작업자는 반드시 아래 3개를 동시에 비교해야 한다.

- `gvisor_hook/launcher.py`
- `.gvisor-hook/run-*/bundle/config.json`
- `.gvisor-hook/run-*/runsc-logs/debug`

## 8. 최신 재현 실패 상태

사용자가 보고한 최신 실패 증상:

- Open Interpreter 프롬프트는 정상적으로 뜬다.
- 사용자 요청을 한 번 입력하면 곧바로 sandbox가 종료되고 셸 prompt로 돌아간다.
- 웹 UI에는 기대한 syscall 승인 이벤트가 보이지 않는다.

최신 로그 기준 파일:

- `.gvisor-hook/run-lvs9xpkr/runsc-logs/debug`
- `.gvisor-hook/run-lvs9xpkr/runsc-logs/user.log`

이 런의 핵심 관찰:

- Open Interpreter는 정상 시작함
- approval hook는 warmup 이후 활성화됨
- 실제로 `execve "/usr/local/sbin/uname"` 요청 직후
- 곧 `Wait RPC ... EOF` 와 함께 sandbox가 종료됨

즉, 현재 마지막 문제는 “Open Interpreter가 안 뜨는 것”이 아니라 “요청 후 첫 실질 execve approval 요청 시점에서 sandbox가 죽는 것”에 가깝다.

## 9. 최신 로그에서 읽히는 가설

현재 가장 유력한 가설은 다음 중 하나다.

### 가설 A

approval backend 우선순위 때문에 실제로는 TCP backend가 사용되고 있고, 이 경로가 여전히 불안정하다.

근거:

- 최신 `debug` 로그에 `network="tcp"` 로 찍힘
- 최신 bundle env에 `GVISOR_HOOK_ADDR` 가 실제로 존재함

### 가설 B

approval 이벤트를 보낸 뒤 결과를 기다리는 과정에서 sentry가 EOF를 맞고 있고, 브로커 쪽까지 요청이 도달하지 못한다.

근거:

- 최신 실패에서는 브로커 수신 로그가 안 보였음
- `request syscall=execve path="/usr/local/sbin/uname"` 직후 sandbox 종료

### 가설 C

소스 코드, 생성된 bundle, 마지막으로 빌드된 `runsc-hook` 바이너리의 상태가 서로 맞지 않는다.

근거:

- source 상으로는 socket 위주처럼 보이는 부분이 있음
- 하지만 최신 실제 bundle에는 `GVISOR_HOOK_ADDR` 가 들어 있음
- 여러 차례 실험 도중 런타임 구조가 자주 바뀌었음

## 10. 현재 바이너리 상태

현재 `runsc-hook` 바이너리 경로:

- `third_party/gvisor/bin/runsc-hook`

확인 시각:

- `LastWriteTime: 2026-04-05 13:37:51`

즉, 현재 이 바이너리는 2026-04-05 13:37 KST 시점의 소스를 반영한 빌드다.  
다만 여러 번 디버깅 중에 소스와 런타임 산출물의 상태가 바뀌었기 때문에, 다음 작업 시작 시에는 “source와 binary가 일치한다”는 가정을 두지 말고 다시 확인하는 것이 안전하다.

## 11. 보안 / 저장소 위생 관련 매우 중요한 경고

현재 `.gvisor-hook/run-*/bundle/config.json` 에는 런타임 env가 그대로 기록된다.  
여기에는 forwarded API 키가 포함될 수 있다.

실제로 최신 bundle에는 `OPENAI_API_KEY=...` 가 들어 있었다.

따라서 다음 조치는 매우 중요하다.

- `.gvisor-hook/` 아래 산출물은 절대 커밋하면 안 된다.
- 이미 `git status` 기준으로 `.gvisor-hook/run-*` 산출물이 대량 staged 되어 있다.
- 이 디렉터리는 `.gitignore` 로 제외하거나, tracked 상태를 정리해야 한다.
- handoff 문서나 이슈에 secret 값을 복사하지 말 것

현재 확인된 git 상태의 특징:

- `.gvisor-hook/run-*` 아래 `bundle/config.json`, `runsc-logs/*`, `network/*`, `bootstrap/*` 가 대량 staged 상태
- 이 중 일부는 로그뿐 아니라 secret-bearing env를 포함

## 12. 저장소 현재 상태에서 주의할 점

- 이 worktree는 이미 상당히 dirty 하다.
- `.gvisor-hook/` 런타임 산출물이 많이 쌓여 있다.
- 이 프로젝트를 이어받는 사람은 기능 디버깅 전에 먼저 아래를 구분해야 한다.
  - 소스 파일
  - 실제 최신 런타임 산출물
  - 마지막 빌드 바이너리

## 13. 재현 및 확인 명령

### 빌드

```bash
cd /home/kimjisu/gvisorHook
./scripts/build_runsc.sh
```

### 실행

```bash
cd /home/kimjisu/gvisorHook
python3 -m gvisor_hook launch --workdir /home/kimjisu/gvisorHook --web-port 8080
```

### 브로커 테스트

```bash
cd /home/kimjisu/gvisorHook
python3 -m unittest tests/test_broker.py
```

### Python 문법 확인

```bash
cd /home/kimjisu/gvisorHook
python3 -m py_compile gvisor_hook/*.py
```

## 14. 다음 작업자가 가장 먼저 해야 할 일

우선순위를 분명히 적는다.

### 1순위

실제 approval backend가 무엇으로 선택되고 있는지 확정해야 한다.

체크 포인트:

- `gvisor_hook/launcher.py`
- `gvisor_hook/bundle.py`
- 새로 생성된 `.gvisor-hook/run-*/bundle/config.json`
- 새로 생성된 `.gvisor-hook/run-*/runsc-logs/debug`

특히 `GVISOR_HOOK_ADDR` 가 왜 bundle에 들어가는지 먼저 확인해야 한다.  
현재 최신 증상은 이 값 때문에 approval.go가 TCP를 우선 선택하는 것이 핵심 원인일 가능성이 높다.

### 2순위

approval backend를 하나로 단순화해야 한다.

권장 방향:

- TCP, UDS, file backend를 동시에 싣지 말고
- 먼저 하나만 남긴 상태에서 재현
- 개인적으로는 UDS 또는 file backend 단일화가 디버깅에 더 유리하다

현재처럼 여러 backend를 동시에 env에 넣으면 원인 파악이 어렵다.

### 3순위

첫 execve approval 시 sandbox가 왜 종료되는지 추가로 좁혀야 한다.

재현 기준:

- Open Interpreter 프롬프트가 뜬 뒤
- 간단한 파일 생성 요청 입력
- 첫 approval request 발생 시점
- 브로커 수신 여부와 sandbox 종료 여부 확인

### 4순위

`.gvisor-hook/` 산출물과 secret 노출 가능성을 정리해야 한다.

권장 조치:

- `.gitignore` 에 `.gvisor-hook/` 추가 검토
- 이미 staged 된 런타임 산출물 제거
- secret-bearing config 산출물은 repo 밖으로 빼거나 생성 후 즉시 정리

## 15. 다음 작업자가 참고할 만한 파일

핵심 소스:

- `gvisor_hook/launcher.py`
- `gvisor_hook/bundle.py`
- `gvisor_hook/broker.py`
- `third_party/gvisor/pkg/sentry/syscalls/linux/approval.go`
- `third_party/gvisor/runsc/boot/filter/config/extra_filters_hostinet.go`
- `third_party/gvisor/runsc/boot/filter/filter.go`

최신 재현 로그:

- `.gvisor-hook/run-lvs9xpkr/runsc-logs/debug`
- `.gvisor-hook/run-lvs9xpkr/runsc-logs/user.log`
- `.gvisor-hook/run-lvs9xpkr/bundle/config.json`

검증용 테스트:

- `tests/test_broker.py`

## 16. 한 줄 요약

이 프로젝트는 “Open Interpreter를 수정하지 않고 gVisor 안에서 실행하고, 파일 변경/execve syscall을 웹에서 승인받는 MVP”까지 거의 도달했지만, 현재 최신 상태의 핵심 blocker는 “사용자 요청 후 첫 execve approval 시점에서 sandbox가 종료되는 문제”다. 그리고 최신 런타임은 여전히 `GVISOR_HOOK_ADDR` 를 포함하고 있어, approval backend가 의도와 다르게 TCP로 선택되고 있을 가능성이 매우 높다.
