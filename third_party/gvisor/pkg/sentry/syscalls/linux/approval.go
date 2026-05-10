package linux

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	abiLinux "gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/proc"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

type approvalConfig struct {
	enabled     bool
	donated     bool
	network     string
	address     string
	socketPath  string
	eventLog    string
	decisionDir string
	containerID string
	timeout     time.Duration
	enableAfter time.Time
}

type approvalEvent struct {
	ID          string   `json:"id"`
	ContainerID string   `json:"container_id"`
	PID         int      `json:"pid"`
	TID         int      `json:"tid"`
	Syscall     string   `json:"syscall"`
	Summary     string   `json:"summary"`
	Path        string   `json:"path,omitempty"`
	Argv        []string `json:"argv,omitempty"`
	StartedAt   string   `json:"started_at"`
	Status      string   `json:"status"`
}

type ipcEnvelope struct {
	Type    string         `json:"type"`
	Payload *approvalEvent `json:"payload,omitempty"`
}

type decisionResult struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Decision string `json:"decision"`
	Errno    string `json:"errno"`
}

var (
	hookConfig     approvalConfig
	hookConfigOnce sync.Once
	eventCounter   uint64

	approvalTransportMu sync.Mutex
	approvalTransport   *approvalStream
)

var approvalHookedSyscalls = map[string]struct{}{
	"accept":             {},
	"accept4":            {},
	"afs_syscall":        {},
	"alarm":              {},
	"arch_prctl":         {},
	"bind":               {},
	"capset":             {},
	"chdir":              {},
	"chmod":              {},
	"chown":              {},
	"chroot":             {},
	"clock_settime":      {},
	"clone":              {},
	"clone3":             {},
	"close_range":        {},
	"connect":            {},
	"creat":              {},
	"dup2":               {},
	"dup3":               {},
	"epoll_create":       {},
	"epoll_create1":      {},
	"epoll_ctl":          {},
	"eventfd":            {},
	"eventfd2":           {},
	"execve":             {},
	"execveat":           {},
	"exit":               {},
	"exit_group":         {},
	"fallocate":          {},
	"fchdir":             {},
	"fchmod":             {},
	"fchmodat":           {},
	"fchown":             {},
	"fchownat":           {},
	"fcntl":              {},
	"fdatasync":          {},
	"flock":              {},
	"fork":               {},
	"fremovexattr":       {},
	"fsetxattr":          {},
	"fsync":              {},
	"ftruncate":          {},
	"futimesat":          {},
	"inotify_add_watch":  {},
	"inotify_init":       {},
	"inotify_init1":      {},
	"inotify_rm_watch":   {},
	"io_cancel":          {},
	"io_destroy":         {},
	"io_setup":           {},
	"io_submit":          {},
	"io_uring_enter":     {},
	"io_uring_setup":     {},
	"ioctl":              {},
	"keyctl":             {},
	"kill":               {},
	"lchown":             {},
	"link":               {},
	"linkat":             {},
	"listen":             {},
	"lremovexattr":       {},
	"lsetxattr":          {},
	"mbind":              {},
	"membarrier":         {},
	"memfd_create":       {},
	"mkdir":              {},
	"mkdirat":            {},
	"mknod":              {},
	"mknodat":            {},
	"mlock":              {},
	"mlock2":             {},
	"mlockall":           {},
	"mmap":               {},
	"mount":              {},
	"mprotect":           {},
	"mq_open":            {},
	"mq_unlink":          {},
	"mremap":             {},
	"msgctl":             {},
	"msgget":             {},
	"msgsnd":             {},
	"msync":              {},
	"munlock":            {},
	"munlockall":         {},
	"open":               {},
	"openat":             {},
	"pipe":               {},
	"pipe2":              {},
	"pivot_root":         {},
	"prctl":              {},
	"prlimit64":          {},
	"process_vm_writev":  {},
	"ptrace":             {},
	"pwrite64":           {},
	"pwritev":            {},
	"pwritev2":           {},
	"removexattr":        {},
	"rename":             {},
	"renameat":           {},
	"renameat2":          {},
	"rmdir":              {},
	"rt_sigaction":       {},
	"rt_sigprocmask":     {},
	"rt_sigqueueinfo":    {},
	"rt_tgsigqueueinfo":  {},
	"sched_setaffinity":  {},
	"sched_setscheduler": {},
	"seccomp":            {},
	"semctl":             {},
	"semget":             {},
	"semop":              {},
	"semtimedop":         {},
	"sendfile":           {},
	"sendmmsg":           {},
	"sendmsg":            {},
	"sendto":             {},
	"set_mempolicy":      {},
	"set_robust_list":    {},
	"setdomainname":      {},
	"setgid":             {},
	"setgroups":          {},
	"sethostname":        {},
	"setitimer":          {},
	"setns":              {},
	"setpgid":            {},
	"setpriority":        {},
	"setregid":           {},
	"setresgid":          {},
	"setresuid":          {},
	"setreuid":           {},
	"setrlimit":          {},
	"setsid":             {},
	"setsockopt":         {},
	"setuid":             {},
	"setxattr":           {},
	"shmat":              {},
	"shmctl":             {},
	"shmget":             {},
	"shutdown":           {},
	"sigaltstack":        {},
	"signalfd":           {},
	"signalfd4":          {},
	"socket":             {},
	"socketpair":         {},
	"splice":             {},
	"symlink":            {},
	"symlinkat":          {},
	"sync":               {},
	"sync_file_range":    {},
	"syncfs":             {},
	"syslog":             {},
	"tee":                {},
	"tgkill":             {},
	"timer_create":       {},
	"timer_delete":       {},
	"timer_settime":      {},
	"timerfd_create":     {},
	"timerfd_settime":    {},
	"tkill":              {},
	"truncate":           {},
	"umask":              {},
	"umount2":            {},
	"unlink":             {},
	"unlinkat":           {},
	"unshare":            {},
	"utime":              {},
	"utimensat":          {},
	"utimes":             {},
	"vfork":              {},
	"write":              {},
	"writev":             {},
}

type approvalStream struct {
	conn    net.Conn
	reader  *bufio.Reader
	decoder *json.Decoder
	encoder *json.Encoder
}

var ignoredApprovalPrefixes = []string{
	"/tmp/bootstrap",
	"/tmp/oi-home",
	"/tmp/open-interpreter",
	"/dev",
	"/proc",
	"/sys",
	"/etc",
	"/mnt",
}

var monitoredApprovalPrefixes = []string{
	"/tmp/workspace",
	"/tmp/oi-home",
}

func shouldIgnoreApprovalPath(path string) bool {
	if path == "" {
		return true
	}
	if path == "[unknown]" {
		return true
	}
	for _, prefix := range ignoredApprovalPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	if strings.HasSuffix(path, "/__pycache__") || strings.Contains(path, "/__pycache__/") {
		return true
	}
	if strings.HasSuffix(path, ".pyc") {
		return true
	}
	return false
}

func shouldMonitorApprovalPath(path string) bool {
	if shouldIgnoreApprovalPath(path) {
		return false
	}
	for _, prefix := range monitoredApprovalPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func readTaskEnv(t *kernel.Task, key string) string {
	mm := t.MemoryManager()
	if mm == nil {
		return ""
	}
	var buf bytes.Buffer
	if err := proc.GetMetadata(t, mm, &buf, proc.Environ); err != nil {
		return ""
	}
	prefix := key + "="
	for _, entry := range bytes.Split(buf.Bytes(), []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		if strings.HasPrefix(string(entry), prefix) {
			return string(entry[len(prefix):])
		}
	}
	return ""
}

// SetApprovalIPCFile installs a donated approval transport for the sentry to
// use when prompting the external broker.
func SetApprovalIPCFile(file *os.File) error {
	approvalTransportMu.Lock()
	defer approvalTransportMu.Unlock()
	if approvalTransport != nil {
		_ = approvalTransport.conn.Close()
		approvalTransport = nil
	}
	if file == nil {
		return nil
	}
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	approvalTransport = &approvalStream{
		conn:    conn,
		reader:  reader,
		decoder: json.NewDecoder(reader),
		encoder: json.NewEncoder(conn),
	}
	log.Infof("gvisor-hook: donated approval transport installed")
	return nil
}

func hasApprovalTransport() bool {
	approvalTransportMu.Lock()
	defer approvalTransportMu.Unlock()
	return approvalTransport != nil
}

func loadApprovalConfigForTask(t *kernel.Task) approvalConfig {
	hookConfigOnce.Do(func() {
		hookAddr := readTaskEnv(t, "GVISOR_HOOK_ADDR")
		socketPath := readTaskEnv(t, "GVISOR_HOOK_SOCKET")
		eventLog := readTaskEnv(t, "GVISOR_HOOK_EVENT_LOG")
		decisionDir := readTaskEnv(t, "GVISOR_HOOK_DECISION_DIR")
		donated := hasApprovalTransport()
		if !donated && hookAddr == "" && socketPath == "" && (eventLog == "" || decisionDir == "") {
			log.Infof("gvisor-hook: disabled; no approval backend configured")
			hookConfig = approvalConfig{}
			return
		}
		timeout := 30 * time.Second
		if raw := readTaskEnv(t, "GVISOR_HOOK_TIMEOUT_MS"); raw != "" {
			if parsed, err := time.ParseDuration(raw + "ms"); err == nil {
				timeout = parsed
			}
		}
		warmup := 0 * time.Second
		if raw := readTaskEnv(t, "GVISOR_HOOK_WARMUP_MS"); raw != "" {
			if parsed, err := time.ParseDuration(raw + "ms"); err == nil {
				warmup = parsed
			}
		}
		containerID := readTaskEnv(t, "GVISOR_HOOK_CONTAINER_ID")
		if containerID == "" {
			containerID = "gvisor-hook"
		}
		network := "tcp"
		address := hookAddr
		if address == "" {
			network = "unix"
			address = socketPath
		}
		hookConfig = approvalConfig{
			enabled:     true,
			donated:     donated,
			network:     network,
			address:     address,
			socketPath:  socketPath,
			eventLog:    eventLog,
			decisionDir: decisionDir,
			containerID: containerID,
			timeout:     timeout,
			enableAfter: time.Now().Add(warmup),
		}
		log.Infof(
			"gvisor-hook: enabled donated=%t network=%q address=%q socket=%q event_log=%q decision_dir=%q container=%q timeout=%s warmup=%s",
			donated,
			network,
			address,
			socketPath,
			eventLog,
			decisionDir,
			containerID,
			timeout,
			warmup,
		)
	})
	return hookConfig
}

func shouldApproveOpenFlags(flags uint32) bool {
	writeMode := flags & abiLinux.O_ACCMODE
	return writeMode == abiLinux.O_WRONLY ||
		writeMode == abiLinux.O_RDWR ||
		flags&abiLinux.O_CREAT != 0 ||
		flags&abiLinux.O_TRUNC != 0 ||
		flags&abiLinux.O_APPEND != 0
}

func filePath(t *kernel.Task, file *vfs.FileDescription) string {
	path := file.MappedName(t)
	if path == "" {
		return "[unknown]"
	}
	return path
}

func installApprovalHooks(table *kernel.SyscallTable) {
	for sysno, sc := range table.Table {
		if _, ok := approvalHookedSyscalls[sc.Name]; !ok || sc.Fn == nil {
			continue
		}
		syscallName := sc.Name
		fn := sc.Fn
		sc.Fn = func(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
			if err := approveGenericSyscall(t, syscallName, args); err != nil {
				return 0, nil, err
			}
			return fn(t, sysno, args)
		}
		table.Table[sysno] = sc
	}
}

func approveGenericSyscall(t *kernel.Task, syscallName string, args arch.SyscallArguments) error {
	path, argv := approvalSyscallDetails(t, syscallName, args)
	summary := fmt.Sprintf("%s(%#x, %#x, %#x, %#x, %#x, %#x)",
		syscallName,
		args[0].Uint64(),
		args[1].Uint64(),
		args[2].Uint64(),
		args[3].Uint64(),
		args[4].Uint64(),
		args[5].Uint64(),
	)
	if path != "" {
		summary = fmt.Sprintf("%s %s", syscallName, path)
	}
	if len(argv) > 0 {
		summary = fmt.Sprintf("%s %s", summary, strings.Join(argv, " "))
	}
	return requestApproval(t, syscallName, summary, path, argv)
}

func approvalSyscallDetails(t *kernel.Task, syscallName string, args arch.SyscallArguments) (string, []string) {
	switch syscallName {
	case "chdir", "chmod", "chown", "chroot", "creat", "lchown", "mkdir", "mknod", "mq_open", "mq_unlink", "open", "removexattr", "rmdir", "setxattr", "symlink", "truncate", "unlink", "utime", "utimes":
		return copyApprovalPath(t, args[0].Pointer()), nil
	case "execve":
		path := copyApprovalPath(t, args[0].Pointer())
		return path, copyApprovalArgv(t, args[1].Pointer())
	case "execveat":
		path := copyApprovalPath(t, args[1].Pointer())
		return path, copyApprovalArgv(t, args[2].Pointer())
	case "fchmodat", "fchownat", "fremovexattr", "futimesat", "linkat", "mkdirat", "mknodat", "openat", "renameat", "renameat2", "symlinkat", "unlinkat", "utimensat":
		return copyApprovalPath(t, args[1].Pointer()), nil
	case "link", "rename":
		oldPath := copyApprovalPath(t, args[0].Pointer())
		newPath := copyApprovalPath(t, args[1].Pointer())
		if oldPath == "" {
			return newPath, nil
		}
		if newPath == "" {
			return oldPath, nil
		}
		return oldPath + " -> " + newPath, nil
	case "lremovexattr", "lsetxattr":
		return copyApprovalPath(t, args[0].Pointer()), nil
	case "mount":
		source := copyApprovalPath(t, args[0].Pointer())
		target := copyApprovalPath(t, args[1].Pointer())
		if source == "" {
			return target, nil
		}
		if target == "" {
			return source, nil
		}
		return source + " -> " + target, nil
	case "pivot_root":
		newRoot := copyApprovalPath(t, args[0].Pointer())
		putOld := copyApprovalPath(t, args[1].Pointer())
		if newRoot == "" {
			return putOld, nil
		}
		if putOld == "" {
			return newRoot, nil
		}
		return newRoot + " -> " + putOld, nil
	case "umount2":
		return copyApprovalPath(t, args[0].Pointer()), nil
	}
	return "", nil
}

func copyApprovalPath(t *kernel.Task, addr hostarch.Addr) string {
	if addr == 0 {
		return ""
	}
	path, err := t.CopyInString(addr, abiLinux.PATH_MAX)
	if err != nil {
		return "[unknown]"
	}
	return path
}

func copyApprovalArgv(t *kernel.Task, addr hostarch.Addr) []string {
	if addr == 0 {
		return nil
	}
	argv, err := t.CopyInVector(addr, ExecMaxElemSize, ExecMaxTotalSize)
	if err != nil {
		return nil
	}
	return argv
}

func requestApproval(t *kernel.Task, syscallName, summary, path string, argv []string) error {
	cfg := loadApprovalConfigForTask(t)
	if !cfg.enabled {
		return nil
	}
	if !cfg.enableAfter.IsZero() && time.Now().Before(cfg.enableAfter) {
		return nil
	}
	log.Infof("gvisor-hook: request syscall=%s path=%q", syscallName, path)
	event := approvalEvent{
		ID:          fmt.Sprintf("%s-%d", cfg.containerID, atomic.AddUint64(&eventCounter, 1)),
		ContainerID: cfg.containerID,
		PID:         int(t.ThreadGroup().ID()),
		TID:         int(t.ThreadID()),
		Syscall:     syscallName,
		Summary:     summary,
		Path:        path,
		Argv:        argv,
		StartedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Status:      "pending",
	}
	if cfg.donated {
		return requestApprovalViaDonatedStream(cfg, syscallName, event)
	}
	if cfg.address != "" {
		return requestApprovalViaSocket(cfg, syscallName, event)
	}
	if cfg.eventLog != "" && cfg.decisionDir != "" {
		return requestApprovalViaFiles(cfg, syscallName, event)
	}
	log.Warningf("gvisor-hook: no usable backend for syscall=%s id=%s", syscallName, event.ID)
	return linuxerr.EPERM
}

func requestApprovalViaDonatedStream(cfg approvalConfig, syscallName string, event approvalEvent) error {
	approvalTransportMu.Lock()
	defer approvalTransportMu.Unlock()
	if approvalTransport == nil {
		log.Warningf("gvisor-hook: donated transport missing syscall=%s id=%s", syscallName, event.ID)
		return linuxerr.EPERM
	}
	if err := approvalTransport.encoder.Encode(ipcEnvelope{Type: "syscall_event", Payload: &event}); err != nil {
		log.Warningf("gvisor-hook: donated send failed syscall=%s id=%s err=%v", syscallName, event.ID, err)
		_ = approvalTransport.conn.Close()
		approvalTransport = nil
		return linuxerr.EPERM
	}
	log.Infof("gvisor-hook: sent syscall=%s id=%s waiting-for-decision (donated transport)", syscallName, event.ID)
	var result decisionResult
	if err := approvalTransport.decoder.Decode(&result); err != nil {
		log.Warningf("gvisor-hook: donated receive failed syscall=%s id=%s err=%v", syscallName, event.ID, err)
		_ = approvalTransport.conn.Close()
		approvalTransport = nil
		return linuxerr.EPERM
	}
	if result.Decision != "allow" {
		log.Infof("gvisor-hook: denied syscall=%s id=%s errno=%s", syscallName, event.ID, result.Errno)
		return linuxerr.EPERM
	}
	log.Infof("gvisor-hook: allowed syscall=%s id=%s path=%q", syscallName, event.ID, event.Path)
	return nil
}

func requestApprovalViaFiles(cfg approvalConfig, syscallName string, event approvalEvent) error {
	file, err := os.OpenFile(cfg.eventLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		log.Warningf("gvisor-hook: open event log failed syscall=%s path=%q err=%v", syscallName, cfg.eventLog, err)
		return linuxerr.EPERM
	}
	if err := json.NewEncoder(file).Encode(event); err != nil {
		_ = file.Close()
		log.Warningf("gvisor-hook: write event log failed syscall=%s id=%s err=%v", syscallName, event.ID, err)
		return linuxerr.EPERM
	}
	if err := file.Close(); err != nil {
		log.Warningf("gvisor-hook: close event log failed syscall=%s id=%s err=%v", syscallName, event.ID, err)
		return linuxerr.EPERM
	}
	log.Infof("gvisor-hook: queued syscall=%s id=%s waiting-for-decision (file backend)", syscallName, event.ID)
	deadline := time.Now().Add(cfg.timeout)
	decisionPath := filepath.Join(cfg.decisionDir, event.ID+".json")
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(decisionPath)
		if err == nil {
			var result decisionResult
			if err := json.Unmarshal(data, &result); err != nil {
				log.Warningf("gvisor-hook: invalid decision file syscall=%s id=%s err=%v", syscallName, event.ID, err)
				return linuxerr.EPERM
			}
			if result.Decision != "allow" {
				log.Infof("gvisor-hook: denied syscall=%s id=%s errno=%s", syscallName, event.ID, result.Errno)
				return linuxerr.EPERM
			}
			log.Infof("gvisor-hook: allowed syscall=%s id=%s path=%q", syscallName, event.ID, event.Path)
			return nil
		}
		if !os.IsNotExist(err) {
			log.Warningf("gvisor-hook: read decision file failed syscall=%s id=%s err=%v", syscallName, event.ID, err)
			return linuxerr.EPERM
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Warningf("gvisor-hook: timed out waiting for decision syscall=%s id=%s", syscallName, event.ID)
	return linuxerr.EPERM
}

func requestApprovalViaSocket(cfg approvalConfig, syscallName string, event approvalEvent) error {
	conn, err := net.DialTimeout(cfg.network, cfg.address, cfg.timeout)
	if err != nil {
		log.Warningf(
			"gvisor-hook: dial failed syscall=%s network=%q address=%q err=%v",
			syscallName,
			cfg.network,
			cfg.address,
			err,
		)
		return linuxerr.EPERM
	}
	log.Infof("gvisor-hook: connected syscall=%s id=%s", syscallName, event.ID)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.timeout))

	if err := json.NewEncoder(conn).Encode(ipcEnvelope{Type: "syscall_event", Payload: &event}); err != nil {
		log.Warningf("gvisor-hook: send failed syscall=%s id=%s err=%v", syscallName, event.ID, err)
		return linuxerr.EPERM
	}
	log.Infof("gvisor-hook: sent syscall=%s id=%s waiting-for-decision", syscallName, event.ID)
	var result decisionResult
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&result); err != nil {
		log.Warningf("gvisor-hook: receive failed syscall=%s id=%s err=%v", syscallName, event.ID, err)
		return linuxerr.EPERM
	}
	if result.Decision != "allow" {
		log.Infof("gvisor-hook: denied syscall=%s id=%s errno=%s", syscallName, event.ID, result.Errno)
		return linuxerr.EPERM
	}
	log.Infof("gvisor-hook: allowed syscall=%s id=%s path=%q", syscallName, event.ID, event.Path)
	return nil
}

func approveOpen(t *kernel.Task, syscallName, path string, flags uint32) error {
	if _, ok := approvalHookedSyscalls[syscallName]; ok {
		return nil
	}
	if !shouldApproveOpenFlags(flags) {
		return nil
	}
	if !shouldMonitorApprovalPath(path) {
		return nil
	}
	return requestApproval(t, syscallName, fmt.Sprintf("%s write-intent open", syscallName), path, nil)
}

func approvePathMutation(t *kernel.Task, syscallName, path string) error {
	if _, ok := approvalHookedSyscalls[syscallName]; ok {
		return nil
	}
	if !shouldMonitorApprovalPath(path) {
		return nil
	}
	return requestApproval(t, syscallName, fmt.Sprintf("%s %s", syscallName, path), path, nil)
}

func approveRename(t *kernel.Task, oldPath, newPath string) error {
	if _, ok := approvalHookedSyscalls["rename"]; ok {
		return nil
	}
	if !shouldMonitorApprovalPath(oldPath) && !shouldMonitorApprovalPath(newPath) {
		return nil
	}
	return requestApproval(t, "rename", fmt.Sprintf("rename %s -> %s", oldPath, newPath), oldPath+" -> "+newPath, nil)
}

func approveWriteFD(t *kernel.Task, syscallName string, file *vfs.FileDescription, count int) error {
	if _, ok := approvalHookedSyscalls[syscallName]; ok {
		return nil
	}
	path := filePath(t, file)
	if !shouldMonitorApprovalPath(path) {
		return nil
	}
	return requestApproval(t, syscallName, fmt.Sprintf("%s %d bytes", syscallName, count), path, nil)
}

func approveExec(t *kernel.Task, path string, argv []string) error {
	if _, ok := approvalHookedSyscalls["execve"]; ok {
		return nil
	}
	if shouldIgnoreApprovalPath(path) {
		return nil
	}
	summary := fmt.Sprintf("execve %s", path)
	if len(argv) > 0 {
		summary = fmt.Sprintf("execve %s %s", path, strings.Join(argv, " "))
	}
	return requestApproval(t, "execve", summary, path, argv)
}
