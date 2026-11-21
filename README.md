# svbox

**AArch64 userspace syscall-rewriting sandbox, VFS virtualization, and container runtime (MIT License).**
**面向 HarmonyOS / Linux AArch64 的用户态系统调用重写沙盒与容器运行时（纯 MIT 许可证）。**

---

## English

`svbox` runs unmodified AArch64 Linux binaries inside an isolated virtual filesystem view (root, bind mounts, copy-on-write lower layers, EROFS lazy layers, emulated mount tables, fake root/uid/gid, and virtual container networking) **without requiring `ptrace`, Linux namespaces, or root privileges**.

Guest executables are loaded by the static non-PIE `svbox` loader at a fixed address, with `svc #0` instructions rewritten to jump into an embedded position-independent payload. For stronger isolation (`--isolate`), `svbox` installs a strict seccomp-BPF guest filter and forks an out-of-process **broker** that enforces every filesystem policy (`rw` / `ro` / `deny`) and maintains an exec trust chain across `execve`.

### Key Features

- **100% MIT Licensed**: Clean-room MIT path/binding/canonicalization core (`src/path/`), zero GPL dependencies.
- **Single Consolidated Binary**: One static binary (`build/svbox`) serves both fast-path containers (zero FD-tracking overhead when `--guard none`) and full guarded / `--sandbox` / `--isolate` enforcement.
- **Clean CLI & Binary Exec Handoff**: Per-mount `:rw` / `:ro` / `:deny` access suffixes, `--sandbox` preset, and a hidden memfd binary handoff (`--__handoff-fd`) across guest `execve` calls.
- **Real Linux Workloads Verified**: Alpine, Ubuntu (`apt`, `dpkg`, `gcc`, `pip`, `node`, `cargo`, Go runtime, Redis, Nginx), HarmonyOS agent sandboxes, and Docker/OCI containers (`tools/oci/`).

### Build & Test

Requires Python 3, GNU `make`, `clang`, `ld.lld`, `llvm-objcopy`, and AArch64 Linux ABI headers.

```sh
make build            # Build build/svbox and build/svbox-exec
make check            # Core regressions
make check-guarded    # Guarded FD runtime and filesystem policy regressions
make check-isolation  # Seccomp + broker isolation acceptance suite
make check-oci        # OCI / docker CLI acceptance (needs build/alpine-test-root)
make check-alpine ALPINE_ARCHIVE=/path/to/alpine-minirootfs-aarch64.tar.gz
make check-ubuntu UBUNTU_ARCHIVE=/path/to/ubuntu-base-arm64.tar.gz
make bench            # Native vs svbox syscall micro-benchmarks
```

### Usage Examples

Run a container shell with a writable workspace bind:

```sh
build/svbox --root /path/to/rootfs \
  -v /path/to/workspace:/workspace -- ./bin/busybox sh
```

Run a read-only rootfs with a writable workspace and `--isolate` broker enforcement:

```sh
build/svbox --isolate --root /path/to/rootfs --root-mode ro \
  -v /path/to/workspace:/workspace:rw --sandbox -- ./bin/busybox sh
```

Run an agent profile via the companion launcher:

```sh
python3 tools/agent/launch.py profiles/harmonyos-agent.json \
  --brew-prefix /path/to/brew --workspace /path/to/work --state /path/to/state \
  -- /bin/sh -c 'ls -la /workspace'
```

Run `build/svbox --help` for the complete option reference.

---

## 中文说明

`svbox` 在 HarmonyOS 系统沙盒或无特权 Linux AArch64 环境下，通过静态 ELF 装载与 `svc #0` 指令重写提供完整的用户态文件系统视图与容器运行时（root、bind、写时复制下层与 EROFS 懒加载层、模拟挂载表、虚拟 root/uid/gid、虚拟容器网络），**完全不依赖 `ptrace`、namespace 或 root 权限**。

### 核心特性

- **100% 纯 MIT 许可**：路径规范化、绑定表与符号链接解析核心（`src/path/`）采用 Clean-room MIT 重写，彻底移除 GPL 依赖。
- **单二进制架构**：合并原有的双构建为单一静态二进制 `build/svbox`；默认模式（`--guard none`）走快路径零 FD 追踪开销，开启 `--guard` / `--sandbox` / `--isolate` 即时启用运行时策略与进程隔离。
- **简洁 CLI 与二进制 Exec 交接**：挂载权限直接内联在 `--root-mode rw|ro|deny` 和 `-v HOST:GUEST[:rw|ro|deny]`，跨 `execve` 状态通过单个私有 memfd（`--__handoff-fd`）二进制传递，不再向命令行暴露内部参数。
- **三层安全模型**：
  - **视图模式（默认）**：路径映射与容器语义视图，零追踪开销（非对抗边界）。
  - **进程内策略（`--guard` / `--sandbox`）**：基于 FD 溯源与挂载策略（`rw`/`ro`/`deny`）拦截越权读写与元数据变更（面向合作程序）。
  - **进程外隔离（`--isolate`）**：为 guest 安装 seccomp-BPF 过滤器，所有路径系统调用必须交由独立 **broker** 进程校验与代办，并维持跨 `execve` 的执行可信链（剩余风险见 [docs/ISOLATION.md](docs/ISOLATION.md)）。

### 常用选项

| 选项 | 作用 |
| --- | --- |
| `-h, --help` / `-V, --version` | 显示帮助或版本信息 |
| `--mode compat\|container` | `compat` 保留宿主环境与身份；`container` 清空环境并伪装 root（指定 `--root` 时默认启用） |
| `--root DIR` | 容器根目录；首个程序路径相对于根目录 |
| `--root-mode rw\|ro\|deny` | 根目录访问策略（默认 `rw`） |
| `-v, --bind HOST:GUEST[:MODE]` | 绑定挂载，`MODE` 可选 `rw`（默认）、`ro`、`deny`（最多 64 个） |
| `--lower DIR[:IMAGE]` | 写时复制只读下层目录，可选绑定 EROFS 层镜像 |
| `--guard none\|track\|observe\|paths\|files\|access` | 运行时策略级别（默认 `none` 快路径） |
| `--sandbox` | 预设组合：`--guard access` + `--allow-stdio` / `--allow-pipes` / `--allow-local-io` / `--allow-streams` / `--revalidate-fds` |
| `--isolate` | 启用 seccomp 过滤器 + broker 进程隔离 |
| `--allow-device DEV` | 隔离模式下放行白名单 GPU 设备节点直连（如 `/dev/hvgr0`） |
| `--pass-fd N` | 在受保护模式下显式授予继承的文件描述符 `N` |
| `-w, --workdir DIR` | 指定 guest 初始工作目录 |
| `-u, --user UID[:GID]` | 指定 guest 初始用户与用户组 |
| `-e, --env KEY=VALUE` | 设置 guest 环境变量 |
| `--link-copy` | 宿主存储拒绝硬链接时自动回退为复制（`dpkg`/`apt` 需要） |
| `--emulate-mounts` / `--mount-table PATH` | 启用容器内 `mount(2)`/`umount2(2)` 模拟 |
| `--owner-db PATH` | 启用虚拟文件属主与权限数据库 |
| `--seccomp-backstop` | 启用 seccomp SIGSYS 兜底截获未改写的 `svc` |
| `--log-level 0..4` | loader 诊断日志级别（默认 `0` 静默） |

### 代码地图

| 路径 | 职责 |
| --- | --- |
| `src/path/` | 纯 MIT 路径核心（`path_helpers.c`、`binding_core.c`、`canon_core.c`、`resolve_core.c`） |
| `src/loader/` | CLI 解析、二进制 handoff、ELF 装载与补钩、seccomp 过滤器、broker 进程、懒加载层 |
| `src/payload/arch/aarch64/` | AArch64 汇编入口、桩模板、分发器、重入保护、payload 栈、clone 门 |
| `src/payload/logic/` | VFS 桥接（`vfs_bridge.c`/`vfs_mounts.c`/`vfs_procfs.c`/`vfs_exec.c`/`vfs_auxv.c`）、FD 运行时与策略、联合视图、容器网络 |
| `tools/agent/` | Agent 沙盒配置编译器（`plan.py`）与启动器（`launch.py`） |
| `tools/oci/` | Docker/OCI 兼容工具、compose、镜像构建、EROFS 读写 |
| `test/` | 全量单元与真机集成回归套件 |

### 相关文档

- [架构说明](docs/ARCHITECTURE.md)
- [当前进度与验收](docs/STATUS.md)
- [隔离模式设计](docs/ISOLATION.md)
- [OCI / Docker 兼容设计](docs/OCI.md)
- [性能数据](docs/BENCHMARKS.md)
- [Agent 沙盒启动器](tools/agent/README.md)

## License

MIT License — see [LICENSE](LICENSE).
