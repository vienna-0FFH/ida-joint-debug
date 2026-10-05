# IDA Joint Debug

IDA Joint Debug 是面向 x86-64 Linux 的 **IDA 父子进程联合动态调试框架**。
通过内核辅助、Linux debug server 运行时适配和轻量 IDAPython 插件，让 IDA
观察程序的父进程与子进程，同时保留原程序自己的 ptrace 调试关系和异常控制流。

当前实现基于 Linux 原生 ptrace、regset 与 perf 硬件断点，不依赖 VT/KVM。
VT、KVM、EPT/NPT 或 guest 调试仅是未来可能扩展，不属于当前已提供的功能。

## 功能

- **父子联合视图**：在一个 IDA 远程会话中展示父进程与 shadow 子 TID，
  可切换检查寄存器、内存与断点。shadow 视图不改变真实进程地址空间。
- **保留真实调试所有权**：IDA server 调试父进程，父继续作为子进程的
  实际 ptrace owner，不把子交给第二个真实 tracer。
- **程序异常与调试器事件隔离**：区分程序自有协议异常和 IDA 主动产生的
  软件断点、硬件断点、单步与内部观察点。
- **协议控制流观察**：子进程因程序异常交权给父，父处理并修改寄存器后，
  可观察父实际选定的恢复位置，不按异常地址加一猜测控制流。
- **父等待语义**：父在 blocking wait 时呈现保存的调用帧，允许检查/设置
  断点，不让 F7/F8 提前推进通信循环；父真正被唤醒并命中真实停点后可正常单步。
- **软硬件断点管理**：按目标真实字节管理软件断点、恢复与跨视图同步。
  四个用户硬件槽占满时，明确来源的 F8 call-over 可使用软件临时断点。
- **停止态 DR 事务**：父已停住时，驱动可更新已分配的原生子进程 DR bank，
  避免向不能运行的真实 owner 递交同步 mailbox 请求。
- **会话与生命周期**：固定 PID 身份、owner TID、sequence、退出取消与
  晚到事件处理，支持调试结束后的重新连接。
- **按会话兼容策略**：受支持路径中的 `PTRACE_TRACEME`、
  procfs `TracerPid`、`PR_GET_DUMPABLE` 自检兼容。
- **协议模式与记录**：`stop` 逐程序协议暂停，`log` 记录并自动放行程序
  协议；普通 IDA 用户断点保持可见。

这是本地、授权调试工具，不提供无差别宿主隐藏、任意检测绕过或全系统 hook。
程序主动产生异常并不自动等于反调试；未知异常不得仅因来源于程序就无条件吞掉。

## 架构

```text
IDA GUI / idalib
    │ 标准 Linux debugger RPC + IDA 已有 ioctl 通知
    ▼
原厂 linux_server + libida_joint_shim.so
    │ ioctl 控制/命令/停止态访问；mmap + poll 事件流
    ▼
ida_joint_policy.ko
    │ owner wait 帧、固定 PID、sequence、生命周期与停止态 DR
    ▼
父进程 ── 原生 ptrace / wait ── 子进程及线程
```

server shim 通过 `LD_PRELOAD` 加载，事件适配仅修改 server 运行时内存，
不修改商业 IDA 或 `linux_server` 的磁盘文件。前端插件安装在 IDA 用户目录，
不覆盖商业安装文件。

网络连接仍由 IDA 的原有 RPC 承担；内核/用户层通信使用 ioctl 与共享事件页。
共享页没有可写内核指针，敏感访问要求已注册会话、权限和真实 ptrace 关系。

IDA 插件负责动作来源与展示，不执行目标的 VM 算法。内核负责生命周期、
停止态检查和寄存器事务；server 适配负责原厂后端无法直接表达的 shadow
视图和事件映射。

## 源码模块

```text
ida-joint-debug/
├── driver/     内核策略、owner wait 与停止态 DR
├── include/    内核/用户态 ABI、共享事件消费逻辑
├── src/        Linux server shim 和 IDA 运行时事件适配
├── tools/      构建、启动与 IDA 用户插件
├── tests/      源码生成的 fixture 和通用 smoke/integration tests
├── Makefile
└── README.md
```

### 内核与公共接口

| 文件 | 职责 |
|---|---|
| [driver/joint_policy.c](driver/joint_policy.c) | 设备注册、会话/权限、ptrace/wait/fork/exit 探针、mmap/poll 事件、命令 mailbox、退出取消和停止态寄存器/内存桥接 |
| [driver/owner_wait_context.inc](driver/owner_wait_context.inc) | 按 owner TID 保存 wait ENTER/LEAVE/QUERY 调用帧和 sequence，限制谁能写入等待状态 |
| [driver/stopped_debugregs.inc](driver/stopped_debugregs.inc) | 校验并冻结真实停止态父/子，更新已有原生 perf DR0–3/6/7，校验 DR7 并回滚错误事务 |
| [include/joint_debug_abi.h](include/joint_debug_abi.h) | 会话、事件、命令、ioctl 和逻辑 wait 帧 ABI |
| [include/shared_event_reader.h](include/shared_event_reader.h) | 共享页布局校验、sequence 与 acquire/release 消费 |
| [driver/Makefile](driver/Makefile) | 构建 `ida_joint_policy.ko` |

`.inc` 是主源码编译时纳入的模块分拆，不是独立驱动。DR 更新保留 Linux
原有 perf callback 和真实 ptracer，不创建模块私有溢出回调。未分配的槽、
权限不符或非法值会报错，不以虚拟 ACK 冒充真实断点安装。

### Server 与前端

| 文件 | 职责 |
|---|---|
| [src/linux_server_shim.c](src/linux_server_shim.c) | preload 入口、libc/raw ptrace 与 wait/exec 适配、shadow 视图、内核通信、来源状态、断点字节事务、协议恢复观察及退出清理 |
| [src/ida90_event_adapter.inc](src/ida90_event_adapter.inc) | 已支持 IDA server 版本的符号/签名校验、运行时事件与断点映射、F8 fallback、展示一致性 |
| [src/parent_resume_semantics.inc](src/parent_resume_semantics.inc) | 单步 intent、动作所属 TID、未呈现父停点的恢复门控 |
| [src/owner_wait_view.inc](src/owner_wait_view.inc) | 驱动 wait 帧查询、逻辑等待与真实 native stop 的区分 |
| [src/wait_entry_x86_64.S](src/wait_entry_x86_64.S) | 在 wait ABI 入口保存寄存器调用帧，避免将 shim prologue 当成程序停点 |
| [tools/ida_joint_client.py](tools/ida_joint_client.py) | 真实 F8 来源通知、wait 查询、父等待时 GUI/公开单步 API 保护 |
| [tools/ida_joint_plugin.py](tools/ida_joint_plugin.py) | IDA 用户插件 loader |
| [tools/start_joint_server.sh](tools/start_joint_server.sh) | 通用前台启动器：模块版本检查、preload、协议模式、stdin 和日志配置 |

### 构建与测试

| 文件/类别 | 职责 |
|---|---|
| [tools/build_kernel_module.sh](tools/build_kernel_module.sh) | 使用已准备且匹配运行内核的 Kbuild，拒绝 release 不一致 |
| [tools/export_kernel_headers.sh](tools/export_kernel_headers.sh) | 导出运行内核 kheaders，不覆盖已有目录 |
| [tools/build_kernel_overlay.sh](tools/build_kernel_overlay.sh) | 缺少完整匹配 Kbuild 时的显式 exported-header fallback；必须另验证可加载性 |
| `tests/policy_*_smoke.c` | 策略、mailbox、wait-TID 隔离、停止态寄存器/DR、权限和退出竞态 |
| `tests/shared_ring_reader_smoke.c` | 跨进程共享 ring 消费 |
| `tests/server_ptrace_harness.c` / `anti_debug_tracee.c` | 无 IDA 依赖的 shim 策略和 exec 环境清理检查 |
| `tests/parent_owned_call_tracee.c` | 返回型 call、两个程序协议 INT3、原生 syscall；父拒绝额外 debugger stop |
| `tests/parent_owned_exception_tracee.c` / `nested_mt_tracee.c` | 自建异常与多线程 fixture |
| [tests/run_kernel_smokes.sh](tests/run_kernel_smokes.sh) | 加载当前模块并运行内核 smoke，不通过 sleep 猜同步 |
| [tests/ida_joint_fixture.py](tests/ida_joint_fixture.py) | IDA call-over、callee 内 BP、syscall、同字软件断点、四槽 fallback |
| [tests/run_joint_fixture.py](tests/run_joint_fixture.py) | Windows/WSL 自动化 runner：动态路径、隔离数据库/结果、独立端口和 owned-process 清理 |

## 依赖

- x86-64 Linux；Windows + WSL2 Ubuntu 可作为运行环境。
- GCC、Make、glibc、pthread、binutils；测试中使用 Python 和 `nm`。
- 模块构建需要匹配运行内核的 headers、config、Kbuild 与符号版本，内核需
  支持模块、kprobe、ptrace/regset、perf 硬件断点。加载/内核测试需要 root。
- 用户自行提供合法安装的 IDA Pro 和同架构 `dbgsrv/linux_server`。
  runtime adapter 当前针对 **IDA Pro 9.0 / Linux server 9.0.30**，其他
  版本需重新适配签名和 ABI，不能默认兼容。
- 无头 IDA integration test 需要 Windows Python 可导入 `idapro`。
  GUI、idalib 和同一个数据库应避免并发使用造成许可证/数据库争用。
- 当前框架不要求 `/dev/kvm`。

## 构建

以下命令在 Linux/WSL Bash 中执行：

```bash
cd /path/to/ida-joint-debug
make -j4
make test
```

`make` 构建 `tools/libida_joint_shim.so`、内核 smoke 的用户态部分和自建
fixture，**不自动构建或加载驱动**。`make test` 不需要商业 IDA 和已加载
模块，只检查共享 ring 与测试策略下的 server shim。

优先用已配置/准备好的匹配内核：

```bash
make module KERNEL_BUILD=/path/to/matching/prepared/kernel
```

默认 `KERNEL_BUILD=/lib/modules/$(uname -r)/build`。release 一致不等于
config/结构布局/符号 CRC 全部匹配。`make module-check` 只编译，不证明
能安全加载。不要把其他内核的 `.ko` 强行装入当前内核。

### WSL exported-header fallback

只在缺少完整匹配 Kbuild、能够导出当前内核头文件时显式使用：

```bash
# root；若同名目录已有导出的 headers，直接复用或指定一个新目录。
bash tools/export_kernel_headers.sh

# IDA_JOINT_KBUILD_SOURCE 是本地源码路径，不需要放进本仓库。
IDA_JOINT_KBUILD_SOURCE=/path/to/local/kernel/source \
  bash tools/build_kernel_overlay.sh
```

该 fallback 使用运行内核的 generated headers/config 和本地 Kbuild 脚本，
生成新的临时 overlay，不删除已有内核树。它缺少完整匹配 Kbuild/符号 CRC，
可能输出 modpost/objtool 警告，并使用 `-fno-stack-protector` 避免混合脚本
的栈保护 ABI 差异。**它不是跨版本兼容保证**；必须重新加载并执行内核 smoke，
正式环境应优先准备完整匹配工具链。输出 overlay 路径与构建产物留在本地。

## 启动与 IDA 配置

### Linux / WSL server

停止旧调试会话后，在 Linux root 下运行：

```bash
bash tools/start_joint_server.sh \
  --server "/path/to/IDA/dbgsrv/linux_server" \
  --reload-module \
  --protocol-mode stop \
  --workdir "/path/to/targets"
```

启动器不绑定任何样本。目标由 IDA 的正常远程启动流程启动。模块被活跃会话
占用时重载会失败，不杀其他调试服务。server 在前台运行，可用 Ctrl+C 结束。

Windows PowerShell 使用同一入口，Linux 路径由实际安装位置决定：

```powershell
wsl.exe -d Ubuntu -u root -e bash /mnt/d/ida-joint-debug/tools/start_joint_server.sh --server "/mnt/c/Program Files/IDA Professional 9.0/dbgsrv/linux_server" --reload-module --protocol-mode stop --workdir /mnt/d/targets
```

### IDA 用户插件

将 `tools/ida_joint_plugin.py` 与 `tools/ida_joint_client.py` 放入 IDA
**用户插件目录**，重新打开 IDA；不复制到商业安装目录覆盖已有文件。

也可只部署 loader，并在启动 IDA 前设置 `IDA_JOINT_CLIENT_PATH` 为 checkout
内 `tools/ida_joint_client.py` 的完整路径。没有插件的精确动作来源时，
不能默认声称所有 F8/HW breakpoint 情况都拥有完整语义。

### Remote Linux debugger 设置

| 设置 | 说明 |
|---|---|
| Host / Port | server 地址 / 默认 `23960`，可用 `--port` 更改 |
| Application | 目标 ELF 的 Linux 绝对路径 |
| Directory | 目标工作目录，与 launcher 的 `--workdir` 对应 |
| Parameters | 目标参数 |
| Input file | IDA 本地打开的原 ELF，**不能留空**，须与远程目标字节一致 |

Input file 留空或 CRC 不一致可能触发原厂 copy-file 流程。不要用修改商业文件
或取消 CRC 检查解决路径错误。

### 联调操作语义

- 在 IDA Threads 视图切换父与 shadow 子 TID 检查状态。同会话不表示同地址空间。
- 父在逻辑 wait：查看/下断后切子继续调试，父 F7/F8 保持等待。
- 子程序协议唤醒父后，父真实断点正常命中，父可 F7/F8/F9，包括 ptrace call。
- 子协议 F7/F8：先让真实父处理，再观察其选定恢复点；IDA 的 BP/STEP 不递交
  给父当作程序协议。
- 非返回型 call 的 F8 可一直执行到原程序退出，不制造不存在的返回停点。

## 协议与输入配置

```bash
# 记录并放行程序协议，普通用户断点仍可停住。
bash tools/start_joint_server.sh --server /path/to/linux_server --protocol-mode log

# 暂停，同时记录程序 handler。
bash tools/start_joint_server.sh --server /path/to/linux_server \
  --protocol-mode stop --record-handlers --handler-log /tmp/joint-handlers.log

# 为目标提供 stdin；文件可以包含任意输入，不内置预期字符串。
bash tools/start_joint_server.sh --server /path/to/linux_server --input-file /path/to/input.txt
```

| 选项/变量 | 作用 |
|---|---|
| `--server` / `IDA_JOINT_SERVER` | 用户提供的 Linux debug server |
| `--port` / `IDA_JOINT_PORT` | 监听端口 |
| `--workdir` / `IDA_JOINT_WORKDIR` | server 工作目录，默认当前目录 |
| `--reload-module` | 重载本项目驱动，活跃引用时拒绝 |
| `--protocol-mode stop` / `log` | 程序协议暂停或放行 |
| `--record-handlers` | 详细 handler 记录 |
| `--handler-log` / `IDA_JOINT_HANDLER_LOG` | handler 追加日志，空则 server stderr |
| `--input-file` / `IDA_JOINT_INPUT_FILE` | stdin 文件，空则继承前台 stdin |
| `IDA_JOINT_SERVER_LOG` | server 输出文件，默认前台 stdout；指定文件会被打开截断 |
| `IDA_VTDBG_TRACE` / `IDA_VTDBG_TRACE_EVENTS` | 底层 ptrace/事件诊断，默认关闭 |

kernel ABI 的设备名 `/dev/vtdbg_policy`、`IDA_VTDBG_*` 低层配置及部分
协议标识保持稳定，用于已有 adapter/client 的通信兼容；它们不代表当前
框架具有 VT 虚拟化拦截。项目/源码/产物的正式名称为 IDA Joint Debug。

共享页只承载事件，策略与寄存器写入通过授权 ioctl。handler 记录区分程序
stop、恢复位置和 debugger 操作；未知信号不能直接当反调试吞掉。

## 测试方法

### 内核 smoke

无活跃调试会话时，以 Linux root 执行：

```bash
make kernel-smokes
bash tests/run_kernel_smokes.sh
```

覆盖共享页、逻辑 wait 帧、mailbox PENDING/INFLIGHT 退出取消、停止态
GPR/FP/REGSET/内存、原生 DR 槽/DR6/DR7、非法配置与权限拒绝、恢复边界、
寄存器访问/更新与 SIGKILL 退出竞态。该入口会重载本项目模块，模块在使用时
拒绝；不是生产环境在线监控命令。

### IDA integration fixture

Windows PowerShell：

```powershell
python tests/run_joint_fixture.py --server "/mnt/c/Program Files/IDA Professional 9.0/dbgsrv/linux_server" --name fixture_001
```

runner 从本机路径动态得到 WSL 路径，为源码生成的 fixture 准备隔离数据库，
通过同一个 server 依次检查 call-over、raw syscall、同字软件断点与四槽 fallback。
可用 `--mode over|syscall|multi_sw|slot4` 选择单项，用 `--distro`、
`--port`、`--timeout` 调整环境。结果仅生成在本地 `artifacts/`，不提交。

失败预算不是协议等待时间。server readiness 以监听事件为条件，ptrace/owner
状态由真实停点与内核 sequence 决定；runner 只清理自己启动的进程和自己
观察到的目标，发现已有监听服务时拒绝覆盖。

## 支持范围与限制

- 当前为 x86-64 Linux 和特定 IDA server 版本的适配，不承诺未知 ABI/架构兼容。
- 提供 owner-TID、多线程 fixture 与生命周期逻辑，但未穷举任意多线程 tracer
  的全部动作组合。raw waitid、未知信号协议和自修改代码需要独立适配/测试。
- 停止态 DR 支持已有原生 perf 槽更新；没有分配的槽不会被假装安装成功。
- 兼容策略只作用于注册目标及受支持的 syscall/procfs 路径，不全局隐藏宿主。
- 不保证任意 timing、CPUID、seccomp、外部监控或未知反调试检测兼容。
- 目前没有独立 IDA 用户入口用于 `PTRACE_SYSEMU`、
  `PTRACE_SYSEMU_SINGLESTEP` 或 `PTRACE_SINGLEBLOCK`。
- 模块可能影响 Linux/WSL 稳定性；构建成功不等于内核 ABI 匹配，勿强制加载。
- 内核/IDA/工具链或目标变更时应重新测试，不从一个 fixture 推导全称保证。

## 未来可能扩展

- **VT/KVM 后端**：在隔离 guest 内观察 VM-exit、guest 寄存器和内存。
- **EPT/NPT 与 guest hook**：在虚拟机范围内探索执行/访问观察与断点机制。
- **多目标与更完整线程调度**：加强多个 owner-TID、多层父子以及跨线程动作。
- **更丰富事件 API**：显式暴露程序异常→owner 处理→child 恢复的状态链。
- **更多前端版本/架构**：将 runtime adapter 与 x86-64 相关代码做可替换后端。

上述是可选研究方向，尚非当前交付能力；任何扩展应保持真实控制流、会话隔离
和权限约束，不以假事件或全局宿主修改代替调试语义。

## 仓库与授权

仓库只收录框架源码、构建/启动工具和源码生成的测试。不收录编译二进制、
内核树、日志、转储、IDA 数据库、第三方样本、商业软件或本机工作记录。
忽略不等于删除本地文件；新 checkout 应自行准备依赖并重新构建。

`.gitattributes` 对 C/汇编、Python、shell 和 Makefile 固定 LF，
避免 Windows checkout 导致 WSL shell CRLF 问题。

当前未为整个仓库指定统一 LICENSE。驱动的 `MODULE_LICENSE("GPL")`
是内核模块元数据，不自动代表所有用户态文件的许可证；使用/分发前请确认
相关授权。IDA 与其 server 由用户合法安装，本项目只提供适配代码。
