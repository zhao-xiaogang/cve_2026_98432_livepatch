# CVE-2026-98432 Livepatch Reference

中文 | [English](#english)

> **重要提示：本仓库是 Ubuntu 22 `5.15.0-71-generic` 的参考实现，不是通用热补丁。不要直接在其他内核版本、发行版或架构上编译、加载。**
>
> **Warning: This repository is a reference implementation for Ubuntu 22 `5.15.0-71-generic`. It is not a generic livepatch. Do not build or load it unchanged on any other kernel, distribution, or architecture.**

## 项目说明

CVE-2026-98432 是 Linux IPv4 TCP 连接处理中的释放后使用（UAF）漏洞。上游修复将 `inet_sock_destruct()` 和 `tcp_v4_reqsk_destructor()` 中 IPv4 选项的立即释放改为经过 RCU 宽限期的延迟释放。

本项目使用 Linux livepatch 替换上述两个函数，演示如何在不立即重启的情况下应用该修复思路。模块名为 `fix_cve_2026_98432`。

- 上游修复：[e3f33b0a1d89d738e2b913dab519226eaf76e15b](https://github.com/torvalds/linux/commit/e3f33b0a1d89d738e2b913dab519226eaf76e15b)
- 参考源码：[Ubuntu 5.15.0-71.78](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy/tree/?h=Ubuntu-5.15.0-71.78)

热补丁只是临时风险控制手段。仍应尽快安装发行版提供的正式修复内核，并安排重启。

## 1. 漏洞严重，但实际稳定利用并不容易

该漏洞可能造成内核崩溃、内存损坏，公开研究还展示了远程代码执行的可能性。但**严重的影响不等于容易被稳定利用**：

- 攻击流量需要涉及 IPv4 选项，并进入存在问题的 TCP 处理路径。
- 漏洞依赖并发竞争，攻击者需要在很窄的生命周期窗口内让相关操作同时发生。
- 稳定的远程代码执行还依赖内核版本、配置、内存布局、调度和利用链质量，不是发送一个报文就必然成功。
- MPTCP 是公开利用研究中的重要入口，但不是漏洞存在的必要条件，普通 IPv4 TCP 也可能受影响。

因此，不应因为“难以利用”而忽略修复，也不应仅凭没有观察到攻击就认为系统安全。

## 2. 使用本补丁思路的前提

### 2.1 必须确定运行内核对应的准确源码

不能只根据 `5.15`、`4.19` 等上游版本号适配。发行版可能回移植大量修改，相同 `uname -r` 的不同构建也可能存在差异。

```bash
uname -r
readlink -f /lib/modules/$(uname -r)/build
```

Ubuntu 可进一步查询源码包版本：

```bash
dpkg-query -W -f='${Version}\n' linux-image-$(uname -r)
```

然后获取该版本的发行版源码包或对应 Git 标签。例如，本参考实现对应 `5.15.0-71.78`，而不是任意一个上游 5.15 源码树。

编译头文件必须与运行内核匹配。`/lib/modules/$(uname -r)/build` 存在只说明具备构建条件，不能证明补丁代码已经适配。

### 2.2 检查内核配置和 livepatch 支持

至少需要确认内核启用了 livepatch、模块、ftrace 和符号解析支持。常见检查项包括：

- `CONFIG_LIVEPATCH=y`
- `CONFIG_MODULES=y`
- `CONFIG_FTRACE=y`
- `CONFIG_FUNCTION_TRACER=y`
- `CONFIG_DYNAMIC_FTRACE=y`
- `CONFIG_KALLSYMS=y`
- `CONFIG_KALLSYMS_ALL=y`
- `CONFIG_DYNAMIC_FTRACE_WITH_REGS=y`，视架构和内核版本而定
- `CONFIG_MODULE_UNLOAD=y`，仅在需要卸载模块时适用

Ubuntu 可执行：

```bash
grep -E 'CONFIG_(LIVEPATCH|MODULES|MODULE_UNLOAD|FTRACE|FUNCTION_TRACER|DYNAMIC_FTRACE|DYNAMIC_FTRACE_WITH_REGS|KALLSYMS|KALLSYMS_ALL)=' /boot/config-$(uname -r)
```

具体依赖会随架构和版本变化，应以目标内核的 Kconfig、头文件和构建结果为准。还要确认模块签名、Secure Boot/lockdown 和符号版本策略是否允许加载。

### 2.3 检查目标函数及调用路径

确认 `inet_sock_destruct()` 和 `tcp_v4_reqsk_destructor()` 在目标源码中存在，并检查：

- 完整函数体和函数原型；
- 目标函数是否被内联，是否存在未覆盖的调用路径；
- `struct sock`、`struct inet_sock`、`struct request_sock` 等字段及语义；
- 目标内核的 livepatch API；
- 目标内核的 RCU 和 `kfree_rcu` 语义。

livepatch 替换的是函数，不会自动修正被内联到其他函数中的代码副本。

## 3. 如何为目标内核制作补丁

1. 从目标内核的准确源码中取出两个原始析构函数。
2. 保留原函数的全部清理、状态检查、引用释放和内存记账逻辑。
3. 只将 `inet_opt` 和 `ireq_opt` 的立即释放改为符合目标内核语义的 RCU 延迟释放。
4. 根据目标内核调整 livepatch 注册、启用和退出流程。
5. 编译后检查 `vermagic`、目标内核元数据、未解析符号和实际加载状态。
6. 在隔离环境中验证正常 TCP、携带 IPv4 选项的 TCP、启停切换和最终内存回收。

**不要直接复制本仓库的 5.15 函数体到其他版本。**例如，本参考实现的 `inet_sock_destruct()` 包含 `sk_rx_skb_cache` 清理，这是从参考目标源码保留的逻辑，其他内核可能不同。

### 3.1 老内核的 `kfree_rcu` 可能需要判空

不同内核版本的 `kfree_rcu` 实现不同，不能假设所有版本都接受 `NULL`。

本参考目标 Ubuntu 22 5.15 的宏内部会判空，因此可以写：

```c
kfree_rcu(opt, rcu);
```

一些老版本会直接根据 `ptr` 和其 `rcu_head` 成员计算回调地址，传入 `NULL` 并不安全。此时必须保留显式判断：

```c
opt = rcu_dereference_protected(inet->inet_opt, 1);
if (opt)
	kfree_rcu(opt, rcu);
```

`tcp_v4_reqsk_destructor()` 中的 `ireq_opt` 也要按同样原则检查。判断依据必须是**目标内核的实际宏实现**，而不是仅凭版本号猜测。

### 3.2 livepatch API 也有版本差异

本参考目标 5.15 使用 `klp_enable_patch()`，由它完成注册、启用和失败清理，没有旧式公开注册/注销流程。

一些老版本则需要在启用前显式调用 `klp_register_patch()`，并在错误路径或退出时调用 `klp_unregister_patch()`。必须根据目标内核的 `include/linux/livepatch.h` 和 `kernel/livepatch/core.c` 调整，不能混用两套流程。

## 4. 构建、验证与卸载

以下命令只适用于已经完成源码核对和适配的环境：

```bash
make
modinfo ./fix_cve_2026_98432.ko
```

加载后不能只看 `insmod` 或 `modprobe` 的返回值，还要检查：

```bash
cat /sys/kernel/livepatch/fix_cve_2026_98432/enabled
lsmod | grep fix_cve_2026_98432
dmesg
```

应确认补丁已启用、切换已完成且没有符号或框架错误。随后进行正常通信、IPv4 选项、并发和长时间运行测试。编译成功和加载成功都不等于漏洞已正确修复。

卸载前先停用补丁，并等待 livepatch 完成切换、异步清理和模块引用释放：

```bash
sudo make uninstall
```

本仓库 Makefile 会等待模块引用归零。若超时仍显示模块被占用，不要强制卸载，应检查切换状态和内核日志。某些老内核即使停用补丁也会继续持有模块引用，只能保留模块或安排重启。

停用或卸载会移除热补丁保护。重启后还要检查模块是否按预期重新加载；升级内核后必须重新适配，不能复用旧产物。

## 5. 借助 AI 适配时的边界

可以参考本仓库，并借助 AI 比较目标源码、整理 API 差异、生成适配初稿和检查清单。但 AI 输出不能替代以下工作：

- 获取并阅读准确的发行版源码；
- 人工核对两个完整函数体及其并发语义；
- 在目标环境编译并检查符号和模块元数据；
- 在隔离环境中完成加载、通信、RCU 回收和启停测试。

**请将本仓库作为适配参考，而不是可直接部署的通用修复。**

---

## English

### Overview

CVE-2026-98432 is a use-after-free in Linux IPv4 TCP connection handling. The upstream fix changes immediate frees of IPv4 options in `inet_sock_destruct()` and `tcp_v4_reqsk_destructor()` to deferred frees after an RCU grace period.

This repository demonstrates that approach with Linux livepatch. The module name is `fix_cve_2026_98432`.

A livepatch is only a temporary risk-control measure. Install the vendor's fixed kernel and plan a reboot as soon as practical.

### 1. Severe impact, but reliable exploitation is non-trivial

The vulnerability may cause kernel crashes or memory corruption, and public research has demonstrated remote code execution. However, severe impact does not mean reliable exploitation is easy:

- The traffic must involve IPv4 options and reach an affected TCP path.
- Triggering the flaw depends on winning a narrow concurrency and object-lifetime race.
- Reliable remote code execution additionally depends on the kernel build, configuration, memory layout, scheduling, and the quality of the exploit chain.
- MPTCP was important to the public exploit research, but it is not required for the underlying vulnerability.

Do not use exploitation difficulty or a lack of observed attacks as a reason to remain unpatched.

### 2. Prerequisites

#### Identify the exact source for the running kernel

Do not adapt from an upstream version number alone. Distribution kernels contain backports, and different builds with the same release string may still differ.

```bash
uname -r
readlink -f /lib/modules/$(uname -r)/build
```

On Ubuntu, query the source package version with:

```bash
dpkg-query -W -f='${Version}\n' linux-image-$(uname -r)
```

Obtain that exact vendor source package or Git tag. This reference targets Ubuntu source package `5.15.0-71.78`, not an arbitrary upstream 5.15 tree. Matching build headers are necessary, but they do not prove that the replacement functions are compatible.

#### Check kernel configuration and livepatch support

Check livepatch, module, ftrace, and symbol-resolution support. Common options include:

- `CONFIG_LIVEPATCH=y`
- `CONFIG_MODULES=y`
- `CONFIG_FTRACE=y`
- `CONFIG_FUNCTION_TRACER=y`
- `CONFIG_DYNAMIC_FTRACE=y`
- `CONFIG_KALLSYMS=y`
- `CONFIG_KALLSYMS_ALL=y`
- `CONFIG_DYNAMIC_FTRACE_WITH_REGS=y`, depending on architecture and kernel version
- `CONFIG_MODULE_UNLOAD=y` if module unloading is required

On Ubuntu:

```bash
grep -E 'CONFIG_(LIVEPATCH|MODULES|MODULE_UNLOAD|FTRACE|FUNCTION_TRACER|DYNAMIC_FTRACE|DYNAMIC_FTRACE_WITH_REGS|KALLSYMS|KALLSYMS_ALL)=' /boot/config-$(uname -r)
```

Dependencies vary by version and architecture. Check the target Kconfig and headers, as well as module signing, Secure Boot/lockdown, and symbol-version policies.

#### Review the target functions and call paths

Review the complete bodies and prototypes of `inet_sock_destruct()` and `tcp_v4_reqsk_destructor()`. Check structure fields, cleanup semantics, inlining, livepatch APIs, and RCU behavior. Livepatch does not automatically fix inlined copies of a function.

### 3. Adapting the patch

1. Start with both original destructors from the exact target source.
2. Preserve all cleanup, state checks, reference releases, and memory accounting.
3. Change only the `inet_opt` and `ireq_opt` frees to target-appropriate RCU-delayed reclamation.
4. Adapt livepatch initialization, failure handling, and exit logic to the target API.
5. Inspect `vermagic`, metadata, unresolved symbols, and load-time errors.
6. Test ordinary TCP, TCP with IPv4 options, transitions, concurrency, and eventual reclamation in an isolated environment.

Do not copy the 5.15 function bodies unchanged into another kernel. For example, this reference retains `sk_rx_skb_cache` cleanup because that is present in its target source.

#### `kfree_rcu(NULL)` is not portable across old kernels

The Ubuntu 22 5.15 reference target checks for `NULL` inside the macro, so this is valid:

```c
kfree_rcu(opt, rcu);
```

Some older implementations derive the callback address directly from `ptr` and its `rcu_head` member and require an explicit check:

```c
opt = rcu_dereference_protected(inet->inet_opt, 1);
if (opt)
	kfree_rcu(opt, rcu);
```

Apply the same review to `ireq_opt`. Base this decision on the target's actual macro implementation, not on a version-number assumption.

#### Livepatch APIs differ

On the 5.15 reference target, `klp_enable_patch()` performs registration, enablement, and failure cleanup. Some older kernels require explicit `klp_register_patch()` and `klp_unregister_patch()` calls. Follow the target's `include/linux/livepatch.h` and `kernel/livepatch/core.c`; do not mix the two lifecycles.

### 4. Build, validation, and removal

Build and inspect only after completing the target-specific review:

```bash
make
modinfo ./fix_cve_2026_98432.ko
```

After loading, verify more than the command's return value:

```bash
cat /sys/kernel/livepatch/fix_cve_2026_98432/enabled
lsmod | grep fix_cve_2026_98432
dmesg
```

Confirm enablement and transition completion, then test communication and reclamation behavior. A successful build or module load does not by itself prove that the vulnerability is fixed.

To disable and remove the module:

```bash
sudo make uninstall
```

The Makefile waits for livepatch to release its module reference. If the module remains in use, do not force removal; inspect the transition state and kernel log. Some older kernels pin a livepatch module even after it is disabled.

Disabling or removing the module removes its protection. Recheck protection after reboot and re-adapt the patch after every kernel upgrade.

### 5. Using AI for adaptation

AI can help compare source versions, identify API differences, draft an adaptation, and produce review checklists. It cannot replace exact vendor sources, human review of both complete destructors, target builds, symbol inspection, or isolated runtime and RCU-reclamation tests.

**Treat this repository as adaptation reference code, not as a generic drop-in fix.**
