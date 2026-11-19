# RSM 内核观测原型：从一次 bind 到用户态计数

在双 vCPU 的 x86-64 QEMU 中启动 Asterinas，运行一个端口冲突实验，用户态读到了下面这行结果。

```text
bind-outcomes: TCP ok=2 failed=1, UDP ok=2 failed=3
```

产生这四个数只用了一个 Rust 插件。
它挂在 TCP 和 UDP 各自的 `bind` 实现上，在函数返回时更新计数。
插件可以在内核运行期间更换，另一个用户态程序可以在解除挂载后读取结果。
这条路径串起了本阶段的四项工作。

| Asterinas 提交 | 增加的能力 | 在实验中如何看到 |
| --- | --- | --- |
| `42561c774` | 在编译期选定的内核函数上生成入口和正常返回观测点 | 测试内核在六个子系统中列出了 4,133 个函数描述符。每个描述符有入口和返回两个阶段。 |
| `71fdc709a` | 加载 Rssembly v2 机器码产物，支持代码引用只读数据 | 字符串回归插件在 `sys_read` 的入口和错误返回各输出一条不同的消息。v1 回归也通过。 |
| `d2616548c` | 为每次加载的插件实例提供命名数组，为单次回调提供 Rust 分配空间 | 计数跨调用保留。另一个测试故意申请超额空间，一次回调中止，随后的回调仍能成功分配。 |
| `82c9c1c1b` | 增加四个观测插件和用户态工具 `rsm-observe` | 测试程序发起真实的文件、网络、虚拟内存和线程同步操作，读出插件的统计值。 |

以下代码和数字对应最后一行的 Asterinas 版本，配套 Rssembly 版本为 `25dbf9e3`。

## 为什么选两个 bind 返回点

冲突发生在什么地方，决定了应该在哪里计数。
`sys_bind` 先读取用户态地址、查找文件描述符、取得 socket，再调用 `socket.bind(socket_addr)?`。
这个调用根据 socket 类型进入 `StreamSocket::bind` 或 `DatagramSocket::bind`。
我们想知道“到了 TCP 或 UDP 的绑定请求各有多少成功、多少失败”，因此选择这两个实现的返回点。
`bind(-1, ...)` 在查描述符时就以 `EBADF` 返回，两个计数器都不会看到它。
[系统调用分派][sys-bind] · [TCP 实现][tcp] · [UDP 实现][udp]

测试程序先让一个 socket 绑定到回环地址上的空闲端口，再让第二个 socket 请求同一端口。
TCP 故意冲突一次，UDP 故意冲突三次，测试程序逐次检查 `EADDRINUSE`。
最后，第二个 socket 改为申请空闲端口，两种协议都成功。
因此两列成功数都是 2，失败数分别是 1 和 3。
这个方法的返回值载荷只给出成功或失败这一位。具体错误码由发起系统调用的测试程序核对。
[负载与断言][bind-test]

## 从源码到回调

**编译内核时确定能挂在哪里。**
启用 `rsm-hooks` 后，`kernel/core/build.rs` 按 `rsm-hooks.toml` 选取源文件，
在 Cargo 的 `OUT_DIR/rsm-hook-src` 中生成副本，再编译副本。
以 UDP 为例，原函数体先执行 `socket_addr.try_into()?`，再调用内部绑定方法。
下面用短变量名展示插桩后的结构，闭包里面保留了原函数体的操作。
实际生成器还会生成描述符并转发带类型的参数。
[构建入口][build] · [生成模板][transform]

```rust,ignore
// DatagramSocket::bind 的函数体（生成代码示意）
let call = hook.enter([0; 4]);
let result = (move |socket_addr: SocketAddr| -> Result<()> {
    let endpoint = socket_addr.try_into()?;
    let can_reuse = self.options.read().socket.reuse_addr();
    self.inner.write().bind(&endpoint, &self.pollee, BindOptions { can_reuse })
})(socket_addr);
call.finish([u64::from(result.is_err()), 0, 0, 0]);
result
```

生成器只把支持的标量写进事件，`SocketAddr` 和 `self` 都被省略，所以这里的入口四个字段都是零。
闭包让 `?` 和提前的 `return` 先产生 `result`，随后统一经过 `finish`。
因此 `Err` 也是一次正常返回。panic、终止或永不返回的调用没有正常返回事件。
构建后可从 `/proc/rsm/hooks` 查到本次内核中的函数名、ID 和各阶段字段。
未挂载时，已编入的 `enter` 仍会读取启用标志，随后直接返回。
[字段生成][fields] · [运行时入口][dispatch]

**插件单独编译，运行时按目录 ID 挂载。**
`build-observer.py` 用 `cargo-rsmc` 把插件源码编译为 `.rsm`。
`rsm-emit --host` 验证模块并生成带宿主辅助函数重定位的 x86-64 v2 产物 `.rsm.bin`。
本例的产物为 780 字节。
加载时，`RsmProgram::load` 找到导出的 `main`，检查栈用量上界，写入映像并应用重定位，
把宿主调用连接到内核的分派入口。
OSTD 随后将代码页设为可读、可执行，只读数据页设为只读、不可执行。
管理员通过 `SYS_RSM` 挂载同一实例两次，分别选择 TCP 和 UDP 的 ID 以及返回阶段。
改变挂载关系只更新描述符中的状态，原函数的指令保持固定。
[插件构建][compiler] · [内核加载][loader] · [页权限转换][pages]

**一次 UDP 冲突怎样变成一个数。**
回调 ABI 有七个标量槽，依次放入 `hook_id`、`phase`、`invocation_id` 和四个载荷字段。
一次失败的 UDP 返回可写成 `[UDP_HOOK_ID, 1, 本次调用ID, 1, 0, 0, 0]`。
第一个 `1` 表示返回阶段，第二个 `1` 是 `result.is_err()`。
下面是插件的计数代码。[完整插件][observer]

```rust,ignore
if phase == 1 && is_error <= 1 {
    let counts = rsm_map_get_or_create(hook, 2);
    if counts != 0 {
        rsm_map_fetch_add(counts, is_error, 1);
    }
}
```

`hook` 是数组的名字，`counts` 是内核返回给插件的不透明句柄。
同一个实例挂在两处，按两个不同的 hook ID 建立两组数组。
每组的下标 0 表示成功，1 表示失败。上面的 UDP 事件只给 UDP 数组的第 1 项加一。
这两个辅助函数在约定的宿主表中占第 4 和第 7 号槽。
`ProgramState` 在实例自己的锁内完成查找和加法，两个 CPU 同时计数也能保留每次增量。
[辅助函数分派][helpers] · [数组与并发更新][state]

## 数据归谁，用户态怎样读取

| 数据 | 由谁持有 | 何时失效 |
| --- | --- | --- |
| `invocation_id` 与返回挂载版本 | 函数入口保存本次调用的 ID 和当时的返回挂载版本，以便在函数结束时核对。 | 返回前若已解除并重新挂载，旧调用不会转投新插件。 |
| 命名数组 | 一次加载的插件实例。它的所有挂载点共享该实例的数组。 | 插件可调用 `rsm_map_free` 提前删除数组。剩下的数组随实例的最后一个引用一起释放。单独解除挂载保留数据。 |
| `std::alloc` 得到的缓冲区 | 当前回调从本实例的专用空间取得。编译器把受支持的常量 `Layout` 分配和释放转成宿主调用。 | 插件可显式释放。回调返回或中止时回收剩余空间。需跨回调保存的内容可以整体复制到等长的命名数组。 |

加载需要宿主辅助函数的 v2 产物时，内核预留数组和临时分配池的容量。
这样的实例最多有 16 个命名数组，每个数组容纳 1～64 个 `u64`。
临时分配池有 8 个 512 字节区域，需要分配的回调独占其中一个。
宿主表的 9、10 号槽对应分配和释放，保存和恢复整块缓冲区分别走 13、14 号槽。
`heap-snapshot` 在一次回调中申请 8 字节，恢复上次保存的内容，更新读请求大小，再保存并释放。
连续九次调用后，用户态读到了测试预期的 `0x020d0a09ff0b1311`。
复制时，内核检查缓冲区所属的回调和大小，整块数据一起更新。
两个回调并发执行“恢复、修改、保存”时，后一次保存可能覆盖前一次修改，因此这个滑动窗口示例使用串行负载。
当前验证过的 Rust 用法是直接调用 `std::alloc::{alloc, dealloc}` 并通过辅助函数访问字节。通用 `Box` 和 `Vec` 仍待支持。
[分配池][heap] · [滑动窗口插件][snapshot] · [用户态断言][snapshot-test]

用户态通过系统调用 500 管理插件。命令 4/5 挂载和解除某个函数阶段，6 读取回调统计，
7（`ReadStateWord`）按 `{key, index, value}` 从当前加载实例复制一个词，8 卸载空闲实例。
命令 7 需要 `CAP_SYS_MODULE`，用户态对命名数组只有逐词读取接口。
没有打开 map FD 或向 map 写入的接口。加载下一个实例之后，命令 7 的读取目标也随之改变。
另一个线程已经取得的回调引用可以在解除挂载后继续执行，所以逐词读取多个计数时需考虑并发。
[控制接口][sys-rsm]

`rsm-observe` 先从目录里解析函数名，加载并挂载插件，然后运行指定命令。
命令结束后解除挂载、读出各个词、卸载实例，并保留命令的退出状态。
下面是回归测试中**只挂 UDP** 的一次调用，按测试镜像中的路径写成 shell 命令。
`@` 让工具把后面的完整函数名解析为数组 key。
[用户态工具][cli] · [端到端断言][cli-test]

```sh
cd /test/rsm
udp='aster_core::net::socket::ip::datagram::<DatagramSocket as Socket>::bind'
./rsm-observe bind-outcomes.rsm.bin --attach return "$udp" \
    --read "@$udp" 2 --read 0 1 -- ./plugin_memory_test bind-workload
```

```text
bind workload complete
map @aster_core::net::socket::ip::datagram::<DatagramSocket as Socket>::bind: 2 3
map 0: no samples
```

这里的 key 0 从未被插件创建。负载特意以 23 退出，测试也检查工具返回 23。
实际使用时需要独占全局的已加载程序槽。挂载期间，系统中其他任务经过同一函数也会被统计。

## 另外三个示例各验证了什么

| 观测问题 | 实现 | 双 vCPU QEMU 中的结果 |
| --- | --- | --- |
| 哪种文件打开请求容易失败？ | `open-intent` 把 `sys_openat` 的入口标志与返回结果按调用 ID 配对。用 64 个槽保存入口类别，无法配对的返回单独计数。 | 成功/失败分别为读 `2/1`、写 `1/2`、请求创建 `1/1`、其他 `1/0`。测试特意只挂返回一次，得到 1 个未配对样本。[源码][open] |
| 同一批内存第二次写入还会缺页吗？ | `page-faults` 在进程地址空间缺页处理函数的返回点统计已处理和被拒绝的次数，测试程序两次遍历同一匿名映射。 | 首次写 32 页，观察到 32 次已处理缺页。重复写入为 0 次，被拒绝为 0 次。[源码][faults] |
| futex 等待多久才被唤醒？ | `futex-wait` 按调用 ID 匹配普通 `FUTEX_WAIT` 的进入与返回，将成功调用的耗时分桶，失败和未配对的成功分别计数。 | 一次真实等待被另一线程唤醒，一次值不匹配立即返回 `EAGAIN`，未配对成功数为 0。时间包括等待及重新调度。[源码][futex] |

## 如何重放，以及如何解释结果

在 Linux 构建环境准备好上述版本的两个源码树。
从 Asterinas 根目录执行以下命令，`RSM_SRC` 指向 Rssembly 检出目录。
脚本将四个新编译的产物放入最小 initramfs，启动双 vCPU 的 Asterinas 并自动执行负载。
[工具链准备][setup] · [QEMU 测试入口][runner]

```sh
RSM_SRC=/path/to/rssembly
for name in open-intent bind-outcomes page-faults futex-wait; do
    python3 tools/rsm-instrument/build-observer.py "$RSM_SRC" \
        "target/rsm-showcases/$name.rsm.bin" \
        --source "tools/rsm-instrument/observers/$name.rs" || exit 1
done
python3 tools/rsm-instrument/run-kernel-tests.py --smp 2 --profile release-lto \
    --showcase-observers target/rsm-showcases
```

在本阶段的 `dev` 和 `release-lto` 构建中，四组断言均通过。
重放后可在 `target/rsm-function-hooks/release-lto-smp2/serial.log` 搜索 `RSM_SHOWCASES_QEMU_PASS`。
分配器回归在两组各 16 次成功分配之间请求了 513 字节。
这次请求超过单个区域的 512 字节上限，钩子的 `traps` 计数恰好加 1，后 16 次回调均成功读写。
这些 QEMU 记录支持功能和生命周期结论。比较挂载开销还需要在同等条件下测量关闭插桩、已插桩但未挂载、已挂载三种配置。

每个函数阶段同一时刻只能挂一个观察者。
回调实际执行期间会关闭本地中断并禁用抢占。这些保护只覆盖回调，不跨越原函数体。
原子或中断上下文、获取挂载快照时发生竞争、栈空间不足，都可能造成跳过。
解读业务计数时，应同时看命令 6 提供的 `invocations`、`skipped` 和 `traps`。
当前加载器要求调用者具有 `CAP_SYS_MODULE`，并信任外部编译器。
编译器先在内核外验证 Rssembly 中间表示，再生成原生代码。
内核检查映像结构和重定位，加载时尚无签名认证和机器码验证。
[回调执行条件][dispatch] · [加载前提][sys-rsm] · [完整接口说明](rsm-function-hooks.md)

[sys-bind]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/kernel/core/src/syscall/bind.rs#L10-L26
[tcp]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/kernel/core/src/net/socket/ip/stream/mod.rs#L475-L486
[udp]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/kernel/core/src/net/socket/ip/datagram/mod.rs#L147-L155
[bind-test]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/test/initramfs/src/regression/rsm/showcase_bind_outcomes.h#L9-L56
[build]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/kernel/core/build.rs#L11-L49
[transform]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/tools/rsm-instrument/src/transform.rs#L240-L273
[fields]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/tools/rsm-instrument/src/transform.rs#L423-L465
[dispatch]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/kernel/libs/aster-rsm/src/hooks.rs#L372-L475
[compiler]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/tools/rsm-instrument/build-observer.py#L62-L81
[loader]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/kernel/libs/aster-rsm/src/program.rs#L45-L86
[pages]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/ostd/src/mm/native_program.rs#L111-L124
[observer]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/tools/rsm-instrument/observers/bind-outcomes.rs#L5-L17
[helpers]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/ostd/src/mm/callback/rsm.rs#L290-L312
[state]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/kernel/libs/aster-rsm/src/state.rs#L56-L131
[heap]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/ostd/src/mm/native_heap.rs
[snapshot]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/tools/rsm-instrument/observers/heap-snapshot.rs
[snapshot-test]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/test/initramfs/src/regression/rsm/plugin_memory_test.c#L197-L210
[sys-rsm]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/kernel/core/src/syscall/rsm.rs
[cli]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/tools/rsm-instrument/rsm-observe.c#L240-L286
[cli-test]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/test/initramfs/src/regression/rsm/plugin_memory_test.c#L255-L309
[open]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/tools/rsm-instrument/observers/open-intent.rs
[faults]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/tools/rsm-instrument/observers/page-faults.rs
[futex]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/tools/rsm-instrument/observers/futex-wait.rs
[setup]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/tools/rsm-instrument/README.md
[runner]: https://github.com/jellllly420/asterinas/blob/82c9c1c1b9fb27ff1a7eda22e669b363fd2d2fe1/tools/rsm-instrument/run-kernel-tests.py
