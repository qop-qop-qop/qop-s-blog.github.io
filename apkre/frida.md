frida的基操

```
frida -U -f 进程名 -l hook.js #以Spawn模式连接
frida -U  进程名 -l hook.js #以attach模式连接
```

firda 默认窗口为27042

```
$su
#cd data/local/tmp/
cd data/local/tmp/# ./fs1280 -l 0.0.0.0:6666
```

基础框架

```javascript
//定义一个名为hookTest1的函数
function hookTest1(){
	//获取一个名为”类名”的Java类,并将其实例赋值给JavaScript变量utils
	var utils = Java.use("com.zj.wuaipojie.Demo");
	//修改“类名“的"method"方法的实现。这个新的实现会接收两个参数(a和b)
	utils.a.implementation = function(a,b){
	//将参数a和b的值改为123和456。
	a = 123;
	b=456;
	//调用修改过的"method"方法,并将返回值存储在`retval`变量中
	var retval = this.method(a,b);
	//在控制台上打印参数a,b的值以及"method"方法的返回值
     console.log(a,b,retval)
	//返回"method"方法的返回值
	return retval;

//main函数触发hook函数
function main(){
    Java.perform(function(){
       hooktest1(); 
    });
}
```

frida可以直接进行传入js脚本对.so的库进行hook。类似于

```
function waitLib(cb) {
    var m = Process.findModuleByName("libil2cpp.so");
    if (m) cb(m.base);
    else setTimeout(function () { waitLib(cb); }, 500);
}

waitLib(function (base) {
    Interceptor.attach(base.add(0xC02734), {          // CurrencyAccount.Credit
        onEnter: function (args) {
            this.acc = args[0];
            args[1] = ptr(200000);                     // amount 改写
        },
        onLeave: function () {
            console.log("余额 -> " + this.acc.add(0x18).readS32());
        }
    });
});
```

```
function waitLib(cb) {
    var m = Process.findModuleByName("libil2cpp.so");
    if (m) cb(m.base);
    else setTimeout(function () { waitLib(cb); }, 500);
}
```

这个js函数等待着库被加载，也就是libil2cpp.so，每500毫秒轮询一次

然后如果找到了进入

```
 if (m) cb(m.base);
```

而cb代表的函数就是

```
function (base) {
    Interceptor.attach(base.add(0xC02734), {          // CurrencyAccount.Credit
        onEnter: function (args) {
            this.acc = args[0];
            args[1] = ptr(200000);                     // amount 改写
        },
        onLeave: function () {
            console.log("余额 -> " + this.acc.add(0x18).readS32());
        }
    });
```

这个匿名函数。

在这个匿名函数执行了方法

```
CurrencyAccount.Credit
        onEnter: function (args) {
            this.acc = args[0];
            args[1] = ptr(200000);                     // amount 改写
        },
        onLeave: function () {
            console.log("余额 -> " + this.acc.add(0x18).readS32());
        }
```

```
游戏调 Credit(acc, 100)
   ↓
① onEnter 执行          ← 函数体还没跑: 改 x1 = 200000
   ↓
② Credit 函数体执行      ← acc->balance += 200000
   ↓
③ onLeave 执行          ← 函数体已跑完: 读余额, 或改返回值
   ↓
④ 控制权交还游戏
```

这个属于最简单的hook执行。

然后是frida的侦察功能

```
import json

# 更改点: 侦察关键词
KEYS = ["Currency", "Account"]
# 更改点: 上限保护, 别超过500
LIMIT = 300

d = json.load(open(r"字符表路径", encoding="utf-8"))
out = {}
for m in d["ScriptMethod"]:
    if len(out) >= LIMIT:
        break
    if any(k in m["Name"] for k in KEYS):
        out[hex(m["Address"])] = m["Name"]

open(r"存放路径", "w", encoding="utf-8").write(
    "const TARGETS=" + json.dumps(out, ensure_ascii=False) + ";")
print(len(out), "个候选已生成")
```

这个就不解释了，拿着直接用就行

这个生成筛选之后的符号表

然后利用

```
const LIB = "libil2cpp.so";
// 更改点: 节流/帧数
const THROTTLE_MS = 1000;
const FRAMES = 6;

// 【固定】库定位+重定位: 基址每次启动都变, 必须运行时现取
const base = Process.findModuleByName(LIB).base;
const last = {};
let n = 0;

for (const [rva, name] of Object.entries(TARGETS)) {
    // 【固定】hook 机制: 只挂函数入口, 只读
    Interceptor.attach(base.add(parseInt(rva)), {
        onEnter: function () {
            const now = Date.now();
            if (now - (last[name] || 0) < THROTTLE_MS) return;
            last[name] = now;
            // 【固定】调用点反查: 栈帧-基址=偏移, 回表译名
            const bt = Thread.backtrace(this.context, Backtracer.FUZZY)
                .slice(0, FRAMES)
                .map(a => { const d = a.sub(base).toString(); return TARGETS[d] || d; });
            console.log("[CALL] " + name + "  ← " + bt.join(" ← "));
        }
    });
    n++;
}
console.log("[INIT] " + LIB + " @" + base + "  已挂 " + n + " 个, 等待触发...");
```

```
frida -U -p <PID> -l 第一个脚本生成的文件 -l 程序文件
```

用法如此可以进行批量hook从而来确定程序真正用到的是哪个。

这个只是简单的演示脚本。

在开启frida的详细学习之前，先了解一下frida的详细部分。

frida利用的是注入器（Injector）

Frida 首先会使用一种方式把它的“魔法核心”注入目标进程中：

- 在 Android 上是通过 **ptrace** 或 `frida-server` 以 root 身份注入
- 在 iOS/macOS/Windows 上是通过 **动态库注入（Dylib / DLL Injection**

注入发生后，frida-agent会把js脚本放入目标进程里面。js脚本通过frida的api比如Java.perform， Interceptor.attach来ook或者替换原本的逻辑。

那frida的插桩注入，以及注入后的过程是如何实现的呢？

#### 注入

frida的注入利用的跟gdb类似都是利用ptrace进行劫持进程。

注入器首先调用 `ptrace(PTRACE_ATTACH, target_pid, ...)` 附加到目标进程，然后选择一个线程，调用 `PTRACE_GETREGS` 获取该线程的全部寄存器状态。

为了进入函数或说activity里面在java层改动的是ArtMethod的入口指针。

而在Native层的hook则是直接改写目标函数入口的机器码。

在ARM64架构的情况下将入口汇编改写为

```
ldr x16, #8 ;
br x16 
8 字节字面量（地址）
```

最后8个字节的数据指向为
