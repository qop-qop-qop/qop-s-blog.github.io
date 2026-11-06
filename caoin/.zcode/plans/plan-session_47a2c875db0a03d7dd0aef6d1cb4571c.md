# mprotect/madvise 静默失效 → 可感知

## 思路

README 边界里"受管页被 mprotect/madvise 改写 → hook **静默**失效"的根因之一是感知盲区:自愈逻辑挂在 fault 路径上,而 STEP 态被 mprotect 改成可执行后**不再 fault**,模块永远不知道发生了什么。本改动加**主动观察**:用现有 `hook_wrap` 框架挂 `SyS_mprotect` / `SyS_madvise` 入口,命中受管页范围时记录,用户态经 ctl0 查询。第一版只做记录(可感知),不做主动恢复 PTE(拉锯问题,另开实验)。

调研结论(全部有先例可抄):挂第二个内核函数 = 照抄 `follow_page_pte` 可选块模式(kpm.c:3173-3189);相交检测所需数据 `hooks[].tva` 现成;ctl0 出参样板 = `dump` 子命令(3274-3297),kpmctl 零改动。

## 改动(全部在 caoin_ko/caoin_kpm.c)

1. **全局量**(`g_follow_pte` ~281 旁):`g_mprot` / `g_madv` 函数指针、`g_mprot_hits` 等计数、`last_addr/last_len/last_prot/last_advice/last_ret`、命中时 `per_hook_view[CAOIN_MAX_HOOKS]` 快照、`cfg_mprot = 1`。

2. **handler**(仿 `gup_pte_before`:2078 的"快速过滤"结构):
   - `before_mprotect` / `before_madvise`:先 `hooks_n==0` 廉价早退 → `caoin_is_target_proc()`(1225)过滤 → `[addr, addr+len)` 与受管页 `[tva&~0xFFF, +0x1000)` 相交判定 → 计数 + 记录 + cur_view 快照。madvise 只记 `MADV_DONTNEED(4)/MADV_FREE(8)`,避免噪音。
   - after 版仅记 `args->ret`(区分失败尝试)。**只读记录,不改 args、不 skip_origin**;before 上下文未持 mmap_sem、不拿任何锁(观察型,竞态最多漏记一次)。

3. **parse_args**(1889-2021):加 `mprot=0/1`(默认 1,观察型零干扰;不想要可关)。

4. **caoin_init**:`__switch_to` 块后(3192-3209 之后、`g_hooks_installed=1` 前)加可选安装块:`kallsyms_lookup_name("SyS_mprotect")` 回退 `"sys_mprotect"`;`"SyS_madvise"` 回退 `"sys_madvise"`(照抄 3174-3176 回退链写法),`hook_wrap3(..., before, after, NULL)`,失败只 CK_ERR + 置 NULL(可选块,不阻断)。

5. **caoin_restore**:成对 `caoin_unhook(g_mprot, before_mprotect, after_mprotect)` / madvise 同理——**before/after 指针必须与安装时一致**,否则链残留 → 下次加载 -4094(2209-2217 已踩坑)。

6. **ctl0 加 `mstat` 子命令**(仿 dump 3274-3297):把 `{calls, hits, last_addr, last_len, last_prot/advice, last_ret, ts, per_hook_view[4]}` 结构体拷进 out_msg、返回字节数。`kpmctl su caoin-shadow "mstat"` / `caoin ctl "mstat"` 直接可查。

7. **dmesg**:命中打印走 `verbose=1` 门控 + 限速(前 N 次),保持静音版默认零输出。

## 验证(分两步,每步汇报)

1. **编译验证**(我做):用 `F:\work\tmp\mkpms` KP 树重编 `caoin-shadow.kpm`,确认编译/链接通过;若本机树不可用则交回你的环境构建。
2. **真机验证**(步骤给你,测试机跑):
   - 加载 hook shtarget → 跑 `selfread` C7(mprotect)/ C8(madvise)→ `kpmctl "mstat"` 核对 hits≥1、last_addr、per_hook_view、ret;
   - C9(同权限 mprotect)对照:hits 会计到(入口层看不到早退),但文档标注语义区分;
   - unload → 再 load,确认无 -4094(链残留回归检查)。
   - **实测通过前,README"静默失效"表述不改**;通过后同步 README 边界表 + DEVLOG 各一小节。

## 不做(明确排除)

- 主动恢复 PTE(mprotect 后抢写影子 PTE)——与目标拉锯,单独实验;
- status 页写 magic 告警——单槽会覆盖 INJ_REQ 握手,干扰注入流程;
- munmap / mmap(MAP_FIXED) 检测——同属"内核改页表"但不在本次 README 边界范围,后续可加。