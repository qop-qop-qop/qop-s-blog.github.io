/*
 * 纯被动 agent（反检测二分定位用）：
 * dlopen 加载成功即目标达成——不读 config、不装 hook、不写任何文件。
 * 配合 memfd 注入：若进程仍死 → 检测的是注入过程/memfd 映射本身；
 * 若存活 → 检测的是 agent 的行为（config 读取/日志/hook 改写）。
 */
int caoin_passive_marker;   /* 非空 so（留一个全局符号） */
