system()的底层本质:
- 不是直接执行命令,而是调用系统的shell来执行:  Linux下默认是/bin/sh
- 完整流程: system(cmd) -> fork()字进程 -> execl("/bin/sh","sh","-c",cmd,NULL) -> 子进程执行shell解析命令 -> 父进程等待结束
- 这意味着: 所有shell支持的语法,特殊字符,环境变量,system()都支持 

命令分隔符: 一次system()执行多条命令
-    ;     顺序执行,不管前一条成败         `system("id; whoami; cat /etc/passwd")` 一次性执行多个命令
-   &&       前一条成功才执行后一条     `system("mkdir /tmp/pwn && chmod 777 /tmp/pwn")` 确保目录创建成功再授权
- || 前一条失败才执行后一条


特殊字符: 绕过过滤