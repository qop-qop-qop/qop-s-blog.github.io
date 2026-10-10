整体语法类似于python加php

shell脚本类型多样这里就只有最基本的 Bourne Shell 

# 变量

shell脚本变量的命名

```
your_name="runoob"
```

创建不需要太多字符

使用为了区分变量用 $进行区分{}进行边界分别，如：

```
for skill in Ada Coffe Action Java; do
    echo "I am good at ${skill}Script"
done
```

命名须遵循如下规则：

- **只包含字母、数字和下划线：** 变量名可以包含字母（大小写敏感）、数字和下划线 **_**，不能包含其他特殊字符。
- **不能以数字开头：** 变量名不能以数字开头，但可以包含数字。
- **避免使用 Shell 关键字：** 不要使用Shell的关键字（例如 if、then、else、fi、for、while 等）作为变量名，以免引起混淆。
- **使用大写字母表示常量：** 习惯上，常量的变量名通常使用大写字母，例如 **PI=3.14**。
- **避免使用特殊符号：** 尽量避免在变量名中使用特殊符号，因为它们可能与 Shell 的语法产生冲突。
- **避免使用空格：** 变量名中不应该包含空格，因为空格通常用于分隔命令和参数。

这些与很多语言的语法要求类似

除了显式地直接赋值，还可以用语句给变量赋值，如：

```
for file in `ls /etc`
或
for file in $(ls /etc)
```

以上语句将 /etc 下目录的文件名循环出来。

### 只读变量

```
readonly myUrl
```

之后变量myUrl就无法被改变

### 删除变量

```
unset variable_name
```

# 变量类型

Shell 支持不同类型的变量，其中一些主要的类型包括：

| 变量名     | 使用                                                         | 举例                                                    |
| ---------- | ------------------------------------------------------------ | ------------------------------------------------------- |
| 字符串变量 | 使用单引号 **'** 或双引号 **"** 来定义字符串                 | my_string='Hello, World!'                               |
| 整数变量   | 使用 **declare** 或 **typeset** 命令来声明整数变量           | declare -i my_integer=42                                |
| 环境变量   | 这些是由操作系统或用户设置的特殊变量，用于配置 Shell 的行为和影响其执行环境 | echo $PATH                                              |
| 特殊变量   | $0，$1，$2等                                                 | **$0** 表示脚本的名称，**$1**, **$2**, 等表示脚本的参数 |

## Shell 字符串

### 单引号

```
str='this is a string'
```

单引号字符串的限制：

- 单引号里的任何字符都会原样输出，单引号字符串中的变量是无效的；
- 单引号字符串中不能出现单独一个的单引号（对单引号使用转义符后也不行），但可成对出现，作为字符串拼接使用。

### 双引号

```
your_name="runoob"
str="Hello, I know you are \"$your_name\"! \n"
echo -e $str
```

双引号的优点：

- 双引号里可以有变量
- 双引号里可以出现转义字符

### 拼接字符串

```
your_name="runoob"
# 使用双引号拼接
greeting="hello, "$your_name" !"
greeting_1="hello, ${your_name} !"
echo $greeting  $greeting_1

# 使用单引号拼接
greeting_2='hello, '$your_name' !'
greeting_3='hello, ${your_name} !'
echo $greeting_2  $greeting_3
```

### 获取字符串长度

```
string="abcd"
echo ${#string}   # 输出 4
```

变量为字符串时，**${#string}** 等价于 **${#string[0]}**:

### 提取子字符串

以下实例从字符串第 **2** 个字符开始截取 **4** 个字符：

```
string="runoob is a great site"
echo ${string:1:4} # 输出 unoo
```

