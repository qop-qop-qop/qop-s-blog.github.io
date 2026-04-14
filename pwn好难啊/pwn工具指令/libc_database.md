~/libc-database/ # 工具根目录 
├── db/ # 核心：存放所有 libc 版本的数据库目录 
│ ├── * .so # 各个版本的 libc.so 文件 
│ └── * .symbols # 对应 libc 的符号表（函数地址偏移） 
├── find # 核心查询脚本 
├── add # 新增 libc 脚本 
└── ...

扩展db库模板   - ---   git版

cd ~/libc-database

git  clone  https://github.com.niklasb/libc-database.git   tmp

mv  tmp/db/*  db/

rm -rf tmp  //删掉临时文件

手动添加单个/多个libc   --- 手动版

cd  ~/libc-database

./add    <libc.so的文件路径>