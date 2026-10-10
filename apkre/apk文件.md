apk文件包更像是安卓文件的一个函数库，先给安卓框架一个地图然后安卓框架会去按照地图调用函数（粗略理解对于熟悉c的比较友好的理解方式）

**APK = 函数库 + 声明文件**

```
Android 框架
   地图①: AndroidManifest.xml —— "入口是 com.jinke.OrdinarySplash"
      ↓ 按地图调 onCreate / onStart ...
Java 层 (dex)
      ↓
Unity 引擎 (libunity.so)
   地图②: assets/bin/Data/level0~19 —— "场景里摆了哪些 GameObject、
          每个挂了哪个 C# 脚本类"
      ↓ 按场景实例化，调 Awake / Start / Update ...
IL2CPP 游戏逻辑 (libil2cpp.so)
```

两个地图，一个作用于Android 框架，一个作用于Unity 