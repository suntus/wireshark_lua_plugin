### 用法：
1. 需要wireshark支持lua;
2. 将gmv11.lua放到位置: `F:\\wireshark_lua_plugin\\gmv11.lua`
2. "帮助"-->"关于"-->"全局配置"，打开后找`init.lua`;
3. 在`init.lua`最后添加:
```
dofile("F:\\wireshark_lua_plugin\\gmv11.lua")
```
4. "分析"-->"重新载入lua插件"

默认是`tcp.port == 8899`解析，可以直接右键`解码为`，查找"GMV1.1"协议。也可以直接改`gmv11.lua`文件中的端口号，再重新加载lua插件。

ps: 只试过windows，还没试过linux和mac