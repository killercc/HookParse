# HookParse
钉钉直播回放信息拦截
## 说明
使用HOOK实现，针对Windows 钉钉7.0.40-Release.7049102 Native

## 使用方法：
钉钉启动后使用任意注入器注入，点击直播回放列表后显示包含m3u8链接的json数据
注入后点击直播回放列表，任意http客户端访问GET：http://127.0.0.1:52101/list 获取已拦截的回放信息(已去重),使用任意方式格式化数据并导入下载器。
