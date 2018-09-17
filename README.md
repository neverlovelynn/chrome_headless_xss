# **基于Chorme headless的xss检测**
## 源码及使用方法
Mac os 安装 chrome-canary：
```
brew install Caskroom/versions/google-chrome-canary
```
启动chrome远程调试：
```
chrome-canary --remote-debugging-port=9222 --headless -remote-debugging-address=0.0.0.0 --disable-xss-auditor --no-sandbox --disable-web-security
```
centos7：
安装chrome
```
$ vi /etc/yum.repos.d/google-chrome.repo
```
写入如下内容：
```
[google-chrome]
name=google-chrome
baseurl=http://dl.google.com/linux/chrome/rpm/stable/$basearch
enabled=1
gpgcheck=1
gpgkey=https://dl.google.com/linux/linux_signing_key.pub
```
然后
```
$ sudo yum install google-chrome-stable
```
后台启动chrome-stable
```
nohup google-chrome-stable --disable-gpu --remote-debugging-port=9222 --headless -remote-debugging-address=0.0.0.0 --disable-xss-auditor --no-sandbox --disable-web-security > chromeheadless.out 2>&1 & 
```
chrome_headless_xss
```
# tmp_url为添加payload的url，如果是post请求则为原始url
chrome_headless_drive = ChromeHeadLess(url=tmp_url,
ip="127.0.0.1",
port="9222",
cookie="",
post="",
auth="",
payloads= payload
#添加监听弹窗内容
check_message = "you_alert_message")
scan_result = chrome_headless_drive.run()
```
scan_result结果：
```
# level 3 代表触发了Page.javascriptDialogOpening事件
{'url': u'http://xss.php', 'vul': 'xss', 'post': '', 'method': u'GET', 'level': '3'}
# level 2 代表dom树的节点包含了我们自定义的<webscan></webscan>标签
{'url': u'http://xss.php', 'vul': 'xss', 'post': '', 'method': u'GET', 'level': '2'}
# level 1 代表渲染后的nodeValue包含我们的payload
{'url': u'http://xss.php', 'vul': 'xss', 'post': u'id1=1&id2=2test_test', 'method': u'POST', 'level': '1'}
```
源码链接：
```
https://github.com/neverlovelynn/chrome_headless_xss/
```
文章链接:
```
https://blog.formsec.cn/2018/07/12/%E5%9F%BA%E4%BA%8EChrome-headless%E7%9A%84XSS%E6%A3%80%E6%B5%8B/
```
tips:
  由于最新版本的chrome69在linux下会存在一个 lost ui context的error，所以推荐使用chrome64的稳定版本。历史安装包连接：
https://www.slimjet.com/chrome/google-chrome-old-version.php
  有时候也会存在chrome崩溃的情况，也可以使用supervise创建守护进程自动重启。


