# BurpCRLFScan
---
使用java编写的CRLF-Injection的burp被动扫描插件
# 简介
---
java maven项目，可以使用`mvn package`进行编译
# payload
---
```url
- "%0D%0A%20Set-CRLF-injection:crlftoken=injection"  
- "%20%0D%0ASet-CRLF-injection:crlftoken=injection"  
- "%0A%20Set-CRLF-injection:crlftoken=injection"  
- "%2F%2E%2E%0D%0ASet-CRLF-injection:crlftoken=injection"  
- "%E5%98%8D%E5%98%8ASet-CRLF-injection:crlftoken=injection"
```
可以在resources/config.yml修改

# 使用

---

### 00x1 CRLF环境

使用vulhub中的nginx/insecure-configuration搭建环境

[https://vulhub.org/#/environments/nginx/insecure-configuration/](https://vulhub.org/#/environments/nginx/insecure-configuration/)

### 0x02 插件

代理访问http://yourip:8080，扫描出结果

![image-20221124231706096](https://raw.githubusercontent.com/A0WaQ4/BurpCRLFScan/main/img/image-20221124231706096.png)

# 参考

---

[https://github.com/pmiaowu/BurpFastJsonScan](https://github.com/pmiaowu/BurpFastJsonScan)

# 待完成

- [ ] 请求走私扫描

# 免责声明
---
该工具仅用于安全自查检测

由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。

本人拥有对此工具的修改和解释权。未经网络安全部门及相关部门允许，不得善自使用本工具进行任何攻击活动，不得以任何方式将其用于商业目的。
