# BurpCRLFScan

---
使用java编写的CRLF-Injection的burp被动扫描插件
# 简介

---
java maven项目，可以使用`mvn package`进行编译

# 更新

---
```
1.0 - 对目标进行CRLF-Injection扫描
1.1 - 取消对cookie对扫描
1.2 - 在开始CRLF注入扫描前先判断Response Header是否可控
1.3 - 添加了对json的扫描
```

# payload

---
```url
- "%0D%0A%20Set-CRLF-injection:crlftoken=injection"  
- "%20%0D%0ASet-CRLF-injection:crlftoken=injection"  
- "%0A%20Set-CRLF-injection:crlftoken=injection"  
- "%2F%2E%2E%0D%0ASet-CRLF-injection:crlftoken=injection"  
- "%E5%98%8D%E5%98%8ASet-CRLF-injection:crlftoken=injection"
- "\u010D\u010ASet-CRLF-injection:crlftoken=injection"
- "%C4%8DSet-CRLF-injection:crlftoken=injection"
- "čĊSet-CRLF-injection:crlftoken=injection"
```
可以在resources/config.yml修改

# 使用

---

### 00x1 CRLF环境

使用vulhub中的nginx/insecure-configuration搭建环境

[https://vulhub.org/#/environments/nginx/insecure-configuration/](https://vulhub.org/#/environments/nginx/insecure-configuration/)

### 0x02 插件

代理访问`http://yourip:8080`，开始扫描

扫描CRLF前先确认Response Header是否可控

![image-20221126210035.png](https://raw.githubusercontent.com/A0WaQ4/BurpCRLFScan/main/img/image-20221126210035.png)

若Response Header可控，则开始扫描CRLF-Injection，获得结果

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
