
- [English](README.MD)
- 中文

# Login Proxy

*如果本插件有用, 请给个star吧 :)*

### 特性

- 使用**反向代理**代理minecraft服务器**登录包**, *不必担心客户端绕开白名单*
- 最好的离线登录白名单插件
- 为MCDR最高级的白名单 ~~(没有之一)~~

### 计划中

- 暂无

### 配置文件

#### login_proxy/config.json _(主配置文件)_

```javascript
{
    "minimum_permission_level": { // 指令权限
        "help": 0,
        "list": 1,
        "query": 2,
        "banned": 2,
        "ban": 2,
        "banip": 3,
        "pardon": 3,
        "pardonip": 3
    },
    "proxy_addr": { // 代理服务器地址&端口. 请注意不要与minecraft服务器的重复! 否则你电脑可能会崩溃
        "ip": "",
        "port": 25565
    },
    "enable_whitelist": false, // 是否启用白名单
    "enable_ip_whitelist": false, // 是否启用IP白名单
    "kick_cmd": "kick {name} {reason}", // 将在线玩家踢出游戏的指令; 留空为强制断开连接(不推荐)
    "messages": { // 一些提示消息
        "banned.name": "Your account has been banned", // 当玩家名被ban的时候提示
        "banned.ip": "Your ip has been banned", // 当玩家IP被ban的时候提示
        "whitelist.name": "Your account not in the whitelist", // 当玩家名不在白名单的时候提示
        "whitelist.ip": "Your ip not in the whitelist" // 当玩家名IP不在白名单的时候提示
    }
}
```

#### login_proxy/list.json _(玩家白名单黑名单列表)_

```javascript
{
    "banned": [], // 被禁止的玩家名
    "bannedip": [], // 被禁止的IP
    "allow": [], // 玩家名白名单
    "allowip": [] // IP白名单
}
```
