# instabox-panel

给 [Instabox](https://instabox.sh) 云机器用的单文件 Web 运维面板：纯 Python 标准库、零第三方依赖，一个 `panel.py` 搞定。

## 功能

- **本机实时状态**：系统/内核/主机名/运行时长、CPU 占用、内存与 Swap、磁盘、网卡与流量、公网出口 IP 与归属（带缓存）
- **Web 服务与端口**：自动发现本机监听端口，一键通过 `instabox-port` 发布到公网 HTTPS / 取消发布
- **systemd 服务管理**：查看状态，启动 / 停止 / 重启；关键系统服务（ssh、dbus、journald、面板自身等）禁止停止
- **Docker 容器管理**：查看状态，启动 / 停止 / 重启
- **全舰队视图（可选）**：同目录放一份 `fleet.json` 快照时，页面顶部会多出跨机器总览（机器、账号、CPU/内存/磁盘、出口、已发布服务、详情展开）；没有该文件时自动隐藏，不影响本机功能
- **安全**：仅监听 `127.0.0.1`；令牌登录（POST 登录、HttpOnly + Secure Cookie、常量时间比较）；写操作强制要求 `X-Panel-Token` 请求头（防 CSRF）；所有操作写审计日志（journald 可查）
- **性能**：状态采集后台线程每 4 秒刷新缓存，接口直接读缓存；响应 gzip 压缩，舰队快照支持 ETag

## 快速开始

环境要求：Linux + systemd、Python 3.9+；Docker 相关功能需机器上装有 Docker；端口发布需 Instabox 机器自带的 `instabox-port` 命令。

```bash
mkdir -p /data/workspace/panel && cd /data/workspace/panel
# 把 panel.py 放到这个目录
openssl rand -hex 24 > token.txt && chmod 600 token.txt   # 生成访问令牌，请妥善保管

cp instabox-panel.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now instabox-panel

instabox-port publish 18090   # 发布面板端口，得到 https://18090-<机器ID>.instabox.tech
```

打开发布得到的地址，输入 `token.txt` 里的令牌即可进入。

> 面板服务需要能执行 `systemctl` / `docker`：示例 unit 默认以 root 运行；若改用普通用户运行，请给该用户配置免密 sudo 并加入 docker 组。

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PANEL_PORT` | `18090` | 本地监听端口（只绑 127.0.0.1） |
| `PANEL_TOKEN_FILE` | 与 panel.py 同目录的 `token.txt` | 访问令牌文件；修改后需重启服务生效 |
| `PANEL_FLEET_FILE` | 与 panel.py 同目录的 `fleet.json` | 舰队快照文件（可选） |
| `MACHINE_ID` | 自动从 `/data/home/MACHINE.md` 解析 | 机器 ID，用于拼公网网关地址 |

## 安全须知

- 面板能停止服务、重启机器上的组件、把端口发布到公网——**令牌等同于这台机器的管理钥匙**，请用随机长令牌并妥善保管，不要写进任何仓库。
- 面板只应通过 Instabox 的 HTTPS 网关（`instabox-port` 发布）访问，不要把本地端口直接暴露到公网。
- 关键服务禁停名单在 `panel.py` 顶部的 `CRITICAL_UNITS`，可按需增删。

## fleet.json 格式（可选）

```json
{
  "generated_at_beijing": "2026-10-28 16:00:00",
  "summary": {"accounts": 1, "machines": 1, "running": 1, "collected": 1, "errors": 0, "woken": 0},
  "machines": [
    {"id": "m_xxx", "name": "box1", "account_login": "you@example.com", "state": "running",
     "auto_suspend": 1800,
     "stats": {"os": "Debian GNU/Linux 13", "hostname": "instabox-box1", "kernel": "6.x", "arch": "x86_64",
               "cpu_model": "...", "cpu_cores": 2, "cpu_percent": 3.1, "load": [0.1, 0.1, 0.1],
               "uptime_seconds": 3600,
               "memory": {"total": 1, "used": 1, "percent": 40.0},
               "disks": [{"mount": "/", "total": 1, "used": 1, "percent": 30.0}],
               "interfaces": [], "default_route": "", "egress": {"ip": "1.2.3.4", "city": "", "region": "", "country": "", "org": ""},
               "listening": [], "published": [], "docker": [],
               "systemd_running": 10, "systemd_failed": []}}
  ]
}
```

## License

MIT
