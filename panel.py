#!/usr/bin/env python3
"""Instabox info 机器运维面板（纯标准库，无第三方依赖）。

功能：
- 系统检查：OS/内核/主机名/运行时长、CPU 核数与占用、内存、磁盘、网络（含公网出口）
- Web 服务管理：监听端口发现、instabox-port 发布/取消发布、公网访问链接
- systemd 服务与 Docker 容器的状态查看与启停/重启（关键系统服务禁止停止）

监听 127.0.0.1:18090，通过 instabox-port 网关对外提供 HTTPS 访问。
访问控制：token 文件同目录 token.txt；首次用带 token 的链接打开即写入 Cookie。
"""
import gzip
import hashlib
import hmac
import io
import json
import os
import re
import signal
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PANEL_VERSION = "2026.10.28-r2"

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PANEL_PORT", "18090"))
MACHINE_ID = os.environ.get("MACHINE_ID", "")
TOKEN_FILE = os.environ.get("PANEL_TOKEN_FILE", os.path.join(HERE, "token.txt"))
FLEET_FILE = os.environ.get("PANEL_FLEET_FILE", os.path.join(HERE, "fleet.json"))

CRITICAL_UNITS = {
    "ssh.service", "instabox-guest-agent.service", "dbus.service",
    "systemd-journald.service", "systemd-logind.service", "systemd-udevd.service",
    "serial-getty@ttyS0.service", "instabox-panel.service",
}


def load_token():
    try:
        with open(TOKEN_FILE) as f:
            return f.read().strip()
    except Exception:
        return ""


TOKEN = load_token()


def machine_suffix():
    mid = MACHINE_ID
    if not mid:
        try:
            with open("/data/home/MACHINE.md") as f:
                m = re.search(r"Machine ID\s*\|\s*`(m_[a-z0-9]+)`", f.read())
                if m:
                    mid = m.group(1)
        except Exception:
            pass
    return mid[2:] if mid.startswith("m_") else mid


SUFFIX = machine_suffix()


def gateway_url(port):
    return f"https://{port}-{SUFFIX}.instabox.tech" if SUFFIX else ""


def run(cmd, timeout=15):
    """执行命令。cmd 可为字符串（shell）或参数列表（优先，无 shell 注入面）。
    超时后杀整个进程组，避免孙进程残留；输出截断到 64KB。"""
    try:
        p = subprocess.Popen(cmd, shell=isinstance(cmd, str),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, start_new_session=True)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except Exception:
                pass
            out, err = p.communicate()
            return 1, (out or "").strip()[:65536], ((err or "") + " [timeout killed]").strip()[:65536]
        return p.returncode, (out or "").strip()[:65536], (err or "").strip()[:65536]
    except Exception as e:
        return 1, "", str(e)


# ---------------- 指标采集 ----------------

def cpu_times():
    with open("/proc/stat") as f:
        for line in f:
            if line.startswith("cpu "):
                parts = [int(x) for x in line.split()[1:]]
                idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
                return sum(parts), idle
    return 0, 0


def cpu_percent():
    t1, i1 = cpu_times()
    time.sleep(0.25)
    t2, i2 = cpu_times()
    dt, di = t2 - t1, i2 - i1
    if dt <= 0:
        return 0.0
    return round(max(0.0, min(100.0, (1 - di / dt) * 100)), 1)


def mem_info():
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            info[k] = int(v.split()[0]) * 1024
    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", 0)
    used = total - avail
    swap_t = info.get("SwapTotal", 0)
    swap_f = info.get("SwapFree", 0)
    return {
        "total": total, "used": used, "available": avail,
        "percent": round(used * 100 / total, 1) if total else 0,
        "swap_total": swap_t, "swap_used": swap_t - swap_f,
    }


import platform
import shutil


def disk_info():
    out = []
    for mount in ("/", "/data"):
        if not os.path.exists(mount):
            continue
        try:
            u = shutil.disk_usage(mount)
            out.append({
                "mount": mount, "total": u.total, "used": u.used, "free": u.free,
                "percent": round(u.used * 100 / u.total, 1) if u.total else 0,
            })
        except Exception:
            pass
    return out


def sys_info():
    osname = ""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    osname = line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    uptime_s = 0
    try:
        with open("/proc/uptime") as f:
            uptime_s = int(float(f.read().split()[0]))
    except Exception:
        pass
    load = (0, 0, 0)
    try:
        load = os.getloadavg()
    except Exception:
        pass
    return {
        "hostname": platform.node(),
        "os": osname,
        "kernel": platform.release(),
        "arch": platform.machine(),
        "machine_id": MACHINE_ID or ("m_" + SUFFIX if SUFFIX else ""),
        "uptime_seconds": uptime_s,
        "cpu_cores": os.cpu_count() or 0,
        "cpu_percent": cpu_percent(),
        "load": [round(x, 2) for x in load],
        "time_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }


_egress_cache = {"at": 0, "data": None}


def egress_info():
    now = time.time()
    if _egress_cache["data"] and now - _egress_cache["at"] < 600:
        return _egress_cache["data"]
    data = {"ip": "", "city": "", "region": "", "country": "", "org": ""}
    try:
        req = urllib.request.Request("https://ipinfo.io/json", headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=5) as r:
            j = json.loads(r.read().decode())
            for k in data:
                data[k] = j.get(k, "") or ""
    except Exception:
        try:
            req = urllib.request.Request("https://ifconfig.me/ip", headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=5) as r:
                data["ip"] = r.read().decode().strip()
        except Exception:
            pass
    if data["ip"]:
        _egress_cache.update(at=now, data=data)
    return data


def net_info():
    ifaces = []
    rc, out, _ = run(["ip", "-j", "addr"], 8)
    if rc == 0 and out:
        try:
            for it in json.loads(out):
                addrs = [a.get("local", "") for a in it.get("addr_info", [])]
                ifaces.append({"name": it.get("ifname"), "state": it.get("operstate"), "addrs": addrs})
        except Exception:
            pass
    rc, route, _ = run(["ip", "route", "show", "default"], 8)
    traffic = {}
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if ":" in line:
                    name, rest = line.split(":", 1)
                    nums = rest.split()
                    traffic[name.strip()] = {"rx": int(nums[0]), "tx": int(nums[8])}
    except Exception:
        pass
    for it in ifaces:
        if it["name"] in traffic:
            it["rx"] = traffic[it["name"]]["rx"]
            it["tx"] = traffic[it["name"]]["tx"]
    return {"interfaces": ifaces, "default_route": route, "egress": egress_info()}


def listening_ports():
    rc, out, _ = run(["ss", "-tlnp"], 8)
    ports = []
    if rc == 0:
        for line in out.splitlines():
            if "LISTEN" not in line:
                continue
            m = re.search(r"(\S+):(\d+)\s", line)
            if not m:
                continue
            proc = ""
            pm = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            if pm:
                proc = f"{pm.group(1)} (pid {pm.group(2)})"
            ports.append({"addr": m.group(1), "port": int(m.group(2)), "process": proc})
    # 去重（同端口多地址合并）
    merged = {}
    for p in ports:
        key = p["port"]
        if key in merged:
            if p["addr"] not in merged[key]["addr"]:
                merged[key]["addr"] += ", " + p["addr"]
            if not merged[key]["process"] and p["process"]:
                merged[key]["process"] = p["process"]
        else:
            merged[key] = p
    return sorted(merged.values(), key=lambda x: x["port"])


def published_ports():
    rc, out, _ = run(["instabox-port", "list"], 10)
    result = []
    if rc == 0 and out:
        try:
            j = json.loads(out)
            for item in j.get("ports", []):
                if isinstance(item, int):
                    result.append({"port": item, "name": ""})
                elif isinstance(item, dict):
                    result.append({"port": int(item.get("port")), "name": item.get("name", "") or ""})
        except Exception:
            pass
    return result


NON_WEB_PORTS = {22, 5901}  # SSH / VNC 是系统服务，不是 Web 服务，不进面板的 Web 列表


def web_services():
    listening = [p for p in listening_ports() if p["port"] not in NON_WEB_PORTS]
    published = {p["port"]: p for p in published_ports() if p["port"] not in NON_WEB_PORTS}
    services = []
    for lp in listening:
        port = lp["port"]
        pub = port in published
        services.append({
            "port": port, "addr": lp["addr"], "process": lp["process"],
            "published": pub, "name": published.get(port, {}).get("name", ""),
            "url": gateway_url(port) if pub else "",
            "local_url": f"http://127.0.0.1:{port}",
        })
    # 已发布但当前未监听的也列出（服务可能已停）
    known = {s["port"] for s in services}
    for p, info in published.items():
        if p not in known:
            services.append({
                "port": p, "addr": "-", "process": "(未监听，服务可能已停止)",
                "published": True, "name": info.get("name", ""), "url": gateway_url(p), "local_url": "",
            })
    return sorted(services, key=lambda x: x["port"])


def systemd_services():
    rc, out, _ = run(["systemctl", "list-units", "--type=service", "--state=running,failed", "--no-pager", "--no-legend"], 10)
    units = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 4 and parts[0].endswith(".service"):
                units.append({
                    "unit": parts[0], "active": parts[2], "sub": parts[3],
                    "desc": parts[4] if len(parts) > 4 else "",
                    "critical": parts[0] in CRITICAL_UNITS,
                })
    return sorted(units, key=lambda u: u["unit"])


def docker_containers():
    rc, out, _ = run(["docker", "ps", "-a", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"], 10)
    items = []
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) >= 4:
                items.append({
                    "id": parts[0], "name": parts[1], "image": parts[2],
                    "status": parts[3], "ports": parts[4] if len(parts) > 4 else "",
                    "running": parts[3].lower().startswith("up"),
                })
    return items


def collect_stats():
    """逐项容错：单项采集失败只降级该字段，不拖垮整个接口。"""
    def safe(fn, default):
        try:
            return fn()
        except Exception:
            return default
    return {
        "system": safe(sys_info, {}),
        "memory": safe(mem_info, {}),
        "disks": safe(disk_info, []),
        "network": safe(net_info, {"interfaces": [], "default_route": "", "egress": {}}),
        "services": safe(web_services, []),
        "systemd": safe(systemd_services, []),
        "docker": safe(docker_containers, []),
    }


# /api/stats 缓存：后台线程每 4 秒刷新一次，请求只读缓存（单飞，避免并发重复 fork 子进程）
_stats_cache = {"at": 0.0, "data": None}
_stats_lock = threading.Lock()


def _stats_refresh_loop():
    while True:
        try:
            data = collect_stats()
            with _stats_lock:
                _stats_cache.update(at=time.time(), data=data)
        except Exception:
            pass
        time.sleep(4)


def get_stats():
    with _stats_lock:
        if _stats_cache["data"] is not None:
            return _stats_cache["data"]
    # 首次请求且后台线程还没填好时，同步采一次兜底
    data = collect_stats()
    with _stats_lock:
        _stats_cache.update(at=time.time(), data=data)
    return data


# ---------------- 动作 ----------------

def do_action(body):
    action = body.get("action", "")
    if action in ("publish", "unpublish"):
        try:
            port = int(body.get("port"))
        except Exception:
            return {"ok": False, "message": "端口无效"}
        if not (1 <= port <= 65535):
            return {"ok": False, "message": "端口超出范围"}
        if action == "publish":
            rc, out, err = run(["instabox-port", "publish", str(port)], 30)
            msg = out or err
            ok = rc == 0
            return {"ok": ok, "message": f"发布 {port}: {msg}".strip(), "url": gateway_url(port) if ok else ""}
        rc, out, err = run(["instabox-port", "unpublish", str(port)], 30)
        return {"ok": rc == 0, "message": f"取消发布 {port}: {out or err}".strip()}
    if action.startswith("service_"):
        unit = str(body.get("unit", ""))
        if not re.fullmatch(r"[A-Za-z0-9@._\-]+\.service", unit):
            return {"ok": False, "message": "服务名无效"}
        verb = action.replace("service_", "")
        if verb not in ("start", "stop", "restart"):
            return {"ok": False, "message": "动作无效"}
        if verb == "stop" and unit in CRITICAL_UNITS:
            return {"ok": False, "message": f"{unit} 是关键服务，禁止停止（可重启）"}
        rc, out, err = run(["sudo", "systemctl", verb, unit], 60)
        return {"ok": rc == 0, "message": f"{verb} {unit}: {(out or err or '完成').strip()}"}
    if action.startswith("docker_"):
        name = str(body.get("container", ""))
        if not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
            return {"ok": False, "message": "容器名无效"}
        verb = action.replace("docker_", "")
        if verb not in ("start", "stop", "restart"):
            return {"ok": False, "message": "动作无效"}
        rc, out, err = run(["docker", verb, name], 60)
        return {"ok": rc == 0, "message": f"docker {verb} {name}: {(out or err).strip()}"}
    return {"ok": False, "message": "未知动作"}


# ---------------- 页面 ----------------

LOGIN_HTML = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Instabox集群面板 · 登录</title>
<style>body{font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{background:#1e293b;padding:32px;border-radius:16px;width:min(92vw,360px)}input{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #475569;background:#0f172a;color:#e2e8f0;margin:12px 0}
button{width:100%;padding:10px;border:0;border-radius:8px;background:#2563eb;color:#fff;cursor:pointer;font-size:15px}</style></head>
<body><div class="box"><h2 style="margin:0 0 6px">🖥️ Instabox集群面板</h2><div style="color:#94a3b8;font-size:13px">请输入访问令牌（在交付的《使用说明》里）</div>
<form method="POST" action="/auth"><input name="token" type="password" placeholder="访问令牌" autocomplete="off"><button type="submit">进入面板</button></form></div></body></html>"""

PANEL_HTML = r"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Instabox集群面板</title>
<style>
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:20px}
.wrap{max-width:1180px;margin:0 auto}h1{font-size:22px;margin:0}h2{font-size:16px;margin:0 0 12px}
.sub{color:#94a3b8;font-size:13px;margin-top:4px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:16px;margin-top:16px}
.card{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:18px}
.kv{display:flex;justify-content:space-between;padding:5px 0;font-size:14px;border-bottom:1px dashed #334155}.kv:last-child{border-bottom:0}
.kv b{font-weight:600;text-align:right;max-width:62%;word-break:break-all}.k{color:#94a3b8}
.bar{height:10px;background:#334155;border-radius:6px;overflow:hidden;margin:6px 0 10px}.bar>i{display:block;height:100%;background:#22c55e;border-radius:6px}
.bar>i.warn{background:#eab308}.bar>i.bad{background:#ef4444}
.big{font-size:26px;font-weight:700}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#22c55e;margin-right:6px}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid #334155;vertical-align:top}
th{color:#94a3b8;font-weight:500}a{color:#60a5fa;text-decoration:none}a:hover{text-decoration:underline}
.btn{background:#2563eb;color:#fff;border:0;border-radius:7px;padding:5px 11px;cursor:pointer;font-size:12.5px;margin:2px 2px 2px 0}
.btn.gray{background:#475569}.btn.red{background:#b91c1c}.btn.green{background:#15803d}.btn:disabled{opacity:.5;cursor:wait}
.cpbtn{background:#334155;color:#e2e8f0;border:0;border-radius:6px;padding:1px 7px;cursor:pointer;font-size:11.5px;margin-left:6px;white-space:nowrap}.cpbtn:hover{background:#475569}
.tag{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11.5px;background:#14532d;color:#86efac}.tag.no{background:#3f3f46;color:#d4d4d8}
.tag.run{background:#14532d;color:#86efac}.tag.stop{background:#450a0a;color:#fca5a5}
#toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%);background:#020617;border:1px solid #475569;padding:10px 18px;border-radius:10px;font-size:14px;display:none;max-width:92vw;z-index:9}
.mut{color:#94a3b8;font-size:12.5px}.full{grid-column:1/-1}
</style></head><body><div class="wrap">
<h1>🖥️ Instabox集群面板</h1>
<div class="sub"><span class="dot"></span><span id="hdr">加载中…</span> · 每 5 秒自动刷新 · <a href="#" onclick="refresh();return false">立即刷新</a></div>
<div class="grid">
<div class="card full"><h2 id="fleetTitle">🌐 全部机器</h2><div id="fleet"><div class="mut">加载中…</div></div>
<div class="mut" style="margin-top:10px">说明：各账号的密钥只保存在 Muse 的安全连接里，info 机器本身不持有其他账号的密钥，所以这部分数据由 Muse 侧每 15 分钟统一采集全部机器的配置生成快照、再推送到本面板展示；被暂停（suspended）的机器会被采集自动唤醒并重新采集（2026-10-25 起经用户确认，行内会标注「本次已唤醒」），已停止（stopped）的机器只显示状态、不会被启动。点每行「详情」可看该机器的磁盘、网卡、全部监听端口、Docker 等完整配置。本机 info 的实时数据在下方。</div></div>
</div>
<div style="margin-top:20px;font-size:17px;font-weight:700">本机（<span id="localHost">…</span>）实时详情</div>
<div class="grid">
<div class="card"><h2>系统</h2><div id="sys"></div></div>
<div class="card"><h2>处理器 / 内存</h2><div id="cpumem"></div></div>
<div class="card"><h2>磁盘</h2><div id="disk"></div></div>
<div class="card"><h2>网络</h2><div id="net"></div></div>
<div class="card full"><h2>🌐 Web 服务与端口（管理与访问）</h2><div id="websvc"></div>
<div class="mut" style="margin-top:10px">「发布」= 通过 instabox-port 给该端口生成公网 HTTPS 地址，发布后点链接即可在浏览器打开该服务；「取消发布」后公网地址失效，服务本身不受影响。新部署的 Web 服务只要监听了端口，就会自动出现在上表。</div>
<div style="margin-top:10px"><input id="newport" type="number" min="1" max="65535" placeholder="手动发布端口，如 3000" style="padding:7px;border-radius:7px;border:1px solid #475569;background:#0f172a;color:#e2e8f0;width:200px">
<button class="btn green" data-act="publish_manual">发布此端口</button></div></div>
<div class="card full"><h2>⚙️ systemd 服务</h2><div id="units"></div></div>
<div class="card full"><h2>🐳 Docker 容器</h2><div id="docker"></div></div>
</div></div><div id="toast"></div>
<div class="mut" style="text-align:center;margin:14px 0 4px">Instabox 集群面板 v__PANEL_VERSION__ · 令牌在机器本地 token.txt，修改后需重启 instabox-panel 服务生效</div>
<script>
let PANEL_TOKEN='';try{PANEL_TOKEN=localStorage.getItem('panel_token')||''}catch(e){}
if(!PANEL_TOKEN){const m=document.cookie.match(/panel_token=([A-Za-z0-9_\-]+)/);if(m){PANEL_TOKEN=m[1];try{localStorage.setItem('panel_token',PANEL_TOKEN)}catch(e){}}}
const fmtB=n=>{if(n==null)return'-';const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(n>=100?0:n>=10?1:2)+' '+u[i]};
const fmtUp=s=>{const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?d+' 天 ':'')+h+' 小时 '+m+' 分'};
const bjTime=()=>new Date().toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false})+'（北京时间）';
const barCls=p=>p>=90?'bad':p>=70?'warn':'';
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function toast(t){const el=document.getElementById('toast');el.textContent=t;el.style.display='block';clearTimeout(el._t);el._t=setTimeout(()=>el.style.display='none',4200)}
async function act(body){const a=body.action||'';
 if(a==='service_restart'&&body.unit==='instabox-panel.service'){if(!confirm('确认重启面板本身？页面会短暂断开，随后自动恢复。'))return;
  toast('正在重启面板…');try{await fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json','X-Panel-Token':PANEL_TOKEN},body:JSON.stringify(body)})}catch(e){}
  setTimeout(()=>location.reload(),4000);return}
 if(a.endsWith('_stop')||a==='unpublish'){if(!confirm(a==='unpublish'?`确认取消发布端口 ${body.port}？公网地址将立即失效`:'确认停止？'))return}
 toast('执行中…');try{const r=await fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json','X-Panel-Token':PANEL_TOKEN},body:JSON.stringify(body)});const j=await r.json();toast((j.ok?'✅ ':'❌ ')+j.message);setTimeout(refresh,600)}catch(e){toast('❌ '+e)}}
document.addEventListener('click',e=>{const b=e.target.closest('[data-act]');if(!b)return;const k=b.getAttribute('data-act');
 if(k==='publish')act({action:'publish',port:parseInt(b.getAttribute('data-port'))});
 else if(k==='publish_manual'){const v=parseInt(document.getElementById('newport').value);if(v>=1&&v<=65535)act({action:'publish',port:v});else toast('❌ 端口无效')}
 else if(k==='unpublish')act({action:'unpublish',port:parseInt(b.getAttribute('data-port'))});
 else if(k==='svc')act({action:b.getAttribute('data-verb'),unit:b.getAttribute('data-unit')});
 else if(k==='dock')act({action:b.getAttribute('data-verb'),container:b.getAttribute('data-name')});
 else if(k==='fleet_toggle')toggleFleet(b.getAttribute('data-id'))});
async function refresh(){try{const r=await fetch('/api/stats');if(r.status===401){location.reload();return}const d=await r.json();render(d)}catch(e){toast('刷新失败：'+e)}}
function render(d){const s=d.system||{};
 const lh=document.getElementById('localHost');if(lh)lh.textContent=(s.hostname||'').replace(/^instabox-/,'')||'本机';
 document.getElementById('hdr').textContent=s.hostname+' · '+bjTime();
 document.getElementById('sys').innerHTML=
 `<div class="kv"><span class="k">主机名</span><b>${esc(s.hostname)}</b></div>
  <div class="kv"><span class="k">系统</span><b>${esc(s.os)}</b></div>
  <div class="kv"><span class="k">内核</span><b>${esc(s.kernel)} (${esc(s.arch)})</b></div>
  <div class="kv"><span class="k">机器 ID</span><b>${esc(s.machine_id)}</b></div>
  <div class="kv"><span class="k">已运行</span><b>${fmtUp(s.uptime_seconds)}</b></div>
  <div class="kv"><span class="k">负载 (1/5/15 分钟)</span><b>${s.load.join(' / ')}</b></div>`;
 const m=d.memory;
 document.getElementById('cpumem').innerHTML=
 `<div class="mut">CPU · ${s.cpu_cores} 核</div><div style="display:flex;align-items:baseline;gap:10px"><span class="big">${s.cpu_percent}%</span><span class="mut">当前占用</span></div>
  <div class="bar"><i class="${barCls(s.cpu_percent)}" style="width:${s.cpu_percent}%"></i></div>
  <div class="mut">内存 · 已用 ${fmtB(m.used)} / 共 ${fmtB(m.total)}</div><div style="display:flex;align-items:baseline;gap:10px"><span class="big">${m.percent}%</span><span class="mut">可用 ${fmtB(m.available)}</span></div>
  <div class="bar"><i class="${barCls(m.percent)}" style="width:${m.percent}%"></i></div>
  <div class="kv"><span class="k">Swap</span><b>${m.swap_total?fmtB(m.swap_used)+' / '+fmtB(m.swap_total):'未配置'}</b></div>`;
 document.getElementById('disk').innerHTML=d.disks.map(x=>
  `<div class="mut">挂载点 ${esc(x.mount)} · 已用 ${fmtB(x.used)} / 共 ${fmtB(x.total)} · 剩余 ${fmtB(x.free)}</div>
   <div style="display:flex;align-items:baseline;gap:10px"><span class="big">${x.percent}%</span></div>
   <div class="bar"><i class="${barCls(x.percent)}" style="width:${x.percent}%"></i></div>`).join('');
 const n=d.network,e=n.egress||{};
 document.getElementById('net').innerHTML=
  `<div class="kv"><span class="k">公网出口 IP</span><b>${esc(e.ip||'-')}</b></div>
   <div class="kv"><span class="k">出口归属</span><b>${esc([e.city,e.region,e.country].filter(Boolean).join(', ')||'-')}</b></div>
   <div class="kv"><span class="k">运营商</span><b>${esc(e.org||'-')}</b></div>
   <div class="kv"><span class="k">默认路由</span><b>${esc(n.default_route||'-')}</b></div>`+
  n.interfaces.filter(i=>i.name!=='lo').map(i=>`<div class="kv"><span class="k">${esc(i.name)} (${esc(i.state||'')})</span><b>${esc((i.addrs||[]).join(', ')||'-')}${i.rx!=null?'<br><span class="mut">↓ '+fmtB(i.rx)+' · ↑ '+fmtB(i.tx)+'</span>':''}</b></div>`).join('');
 document.getElementById('websvc').innerHTML=d.services.length?`<table><tr><th>端口</th><th>监听地址</th><th>进程</th><th>公网状态</th><th>访问 / 操作</th></tr>`+
  d.services.map(x=>`<tr><td><b>${x.port}</b>${x.name?' <span class="mut">'+esc(x.name)+'</span>':''}</td><td>${esc(x.addr)}</td><td>${esc(x.process||'-')}</td>
   <td>${x.published?'<span class="tag">已发布</span>':'<span class="tag no">仅本机</span>'}</td>
   <td>${x.published?`<a href="${esc(x.url)}" target="_blank" rel="noopener">打开服务 ↗</a> <span class="mut">${esc(x.url)}</span><br><button class="btn red" data-act="unpublish" data-port="${x.port}">取消发布</button>`:`<button class="btn green" data-act="publish" data-port="${x.port}">发布到公网</button>`}</td></tr>`).join('')+'</table>':'<div class="mut">当前没有监听中的服务</div>';
 document.getElementById('units').innerHTML=d.systemd.length?`<table><tr><th>服务</th><th>状态</th><th>说明</th><th>操作</th></tr>`+
  d.systemd.map(u=>`<tr><td>${esc(u.unit)}${u.critical?' <span class="mut">(关键)</span>':''}</td><td><span class="tag ${u.active==='active'?'run':'stop'}">${esc(u.active)} / ${esc(u.sub)}</span></td><td class="mut">${esc(u.desc)}</td>
   <td><button class="btn" data-act="svc" data-verb="service_restart" data-unit="${esc(u.unit)}">重启</button>${u.active==='active'?(u.critical?'':`<button class="btn red" data-act="svc" data-verb="service_stop" data-unit="${esc(u.unit)}">停止</button>`):`<button class="btn green" data-act="svc" data-verb="service_start" data-unit="${esc(u.unit)}">启动</button>`}</td></tr>`).join('')+'</table>':'<div class="mut">无</div>';
 document.getElementById('docker').innerHTML=d.docker.length?`<table><tr><th>容器</th><th>镜像</th><th>状态</th><th>端口</th><th>操作</th></tr>`+
  d.docker.map(c=>`<tr><td>${esc(c.name)}</td><td class="mut">${esc(c.image)}</td><td><span class="tag ${c.running?'run':'stop'}">${esc(c.status)}</span></td><td class="mut">${esc(c.ports)}</td>
   <td>${c.running?`<button class="btn" data-act="dock" data-verb="docker_restart" data-name="${esc(c.name)}">重启</button><button class="btn red" data-act="dock" data-verb="docker_stop" data-name="${esc(c.name)}">停止</button>`:`<button class="btn green" data-act="dock" data-verb="docker_start" data-name="${esc(c.name)}">启动</button>`}</td></tr>`).join('')+'</table>':'<div class="mut">当前没有 Docker 容器。以后在这台机器上部署的容器会自动出现在这里。</div>';
}
window._openFleet=window._openFleet||new Set();
function toggleFleet(id){const r=document.getElementById('fd-'+id);if(!r)return;const show=r.style.display==='none';r.style.display=show?'table-row':'none';if(show)window._openFleet.add(id);else window._openFleet.delete(id)}
function fleetDetail(m){const s=m.stats;if(!s)return '<span class="mut">无采集数据</span>';
 const disks=s.disks.map(x=>`${esc(x.mount)}：${fmtB(x.used)}/${fmtB(x.total)}（${x.percent}%）`).join('；');
 const ifs=s.interfaces.filter(i=>i.name!=='lo').map(i=>`${esc(i.name)}[${esc(i.state||'')}] ${esc((i.addrs||[]).join(', '))}`).join('<br>');
 const lis=s.listening.map(p=>`${p.port} · ${esc(p.process||'-')}`).join('<br>')||'无';
 const pub=s.published.map(p=>`<a href="${esc(p.url)}" target="_blank" rel="noopener">${p.port} ↗</a>`).join('、')||'无';
 const dock=s.docker.length?s.docker.map(c=>`${esc(c.name)}（${esc(c.image)}，${esc(c.status)}）`).join('<br>'):'无容器';
 return `<div class="kv"><span class="k">机器 ID</span><b>${esc(m.id)}</b></div>
 <div class="kv"><span class="k">主机名 / 内核</span><b>${esc(s.hostname)} · ${esc(s.kernel)} (${esc(s.arch)})</b></div>
 <div class="kv"><span class="k">CPU 型号</span><b>${esc(s.cpu_model||'-')}</b></div>
 <div class="kv"><span class="k">负载 / 运行时长</span><b>${(s.load||[]).join(' / ')} · ${fmtUp(s.uptime_seconds||0)}</b></div>
 <div class="kv"><span class="k">磁盘</span><b>${disks}</b></div>
 <div class="kv"><span class="k">网卡</span><b>${ifs||'-'}</b></div>
 <div class="kv"><span class="k">默认路由</span><b>${esc(s.default_route||'-')}</b></div>
 <div class="kv"><span class="k">出口归属</span><b>${esc([s.egress.city,s.egress.region,s.egress.country].filter(Boolean).join(', '))} · ${esc(s.egress.org||'')}</b></div>
 <div class="kv"><span class="k">监听端口（端口 · 进程）</span><b>${lis}</b></div>
 <div class="kv"><span class="k">已发布公网服务</span><b>${pub}</b></div>
 <div class="kv"><span class="k">Docker</span><b>${dock}</b></div>
 <div class="kv"><span class="k">systemd</span><b>运行中 ${s.systemd_running} 个${s.systemd_failed&&s.systemd_failed.length?' · 失败：'+esc(s.systemd_failed.join(', ')):' · 无失败'}</b></div>
 <div class="kv"><span class="k">闲置自动暂停</span><b>${m.auto_suspend||'-'} 秒</b></div>`}
function maskLogin(e){e=String(e||'');const at=e.indexOf('@');if(at<0)return e;const local=e.slice(0,at),dom=e.slice(at);const keep=Math.max(0,local.length-8);return local.slice(0,keep)+'********'+dom}
async function copyLogin(btn){const v=btn.getAttribute('data-v')||'';let ok=false;try{await navigator.clipboard.writeText(v);ok=true}catch(e){const ta=document.createElement('textarea');ta.value=v;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();try{ok=document.execCommand('copy')}catch(_){}ta.remove()}
 if(ok){const old=btn.textContent;btn.textContent='已复制 ✓';setTimeout(()=>btn.textContent=old,1200);toast('已复制完整账号')}else{toast('❌ 复制失败，请重试')}}
function renderFleet(d){const el=document.getElementById('fleet');if(!el)return;
 if(!d||!d.machines){el.innerHTML='<div class="mut">暂无舰队快照，等待首次采集…</div>';return}
 const sum=d.summary||{};const ft=document.getElementById('fleetTitle');if(ft&&sum.accounts!=null&&sum.machines!=null)ft.textContent=`🌐 全部机器 · ${sum.accounts} 个账号 / ${sum.machines} 台`;const ageMin=d.generated_at_utc?Math.round((Date.now()-Date.parse(d.generated_at_utc))/60000):null;
 const stale=ageMin!=null&&ageMin>30;
 let h=`<div class="sub" style="margin-bottom:10px">快照时间：${esc(d.generated_at_beijing||'')}（北京时间）${ageMin!=null?` · 约 ${ageMin} 分钟前`:''} · 运行中 <b style="color:#e2e8f0">${sum.running}/${sum.machines}</b> · 已采集 ${sum.collected} 台 · 异常 ${sum.errors} 台${sum.woken?` · 本次自动唤醒 ${sum.woken} 台`:''}${stale?' · <span style="color:#eab308">⚠️ 快照已超过 30 分钟未更新</span>':''}</div>`;
 h+='<table><tr><th>机器</th><th>账号</th><th>系统</th><th>CPU</th><th>内存</th><th>根盘</th><th>公网出口</th><th>已发布服务</th><th></th></tr>';
 for(const m of d.machines){const s=m.stats;const run=m.state==='running';
  const dot=`<span class="dot" style="background:${run?'#22c55e':'#ef4444'}"></span>`;
  if(!s){h+=`<tr><td>${dot}<b>${esc(m.name)}</b></td><td class="mut">${esc(maskLogin(m.account_login))}<button type="button" class="cpbtn" data-v="${esc(m.account_login)}" onclick="copyLogin(this)">复制</button></td><td colspan="6" class="mut">${esc(m.state)}${m.error?' · '+esc(m.error):''}</td><td></td></tr>`;continue}
  const root=(s.disks.find(x=>x.mount==='/')||s.disks[0]||{percent:0});
  const pubs=s.published.length?s.published.map(p=>`<a href="${esc(p.url)}" target="_blank" rel="noopener">${p.port} ↗</a>`).join('<br>'):'<span class="mut">—</span>';
  const open=window._openFleet.has(m.id);
  h+=`<tr><td>${dot}<b>${esc(m.name)}</b>${m.woke?' <span class="tag">本次已唤醒</span>':''}</td><td class="mut">${esc(maskLogin(m.account_login))}<button type="button" class="cpbtn" data-v="${esc(m.account_login)}" onclick="copyLogin(this)">复制</button></td>
  <td class="mut">${esc(s.os)}</td><td>${s.cpu_cores} 核<br><span class="mut">${s.cpu_percent}%</span></td>
  <td>${s.memory.percent}%<br><span class="mut">${fmtB(s.memory.used)}/${fmtB(s.memory.total)}</span></td>
  <td>${root.percent}%<br><span class="mut">${fmtB(root.used)}/${fmtB(root.total)}</span></td>
  <td>${esc(s.egress.ip||'-')}<br><span class="mut">${esc([s.egress.city,s.egress.country].filter(Boolean).join(', '))}</span></td>
  <td>${pubs}</td><td><button class="btn gray" data-act="fleet_toggle" data-id="${esc(m.id)}">详情</button></td></tr>
  <tr id="fd-${m.id}" style="display:${open?'table-row':'none'}"><td colspan="9" style="background:#16213a">${fleetDetail(m)}</td></tr>`}
 h+='</table>';el.innerHTML=h}
async function refreshFleet(){try{const r=await fetch('/api/fleet');if(r.status===401){location.reload();return}renderFleet(await r.json())}catch(e){}}
refresh();setInterval(refresh,5000);refreshFleet();setInterval(refreshFleet,60000);
</script></body></html>"""


def _token_eq(a, b):
    return hmac.compare_digest(str(a or ""), str(b or ""))


def _cookie_header():
    return f"panel_token={TOKEN}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax"


def audit(msg):
    print(f"[audit] {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} {msg}", flush=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "InfoPanel/1.0"

    def log_message(self, fmt, *args):
        pass

    def _authed(self, parsed, qs):
        if not TOKEN:
            return True
        cookie = self.headers.get("Cookie", "")
        m = re.search(r"panel_token=([A-Za-z0-9_\-]+)", cookie)
        if m and _token_eq(m.group(1), TOKEN):
            return True
        if _token_eq(self.headers.get("X-Panel-Token", ""), TOKEN):
            return True
        return _token_eq((qs.get("token") or [""])[0], TOKEN)

    def _authed_write(self):
        # 写操作只认 X-Panel-Token 头（同源 JS 注入），不认 Cookie，防 CSRF
        if not TOKEN:
            return True
        return _token_eq(self.headers.get("X-Panel-Token", ""), TOKEN)

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        headers = dict(extra or {})
        if "gzip" in (self.headers.get("Accept-Encoding") or "") and len(data) > 1024:
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as g:
                g.write(data)
            data = buf.getvalue()
            headers["Content-Encoding"] = "gzip"
            headers["Vary"] = "Accept-Encoding"
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        path = parsed.path
        if path == "/health":
            return self._send(200, json.dumps({"ok": True, "version": PANEL_VERSION}), "application/json")
        if path == "/auth":
            # 旧的 GET 登录链接兼容：种 Cookie 后跳回首页（新登录表单走 POST）
            token = (qs.get("token") or [""])[0]
            if TOKEN and not _token_eq(token, TOKEN):
                return self._send(403, "令牌不正确")
            return self._send(302, "", extra={"Location": "/", "Set-Cookie": _cookie_header()})
        if not self._authed(parsed, qs):
            if path.startswith("/api/"):
                return self._send(401, json.dumps({"ok": False, "message": "未登录"}), "application/json")
            return self._send(200, LOGIN_HTML)
        if (qs.get("token") or [""])[0] and _token_eq((qs.get("token") or [""])[0], TOKEN):
            return self._send(302, "", extra={"Location": "/", "Set-Cookie": _cookie_header()})
        if path == "/":
            return self._send(200, PANEL_HTML.replace("__PANEL_VERSION__", PANEL_VERSION))
        if path == "/api/stats":
            return self._send(200, json.dumps(get_stats(), ensure_ascii=False), "application/json")
        if path == "/api/fleet":
            try:
                with open(FLEET_FILE, "rb") as f:
                    raw = f.read()
            except Exception:
                return self._send(200, json.dumps({"ok": False, "message": "暂无舰队快照"}), "application/json")
            etag = '"' + hashlib.sha256(raw).hexdigest()[:16] + '"'
            if (self.headers.get("If-None-Match") or "") == etag:
                return self._send(304, b"", "application/json", extra={"ETag": etag})
            return self._send(200, raw, "application/json", extra={"ETag": etag})
        return self._send(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/auth":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                form = parse_qs(self.rfile.read(length).decode() or "")
            except Exception:
                form = {}
            token = (form.get("token") or [""])[0]
            if TOKEN and not _token_eq(token, TOKEN):
                audit(f"login_failed from={self.client_address[0]}")
                return self._send(403, "令牌不正确")
            audit(f"login_ok from={self.client_address[0]}")
            return self._send(302, "", extra={"Location": "/", "Set-Cookie": _cookie_header()})
        if parsed.path != "/api/action":
            return self._send(404, "not found")
        if not self._authed_write():
            return self._send(401, json.dumps({"ok": False, "message": "写操作需要 X-Panel-Token 头"}), "application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode() or "{}")
        except Exception:
            return self._send(400, json.dumps({"ok": False, "message": "请求体无效"}), "application/json")
        result = do_action(body)
        audit(f"action from={self.client_address[0]} body={json.dumps(body, ensure_ascii=False)[:200]} ok={result.get('ok')} msg={str(result.get('message', ''))[:120]}")
        return self._send(200, json.dumps(result, ensure_ascii=False), "application/json")


if __name__ == "__main__":
    threading.Thread(target=_stats_refresh_loop, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"panel v{PANEL_VERSION} listening on 127.0.0.1:{PORT}, machine suffix={SUFFIX}, token={'set' if TOKEN else 'NONE'}", flush=True)
    server.serve_forever()
