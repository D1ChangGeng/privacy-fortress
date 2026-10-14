# -*- coding: utf-8 -*-
# 每日信号面巡检 - 出口一致性 / DNS泄漏面 / WebRTC STUN / CF校验 / IPv6 / 系统信号 / killswitch / 检测站可达性
# 纯标准库实现; 走系统默认路由(TUN接管), 不额外设代理.
# 基线与哨兵全部经环境变量注入, 本脚本不含任何机器相关的硬编码值:
#   SIGNAL_BASELINE_IP     住宅出口基线(必填, 未设置时出口项记WARN)
#   SIGNAL_MACHINE_GUID    轮换后的 MachineGuid 基线(可选, 未设置时该项只记录不判定)
#   SIGNAL_OLD_GUID        旧泄露值(可选, 设置后与基线共同判定漂移)
#   SIGNAL_CULTURE         区域格式基线(默认 ja-JP)
#   SIGNAL_KILLSWITCH      JSON: {"<防火墙规则名>": ["<Appx包名>", "<exe名>"], ...}(可选, 未设置时跳过)
import json, os, re, socket, ssl, struct, subprocess, sys, time, urllib.request
from datetime import datetime

EXPECTED_EXIT = os.environ.get("SIGNAL_BASELINE_IP", "")
EXPECTED_GUID = os.environ.get("SIGNAL_MACHINE_GUID", "")
OLD_GUID = os.environ.get("SIGNAL_OLD_GUID", "")
EXPECTED_CULTURE = os.environ.get("SIGNAL_CULTURE", "ja-JP")
KILLSWITCH_TARGETS = json.loads(os.environ.get("SIGNAL_KILLSWITCH") or "{}")
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"}
TIMEOUT = 12

SITES = [
    ("https://ip.net.coffee/claude/", "Claude视角风险面(整体)"),
    ("https://ip.net.coffee/dns/", "DNS泄漏总检(深度测试需浏览器)"),
    ("https://ip.net.coffee/webrtc/", "WebRTC潜在IP泄漏"),
    ("https://ip.net.coffee/cloudflare/", "Cloudflare校验"),
    ("https://iplark.com/", "C段画像/AI检测/代理检测/IPv6"),
    ("https://ippure.com/", "人机占比"),
    ("https://ippure.com/claude.html", "ippure Claude面"),
    ("https://ippure.com/DNS-Leak-Detect.html", "ippure DNS泄漏检测"),
    ("https://cc.mastersgo.cc/", "过关清单"),
]
MANUAL_REVIEW = [
    "【必测】ippure.com/DNS-Leak-Detect.html DNS泄漏检测(用户指定每次必测)",
    "ip.net.coffee/dns 深度测试(需浏览器点击; 测前必须确认TUN已开启, 否则校园网DNS直连会误报泄漏)",
    "ip.net.coffee/claude 过关项逐条核对",
    "iplark AI检测/代理检测应保持'检测失败'",
    "iplark IPv6出口应保持'获取失败'",
    "cc.mastersgo.cc 未过关项清单",
    "ippure.com/claude.html 风险分应<40且语言/字体信号不命中中国",
    "【月度】GitHub commit 搜索 author-email 两个旧gmail变体验证 total=0 (gh api search/commits; 索引延迟以仓库git log为准)",
]

results = []  # (name, status PASS/WARN/FAIL/INFO, detail)
def add(name, status, detail=""):
    results.append((name, status, detail))

def http_get(url, extra=None):
    h = dict(UA)
    if extra:
        h.update(extra)
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.status, r.read().decode("utf-8", "replace")

def find_ips(text):
    out = set()
    for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or ""):
        if all(0 <= int(o) <= 255 for o in m.split(".")):
            out.add(m)
    return sorted(out)

def is_public(ip):
    if ip.startswith(("10.", "192.168.", "127.", "169.254.", "198.18.", "198.19.")) :
        return False
    for p in ("172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."):
        if ip.startswith(p):
            return False
    if ip.startswith("224.") or ip.startswith("255."):
        return False
    return True

def probe_exit_ip():
    try:
        s, ip = http_get("https://api.ipify.org")
        ip = ip.strip()
        if not EXPECTED_EXIT:
            st = "WARN" if is_public(ip) else "FAIL"
            add("出口IP(ipify)", st, f"实测={ip} 基线未配置(SIGNAL_BASELINE_IP), 无法比对" + ("" if is_public(ip) else " 且非公网,异常"))
        else:
            st = "PASS" if ip == EXPECTED_EXIT else ("FAIL" if is_public(ip) else "WARN")
            add("出口IP(ipify)", st, f"实测={ip} 基线={EXPECTED_EXIT}")
        return ip
    except Exception as e:
        add("出口IP(ipify)", "FAIL", f"获取失败: {e}")
        return None

def probe_cf_trace():
    try:
        s, txt = http_get("https://www.cloudflare.com/cdn-cgi/trace")
        kv = dict(l.split("=", 1) for l in txt.strip().splitlines() if "=" in l)
        ip, loc, tls = kv.get("ip", "?"), kv.get("loc", "?"), kv.get("tls", "?")
        if not EXPECTED_EXIT:
            add("Cloudflare trace", "WARN", f"ip={ip} loc={loc} 基线未配置, 仅记录")
        else:
            st = "PASS" if (loc == "JP" and ip == EXPECTED_EXIT) else ("WARN" if loc == "JP" else "FAIL")
            add("Cloudflare trace", st, f"ip={ip} loc={loc} tls={tls}")
    except Exception as e:
        add("Cloudflare trace", "FAIL", f"获取失败: {e}")

def probe_ipinfo():
    try:
        s, txt = http_get("https://ipinfo.io/json")
        d = json.loads(txt)
        cc, city, org = d.get("country"), d.get("city"), d.get("org", "")
        st = "PASS" if cc == "JP" else "FAIL"
        add("出口归属(ipinfo)", st, f"{city}/{cc} {org}")
    except Exception as e:
        add("出口归属(ipinfo)", "FAIL", f"获取失败: {e}")

def stun_probe(server="stun.l.google.com", port=19302):
    """最小STUN绑定请求, 测WebRTC同款UDP泄漏面"""
    tid = struct.pack(">L", 0x2112A442) + os.urandom(12)
    msg = struct.pack(">HHL", 0x0001, 0, 0x2112A442) + tid[4:]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        s.sendto(msg, (socket.gethostbyname(server), port))
        data, _ = s.recvfrom(1024)
        if len(data) < 20:
            return None, "响应过短"
        # 找 XOR-MAPPED-ADDRESS (0x0020)
        i = 20
        while i + 4 <= len(data):
            atype, alen = struct.unpack(">HH", data[i:i+4])
            if atype == 0x0020 and alen >= 8:
                fam = struct.unpack(">H", data[i+5:i+7])[0]
                xip = struct.unpack(">L", data[i+8:i+12])[0]
                ip = socket.inet_ntoa(struct.pack(">L", xip ^ 0x2112A442))
                return ip, "ok"
            i += 4 + alen
        return None, "无XOR-MAPPED-ADDRESS"
    except socket.timeout:
        return None, "超时"
    except Exception as e:
        return None, str(e)
    finally:
        s.close()

def probe_stun():
    ip, note = stun_probe()
    if ip is None:
        add("WebRTC STUN泄漏面", "WARN", f"探测失败({note}) - 需浏览器复核ip.net.coffee/webrtc")
        return
    if not EXPECTED_EXIT:
        add("WebRTC STUN泄漏面", "WARN", f"STUN看到的IP={ip} 基线未配置, 仅记录")
    elif ip == EXPECTED_EXIT:
        add("WebRTC STUN泄漏面", "PASS", f"STUN看到的IP={ip}(经隧道, 无真实IP泄漏)")
    elif is_public(ip):
        add("WebRTC STUN泄漏面", "FAIL", f"STUN看到非基线公网IP={ip} - 疑似真实IP泄漏!")
    else:
        add("WebRTC STUN泄漏面", "WARN", f"STUN看到私网/保留IP={ip}")

def probe_ipv6():
    try:
        s, ip = http_get("https://api64.ipify.org")
        ip = ip.strip()
        if ":" in ip:
            add("IPv6出口", "FAIL", f"获取到IPv6全局地址={ip} - 存在IPv6泄漏面!")
        else:
            add("IPv6出口", "PASS", f"api64仅返回IPv4={ip}(IPv6出口不可得)")
    except Exception as e:
        add("IPv6出口", "PASS", f"IPv6出站不可用({type(e).__name__}) - 符合预期")

def probe_dns_consistency():
    try:
        sys_r = sorted(set(x[4][0] for x in socket.getaddrinfo("api.anthropic.com", 443)))
        s, txt = http_get("https://1.1.1.1/dns-query?name=api.anthropic.com&type=A",
                          extra={"Accept": "application/dns-json"})
        cf_r = sorted(a.get("data") for a in json.loads(txt).get("Answer", []) if a.get("type") == 1)
        if sys_r and all(i.startswith("198.18.") for i in sys_r):
            add("DNS解析一致性", "PASS", f"系统解析器返回fake-ip {sys_r}(fake-ip模式预期行为), 真实解析={cf_r}")
        elif sys_r and cf_r and set(sys_r) == set(cf_r):
            add("DNS解析一致性", "PASS", f"系统解析器与Cloudflare一致: {sys_r}")
        else:
            add("DNS解析一致性", "WARN", f"系统={sys_r} CF={cf_r} - 解析漂移, 需复核")
    except Exception as e:
        add("DNS解析一致性", "WARN", f"探测失败: {e}")

def probe_sites():
    for url, desc in SITES:
        try:
            s, body = http_get(url)
            ips = [i for i in find_ips(body or "") if is_public(i)]
            foreign = [i for i in ips if i != EXPECTED_EXIT]
            note = f"HTTP {s}"
            if foreign:
                note += f" | 页面内嵌非基线公网IP: {foreign[:5]}(多为站点自身CDN, 人工复核)"
            add(f"检测站可达: {desc}", "PASS" if s == 200 else "WARN", note)
        except Exception as e:
            add(f"检测站可达: {desc}", "WARN", f"访问失败: {type(e).__name__} {e}")

def probe_tun():
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty ifIndex"],
            capture_output=True, text=True, timeout=15).stdout.strip()
        idx = out.splitlines()[-1].strip() if out else ""
        out2 = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {$_.ifIndex -eq " + idx + "} | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, timeout=15).stdout.strip()
        name = out2.splitlines()[-1].strip() if out2 else "?"
        st = "PASS" if "Meta" in name or "FengWo" in name else "FAIL"
        add("TUN接管状态", st, f"默认路由网卡={name}(ifIndex={idx})")
    except Exception as e:
        add("TUN接管状态", "WARN", f"检测失败: {e}")

def probe_config_integrity():
    """蜂窝配置完整性哨兵: 客户端升级/重启漂移检测。读生成的config.yaml核验三项关键配置"""
    try:
        cy = os.path.join(os.environ.get("LOCALAPPDATA", ""), "..", "Roaming", "com.follow")
        cy = os.path.abspath(os.path.join(cy, "蜂窝加速器", "config.yaml"))
        txt = open(cy, encoding="utf-8").read()
        ok_ns = bool(re.search(r'^  nameserver:\n    - "127\.0\.0\.1"\n', txt, re.M))
        ok_hijack = "dns-hijack" in txt and "any:53" in txt
        ok_match = "MATCH,蜂窝链式代理" in txt or "MATCH,蜂窝" in txt
        ok_doh = ("DOMAIN-SUFFIX,doh.pub,蜂窝链式代理" in txt
                  and "DOMAIN-SUFFIX,alidns.com,蜂窝链式代理" in txt
                  and "DOMAIN-SUFFIX,doh.pub,DIRECT" not in txt
                  and "DOMAIN-SUFFIX,alidns.com,DIRECT" not in txt
                  and "223.5.5.5" in (re.search(r"proxy-server-nameserver:\n((?:    .+\n)+)", txt) or re.match("", "")).group(0))
        bad = []
        if not ok_ns: bad.append("nameserver!=127.0.0.1")
        if not ok_hijack: bad.append("dns-hijack丢失")
        if not ok_match: bad.append("MATCH兜底丢失")
        if not ok_doh: bad.append("DoH硬化被回滚(doh.pub/alidns回到DIRECT)")
        if bad:
            add("配置完整性哨兵", "FAIL", "客户端漂移: " + ",".join(bad) + " - DNS查询面可能重新暴露!")
        else:
            add("配置完整性哨兵", "PASS", "nameserver=127.0.0.1 / dns-hijack / MATCH兜底 / DoH硬化 四项在位")
    except Exception as e:
        add("配置完整性哨兵", "WARN", f"检查失败: {e}")

def probe_whitelist_snapshot():
    """IP直连白名单快照哨兵(2026-09-29终版): 3条必需在位 + 3条已清除境外IP不得回潮"""
    try:
        cy = os.path.join(os.environ.get("LOCALAPPDATA", ""), "..", "Roaming", "com.follow")
        cy = os.path.abspath(os.path.join(cy, "蜂窝加速器", "config.yaml"))
        txt = open(cy, encoding="utf-8").read()
        required = [
            "IP-CIDR,223.5.5.5/32,DIRECT,no-resolve",   # 核心引导解析生命线
            "IP-CIDR,10.108.25.251/32,DIRECT",          # 校园网认证内网
            "IP-CIDR,39.107.142.158/32,DIRECT",         # 阿里北京(唯一真实国内IP, CN地域锁保险)
        ]
        forbidden = [
            "129.226.103.123",  # 腾讯香港(2026-09-29清除)
            "43.154.254.142",   # 腾讯香港(2026-09-29清除)
            "154.64.230.252",   # 美国洛杉矶(2026-09-29清除, 误标国内)
        ]
        missing = [r for r in required if r not in txt]
        revived = [f for f in forbidden if f in txt]
        if missing or revived:
            parts = []
            if missing: parts.append("必需条目缺失: " + ",".join(missing))
            if revived: parts.append("境外IP直连回潮: " + ",".join(revived))
            add("IP白名单快照", "FAIL", "；".join(parts) + " - 直连通道构成已偏离基线!")
        else:
            add("IP白名单快照", "PASS", "3条必需IP直连在位, 3条已清除境外IP未回潮")
    except Exception as e:
        add("IP白名单快照", "WARN", f"检查失败: {e}")

def probe_forwarder():
    """本地DNS转发器健康检查: 127.0.0.1:53 应答真实解析=PASS; 无应答=SERVFAIL/拒接=FAIL(核心会回落223.5.5.5, 查询面重新暴露)"""
    import random, struct as _st
    tid = random.randint(0, 65535)
    qname = b"\x07example\x03com\x00"
    q = _st.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname + _st.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(6)
    try:
        s.sendto(q, ("127.0.0.1", 53))
        data, _ = s.recvfrom(512)
        if len(data) < 12:
            add("DNS转发器健康", "FAIL", "响应过短")
            return
        rcode = data[3] & 0x0F
        if rcode == 0:
            add("DNS转发器健康", "PASS", "127.0.0.1:53 应答正常(境外查询经DoH东京出口)")
        elif rcode == 2:
            add("DNS转发器健康", "FAIL", "SERVFAIL(上游1.1.1.1不可达) - 核心已回落223.5.5.5, 查询面暴露!")
        else:
            add("DNS转发器健康", "WARN", f"RCODE={rcode}")
    except socket.timeout:
        add("DNS转发器健康", "FAIL", "无响应(转发器未运行?) - 核心已回落223.5.5.5, 查询面暴露!")
    except ConnectionRefusedError:
        add("DNS转发器健康", "FAIL", "连接被拒(转发器未运行) - 核心已回落223.5.5.5, 查询面暴露!")
    except Exception as e:
        add("DNS转发器健康", "WARN", f"探测失败: {e}")
    finally:
        s.close()

def probe_system_signals():
    """系统/浏览器/git 信号面哨兵: 系统重装/客户端升级/人为改动导致的信号漂移检测.
    MachineGuid 判定需 SIGNAL_MACHINE_GUID(未配置时只记录当前值不判定); 时区/区域基线按掩护国调整."""
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$o=[ordered]@{};"
        "$o.tz=(tzutil /g);"
        "$o.guid=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid;"
        "$o.rtc=(Get-ItemProperty 'HKCU:\\Software\\Policies\\Google\\Chrome').WebRtcIPHandling;"
        "$o.locale=(Get-ItemProperty 'HKCU:Control Panel\\International').LocaleName;"
        "$gc=$env:USERPROFILE+'\\.gitconfig';"
        "$o.gitmail= if(Test-Path $gc){([regex]::Match((Get-Content $gc -Raw),'email\\s*=\\s*\\S+')).Value}else{'<no gitconfig>'};"
        "$svcs=(Get-Service DiagTrack,dmwappushservice | ForEach-Object { $_.Name+':'+$_.Status+':'+$_.StartType }) -join ';';"
        "$o.telemetry=$svcs;"
        "$o | ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=30).stdout.strip()
        d = json.loads(out[out.index("{"):])
        checks = [
            ("系统时区", d.get("tz") == "Tokyo Standard Time", f"tzutil={d.get('tz')} (期望 Tokyo Standard Time; 其他掩护国改本判据)"),
        ]
        if EXPECTED_GUID:
            checks.append(("MachineGuid", d.get("guid") == EXPECTED_GUID and (not OLD_GUID or d.get("guid") != OLD_GUID),
             f"当前={d.get('guid')} (期望已配置基线; 不得回退旧泄露值)"))
        else:
            checks.append(("MachineGuid", None, f"当前={d.get('guid')} (SIGNAL_MACHINE_GUID 未配置, 仅记录)"))
        checks += [
            ("Chrome WebRTC策略", d.get("rtc") == "disable_non_proxied_udp",
             f"WebRtcIPHandling={d.get('rtc')!r} (期望 disable_non_proxied_udp)"),
            ("区域格式一致性", d.get("locale") == EXPECTED_CULTURE,
             f"LocaleName={d.get('locale')} (期望 {EXPECTED_CULTURE}; 货币/日期格式与出口国一致)"),
            ("git全局身份", "gmail.com" not in (d.get("gitmail") or ""),
             f"{d.get('gitmail')} (不得含真实邮箱域名)"),
            ("Windows遥测服务", "Stopped:Disabled" in (d.get("telemetry") or "") and "Running" not in (d.get("telemetry") or ""),
             d.get("telemetry", "?")),
        ]
        for name, ok, detail in checks:
            st = "WARN" if ok is None else ("PASS" if ok else "FAIL")
            add(f"系统信号: {name}", st, detail)
    except Exception as e:
        add("系统信号哨兵", "WARN", f"检查失败: {e}")

def probe_killswitch():
    """防火墙 killswitch 哨兵: AI客户端仅允许连 127.0.0.1 + 198.18/15;
    版本漂移检测 = 规则程序路径 vs 当前 Appx 安装位置不一致即 FAIL (商店自动更新会改版本目录).
    目标经 SIGNAL_KILLSWITCH 注入: {"<防火墙规则名>": ["<Appx包名>", "<exe名>"]}; 未配置则跳过."""
    if not KILLSWITCH_TARGETS:
        add("Killswitch 哨兵", "WARN", "SIGNAL_KILLSWITCH 未配置, 跳过")
        return
    rule_names = ",".join("'{}'".format(k) for k in KILLSWITCH_TARGETS)
    pkg_names = ",".join("'{}'".format(v[0]) for v in KILLSWITCH_TARGETS.values())
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$out = [ordered]@{};"
        "foreach ($k in " + rule_names + ") {"
        "  $r = Get-NetFirewallRule -DisplayName $k;"
        "  if (-not $r) { $out[$k] = 'MISSING'; continue };"
        "  $out[$k] = [ordered]@{ enabled = ($r.Enabled -eq 'True');"
        "    prog = ($r | Get-NetFirewallApplicationFilter).Program }"
        "};"
        "$locs = [ordered]@{};"
        "foreach ($p in (Get-AppxPackage | Where-Object { $_.Name -in @(" + pkg_names + ") })) {"
        "  $locs[$p.Name] = $p.InstallLocation"
        "};"
        "[ordered]@{ rules = $out; locs = $locs } | ConvertTo-Json -Compress"
    )
    EXE = KILLSWITCH_TARGETS
    try:
        raw = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=40).stdout.strip()
        d = json.loads(raw[raw.index("{"):])
        rules, locs = d.get("rules", {}), d.get("locs", {})
        for k, (pkg, exe) in EXE.items():
            v = rules.get(k)
            if v == "MISSING" or v is None:
                add(f"Killswitch: {k}", "FAIL", "防火墙规则缺失 - AI客户端失去断连保护!")
                continue
            loc = locs.get(pkg, "")
            expect = os.path.join(loc, "app", exe) if loc else "NOPKG"
            if not loc:
                add(f"Killswitch: {k}", "WARN", f"未找到 {pkg} 包, 无法比对版本")
            elif v.get("prog") == expect:
                add(f"Killswitch: {k}", "PASS" if v.get("enabled") else "WARN",
                    f"规则在位 enabled={v.get('enabled')}")
            else:
                add(f"Killswitch: {k}", "FAIL",
                    f"版本漂移: 规则={v.get('prog')} 当前={expect} - 重跑 guard/killswitch-install.ps1 刷新")
    except Exception as e:
        add("Killswitch 哨兵", "WARN", f"检查失败: {e}")

def main():
    probe_tun()
    exit_ip = probe_exit_ip()
    probe_cf_trace()
    probe_ipinfo()
    probe_stun()
    probe_ipv6()
    probe_dns_consistency()
    probe_config_integrity()
    probe_whitelist_snapshot()
    probe_forwarder()
    probe_system_signals()
    probe_killswitch()
    probe_sites()

    p = sum(1 for _, s, _ in results if s == "PASS")
    w = sum(1 for _, s, _ in results if s == "WARN")
    f = sum(1 for _, s, _ in results if s == "FAIL")
    verdict = "FAIL" if f else ("WARN" if w else "PASS")
    fails = [f"{n}: {d}" for n, s, d in results if s == "FAIL"]

    date = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"# 每日信号面巡检报告 {date}", "", f"**总判定: {verdict}** (PASS={p} WARN={w} FAIL={f})", "",
             "| 检查项 | 结果 | 详情 |", "|---|---|---|"]
    for n, s, d in results:
        lines.append(f"| {n} | {s} | {d} |")
    lines += ["", "## 需人工浏览器复核项"] + [f"- {m}" for m in MANUAL_REVIEW]

    ws = os.environ.get("DAIMON_BLUEPRINT_AUTOMATION_WORKSPACE_PATH") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "workspace")
    ws = os.path.abspath(ws)
    os.makedirs(os.path.join(ws, "reports"), exist_ok=True)
    rpt = os.path.join(ws, "reports", f"daily-signal-scan-{datetime.now().strftime('%Y-%m-%d')}.md")
    with open(rpt, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return {"artifact": {
        "date": date, "verdict": verdict, "pass": p, "warn": w, "fail": f,
        "exit_ip": exit_ip or "", "report_file": rpt,
        "failures": fails, "manual_review": MANUAL_REVIEW,
    }}

def run(ctx):
    return main()

if __name__ == "__main__":
    print(json.dumps(main(), ensure_ascii=False, indent=2))
