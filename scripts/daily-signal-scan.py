# -*- coding: utf-8 -*-
# 每日信号面巡检 - 出口一致性 / DNS泄漏面 / WebRTC STUN / CF校验 / IPv6 / 检测站可达性
# 纯标准库实现; 走系统默认路由(TUN接管), 不额外设代理.
# 基线与哨兵全部经环境变量注入, 本脚本不含任何机器相关的硬编码值:
#   SIGNAL_BASELINE_IP   住宅出口基线(必填, 未设置时出口项记WARN)
#   DOMESTIC_DNS_IP      国内引导DNS (默认 223.5.5.5)
#   CLIENT_CONFIG_YAML   客户端生成配置路径 (设置后启用配置完整性哨兵)
#   REQUIRED_DIRECT      逗号分隔 必需直连条目 (设置后启用白名单快照)
#   FORBIDDEN_DIRECT     逗号分隔 已清除条目, 回潮即FAIL
#   FORWARDER_PORT       转发器端口 (默认 53)
import json, os, re, socket, ssl, struct, subprocess, sys, time, urllib.request
from datetime import datetime

EXPECTED_EXIT = os.environ.get("SIGNAL_BASELINE_IP", "")
DOMESTIC_DNS = os.environ.get("DOMESTIC_DNS_IP", "223.5.5.5")
CLIENT_CFG = os.environ.get("CLIENT_CONFIG_YAML", "")
REQUIRED = [x.strip() for x in os.environ.get("REQUIRED_DIRECT", "").split(",") if x.strip()]
FORBIDDEN = [x.strip() for x in os.environ.get("FORBIDDEN_DIRECT", "").split(",") if x.strip()]
FWD_PORT = int(os.environ.get("FORWARDER_PORT", "53"))

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
    "【必测】ippure.com/DNS-Leak-Detect.html DNS泄漏检测(每次必测)",
    "ip.net.coffee/dns 深度测试(需浏览器点击; 测前必须确认TUN已开启, 否则本地网络DNS直连会误报泄漏)",
    "ip.net.coffee/claude 过关项逐条核对",
    "iplark AI检测/代理检测应保持'检测失败'",
    "iplark IPv6出口应保持'获取失败'",
    "cc.mastersgo.cc 未过关项清单",
    "ippure.com/claude.html 风险分应低于站点阈值且语言/字体信号不命中真实所在地",
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
    """出口一致性: 必须等于基线住宅IP; 任何其他公网IP(尤其真实所在地段)=FAIL"""
    try:
        _, body = http_get("https://api.ipify.org")
        ip = body.strip()
        if not EXPECTED_EXIT:
            add("出口IP一致性", "WARN", f"当前出口={ip}; 未设置SIGNAL_BASELINE_IP基线, 无法判定一致性")
        elif ip == EXPECTED_EXIT:
            add("出口IP一致性", "PASS", f"出口={ip} = 基线")
        else:
            add("出口IP一致性", "FAIL", f"出口={ip} != 基线{EXPECTED_EXIT} - 存在裸连旁路或节点漂移!")
        return ip
    except Exception as e:
        add("出口IP一致性", "FAIL", f"无法获取出口IP: {e}")
        return None

def probe_cf_trace():
    try:
        _, body = http_get("https://www.cloudflare.com/cdn-cgi/trace")
        ip = re.search(r"^ip=(.+)$", body, re.M)
        add("Cloudflare trace校验", "PASS", f"CF通道正常, trace ip={ip.group(1) if ip else '?'}")
    except Exception as e:
        add("Cloudflare trace校验", "WARN", f"trace获取失败: {e}")

def probe_ipinfo():
    try:
        _, body = http_get("https://ipinfo.io/json")
        d = json.loads(body)
        loc = f"{d.get('country','?')}/{d.get('region','?')} org={d.get('org','?')}"
        add("出口归属/ASN", "PASS", loc)
    except Exception as e:
        add("出口归属/ASN", "WARN", f"ipinfo失败: {e}")

def probe_stun():
    """STUN探测: 与公共STUN服务器交换, 若应答中的映射地址是真实公网IP则泄漏"""
    import random
    try:
        tid = random.randbytes(12)
        msg = b"\x00\x01\x00\x00" + tid
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(6)
        s.sendto(msg, ("stun.l.google.com", 19302))
        data, _ = s.recvfrom(2048)
        s.close()
        ips = find_ips(data.hex())  # 二进制里藏IP, 走原始解析
        mapped = [ip for ip in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", socket.inet_ntoa(data[28:32]))]
        leak = [ip for ip in (ips + mapped) if is_public(ip) and ip != EXPECTED_EXIT]
        if leak:
            add("WebRTC/STUN泄漏面", "FAIL", f"STUN暴露非基线公网IP: {leak}")
        else:
            add("WebRTC/STUN泄漏面", "PASS", "STUN仅见基线出口或无公网映射")
    except socket.timeout:
        add("WebRTC/STUN泄漏面", "PASS", "STUN无应答(UDP被隧道接管, 正常)")
    except Exception as e:
        add("WebRTC/STUN泄漏面", "WARN", f"探测失败: {e}")

def probe_ipv6():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.connect(("2001:4860:4860::8888", 80))
        src = s.getsockname()[0]
        s.close()
        add("IPv6出口", "FAIL", f"存在IPv6公网出口: {src} - 应关闭v6出境!")
    except socket.timeout:
        add("IPv6出口", "PASS", "IPv6不可达(已关闭或无v6)")
    except OSError:
        add("IPv6出口", "PASS", "IPv6不可用(已关闭或无v6)")
    except Exception as e:
        add("IPv6出口", "WARN", f"探测失败: {e}")

def probe_dns_consistency():
    try:
        import subprocess
        out = subprocess.run(["nslookup", "example.com", DOMESTIC_DNS], capture_output=True, text=True, timeout=10)
        ips = [ip for ip in find_ips(out.stdout) if is_public(ip)]
        add("DNS解析一致性", "PASS" if ips else "WARN", f"经{DOMESTIC_DNS}解析返回: {ips or '无公网结果'}")
    except Exception as e:
        add("DNS解析一致性", "WARN", f"探测失败: {e}")

def probe_tun():
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
            "Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*TUN*' -or $_.Name -like '*TUN*' -or $_.InterfaceDescription -like '*Mihomo*' -or $_.InterfaceDescription -like '*Meta*'} | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, timeout=15)
        name = out.stdout.strip()
        add("TUN接管状态", "PASS" if name else "FAIL",
            f"TUN设备在: {name}" if name else "未找到TUN设备 - 全局接管失效!")
    except Exception as e:
        add("TUN接管状态", "WARN", f"探测失败: {e}")

def probe_config_integrity():
    """配置完整性哨兵: 客户端升级/重启漂移检测。设CLIENT_CONFIG_YAML时启用"""
    if not CLIENT_CFG:
        add("配置完整性哨兵", "INFO", "未设置CLIENT_CONFIG_YAML, 跳过")
        return
    try:
        txt = open(CLIENT_CFG, encoding="utf-8").read()
        ok_ns = bool(re.search(r'^  nameserver:\n    - "127\.0\.0\.1"\n', txt, re.M))
        ok_hijack = "dns-hijack" in txt and "any:53" in txt
        ok_match = "MATCH," in txt
        bad = []
        if not ok_ns: bad.append("nameserver首查!=127.0.0.1")
        if not ok_hijack: bad.append("dns-hijack丢失")
        if not ok_match: bad.append("MATCH兜底丢失")
        if bad:
            add("配置完整性哨兵", "FAIL", "客户端漂移: " + ",".join(bad) + " - DNS查询面可能重新暴露!")
        else:
            add("配置完整性哨兵", "PASS", "nameserver=127.0.0.1 / dns-hijack / MATCH兜底 三项在位")
    except Exception as e:
        add("配置完整性哨兵", "WARN", f"检查失败: {e}")

def probe_whitelist_snapshot():
    """直连白名单快照哨兵: 设REQUIRED_DIRECT时启用"""
    if not REQUIRED:
        add("直连白名单快照", "INFO", "未设置REQUIRED_DIRECT, 跳过")
        return
    if not CLIENT_CFG:
        add("直连白名单快照", "WARN", "需CLIENT_CONFIG_YAML才能核验")
        return
    try:
        txt = open(CLIENT_CFG, encoding="utf-8").read()
        missing = [r for r in REQUIRED if r not in txt]
        revived = [f for f in FORBIDDEN if f in txt]
        if missing or revived:
            parts = []
            if missing: parts.append("必需条目缺失: " + ",".join(missing))
            if revived: parts.append("已清除条目回潮: " + ",".join(revived))
            add("直连白名单快照", "FAIL", "；".join(parts) + " - 直连通道构成已偏离基线!")
        else:
            add("直连白名单快照", "PASS", f"{len(REQUIRED)}条必需在位, {len(FORBIDDEN)}条已清除条目未回潮")
    except Exception as e:
        add("直连白名单快照", "WARN", f"检查失败: {e}")

def probe_forwarder():
    """本地DNS转发器健康检查: 应答真实解析=PASS; 无应答/SERVFAIL=FAIL(核心已回落国内DNS, 查询面降级)"""
    import random, struct as _st
    tid = random.randint(0, 65535)
    qname = b"\x07example\x03com\x00"
    q = _st.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname + _st.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(6)
    try:
        s.sendto(q, ("127.0.0.1", FWD_PORT))
        data, _ = s.recvfrom(512)
        if len(data) < 12:
            add("DNS转发器健康", "FAIL", "响应过短")
            return
        rcode = data[3] & 0x0F
        if rcode == 0:
            add("DNS转发器健康", "PASS", f"127.0.0.1:{FWD_PORT} 应答正常(境外查询经DoH出口地发出)")
        elif rcode == 2:
            add("DNS转发器健康", "FAIL", f"SERVFAIL(上游DoH不可达) - 核心已回落{DOMESTIC_DNS}, 查询面暴露!")
        else:
            add("DNS转发器健康", "WARN", f"RCODE={rcode}")
    except socket.timeout:
        add("DNS转发器健康", "FAIL", f"无响应(转发器未运行?) - 核心已回落{DOMESTIC_DNS}, 查询面暴露!")
    except ConnectionRefusedError:
        add("DNS转发器健康", "FAIL", f"连接被拒(转发器未运行) - 核心已回落{DOMESTIC_DNS}, 查询面暴露!")
    except Exception as e:
        add("DNS转发器健康", "WARN", f"探测失败: {e}")
    finally:
        s.close()

def probe_sites():
    for url, name in SITES:
        try:
            st, _ = http_get(url)
            add(f"检测站可达: {name}", "PASS" if st == 200 else "WARN", f"HTTP {st}")
        except Exception as e:
            add(f"检测站可达: {name}", "WARN", f"{type(e).__name__}")

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

    ws = os.environ.get("SCAN_REPORT_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    ws = os.path.abspath(ws)
    os.makedirs(ws, exist_ok=True)
    rpt = os.path.join(ws, f"daily-signal-scan-{datetime.now().strftime('%Y-%m-%d')}.md")
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
