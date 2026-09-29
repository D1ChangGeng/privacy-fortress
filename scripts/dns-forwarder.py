# -*- coding: utf-8 -*-
# 本地DNS转发器: 127.0.0.1:53 -> DoH(默认 1.1.1.1)
# 用途: 代理核心 nameserver 首查指向本机, 境外域名查询全程经隧道由出口地发出,
#       本地网络的 UDP/53 透明拦截与 ECS 子网泄漏同时闭合.
# 韧性: 上游失败返回 SERVFAIL, 核心按既定回落配置转用国内 DNS, 联网不断.
# 配置: 环境变量 DOH_UPSTREAM (默认 https://1.1.1.1/dns-query), FORWARDER_PORT (默认 53)
import os, socket, socketserver, ssl, threading, urllib.request

DOH = os.environ.get("DOH_UPSTREAM", "https://1.1.1.1/dns-query")
PORT = int(os.environ.get("FORWARDER_PORT", "53"))
TIMEOUT = 10

def doh_query(msg: bytes) -> bytes:
    req = urllib.request.Request(
        DOH, data=msg,
        headers={"Content-Type": "application/dns-message",
                 "Accept": "application/dns-message",
                 "User-Agent": "dns-forwarder/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read()

def servfail(msg: bytes) -> bytes:
    # DNS header: copy ID, set QR=1 RCODE=2, QDCOUNT=0 即可让客户端判定失败
    if len(msg) < 12:
        return b""
    hdr = bytearray(msg[:12])
    hdr[2] = 0x81; hdr[3] = 0x82  # QR + RD + RA + SERVFAIL
    hdr[4:6] = b"\x00\x00"; hdr[6:12] = b"\x00" * 6
    return bytes(hdr)

class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            ans = doh_query(data)
        except Exception:
            ans = servfail(data)
        if ans:
            sock.sendto(ans, self.client_address)

class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        try:
            conn.settimeout(TIMEOUT)
            hdr = conn.recv(2)
            if len(hdr) < 2:
                return
            ln = int.from_bytes(hdr, "big")
            data = b""
            while len(data) < ln:
                chunk = conn.recv(ln - len(data))
                if not chunk:
                    return
                data += chunk
            try:
                ans = doh_query(data)
            except Exception:
                ans = servfail(data)
            if ans:
                conn.sendall(len(ans).to_bytes(2, "big") + ans)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

def main():
    udp = socketserver.ThreadingUDPServer(("127.0.0.1", PORT), UDPHandler)
    tcp = socketserver.ThreadingTCPServer(("127.0.0.1", PORT), TCPHandler)
    tcp.allow_reuse_address = True
    t = threading.Thread(target=tcp.serve_forever, daemon=True)
    t.start()
    print(f"dns-forwarder: listening on 127.0.0.1:{PORT} (UDP+TCP), upstream {DOH}", flush=True)
    udp.serve_forever()

if __name__ == "__main__":
    main()
