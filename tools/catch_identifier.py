#!/usr/bin/env python3
"""一键帮他抓出 ``x-vehicle-identifier``（Windows / macOS / Linux 通用）。

它做的事：

1. 在本机开一个 mitmproxy 代理（默认 8080 端口）；
2. 在 8081 端口开一个极简网页，手机用它确认「代理 + 证书」是否已经通了；
3. 盯着所有发往 ``*.geely.com`` / ``*.zeekrlife.com`` 的请求，一旦发现
   ``x-vehicle-identifier`` 就把那 44 个字符打进控制台，同时写进
   ``vehicle_identifier.txt``，并把 8081 那个网页从「等待中」翻成「抓到啦」。

用户只需要：手机连同一个 WiFi → 配好代理和证书 → 打开极氪 App 进一次车辆页。

用法::

    pip install mitmproxy
    python catch_identifier.py            # 默认监听 0.0.0.0:8080 / 状态页 8081
    python catch_identifier.py --port 8888 --web-port 8081

依赖只有 ``mitmproxy``；状态页用标准库。Ctrl+C 结束。
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HEADER = b"x-vehicle-identifier"
_LOGGER = logging.getLogger("catch_identifier")
OUT_FILE = Path("vehicle_identifier.txt")

# 共享状态（addon 线程与状态页线程都读）
STATE: dict[str, object] = {"value": "", "hits": 0, "requests": 0, "last": ""}
_lock = threading.Lock()

WAITING_HTML = """<!doctype html><meta charset=utf-8>
<title>极氪车辆标识抓取助手</title>
<style>
 body{font:16px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
      margin:0;padding:32px 20px;background:#0f1115;color:#e8eaed}
 .card{max-width:640px;margin:0 auto;background:#171a21;border:1px solid #262b36;
       border-radius:14px;padding:28px 26px}
 h1{font-size:20px;margin:0 0 6px}
 .ok{color:#4ade80} .wait{color:#fbbf24} .muted{color:#98a2b3}
 code{background:#0b0d11;border:1px solid #262b36;border-radius:6px;
      padding:1px 6px;font-size:14px;word-break:break-all}
 .val{display:block;background:#0b0d11;border:1px solid #2f3644;border-radius:10px;
      padding:14px;margin:14px 0;font:15px/1.5 ui-monospace,Menlo,Consolas,monospace;
      color:#93c5fd;word-break:break-all}
 li{margin:6px 0}
</style>
<div class=card>
<h1>极氪车辆标识抓取助手</h1>
<p class="%s">%s</p>
%s
</div>"""


def _say(message: str) -> None:
    """直接写 fd 1，绕开 mitmproxy 接管过的 sys.stdout。"""
    try:
        os.write(1, (message + "\n").encode("utf-8", errors="replace"))
    except OSError:
        pass


_STOP = threading.Event()


def _monitor() -> None:
    """在普通线程里把抓到的值报到控制台（addon 线程里的 print 会被吞掉）。"""
    announced = ""
    while not _STOP.is_set():
        value = str(STATE["value"])
        if value and value != announced:
            announced = value
            _say("")
            _say("=" * 62)
            _say("✅ 抓到了！x-vehicle-identifier =")
            _say(f"   {value}")
            _say(f"   （已写入 {OUT_FILE.resolve()}）")
            _say("=" * 62)
        _STOP.wait(0.4)


def _page() -> bytes:
    value = str(STATE["value"])
    if value:
        status = "✅ 抓到啦 —— 这就是本车的 x-vehicle-identifier"
        body = (
            f'<span class=val>{value}</span>'
            "<p class=muted>把它填进 Home Assistant 集成向导的输入框。<br>"
            "同时已写到电脑上的 <code>vehicle_identifier.txt</code>。</p>"
        )
        return (WAITING_HTML % ("ok", status, body)).encode()

    status = "⏳ 等待中 —— 手机还没发出带标识的请求"
    body = (
        "<p class=muted>你看到这个页面，说明<b>手机的代理已经指向本机</b>，很好。"
        "如果手机打不开这个页面，回到第 1 步检查代理地址和端口。</p>"
        "<ol>"
        "<li>确认手机和电脑连的是<b>同一个 WiFi</b>。</li>"
        "<li>手机上<b>信任</b>抓包证书（iOS：设置 → 通用 → 关于本机 → "
        "证书信任设置；Android：安装 CA 证书）。不信任就见不到 HTTPS 内容。</li>"
        "<li>打开<b>极氪 App</b>，进一次「爱车」页面、下拉刷新一下。</li>"
        "<li>回到这个页面按刷新 —— 抓到之后这里会直接显示那 44 个字符。</li>"
        "</ol>"
        f"<p class=muted>已看到 {STATE['requests']} 个 geely/zeekr 请求，"
        f"其中 {STATE['hits']} 个带标识头。</p>"
    )
    return (WAITING_HTML % ("wait", status, body)).encode()


class StatusHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - 标准库约定
        body = _page()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # 静音
        return


def lan_ip() -> str:
    """拿本机在局域网里的地址（不真的发包）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.168.1.1", 9))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def banner(proxy_port: int, web_port: int) -> None:
    ip = lan_ip()
    line = "─" * 62
    print(line)
    print("极氪车辆标识抓取助手")
    print(line)
    print(f"1) 手机 WiFi 设置 → 配置代理 → 手动")
    print(f"     服务器 {ip}    端口 {proxy_port}")
    print(f"2) 手机浏览器打开  http://{ip}:{web_port}")
    print(f"     （能看到「等待中」就说明代理通了）")
    print(f"3) 浏览器打开  http://{ip}:{proxy_port}  装根证书并信任")
    print(f"4) 打开极氪 App → 进「爱车」页 → 下拉刷新")
    print(f"5) 抓到后：控制台会打印结果，同时写 {OUT_FILE.name}")
    print(line)
    print("Ctrl+C 结束。抓完记得把手机代理关掉。")
    print(line, flush=True)


def build_addon():
    """只在真正启动时才 import mitmproxy。"""
    from mitmproxy import http

    class Catcher:
        def request(self, flow: "http.HTTPFlow") -> None:
            host = flow.request.pretty_host or ""
            if "geely.com" not in host and "zeekrlife.com" not in host:
                return
            with _lock:
                STATE["requests"] = int(STATE["requests"]) + 1
                STATE["last"] = f"{flow.request.method} {host}{flow.request.path}"

            value = flow.request.headers.get("x-vehicle-identifier", "")
            if not value:
                # 有些抓包路径把值放在小写变体里
                for name, header_value in flow.request.headers.items():
                    if name.lower() == "x-vehicle-identifier":
                        value = header_value
                        break
            if not value:
                return

            value = value.strip()
            with _lock:
                STATE["hits"] = int(STATE["hits"]) + 1
                first = not STATE["value"]
                if first:
                    STATE["value"] = value
            if first:
                OUT_FILE.write_text(value + "\n", encoding="utf-8")
                _LOGGER.warning(
                    "\n%s\n✅ 抓到了！x-vehicle-identifier =\n   %s\n   （已写入 %s）\n%s",
                    "=" * 62,
                    value,
                    OUT_FILE.resolve(),
                    "=" * 62,
                )

    return Catcher()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080, help="代理端口，默认 8080")
    parser.add_argument("--web-port", type=int, default=8081, help="状态页端口，默认 8081")
    args = parser.parse_args()

    try:
        from mitmproxy import options
        from mitmproxy.tools import dump
    except ImportError:
        print("缺少 mitmproxy，先装一下：")
        print("    pip install mitmproxy")
        return 2

    server = ThreadingHTTPServer(("0.0.0.0", args.web_port), StatusHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    banner(args.port, args.web_port)
    monitor = threading.Thread(target=_monitor, daemon=True)
    monitor.start()
    try:
        asyncio.run(_serve(args.port))
    except KeyboardInterrupt:
        pass
    finally:
        _STOP.set()
        server.shutdown()
        time.sleep(0.2)
    value = STATE["value"]
    if value:
        print(f"\n结果: {value}")
        return 0
    print("\n没抓到。检查：手机代理是否生效、证书是否已信任、App 是否进过车辆页。")
    return 1


async def _serve(port: int) -> None:
    """mitmproxy 12 要求 master 建在 running loop 里。"""
    from mitmproxy import options
    from mitmproxy.tools import dump

    opts = options.Options(listen_host="0.0.0.0", listen_port=port, http2=True)
    master = dump.DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(build_addon())
    try:
        await master.run()
    finally:
        master.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
