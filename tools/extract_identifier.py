#!/usr/bin/env python3
"""从抓包文件里抠出 ``x-vehicle-identifier``。

极氪 App 的 ``x-vehicle-identifier`` 是 44 字符 base64（32 字节密文），
只出现在请求头里，服务端不下发，只能从一次真实抓包里抄一次。
本脚本把「从抓包结果里认出那个值」这一步自动化，只做只读解析、不联网。

支持三种输入（自动嗅探，也可以直接喂 stdin）：

* ``.har``  —— Chrome / Reqable / Charles / Stream / Proxyman 导出的 HAR
* ``.jsonl`` —— 每行一个 JSON 对象（mitmproxy addon 自定义落盘、日志等）
* ``.flow`` / 任意文本 —— mitmproxy 的 flow 文件是二进制，本脚本退化为
  整体文本扫描（不保证成功）；纯文本/日志直接扫

用法::

    python extract_identifier.py capture.har
    python extract_identifier.py capture.jsonl
    type log.txt | python extract_identifier.py -

输出最后一行固定是 ``IDENTIFIER=<值>``，便于其它程序取用。
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

HEADER_NAME = "x-vehicle-identifier"
# 44 个 base64 字符且以 = 结尾 —— 32 字节密文的固定形态
B64_44 = re.compile(r"[A-Za-z0-9+/]{43}=")
# 直接命中「头名 + 值」的文本形态（日志、curl -v 输出、devtools 复制等）
NAMED = re.compile(
    r"""x-vehicle-identifier["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{43}=)""",
    re.IGNORECASE,
)


def is_plausible(value: str) -> bool:
    """44 字符 base64 -> 32 字节。这是本车密文的唯一形态。"""
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def scan(obj: Any, found: list[str], depth: int = 0) -> None:
    """递归找 dict 里叫 x-vehicle-identifier 的键（大小写、连字符/下划线都认）。"""
    if depth > 12:
        return
    if isinstance(obj, dict):
        # HAR / 浏览器 devtools 导出的头是 {"name": ..., "value": ...} 的成对形态
        pair_name = obj.get("name")
        pair_value = obj.get("value")
        if (
            isinstance(pair_name, str)
            and isinstance(pair_value, str)
            and pair_name.lower().replace("_", "-") == HEADER_NAME
            and is_plausible(pair_value.strip())
        ):
            found.append(pair_value.strip())
        for key, value in obj.items():
            norm = str(key).lower().replace("_", "-")
            if norm == HEADER_NAME and isinstance(value, str) and is_plausible(value.strip()):
                found.append(value.strip())
            elif norm == HEADER_NAME and isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and is_plausible(item.strip()):
                        found.append(item.strip())
            else:
                scan(value, found, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            scan(item, found, depth + 1)


def scan_text(text: str, found: list[str]) -> None:
    for match in NAMED.finditer(text):
        found.append(match.group(1))


def iter_json(text: str) -> Iterable[Any]:
    """整个文档是一个 JSON，或者每行一个 JSON，都试试。"""
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            yield json.loads(text)
            return
        except json.JSONDecodeError:
            pass
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line[0] not in "{[":
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def collect(text: str) -> tuple[list[str], str]:
    """返回 (候选值列表, 命中方式)。"""
    named: list[str] = []
    for obj in iter_json(text):
        scan(obj, named)
    if named:
        return named, "结构化解析（HAR / JSON 里认出了头名）"

    named = []
    scan_text(text, named)
    if named:
        return named, "文本匹配（认出了 'x-vehicle-identifier:' 字样）"

    loose = [m.group(0) for m in B64_44.finditer(text)]
    loose = [v for v in loose if is_plausible(v)]
    if loose:
        return loose, "宽松匹配（只按 44 字符 base64 形态找的，需人工确认）"
    return [], "没有找到"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2

    source = argv[1]
    if source == "-":
        text = sys.stdin.read()
        label = "<stdin>"
    else:
        path = Path(source)
        if not path.exists():
            print(f"找不到文件: {path}", file=sys.stderr)
            return 1
        raw = path.read_bytes()
        label = str(path)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            # mitmproxy .flow 是二进制；把可打印片段捞出来尽量扫
            text = raw.decode("utf-8", errors="ignore")
            print(f"注意: {path.name} 不是纯文本，按可读片段扫描，可能不完整。")

    values, how = collect(text)
    if not values:
        print(f"文件: {label}")
        print(f"结果: {how}")
        print()
        print("没找到。常见原因：")
        print("  1) 抓包时代理没生效 —— App 走的是直连（检查手机代理设置、证书是否已信任）")
        print("  2) 抓到的请求里没有 gric-zhf-api.geely.com / gric-api.geely.com 的请求")
        print("     —— 在 App 里进一次「车辆」首页、下拉刷新，让它真的发一次车况请求")
        print("  3) 抓包工具没解密 HTTPS —— 需要在手机上信任抓包工具的根证书")
        return 1

    unique: list[str] = []
    for value in values:
        if value not in unique:
            unique.append(value)

    print(f"文件: {label}")
    print(f"方式: {how}")
    print(f"命中: {len(values)} 次，去重后 {len(unique)} 个候选")
    print()
    if len(unique) == 1:
        print(f"车辆标识: {unique[0]}")
        print()
        print("把它填进 Home Assistant 集成向导的「x-vehicle-identifier」输入框。")
        print("这个值跟着车走、不跟账号，抄一次就一直有效。")
    else:
        print("找到多个不同的值，逐个确认哪个是本车的：")
        for index, value in enumerate(unique, 1):
            print(f"  {index}. {value}  （命中 {values.count(value)} 次）")
        print()
        print("提示: 越靠前、命中次数越多的那个通常是本车；也核对一下抓包时那几条请求")
        print("      的响应里 vin 是不是你的车。")
    print()
    print(f"IDENTIFIER={unique[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
