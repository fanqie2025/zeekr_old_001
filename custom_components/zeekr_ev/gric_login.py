# -*- coding: utf-8 -*-
"""手机号 + 短信验证码 → GRIC 令牌（全程不需要抓包）。

官方 App 登录后的三步链，就是这里实现的全部内容：

1. ``POST zeekrlife-app-user/v1/user/pub/login/mobile`` 拿 ``jwtToken``
   —— 这一步由 :mod:`custom_components.zeekr_ev.api_sms` 负责，本模块只取它的结果。
2. ``GET api-gw-toc.zeekrlife-mp-auth2/v1/auth/accessCode?clientId=…``
   带上 App 的 ``x_ca_*`` 签名头换一个一次性 ``accessCode``：

       x_ca_sign = SHA1("".join(sorted([x_ca_secret, x_ca_nonce, x_ca_timestamp])))

3. ``POST gric-api.geely.com/ms-midground-user/api/v1.0/user/auth/get/token``
   body ``{"authCode": "<上一步>", "identityType": "1"}``，带网关的 18 个签名头，
   ``X-SIGNATURE = base64(HMAC-SHA256(<网关密钥>, 规范化串))`` —— 就是 GRIC 控车用的
   那一套签名（复用 :func:`api_gric.sign_request`）。

拿到 ``accessToken`` / ``refreshToken`` 之后，GRIC 通道就能像抓包填进来的一样工作，
所以「手机号 + 验证码」也能控车，而短信通道本身（SNC 三层网关）只能读状态。

链路在 2026-11-13 的真机抓包里逐字核对过（含签名样本验算），见仓库 README 的
「实现依据」一节。
"""
from __future__ import annotations

import hashlib
import json
import logging
import random
import time
from typing import Any

from aiohttp import ClientError, ClientSession

from .api_gric import encode_body, sign_request
from .api_sms import _CA_SECRET as CA_SECRET
from .api_sms import ZeekrError

_LOGGER = logging.getLogger(__name__)

GW1_HOST = "https://api-gw-toc.zeekrlife.com"
ACCESS_CODE_PATH = "/zeekrlife-mp-auth2/v1/auth/accessCode"
TOKEN_HOST = "https://gric-api.geely.com"
TOKEN_PATH = "/ms-midground-user/api/v1.0/user/auth/get/token"

#: App 级的 TSP client id。两次不同账号的抓包里取值相同，说明它不是按用户下发的，
#: 因此可以作为常量；服务端若改了，``accessCode`` 会回非 ``000000``，报错会原样透出。
TSP_CLIENT_ID = "1916361793631214533"

#: ``x_ca_secret``.  It is the App-level signing key shipped with the official
#: client — not an account credential — and the gateway validates it (a wrong
#: value is answered with 401).  Kept as a single source of truth in
#: :mod:`.api_sms`, which already uses it for the SMS channel.
CA_KEY = "APP-SIGN-SECRET-KEY"
APP_CODE = "toc_ios_zeekrapp"
APP_VERSION = "5.0.8"
PHONE_MODEL = "iPhone14ProMax"
PHONE_VERSION = "16.2"

_TIMEOUT = 25


def _bearer(token: str | None) -> str:
    """The gateway wants ``Bearer …``; the login response already has it."""
    value = (token or "").strip()
    if not value:
        return ""
    return value if value.lower().startswith("bearer ") else f"Bearer {value}"


def _gw1_sign(nonce: str, timestamp: str) -> str:
    """``x_ca_sign``: SHA1 over the three values in sorted order."""
    joined = "".join(sorted([CA_SECRET, nonce, timestamp]))
    return hashlib.sha1(joined.encode()).hexdigest()


def _gw1_headers(jwt: str, device_id: str) -> dict[str, str]:
    """Headers every ``api-gw-toc`` App call carries (mirrors the capture)."""
    timestamp = str(int(time.time() * 1000))
    nonce = str(random.randint(10_000_000, 99_999_999))
    return {
        "accept": "*/*",
        "accept-language": "zh-Hans-CN;q=1, en-CN;q=0.9",
        "authorization": _bearer(jwt),
        "x_ca_key": CA_KEY,
        "x_ca_secret": CA_SECRET,
        "x_ca_nonce": nonce,
        "x_ca_timestamp": timestamp,
        "x_ca_sign": _gw1_sign(nonce, timestamp),
        "app_code": APP_CODE,
        "app_type": "IOS",
        "app_version": APP_VERSION,
        "version": "2",
        "workspaceid": "prod",
        "device_id": device_id,
        "phone_model": PHONE_MODEL,
        "phone_version": PHONE_VERSION,
        "request-original": "zeekr-app",
        "riskversion": "1",
        "user-agent": f"ZeekrLife/{APP_VERSION} (iPhone; iOS {PHONE_VERSION}; Scale/3.00){device_id}",
    }


def _tokens_headers(device_id: str) -> dict[str, str]:
    """The signed header set ``gric-api`` expects (device_id doubles as device id)."""
    return {
        "accept": "application/json",
        "accept-language": "zh_CN",
        "content-type": "application/json",
        "x-app-id": "GEELYCNCH001M0001",
        "x-app-version": APP_VERSION,
        "x-device-brand": "iPhone",
        "x-device-id": device_id,
        "x-device-model": "iPhone15,3",
        "x-device-os-version": PHONE_VERSION,
        "x-platform": "iOS",
        "x-sales-platform": "ZEEKR",
        "x-tenant-id": "ZEEKR",
        "x-timestamp": str(int(time.time() * 1000)),
        "x-api-signature-nonce": _nonce_uuid(),
        "x-api-signature-version": "2.1",
    }


def _nonce_uuid() -> str:
    import uuid

    return str(uuid.uuid4()).upper()


async def _read_json(resp, *, what: str) -> dict[str, Any]:
    """Decode a gateway answer, keeping the raw text for the error message."""
    text = await resp.text()
    try:
        payload = json.loads(text)
    except ValueError:
        raise ZeekrError(f"{what}返回的不是 JSON（HTTP {resp.status}）：{text[:200]}")
    if not isinstance(payload, dict):
        raise ZeekrError(f"{what}返回结构异常：{text[:200]}")
    if resp.status >= 400:
        raise ZeekrError(
            f"{what}失败（HTTP {resp.status}）："
            f"{payload.get('msg') or payload.get('error_msg') or text[:200]}"
        )
    return payload


async def async_fetch_access_code(
    session: ClientSession,
    jwt: str,
    device_id: str,
    client_id: str = TSP_CLIENT_ID,
) -> str:
    """Step 2: turn the App JWT into a one-shot ``accessCode``."""
    url = GW1_HOST + ACCESS_CODE_PATH
    try:
        async with session.get(
            url,
            params={"clientId": client_id},
            headers=_gw1_headers(jwt, device_id),
            timeout=_TIMEOUT,
        ) as resp:
            payload = await _read_json(resp, what="换取 accessCode ")
    except ClientError as err:
        raise ZeekrError(f"换取 accessCode 时网络出错：{err}") from err

    code = str(payload.get("code") or "")
    if code != "000000":
        raise ZeekrError(
            "换取 accessCode 被拒绝 "
            f"(code={code} msg={payload.get('msg')})。"
            "通常是登录态已失效，请重新获取验证码登录。"
        )
    value = payload.get("data")
    if not isinstance(value, str) or not value.strip():
        raise ZeekrError(f"accessCode 为空：{json.dumps(payload)[:200]}")
    return value.strip()


async def async_exchange_gric_tokens(
    session: ClientSession,
    jwt: str,
    device_id: str,
    client_id: str = TSP_CLIENT_ID,
) -> dict[str, Any]:
    """Steps 2+3: ``jwtToken`` → GRIC ``accessToken`` / ``refreshToken``.

    Returns the same key names the GRIC client stores in a config entry.
    """
    access_code = await async_fetch_access_code(session, jwt, device_id, client_id)

    body = encode_body({"authCode": access_code, "identityType": "1"})
    headers = _tokens_headers(device_id)
    # The signature covers the signed-header subset plus the body hash, so it
    # can only be computed once every other header is final.
    _, signature = sign_request("POST", TOKEN_PATH, headers, body=body)
    headers["x-signature"] = signature

    try:
        async with session.post(
            TOKEN_HOST + TOKEN_PATH,
            data=body,
            headers=headers,
            timeout=_TIMEOUT,
        ) as resp:
            payload = await _read_json(resp, what="换取 GRIC 令牌 ")
    except ClientError as err:
        raise ZeekrError(f"换取 GRIC 令牌时网络出错：{err}") from err

    if str(payload.get("code")) != "0":
        raise ZeekrError(
            "换取 GRIC 令牌被拒绝 "
            f"(code={payload.get('code')} msg={payload.get('msg')})。"
        )
    data = payload.get("data") or {}
    access = data.get("accessToken")
    refresh = data.get("refreshToken")
    if not access or not refresh:
        raise ZeekrError(f"GRIC 令牌响应缺字段：{json.dumps(payload)[:200]}")
    _LOGGER.debug(
        "手机号登录换到了 GRIC 令牌（access 有效期至 %s）",
        data.get("accessExpiresTimestamp"),
    )
    return {
        "gric_access_token": access,
        "gric_refresh_token": refresh,
        "access_expires": data.get("accessExpiresTimestamp"),
        "refresh_expires": data.get("refreshExpiresTimestamp"),
        "open_id": data.get("openId"),
        "user_id": data.get("userId"),
    }
