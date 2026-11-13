# 极氪 001 老款（2021–2023）Home Assistant 集成

把极氪（Zeekr）App 的车辆状态与远程控制接进 Home Assistant。**手机号 + 短信验证码登录，就能看状态也能控车。**

本仓库是 [RexzeLu/zeekr_ha](https://github.com/RexzeLu/zeekr_ha) 的增强分支（MIT，见 `LICENSE`）。
原版「短信验证码」通道只能读状态、不能控车；这里补上了一条**用手机号登录、但走 GRIC 通道控车**的路径，
另外修了座椅/方向盘加热、极速降温、座舱通风、除霜一共 6 处实测出来的问题（见「相对原版的改动」）。

## 适用车型

- ✅ **已在 2022 款极氪 001 上逐项实测**（400V 平台、Mobileye EyeQ5H 那一代，即通常说的「老款 001」）：
  状态读取、座椅加热/通风、方向盘加热、空调、极速降温/升温、座舱通风、除霜、车锁、车窗。
- ⚠️ **新款 001（2024 款起，800V / 骁龙 8295 / 后来换 OrinX）以及 007、X、009 等未实测**。
  它们用的是另一代车机与网关行为，指令参数可能不同 —— 能用请反馈，不能用也正常，别当 bug 报。

> 免责声明：非官方项目，与浙江极氪智能科技无关。使用的是官方 App 自己调用的接口。
> 接口可能随时变更；控车前请确认车辆处于安全状态（不要把车停在坡道上远程操作车窗/尾门）。


---

## 一、三条登录通道怎么选

| 通道 | 看状态 | 控车 | 需要手工准备的东西 |
|---|---|---|---|
| **手机号 + 验证码**（推荐） | ✅ | ✅ | 只差一个 44 字符的车辆标识（见第四节，抓一次永久有效） |
| **GRIC 令牌** | ✅ | ✅ | 自己抓 `refreshToken` + 同一个车辆标识 |
| **短信验证码（只读）** | ✅ | ❌ | 无 |

为什么「只读」那条不能控车：它拿到的是另一代令牌，网关会按接口粒度拒绝指令接口
（`079001 [SDK]此接口未被授权`），而老的兜底管道会回「操作成功」却什么都不执行 ——
**云端回成功 ≠ 车端执行**，这是这个集成里最容易误判的坑。

「手机号 + 验证码」为什么能控车：登录后集成会拿这次登录换一份 **GRIC 令牌**
（App 自己控车用的那一份），后续所有请求都走 GRIC 网关。换取过程全自动，不需要抓包。

---

## 二、安装

### HACS（自定义仓库）

1. HACS → 集成 → 右上角 ⋮ → 自定义存储库
2. 添加 `https://github.com/fanqie2025/zeekr_old_001`，类别选「集成」
3. 搜索 **Zeekr 001 Old** 安装，重启 Home Assistant
4. 设置 → 设备与服务 → 添加集成 → 搜 **Zeekr EV**

### 手工安装

把本仓库的 `custom_components/zeekr_ev/` 整个目录复制到 Home Assistant 配置目录下的
`custom_components/zeekr_ev/`，重启。

> ⚠️ 本集成的 domain 仍是 `zeekr_ev`，**不能和原版 `RexzeLu/zeekr_ha` 同时安装**
> （两者会互相覆盖）。已经从原版迁移过来时，先删掉原版再装本版，或直接覆盖目录。

---

## 三、用手机号登录

1. 添加集成 → 接入方式选 **手机号 + 验证码（看状态 + 控车，推荐）**
2. 填国家/地区代码（`+86`）和手机号 → 收验证码 → 填进下一步
3. 集成会自己换 GRIC 令牌并读出你账号下的车（会显示 VIN 和车牌）
4. 最后一步要填 **`x-vehicle-identifier`**，见下一节

> 令牌是**单会话**的：同一账号在手机 App 上重新登录，可能会让 HA 这边的会话失效
> （HA 会提示需要重新认证）。这时在集成里点「重新认证」，用手机号再收一次验证码即可，
> 不需要重新抓包。

### 强烈建议：别用你自己的主账号

极氪同一个账号**同一时间只认一处登录**。HA 和手机 App 用同一个账号时，手机那边一退登、
一重登，HA 立刻报 `00A17 The account is currently logged in elsewhere.`，控车全废（云端
仍会回「操作成功」，最容易被误判成集成坏了）。

省心的顺序：

1. **把车分享给一个备用账号**（极氪 App → 我的 → 车辆分享），HA 用备用账号登录，主账号随便折腾
2. 用一张不常用的小号跑 HA
3. 只有一个账号：手机 App 登出后不要再登录那个账号，否则每次都得点「重新认证」

---

## 四、`x-vehicle-identifier` 怎么取（唯一必须手工的一步）

这个值谁也推不出来：App 是在**内存里**用原生库里的密钥现算的，手机上不存、服务端也不下发
（原版 README、以及我们自己的抓包与离线爆破都验证过这一点）。
所以它只能从**一条真实请求的请求头**里抄一次。

**它跟着车走，不跟账号**：抄一次永久有效，换手机、换账号、重装 App 都不用重抓。

取法任选其一：

- **一键助手（最省事，Windows / macOS）**：`pip install mitmproxy` 后跑
  `python tools/catch_identifier.py`，按它打印的地址在手机上设代理、装证书，
  进一次 App 的「爱车」页 —— 脚本会直接把 44 个字符打出来，并写进 `vehicle_identifier.txt`
- **已经有抓包文件**：`python tools/extract_identifier.py capture.har`，最后一行输出
  `IDENTIFIER=...`（HAR / jsonl / 纯文本日志都吃）
- **不想用电脑**：iOS 用 Stream / Proxyman，安卓用 Reqable（Android 7+ 需要 LSPosed 之类
  才认用户证书，比用电脑折腾）
- **原教旨 mitmproxy**：`mitmdump` 起代理 → 手机 WiFi 设 HTTP 代理 → 装 mitmproxy CA 并在
  「证书信任设置」里信任 → 打开极氪 App 进车辆页 → 在 `gric-zhf-api.geely.com` 的请求头里
  找 `x-vehicle-identifier`

图文步骤、常见坑、给不会抓包的人用的 **AI 助手提示词**（可以直接粘给豆包 / DeepSeek /
WorkBuddy，让 AI 一步步带着做）：

- [`docs/获取车辆标识.md`](docs/获取车辆标识.md)
- [`docs/AI助手提示词.md`](docs/AI助手提示词.md)

取值特征：**44 个字符的 base64，以 `=` 结尾**，例如 `GNxEVYPZ7RjM1IPT1vqgC84gsNerq13jzTPXgfEX5Gg=`（示例，不是你的车）。

填错的后果很明确：网关当场回 `00A06 Decrypt X-VEHICLE-IDENTIFIER failed`，
或者业务层报「标识值不是该车的密文」—— 集成会把它变成表单错误，不会静默失败。

---

## 五、相对原版的改动（全部在真车上逐条验过）

验证方式一律是**读车端状态字段**，而不是看 HA 界面（HA 界面有乐观更新，会骗人）。

### 1. 座椅加热 / 通风：`{code}.level` 必须排在 `{code}` 前面

原版发的是 `SH.11` → `SH.11.level` → `SH.11.duration`。这个顺序下，云端每次都回
`{"code":"0","msg":"操作成功"}`，**车端一次都不会加热**。

抓包比对 + 单变量对照（同一台车、同一个令牌、同一条通道）得到的结论：

| 下发顺序 | 车端 `drvHeatLv` |
|---|---|
| `level` → `SH.11` → `duration`（App 的真实顺序） | 2 ✅ |
| `SH.11` → `level` → `duration`（原版） | 0 ❌ |
| `SH.11` → `level` → `duration`，但值改成字符串 | 0 ❌ |
| `level` → `SH.11` → `duration`，值仍是字符串 | 2 ✅ |

即**唯一必要条件是顺序**：先发 `SH.11=true` 会被按 `level=0` 执行，之后再发 `level` 就不生效了。
值类型（字符串/布尔）与结果无关。关闭走同一段逻辑（`level=0` + `false` + `duration=0`）。

### 2. 方向盘加热：`SW` → `SW.level` → `SW.duration`

原版是 `SW` → `SW.duration` → `SW.level`，同样只有顺序问题。车端字段 `steerWhlHeatingSts`：`1` 开、`2` 关。

### 3. 极速降温 / 极速升温：就是设定温度 15.5 / 28.5

原版注释写的是「进极速模式的指令没抓到，所以把设定温度打到刻度两端 15/30 近似」。
抓包抓到了真实值：**极速降温 = 空调 15.5 ℃、极速升温 = 28.5 ℃**（不是量程端点 15.0 / 30.0），
其余参数与普通开空调一致（`AC` / `AC.temp` / `AC.duration`）。车端验证：`preClimateActive=true`，
5 分钟内车内温度 24.8 → 23.6 ℃。

### 4. 座舱通风是独立服务 `RCC`，不在空调指令里

```json
{"command":"start","serviceId":"RCC","setting":{
  "operationScheduling":{"duration":"6"},
  "serviceParameters":[{"key":"rcc.conditioner","value":"50"},
                       {"key":"rcc.ventilation","value":"0"}]}}
```

时长放在 **`setting.operationScheduling.duration`**（分钟），不在 `serviceParameters` 里。
原版的 `async_do_remote_control()` 只拷贝 `serviceParameters`、丢弃 `setting` 里的其它键，
所以这条指令根本发不出去 —— 现已改成**原样透传** `setting` 的所有键。
车端验证：`climateStatus.airBlowerActive=true`。

### 5. 远程除霜：顺序与座椅**相反**，且要带 `duration`

App 的真实报文是 `DF` → `DF.level` → `DF.duration`（开关在前），与座椅的「level 在前」相反。
原版只发 `DF` + `DF.level`，没有 `duration`。请**不要**把这两个服务的顺序当成同一条规则套用 ——
我们就是这么踩过一次。车端验证：`climateStatus.defrost=true` / 关回 `false`（关闭只发 `{"key":"DF","value":"false"}`）。

### 6. 每次下发都会在日志里留一行

`api_gric` 在 DEBUG 级别打印 `command` / `serviceId` / 完整 `payload`，
排查「点了没反应」时直接看日志，不用再猜是不是没发出去。

---

## 六、已知限制

- **`x-vehicle-identifier` 无法自动获取**（见第四节），每辆车需要手工抄一次。
- **单会话令牌**：手机 App 重新登录可能把 HA 踢掉，需要重新认证（不用重新抓包）。
- **HACS 升级会覆盖本仓库的改动**：如果你从原版升级，本仓库的补丁会被覆盖。原版本仓库自己的更新也一样。
- **座椅时长是全局单值**：四个座椅共用「座椅加热/通风时长」，暂不支持每座独立 15/20/30 分钟。
- **空调目标温度读不回来**：车端状态里没有目标温度字段，只有 `temperatureUpdateTime`。
- **不含碳积分签到**：签到属于另一套 H5 接口（签名算法不同），不在本集成范围内。

---

## 七、实现依据（给想自己改的人）

`custom_components/zeekr_ev/gric_login.py` 里就是「手机号登录 → GRIC 令牌」的全部内容，
三步链（2026-11 真机抓包逐字核对，含签名样本验算）：

1. `POST api-gw-toc.zeekrlife.com/zeekrlife-app-user/v1/user/pub/login/mobile`
   → `data.jwtToken`（`Bearer eyJ…`，App 的 JWT）
2. `GET api-gw-toc.zeekrlife.com/zeekrlife-mp-auth2/v1/auth/accessCode?clientId=…`
   头里带 `x_ca_key` / `x_ca_secret` / `x_ca_nonce` / `x_ca_timestamp` / `x_ca_sign`，
   其中 `x_ca_sign = SHA1("".join(sorted([x_ca_secret, nonce, timestamp])))` → 一次性 `accessCode`
3. `POST gric-api.geely.com/ms-midground-user/api/v1.0/user/auth/get/token`
   body `{"authCode": "<上一步>", "identityType": "1"}`，带 18 个签名头 +
   `X-SIGNATURE = base64(HMAC-SHA256(<网关密钥>, 规范化串))` → `accessToken` / `refreshToken`

`accessCode` 与 `authCode` 都是一次性的。签名实现复用 `api_gric.py` 的
`build_base()` / `sign_request()`，与控车接口同一套代码路径。

车端状态字段（`climateStatus` 下）：`drvHeatLv` / `passHeatLv` / `rlHeatLv` / `rrHeatLv`、
`steerWhlHeatingSts`（1 开 / 2 关）、`defrost`、`airBlowerActive`、`preClimateActive`、
`interiorTemp` / `exteriorTemp`。

---

## 八、致谢

- 原版集成：[RexzeLu/zeekr_ha](https://github.com/RexzeLu/zeekr_ha)（MIT）
- 手机号 + 验证码登录的表单流程参考了 [Admingyu/zeekr-homeassistant](https://github.com/Admingyu/zeekr-homeassistant) 的思路

## 许可

MIT，见 `LICENSE`。原版版权归 RexzeLu，本分支的改动同样以 MIT 发布。
