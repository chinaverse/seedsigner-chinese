# SeedSigner 熵 / 随机数使用审计报告

> 审计范围:代码中所有涉及 entropy / 随机数的部分——是否使用真随机数、是否严格按加密算法要求正确使用,**包含每次比特币交易签名所需的 ECDSA nonce(`k`)**。
>
> 方法:**源码审计(权威结论来源)** + **网页一手规范交叉验证**。
> 审计对象:本仓库 `src/` + 锁定依赖 `embit==0.8.0`(`requirements.txt:1`,源码已在 `.venv/Lib/site-packages/embit/` 核对)。
> 审计日期:2026-06-09。

---

## 0. 总结论

这份代码对熵与随机数的处理**稳健且符合密码学要求**,体现为一个刻意的对称:

| 环节 | 随机性策略 | 是否正确 |
|------|-----------|---------|
| **种子生成** | 刻意使用**真随机**(相机传感器噪声 / 骰子 / 抛硬币物理熵),用 SHA-256 做 conditioning | ✅ 正确 |
| **签名 nonce** | 刻意使用**零随机**(RFC 6979 确定性 nonce,签名时不取 RNG) | ✅ 正确 |

两个方向相反,但都符合一手规范。**未发现需要修复的安全缺陷。**

关键设计判断:SeedSigner 运行在 ~15 美元、硬件 RNG 不可审计的 Raspberry Pi Zero 上,因此**故意不信任设备自身的 OS/硬件 RNG 来生成种子**,转而要求用户引入可观测、可外部验证的物理熵;同时签名环节**根本不取随机数**(RFC 6979),从根上免疫"弱 `k` / 重用 `k` 导致私钥泄露"这整类灾难。

---

## 1. 种子熵的生成路径(密钥相关)

全量搜索 `src/**/*.py`:**种子生成路径中完全没有 `os.urandom`、`secrets`、`getrandbits`**——这是设计,不是疏漏。

| 路径 | 熵来源 | 真随机? | 处理 | 代码位置 |
|------|--------|:--:|------|---------|
| 图像 | 相机传感器噪声(50 预览帧 + 1 张全分辨率图)+ CPU 序列号 + 时间戳 | ✅ 物理 TRNG | SHA-256 链式哈希 | `src/seedsigner/views/tools_views.py:145-199` |
| 骰子 | 用户掷 d6 骰子 50/99 次 | ✅ 用户物理熵 | `SHA256(字符串)` | `src/seedsigner/helpers/mnemonic_generation.py:65-82` |
| 抛硬币 | 用户抛硬币 128/256 次 | ✅ 用户物理熵 | `SHA256(字符串)` | `src/seedsigner/helpers/mnemonic_generation.py:86-101` |

### 1.1 图像熵(headline 来源)

`tools_views.py:161-170` 将 CPU 串号哈希、`time.time()`、50 个预览帧、全分辨率图逐级 `SHA256` 链式哈希;12 词取前 16 字节(`tools_views.py:172-174`)。
- 真正的安全押在相机全分辨率图(约 480×480×3 ≈ 69 万字节传感器噪声)上,最小熵远超 256 位。
- CPU 串号(每台恒定)与 `time.time()`(可猜)是**低熵补充项**,仅作附加哈希输入,永不降低熵;串号读取失败回退 `b'0'`(`tools_views.py:158`)无风险。
- 良好实践:图像缓冲用后立即置 `None`,**绝不写盘、不长驻内存**(`tools_views.py:182-188`)。

### 1.2 骰子 / 抛硬币

- `mnemonic_generation.py:75` / `:94`:`hashlib.sha256(roll_data.encode()).digest()`——用密码学哈希做熵白化(whitening / conditioning)。
- 骰子录入为 1–6(`gui/screens/tools_screens.py:182-189`),与 iancoleman.io Base10/Hex 模式一致,**可外部独立验证**(`docs/dice_verification.md`)。

### 1.3 比特数学

- d6 每次 = log₂6 ≈ **2.585 位**。50 次 ≈ **129.2 位**(≥128 ✓);99 次 ≈ **255.9 位**(目标 256,差约 0.09 位,可忽略,与主流工具一致)。
- 128/256 次抛硬币 = 精确 128/256 位。
- "Calc 12th/24th word":末词补 7 位(12 词)/ 3 位(24 词)熵 + 校验和,数学严格(11×11+7+4=128;23×11+3+8=256)(`tools_views.py:308-311`)。
- 校验和由 embit 重算,非手写(`mnemonic_generation.py:49-56`)。

---

## 2. 签名 nonce(ECDSA `k`)——最关键

### 2.1 结论

**SeedSigner 签名时根本不取随机数,使用 RFC 6979 确定性 nonce。** 没有"随机 nonce"需要审计,因为设计上签名里就没有随机性。这是消除"弱 `k` / 重用 `k` 泄露私钥"(2010 Sony PS3、2013 Android `SecureRandom`)整类漏洞的公认正解。

### 2.2 两条签名路径的完整证据链

**路径 A — PSBT 交易签名**
`src/seedsigner/views/psbt_views.py:543` `psbt.sign_with(root)` → embit `ec.py:216` `PrivateKey.sign()`:

```python
# .venv/Lib/site-packages/embit/ec.py:216
def sign(self, msg_hash, grind=True) -> Signature:
    sig = Signature(secp256k1.ecdsa_sign(msg_hash, self._secret))  # nonce_function=None
```

`nonce_function=None` 在两种后端都落到 RFC 6979:
- **C 库后端** `util/ctypes_secp256k1.py:599-612`:`secp256k1_ecdsa_sign(ctx, sig, msg, secret, NULL, NULL)` → libsecp256k1 默认 nonce 函数 = `secp256k1_nonce_function_rfc6979`。
- **纯 Python 后端** `util/key.py:415-424`:`if nonce_function is None: nonce_function = deterministic_k`;`deterministic_k`(`util/key.py:444`)注释 **"RFC6979, optimized for secp256k1"**,HMAC-SHA256 标准 HMAC_DRBG 构造(V/K 初始化、`\x00`/`\x01` 步、对 `[1,n-1]` 拒绝采样)。

**路径 B — 消息签名**
`src/seedsigner/helpers/embit_utils.py:204` `secp256k1.ecdsa_sign_recoverable(msghash, prv._secret)` → `util/ctypes_secp256k1.py:807` `secp256k1_ecdsa_sign_recoverable(ctx, sig, msg, secret, None, None)` → NULL nonce → RFC 6979。

### 2.3 Bitcoin 共识要求

- **Low-S(BIP-62,防交易延展性)**:✅ libsecp256k1 内部强制 low-S;纯 Python 后端 `util/key.py:415` `low_s=True` 默认。
- **`grind=True` 是 low-R 体积优化,非安全隐患**:`ec.py:218-226` 若 DER 签名 > 70 字节,带递增 `counter` 作 `extra_data` 重签至 R 带前导零(省 ~1 字节/输入)。每次 `extra_data` 不同,但 nonce 仍由 `(secret, z, extra_data)` **确定性**导出(RFC 6979 §3.6),**不引入随机性,无 nonce 重用风险**。

---

## 3. 伪随机数(`random`)的使用——已正确隔离

Python `random`(梅森旋转,**不可用于密钥**)仅出现在非安全用途,隔离干净:

| 位置 | 用途 | 涉及密钥? |
|------|------|:--:|
| `src/seedsigner/views/screensaver.py:40,180,181` | 屏保动画 | ❌ |
| `src/seedsigner/views/seed_views.py:1287-1310` | 助记词备份测验的诱饵词 / 随机抽词出题 | ❌ |
| `src/seedsigner/helpers/ur2/random_sampler.py` + fountain | 动画 QR(UR2)喷泉码取样,**必须可复现才能解码**,故用确定性 Xoshiro PRNG | ❌ |
| `tools/mnemonic.py:84-92`(CLI 验证工具)| `random.randint` 生成示例骰子 | ❌(帮助文本明标 **"not-secure"**,`tools/mnemonic.py:59`) |

**没有任何一处把 `random` 用于种子、私钥或 nonce。** 安全/非安全随机源职责分离清晰正确。

---

## 4. 网页一手规范交叉验证

针对上述结论所依赖的**标准本身**,做了一轮对抗式网页核验(一手规范,均 3-0 一致通过):

| 主张 | 裁决 | 一手来源 |
|------|:--:|---------|
| BIP-39:12词=128+4、24词=256+8,CS=ENT/32 取 SHA256(熵)首位 | ✅ 3-0 | [BIP-39 spec](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) |
| SHA-256 对原始物理熵做 conditioning = NIST SP 800-90B 认可做法(§3.1.5.1.1 六种 vetted conditioning,含任意 FIPS 180/202 哈希) | ✅ 3-0 | [NIST SP 800-90B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/nist.sp.800-90b.pdf) |
| d6=log₂6≈2.585 位;50次≈129、99次≈255.9;SeedSigner 用 50/99 | ✅ 3-0 | [Coldcard dice math](https://coldcard.com/docs/verifying-dice-roll-math/) · [SeedSigner dice_verification.md](https://github.com/SeedSigner/seedsigner/blob/main/docs/dice_verification.md) |
| RFC 6979 确定性 nonce:HMAC-DRBG 从私钥+消息哈希导出 k,签名不需 RNG,标准验签可通过 | ✅ 3-0 | [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979) |
| BIP-62 low-S 规则 | (一手规范) | [BIP-62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) |
| 2013 Android `SecureRandom` 致 Bitcoin 钱包 nonce 缺陷 | (历史背景) | [bitcoin.org 2013-08-11 警告](https://bitcoin.org/en/alert/2013-08-11-android) |
| embit 签名实现参考 | (一手代码) | [embit util/key.py](https://github.com/diybitcoinhardware/embit/blob/master/src/embit/util/key.py) · [embit ec.py](https://github.com/diybitcoinhardware/embit/blob/master/src/embit/ec.py) |

**NIST 重要前提:** conditioning **不创造熵**;"满熵"还要求原始输入最小熵足够 + 噪声源验证。→ SeedSigner 的相机噪声 / 50·99 骰子原始最小熵均远超目标,前提满足。

### 4.1 网页留下的 open question 已由源码补全

网页研究因无法直接读库源码,对以下几项弃权(0-0);这些恰好已被本报告 §2 的源码审计**直接证明**:

| 网页 open question | 源码证据 |
|---|---|
| embit 是否真用 RFC 6979? | ✅ `util/key.py:444` `deterministic_k`(RFC6979)+ C 后端 NULL nonce |
| 是否 BIP-62 low-S? | ✅ `util/key.py:415` `low_s=True` + libsecp256k1 强制 |
| 是否 low-R grinding 叠加在 RFC 6979 之上? | ✅ `ec.py:216-226` |

> 网页曾把"种子=对骰子 ASCII 串做 SHA-256"反驳(0-3),原因是它引的是 **Coldcard**(机制不同)文档证不出来;但 SeedSigner **代码确实如此**(`mnemonic_generation.py:75`),对本仓库为真。

---

## 5. 风险登记

| 检查项 | 评级 | 说明 |
|--------|:--:|------|
| 种子是否用真随机 | ✅ 通过 | 相机/骰子/硬币物理熵,非伪 RNG |
| 种子熵 conditioning | ✅ 通过 | SHA-256,NIST 认可;原始熵充足 |
| 签名 nonce 生成 | ✅ 通过 | RFC 6979 确定性,无 RNG 依赖,无 `k` 重用风险 |
| Low-S / Low-R | ✅ 通过 | 强制 low-S + 确定性 grinding |
| `random` 误用于密钥 | ✅ 通过 | 无误用,隔离干净 |
| 99 骰子 ≈ 255.9 位 | 🟡 信息性 | 差 0.09 位,可忽略,属行业惯例(满 256 需 100 次) |
| 图像熵弱补充项(串号/时间) | 🟢 信息性 | 仅附加,不降低熵;headline 为相机噪声 |
| 图像熵依赖拍摄场景 | 🟢 信息性 | 官方建议拍复杂场景;代码层无缺陷 |

**需修复项:无。**

---

## 附:关键代码位置速查

- 种子熵生成:`src/seedsigner/helpers/mnemonic_generation.py`
- 图像熵流程:`src/seedsigner/views/tools_views.py:145-199`
- PSBT 签名:`src/seedsigner/views/psbt_views.py:543`
- 消息签名:`src/seedsigner/helpers/embit_utils.py:191-210`
- embit 确定性 nonce:`.venv/Lib/site-packages/embit/util/key.py:444`(`deterministic_k`)
- embit 签名 + grinding:`.venv/Lib/site-packages/embit/ec.py:216`
- 依赖锁定:`requirements.txt:1`(`embit==0.8.0`)
