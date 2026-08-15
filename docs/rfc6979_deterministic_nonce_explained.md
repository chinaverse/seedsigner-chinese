# 签名 nonce 为什么"零随机"——RFC 6979 确定性 nonce 详解

> 配套文档:[`entropy_rng_audit.md`](./entropy_rng_audit.md)(熵/随机数总审计)。
> 本文专门展开审计结论中最反直觉的一点:**SeedSigner 签名时不使用随机数,反而更安全。**

---

## 1. ECDSA 签名里 nonce `k` 是什么

比特币用 ECDSA(椭圆曲线 secp256k1)签名。记号:

- `d` = 私钥(大整数)
- `Q = d·G` = 公钥(`G` 是曲线基点)
- `z` = 待签消息的哈希(交易的 sighash)
- `n` = 曲线阶(约 2²⁵⁶ 的素数)

签名过程**每次都要先选一个一次性随机数 `k`**(nonce,取值 `[1, n-1]`),然后:

```
R = k·G            # 椭圆曲线点乘
r = R.x mod n      # 取 R 的 x 坐标
s = k⁻¹ · (z + r·d) mod n
签名 = (r, s)
```

这个 `k` 就是"签名 nonce",每次签名都需要一个,教科书要求它"真随机、唯一、保密、不可预测"。

---

## 2. 为什么 `k` 是整个体系最脆弱的点

把 `s` 的公式反解:

```
d = (s·k − z) · r⁻¹  mod n
```

**只要知道 `k`,用一条公开签名 `(r, s)` 就能直接算出私钥 `d`。** 签名公开写在链上,`z`、`r`、`s` 全公开,唯一的秘密屏障就是 `k`。

### 致命场景 A:`k` 重用

对**两条不同消息** `z₁`、`z₂` 用了**同一个 `k`**(于是 `r` 相同):

```
s₁ = k⁻¹(z₁ + r·d)
s₂ = k⁻¹(z₂ + r·d)
相减:  s₁ − s₂ = k⁻¹(z₁ − z₂)
解出:  k = (z₁ − z₂) / (s₁ − s₂)  mod n
代回:  d = (s₁·k − z₁) · r⁻¹  mod n
```

**两条签名就能算出私钥。** 任何人扫到两条 `r` 相同的签名即可盗走资金。

### 致命场景 B:`k` 可预测

哪怕不重用,只要 `k` 由弱随机源生成、能被猜到,**一条签名**就够:`d = (s·k − z)·r⁻¹`。

### 真实事故

- **2010 Sony PS3**:固件签名用了**固定** `k`,黑客算出主签名私钥,整条信任链崩溃。
- **2013 Android `SecureRandom` 缺陷**:RNG bug 导致不同交易**复用相同 `k`**,真实比特币被盗;bitcoin.org 发布官方安全警告。

**历史反复证明:"签名时依赖 RNG 生成 `k`" 是这套密码学里最容易出事的地方——尤其在便宜、不可审计的硬件上。**

---

## 3. RFC 6979 的思路:干脆不用随机数

`k` 真正需要的只有两个性质:

1. **唯一性**:不同消息必须用不同 `k`(否则触发场景 A);
2. **不可预测性**:不知道 `d` 的攻击者必须猜不出 `k`(否则触发场景 B)。

这两条都**不要求 `k` 是"真随机"的,只要求它对攻击者"看起来随机"**。于是 RFC 6979 把 `k` 改成**确定性地从私钥和消息哈希算出来**:

```
k = HMAC_DRBG( 种子 = 私钥 d  ‖  消息哈希 z )
```

用 HMAC-SHA256(一个 PRF)把 `(d, z)` 揉成 `k`:

- **唯一性 ✅**:`z` 进了输入,不同交易 → `k` 必不同,杜绝重用。
- **不可预测性 ✅**:输入含私钥 `d`,HMAC 是 PRF,不知道 `d` 就无法预测 `k`。
- **不需要 RNG ✅**:签名时一个随机数都不取——最容易坏、最容易被后门的环节被直接删除。
- **可复现 ✅**:同私钥签同交易永远得到同一签名,方便测试与独立验证。

并且:**确定性签名用标准验签器照样验通过**——验证方不知道也不关心 `k` 怎么来的。这是纯"签名方内部"的改进,完全兼容比特币网络。

> 一句话:RFC 6979 把"需要一个好随机数"的难题,换成"算一个 HMAC"的确定操作,既消除出错机会,又不损失安全性。

---

## 4. "零随机"到底指什么(避免误解)

要分清两个完全不同的环节:

| 环节 | 是否需要随机性 | 原因 |
|------|:--:|------|
| **生成私钥/种子**(一次性) | ✅ **必须真随机** | 私钥本身必须不可预测——即审计中相机/骰子/抛硬币那部分 |
| **每次签名的 nonce `k`** | ❌ **刻意零随机** | 用 RFC 6979 从已有私钥确定性导出,删掉 RNG 风险点 |

SeedSigner 的"对称"由此成立:**该用真随机的地方(造私钥)一丝不苟用物理熵;不该碰随机的地方(签名)一点随机都不用。两者都是正解。**

---

## 5. 落到代码上

embit 纯 Python 后端的 RFC 6979 实现(`.venv/Lib/site-packages/embit/util/key.py:444`)就是 `HMAC_DRBG(d, z)`:

```python
def deterministic_k(secret, z, extra_data=None):
    # RFC6979, optimized for secp256k1
    k = b"\x00" * 32
    v = b"\x01" * 32
    ...
    # 把私钥 secret 和消息哈希 z 喂进 HMAC-SHA256 链
    k = hmac.new(k, v + b"\x00" + secret_bytes + z_bytes, "sha256").digest()
    v = hmac.new(k, v, "sha256").digest()
    k = hmac.new(k, v + b"\x01" + secret_bytes + z_bytes, "sha256").digest()
    v = hmac.new(k, v, "sha256").digest()
    while True:                       # 拒绝采样:确保 k 落在 [1, n-1]
        v = hmac.new(k, v, "sha256").digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < SECP256K1_ORDER:
            return candidate
        ...
```

里面**没有任何 `os.urandom` / `random` / `secrets`**——`k` 完全由 `secret`(私钥)和 `z`(消息哈希)算出。

C 库后端(`.venv/Lib/site-packages/embit/util/ctypes_secp256k1.py:807`)调 `secp256k1_ecdsa_sign_recoverable(..., NULL, NULL)`,那个 `NULL` 让 libsecp256k1 使用默认 nonce 函数 `nonce_function_rfc6979`——同一套 RFC 6979 的 C 实现。

两条路径殊途同归:**SeedSigner 每次签交易,`k` 都确定性算出,不碰随机数生成器。**

调用链(以 SeedSigner **0.8.7** + `embit==0.8.0` 复核,`chinese-pinyin` 分支已 rebase 到该版本,签名代码路径未被本分支改动):
- PSBT 交易签名(legacy / segwit 输入):`src/seedsigner/views/psbt_views.py:543` `psbt.sign_with(psbt_parser.root)` → embit `psbt.py:919` `PSBT.sign_with()` → `psbt.py:1039/1045` `root.sign(h)` / `prv.sign(h)` → `ec.py:216` `PrivateKey.sign()` → `secp256k1.ecdsa_sign(msg_hash, secret)`,`nonce_function` 缺省为 `None`
- 消息签名:`src/seedsigner/helpers/embit_utils.py:204` → `secp256k1.ecdsa_sign_recoverable(msghash, prv._secret)`,同样 `nonce_function=None`

---

## 6. 一个值得知道的边角(诚实补充)

确定性签名有一个学术上的小代价:**故障注入攻击(fault attack)**。若攻击者能物理 glitch 签名运算,让同一交易产生两个略有差异的签名,理论上可借此恢复私钥。应对手段是 "hedged signatures"——在 RFC 6979 输入里再掺一点真随机(RFC 6979 §3.6 的 `extra_data`),既确定又加随机。

对 SeedSigner 这种"离线、攻击者难有物理接触"的威胁模型,这基本不构成现实风险,故用纯 RFC 6979 是合理的工程选择。(embit `ec.py:218-229` 里 `grind` 用的递增 `extra_data` 是为 low-R 体积优化,不是抗故障攻击,但机制上是同一个口子——`extra_data` 本身仍是确定性的计数器,不是随机数。)

---

## 7. 适用范围:RFC 6979 只管 ECDSA,Taproot 走的是 BIP-340

**严格讲,"RFC 6979" 这个名字只适用于 (EC)DSA 签名**——也就是 legacy / segwit(P2PKH、P2SH、P2WPKH、P2WSH)输入用的那一套。SeedSigner **同时支持 Taproot(P2TR)**(`src/seedsigner/models/psbt_parser.py` 里对 `taproot_bip32_derivations` 的解析,以及 `psbt_views.py` 用 `script.p2tr()` 构造地址),而 Taproot 输入走的是完全不同的签名算法:**BIP-340 Schnorr**,不是 ECDSA,因此字面意义上不受 RFC 6979 约束。

调用链:`psbt.py:1017/1025` `sign_input_with_tapkey()` → embit `ec.py:232` `PrivateKey.schnorr_sign()` → `secp256k1.schnorrsig_sign(msg_hash, secret)`。

关键点:这次调用同样**不传 `aux_rand`**(即传 `None`)。BIP-340 参考实现里,`aux_rand32` 是"补充"用的新鲜随机数(可选,主要用来抗故障注入,不是安全必需),传 `NULL/None` 时 libsecp256k1 按其文档使用固定值(不注入外部随机性),nonce 完全由 `tagged_hash(privkey/pubkey, msg)` 确定性算出。

所以结论是:**Taproot 输入不是"遵守 RFC 6979"(这个说法字面上不适用),而是遵守 BIP-340 的确定性 nonce 方案,并且和 ECDSA 路径一样,SeedSigner 没有额外注入随机数**——两条路径在"零随机"这个安全属性上是一致的,只是标准名字不同,审计时不应把"BIP-340 Schnorr"错误地表述为"RFC 6979"。

---

## 8. 总结

比特币签名每次都需要 nonce `k`,而 `k` 是泄露私钥的头号风险点(重用或可预测 → 一两条公开签名即可反算私钥;PS3、Android 都因此栽过)。RFC 6979 用 `HMAC(私钥, 消息哈希)` **确定性**造出 `k`,既保证唯一又不可预测,还**彻底删除了签名时对随机数的依赖**——这就是"零随机"的含义,也是当前公认的正确做法。SeedSigner 经 embit 在 C 与纯 Python 两套后端上都忠实实现了它。

---

### 一手参考

- RFC 6979(确定性 DSA/ECDSA):https://datatracker.ietf.org/doc/html/rfc6979
- BIP-62(low-S 规则):https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
- bitcoin.org 2013 Android `SecureRandom` 安全警告:https://bitcoin.org/en/alert/2013-08-11-android
- embit 签名源码:https://github.com/diybitcoinhardware/embit/blob/master/src/embit/util/key.py
