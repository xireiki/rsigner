# rsigner — RSA 消息恢复签名 + AES-256-GCM 加密/解密工具

将 RSA 消息恢复签名与 AES-256-GCM 相结合，实现**密文与解密密钥强绑定**的方案。  
任何对密文的篡改（包括攻击者用正确密钥重加密）都会自动导致解密失败，无需依赖显式比对。

---

## 设计原理

### 协议概要

```
M = S(32B) || H(32B) || IV(12B) || Tag(16B) = 92 字节
K = HMAC-SHA256(S, H)
```

| 符号 | 说明 |
|------|------|
| `S` | 随机种子（32 字节，每次加密重新生成） |
| `H` | `SHA256(原始文件)` |
| `K` | 加密密钥，由 `S` 和 `H` 通过 HMAC-SHA256 派生 |
| `IV` | AES-GCM 随机数（12 字节） |
| `Tag` | AES-GCM 认证标签（16 字节） |

### 发送方（加密）

```
1. H = SHA256(File)
2. 生成随机种子 S
3. K = HMAC-SHA256(S, H)
4. 生成随机 IV
5. AES-256-GCM 加密 → 密文 C + 认证标签 Tag
6. 打包 M = S || H || IV || Tag
7. RSA PKCS#1 v1.5 原始签名（消息恢复模式）→ Sig
8. 发送 (Sig, C)
```

### 接收方（解密）

```
1. 从 Sig 恢复 M（RSA 公钥验证 + 消息恢复）
2. 解析出 S, H, IV, Tag
3. K = HMAC-SHA256(S, H)
4. 使用 IV, Tag 解密 C → File'
5. SHA256(File') 与 H 比对
```

### 安全核心

- **防重用密钥攻击**：解密所需的 IV 和 Tag 被签名保护。攻击者截获 `(Sig, C)` 后，即使恢复出 `K`，也无法篡改密文后伪造新的有效签名——接收方使用签名中的原始 IV/Tag 解密，GCM 标签验证必然失败。

---

## 安装

```bash
# 克隆项目
git clone <repo-url> && cd <repo-dir>

# 编译
go build

# 或直接运行
go run .
```

---

## 使用方法

### 命令结构

```
rsigner
├── genkey    生成 RSA 密钥对
├── encrypt   加密文件
└── decrypt   解密文件
```

### 1. 生成密钥对

```bash
# 2048 位（默认）
rsigner genkey -k private.pem -K public.pem

# 或指定 --genrsa
rsigner genkey -g 2048 -k private.pem -K public.pem

# 4096 位密钥
rsigner genkey -g 4096 -k private.pem -K public.pem
```

### 2. 加密文件

```bash
rsigner encrypt \
  -k private.pem \       # RSA 私钥（签名用）
  -i plain.txt \         # 明文输入
  -s plain.txt.sig \     # 签名输出（默认 <输入>.sig）
  -o plain.txt.rsn       # 密文输出（默认 <输入>.rsn）
```

**发送方只需传输 `plain.txt.sig`、`public.pem` 和 `plain.txt.rsn` 给接收方**

### 3. 解密文件

```bash
rsigner decrypt \
  -K public.pem \        # RSA 公钥（验证用）
  -s plain.txt.sig \     # 签名输入
  -i plain.txt.rsn \     # 密文输入
  -o plain.txt           # 明文输出（默认去 .rsn 后缀）
```

### 查看帮助

```bash
rsigner --help
rsigner encrypt --help
rsigner decrypt --help
rsigner genkey --help
```

---

## 安全性测试

以下攻击场景全部被有效拦截：

| 攻击场景 | 拦截点 | 错误信息 |
|----------|--------|----------|
| 篡改密文一个字节 | GCM 认证标签验证失败 | `GCM 认证失败` |
| 篡改签名一个字节 | RSA 填充格式错误 | |
| 重用旧签名 + 新密文 | GCM 用原始 IV/Tag 解密新密文失败 | `GCM 认证失败` |
| 用正确密钥重加密篡改文件 | 攻击者无法伪造新 IV/Tag 的签名 | 签名验证不通过 |

---

## 等效 Shell 命令（OpenSSL）

以下命令与 Go 实现每一步严格对应，可用于交叉验证。

### 密钥生成

```bash
# 2048 位 RSA 密钥对
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl pkey -in private.pem -pubout -out public.pem
```

### 加密流程（发送方）

```bash
# 1. 计算文件哈希
openssl dgst -sha256 -binary plain.txt > hash.bin

# 2. 生成随机种子 S（32 字节）
openssl rand 32 > seed.bin

# 3. 派生密钥 K = HMAC-SHA256(S, H)
openssl dgst -sha256 -mac hmac -macopt hexkey:$(xxd -p -c 32 seed.bin) -binary hash.bin > k.bin

# 4. 生成随机 IV（12 字节）
openssl rand 12 > iv.bin
IV_HEX=$(xxd -p -c 12 iv.bin)

# 5. AES-256-GCM 加密
openssl enc -aes-256-gcm -in plain.txt -out cipher.bin \
    -K $(xxd -p -c 32 k.bin) -iv $IV_HEX -tagfile tag.bin

# 6. 打包 M = S || H || IV || Tag
cat seed.bin hash.bin iv.bin tag.bin > M.bin

# 7. RSA 消息恢复签名
openssl pkeyutl -sign -in M.bin -inkey private.pem \
    -out sign.sig -rawin -pkeyopt rsa_padding_mode:pkcs1

# 发送 (sign.sig, cipher.bin)
```

### 解密流程（接收方）

```bash
# 1. 从签名恢复 M
openssl pkeyutl -verifyrecover -in sign.sig -inkey public.pem -pubin \
    -out M_recovered.bin -pkeyopt rsa_padding_mode:pkcs1

# 2. 拆分字段（跳过 64 字节后读 12 字节 IV，再读 16 字节 Tag）
dd if=M_recovered.bin of=seed.bin bs=32 count=1 2>/dev/null
dd if=M_recovered.bin of=hash.bin bs=32 skip=1 count=1 2>/dev/null
dd if=M_recovered.bin of=iv.bin bs=1 skip=64 count=12 2>/dev/null
dd if=M_recovered.bin of=tag.bin bs=1 skip=76 count=16 2>/dev/null

# 3. 派生密钥
openssl dgst -sha256 -mac hmac -macopt hexkey:$(xxd -p -c 32 seed.bin) -binary hash.bin > k.bin

# 4. 解密（使用签名中恢复的 IV 和 Tag）
IV_HEX=$(xxd -p -c 12 iv.bin)
openssl enc -d -aes-256-gcm -in cipher.bin -out decrypted.txt \
    -K $(xxd -p -c 32 k.bin) -iv $IV_HEX -tagfile tag.bin

# 5. 验证文件哈希
openssl dgst -sha256 -binary decrypted.txt > hash_computed.bin
cmp hash.bin hash_computed.bin && echo "Success" || echo "Hash mismatch"
```

---

## 与 OpenSSL 实现的差异

| 环节 | Go (rsigner) | Shell (OpenSSL) |
|------|--------------|------------------|
| IV/Tag 存储 | 嵌入签名，无单独文件 | 嵌入签名，无单独文件 |
| PKCS8 兼容 | 自动兼容 PKCS1/PKCS8 私钥格式 | `genpkey` 默认 PKCS8 |
| 密钥位长 | `-g 2048` / `-g 4096` | `rsa_keygen_bits:2048` |

---

## 许可证
MIT LICENSE
