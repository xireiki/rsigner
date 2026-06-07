# rsigner.js — RSA 消息恢复签名 + AES-256-GCM 加密/解密

将 RSA 消息恢复签名与 AES-256-GCM 相结合，实现**密文与解密密钥强绑定**的方案。  
任何对密文的篡改（包括攻击者用正确密钥重加密）都会自动导致解密失败，无需依赖显式比对。

纯 JavaScript 实现，基于 Web Crypto API + BigInt，浏览器与 Node.js 均可使用。

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
# 直接复制到项目
cp rsigner.js your-project/
```

---

## API 参考

### 密钥生成

```js
import * as rsigner from './rsigner.js';

const keypair = await rsigner.generateKeyPair(2048);
```

#### `generateKeyPair(bits?)`

| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `bits` | `number` | `2048` | RSA 密钥长度，最低 2048 |

**返回:** `Promise<CryptoKeyPair>` — 包含 `privateKey`、`publicKey` 的 `CryptoKey` 对象。

---

### 密钥导出

```js
const privPem = await rsigner.exportPrivateKey(keypair.privateKey);
const pubPem  = await rsigner.exportPublicKey(keypair.publicKey);
```

#### `exportPrivateKey(key)`

| 参数 | 类型 | 说明 |
|------|------|------|
| `key` | `CryptoKey` | RSA 私钥 |

**返回:** `Promise<string>` — PKCS#8 PEM（`-----BEGIN PRIVATE KEY-----`）。

#### `exportPublicKey(key)`

| 参数 | 类型 | 说明 |
|------|------|------|
| `key` | `CryptoKey` | RSA 公钥 |

**返回:** `Promise<string>` — SPKI PEM（`-----BEGIN PUBLIC KEY-----`）。

---

### 密钥导入

```js
const privateKey = await rsigner.importPrivateKey(pem);
const publicKey  = await rsigner.importPublicKey(pem);
```

#### `importPrivateKey(pem)`

| 参数 | 类型 | 说明 |
|------|------|------|
| `pem` | `string` | PEM 字符串 |

自动检测 PKCS#8（`PRIVATE KEY`）和 PKCS#1（`RSA PRIVATE KEY`）。

**返回:** `Promise<CryptoKey>`。

#### `importPublicKey(pem)`

| 参数 | 类型 | 说明 |
|------|------|------|
| `pem` | `string` | PEM 字符串 |

SPKI 格式（`-----BEGIN PUBLIC KEY-----`）。

**返回:** `Promise<CryptoKey>`。

---

### 加密

```js
const { signature, ciphertext } = await rsigner.encrypt(plaintext, privateKey);
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `plaintext` | `Uint8Array` | 明文数据 |
| `privateKey` | `CryptoKey` | RSA 私钥（需 extractable） |

**返回:**

| 字段 | 类型 | 说明 |
|------|------|------|
| `signature` | `Uint8Array` | RSA 消息恢复签名（长度 = 密钥模长） |
| `ciphertext` | `Uint8Array` | AES-256-GCM 密文 |

---

### 解密

```js
const plaintext = await rsigner.decrypt(signature, ciphertext, publicKey);
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `signature` | `Uint8Array` | RSA 签名（须与密钥模长一致） |
| `ciphertext` | `Uint8Array` | AES-256-GCM 密文 |
| `publicKey` | `CryptoKey` | RSA 公钥（需 extractable） |

**返回:** `Promise<Uint8Array>` — 解密后的明文。

---

## 完整示例

```js
import * as rsigner from './rsigner.js';

async function demo() {
  // 1. 生成密钥
  const kp = await rsigner.generateKeyPair(2048);

  // 2. 导出 PEM（可选）
  const privPem = await rsigner.exportPrivateKey(kp.privateKey);
  const pubPem  = await rsigner.exportPublicKey(kp.publicKey);
  console.log(privPem);

  // 3. 加密
  const plaintext = new TextEncoder().encode('Hello, world!');
  const { signature, ciphertext } = await rsigner.encrypt(plaintext, kp.privateKey);

  // 4. 解密
  const decrypted = await rsigner.decrypt(signature, ciphertext, kp.publicKey);
  console.log(new TextDecoder().decode(decrypted)); // "Hello, world!"
}
```

---

## 浏览器兼容性

| 环境 | 最低版本 |
|------|---------|
| Chrome | 67+ |
| Firefox | 68+ |
| Safari | 14+ |
| Edge | 79+ |
| Node.js | 19+ |

---

## 密钥格式兼容性

rsigner.js 的 PEM 可与 Go / C / Rust 命令行版本互操作：

| 密钥 | 导出格式 | 导入支持 |
|------|---------|---------|
| 私钥 | PKCS#8 (`PRIVATE KEY`) | PKCS#8 + PKCS#1 自动检测 |
| 公钥 | SPKI (`PUBLIC KEY`) | SPKI |

---

## 安全性测试

| 攻击场景 | 拦截点 |
|----------|--------|
| 篡改密文一个字节 | GCM 认证标签验证失败 |
| 篡改签名一个字节 | RSA 填充格式错误 |
| 重用旧签名 + 新密文 | GCM 用原始 IV/Tag 解密新密文失败 |
| 用正确密钥重加密篡改文件 | 攻击者无法伪造新 IV/Tag 的签名 |

---

## 许可证

MIT LICENSE
