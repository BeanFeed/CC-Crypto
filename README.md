# CC: Cryptography

__Purpose__
The initial point of making this mod was to have an easy way to run hashing and encrypting since the lua libraries are hard to find and lua is slow. It was made for an SMP that I was in where I was trying to implement code signing on my computers.

## Function Docs

### RSA

```lua
crypto.rsaEncrypt(value, publicKey)
```
Returns: `string`

---
```lua
crypto.rsaDecrypt(value, privateKey)
```
Returns: `string`

---
```lua
crypto.rsaSign(value, privateKey)
```
Returns: `string`

---
```lua
crypto.rsaVerify(value, signature, publicKey)
```
Returns: `boolean`

### AES

```lua
crypto.aesEncrypt(value, key)
```
Returns: `string`

---
```lua
crypto.aesDecrypt(value, key)
```
Returns: `string`

### Other

```lua
crypto.sha256(value)
```
Returns: `string`
