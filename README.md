GMSSL
========

GmSSL是一个开源的加密包的python实现，支持SM2/SM3/SM4等国密(国家商用密码)算法、项目采用对商业应用友好的类BSD开源许可证，开源且可以用于闭源的商业应用。
本次是在<https://github.com/duanhongyi/gmssl>上进行的修改，需要原版的请到作者github上clone。本次修改增加了生成SM2密钥的功能。

### 安装

```shellpip install gmssl   #原版安装
或
git clone git@github.com:rootklt/gmssl.git
cd gmssl
python3 setup.py install
```

### SM2算法

RSA算法的危机在于其存在亚指数算法，对ECC算法而言一般没有亚指数攻击算法
SM2椭圆曲线公钥密码算法：我国自主知识产权的商用密码算法，是ECC（Elliptic Curve Cryptosystem）算法的一种，基于椭圆曲线离散对数问题，计算复杂度是指数级，求解难度较大，同等安全程度要求下，椭圆曲线密码较其他公钥算法所需密钥长度小很多。

gmssl是包含国密SM2算法的Python实现， 提供了 `encrypt`、 `decrypt`等函数用于加密解密， 用法如下：

#### 1. 初始化`CryptSM2`

```python
import base64
import binascii
from gmssl import sm2, utils  #将原来的func修改成utils
#16进制的公钥和私钥,限bytes类型
private_key = b'00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
public_key = b'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
sm2_crypt = sm2.CryptSM2()

#1.有公钥和私钥的时候直接设置
sm2_crypt.set_key_pair(public_key=public_key, private_key=private_key)

#2.只需要公钥加密的时候
sm_crypt.set_public_key(public_key=public_key)

#3.只需要私钥解密
sm2_crypt.set_private_key(private_key=private_key)
```

#### 2. `encrypt`和`decrypt`

```python
#数据和加密后数据为bytes类型
data = b"111"
enc_data = sm2_crypt.encrypt(data)   #加密后返回的是hex字符串
dec_data =sm2_crypt.decrypt(binascii.unhexlify(enc_data))
assert dec_data == data
```

#### 3. `sign`和`verify`

```python
data = b"111" # bytes类型
random_hex_str = func.random_hex(sm2_crypt.para_len)
sign = sm2_crypt.sign(data, random_hex_str) #  16进制
assert sm2_crypt.verify(sign, data) #  16进制
```

#### 4. `sign_with_sm3`和`verify_with_sm3`

```python
data = b"111" # bytes类型
sign = sm2_crypt.sign_with_sm3(data) #  16进制
assert sm2_crypt.verify_with_sm3(sign, data) #  16进制
```

#### 5.生成密钥

```python
private_key, public_key = sm2_crypt.gen_key_pair()
b'73fbfa0e5416c0fd67250ea7a19312fd33475eb188e0dab2d55a67e648151e29'
b'23d2817e685ec94ffc6c9321a66c63c924a109d52f7dd8993b3625be812e7d65a6a3f19192fc95e290df36249da4c0edfa54821e8e8e7518abbad035b5eea7a0'
#可以设置压缩模式，将公钥进行压缩

sm2_crypt.set_compressed = True #默认为False
private_key, public_key = sm2_crypt.gen_key_pair()
private_key = b'd242a7ec7e3bea0f5c6b2df34705701658638cdc625b1903d7edacddb213359e'
public_key = b'3e206c2c45596028c509f1941259dfb8d3060ae26284f67b8400bfd623e17637'

```

### SM4算法

国密SM4(无线局域网SMS4)算法， 一个分组算法， 分组长度为128bit， 密钥长度为128bit，
算法具体内容参照[SM4算法](https://drive.google.com/file/d/0B0o25hRlUdXcbzdjT0hrYkkwUjg/view?usp=sharing)。

gmssl是包含国密SM4算法的Python实现， 提供了 `encrypt_ecb`、 `decrypt_ecb`、`encrypt_cbc`、`decrypt_cbc`等函数用于加密解密， 用法如下：

#### 1. 初始化`CryptSM4`

```python
from gmssl.sm4 import SM4Crypt, SM4_ENCRYPT, SM4_DECRYPT

key = b'3l5butlj26hvv313'
value = b'111' #  bytes类型
iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' #  bytes
pad_mode = 'pkcs7' # 支持pkcs7 和 zero两种, 默认是pkcs7


crypt_sm4 = SM4Crypt()
crypt_sm4.init(key = key, iv = iv, pad_mode = 'pkcs7')  #初始化key 或 填充模式，ECB加密时可以不设置iv
```

#### 2. `encrypt_ecb`和`decrypt_ecb`

```python

encrypt_value = crypt_sm4.encrypt_ecb(value) #  bytes|str类型,返回hex字符串
decrypt_value = crypt_sm4.decrypt_ecb(binascii.unhexlify(encrypt_value)) #  bytes|str类型
assert value == decrypt_value

```

#### 3. `encrypt_cbc`和`decrypt_cbc`

```python

encrypt_value = crypt_sm4.encrypt_cbc(value) #  bytes|str类型,返回的是hex字符串
decrypt_value = crypt_sm4.decrypt_cbc(binascii.unhexlify(encrypt_value)) #  bytes|str类型
assert value == decrypt_value

```

### SM3消息摘要

```python
from gmssl import sm3

data = 'hello'

sm3.sm3_hash(data)
```