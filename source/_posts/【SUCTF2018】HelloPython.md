---
title: 【SUCTF2018】HelloPython
date: 2022-11-15 13:12:30
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - Buuctf
    - 逆向
    - SUCTF2018
    - WriteUp
    - buuctf
    - HelloPython
description: buuctf SUCTF2018 HelloPython WriteUp
cover: Untitled.png
---
> 題目：[https://github.com/hebtuerror404/CTF_competition_warehouse_2018/tree/master/2018_SUCTF/reverse/hellopython](https://github.com/hebtuerror404/CTF_competition_warehouse_2018/tree/master/2018_SUCTF/reverse/hellopython) 
( 注：buu上的附件沒有給密文，有夠坑= = )
> 

## 反編譯

- 使用`uncompyle6`將`.pyc`轉成`.py`，經測試在Ubuntu 20.04.5 LTS上使用python2安裝的`uncompyle6`能順利反匯譯出如下信息：
- 可以看到它使用lambda表達式進行了混淆
- 根據題目描述可知這是個**加密程序**，**密文在題目描述中給出**

```python
# uncompyle6 version 3.8.0
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.18 (default, Jul  1 2022, 12:27:04) 
# [GCC 9.4.0]
# Warning: this version of Python has problems handling the Python 3 byte type in constants properly.

# Embedded file name: encrypt_ol.py
# Compiled at: 2018-11-01 21:19:40
(lambda __operator, __print, __g, __contextlib, __y: [ (lambda __mod: [ [ [ (lambda __items, __after, __sentinel: __y(lambda __this: lambda : (lambda __i: [ (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda : __this())][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and [ True for __out[0] in [(sys.exit(0), lambda after: after())[1]] ][0]})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [ False for __out[0] in [(v.append(int(word, 16)), lambda __after: __after())[1]] ][0]})())))([None]) for __g['word'] in [__i] ][0] if __i is not __sentinel else __after())(next(__items, __sentinel)))())(iter(p_text.split('_')), lambda : [ [ [ [ [ [ [ (lambda __after: __y(lambda __this: lambda : (lambda __target: [ (lambda __target: [ (lambda __target: [ [ __this() for __g['n'] in [__operator.isub(__g['n'], 1)] ][0] for __target.value in [__operator.iadd(__target.value, (y.value << 4) + k[2] ^ y.value + x.value ^ (y.value >> 5) + k[3])] ][0])(z) for __target.value in [__operator.iadd(__target.value, (z.value << 4) + k[0] ^ z.value + x.value ^ (z.value >> 5) + k[1])] ][0])(y) for __target.value in [__operator.iadd(__target.value, u)] ][0])(x) if n > 0 else __after())())(lambda : [ [ (__print(('').join(map(hex, w)).replace('0x', '').replace('L', '')), None)[1] for w[1] in [z.value] ][0] for w[0] in [y.value] ][0]) for __g['w'] in [[0, 0]] ][0] for __g['n'] in [32] ][0] for __g['u'] in [2654435769] ][0] for __g['x'] in [c_uint32(0)] ][0] for __g['z'] in [c_uint32(v[1])] ][0] for __g['y'] in [c_uint32(v[0])] ][0] for __g['k'] in [[3735928559, 590558003, 19088743, 4275878552]] ][0], [])
 for __g['v'] in [[]] ][0]
 for __g['p_text'] in [raw_input('plain text:\n> ')] ][0]
 for __g['c_uint32'] in [__mod.c_uint32] ][0])(__import__('ctypes', __g, __g, ('c_uint32', ), 0))
 for __g['sys'] in [__import__('sys', __g, __g)] ][0])(__import__('operator', level=0), __import__('__builtin__', level=0).__dict__['print'], globals(), __import__('contextlib', level=0), lambda f: (lambda x: x(x))(lambda y: f(lambda : y(y)())))
# okay decompiling attachment.pyc
```

## 代碼分析

`p_text`是明文，由此可知明文的格式文`XXX_XXX`

```python
# 以下是從反編譯文件截取的部分代碼
p_text.split('_')
```

跟TEA加密的特徵一樣，基本可以判斷是**TEA加密**

```python
# 以下是從反編譯文件截取的部分代碼
(__target.value, (y.value << 4) + k[2] ^ y.value + x.value ^ (y.value >> 5) 
+ k[3])] ][0])(z) for __target.value in [__operator.iadd(__target.value, 
(z.value << 4) + k[0] ^ z.value + x.value ^ (z.value >> 5) + k[1])] ][0])(y)
```

- `key = [3735928559, 590558003, 19088743, 4275878552]`
- `delta = 0x9E3779B9`
- `n = 32`
- `v[0]`、`v[1]`是傳入的明文，賦給了`y`、`z`，最後結果存放在`w`

```python
# 以下是從反編譯文件截取的部分代碼
for __g['k'] in [[3735928559, 590558003, 19088743, 4275878552]
for __g['n'] in [32]
for __g['u'] in [2654435769] # 2654435769 = 0x9E3779B9
for __g['x'] in [c_uint32(0)]
for __g['z'] in [c_uint32(v[1])]
for __g['y'] in [c_uint32(v[0])]
for w[1] in [z.value]
for w[0] in [y.value]
for __g['w'] in [[0, 0]]
```

最後對加密後的東西進行處理並打印，例如加密後`w = [0x123,0x456]`，那麼下面這句會打印`123456`

```python
(__print(('').join(map(hex, w)).replace('0x', '').replace('L', '')
```

## 腳本解密

網上抄的一份TEA通用腳本

```python
#include <stdint.h>
#include <iostream>
using namespace std;

void encrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;           /* set up */
    uint32_t delta = 0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i = 0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }                                              /* end cycle */
    v[0] = v0; v[1] = v1;
}

void decrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i;  /* set up */
    uint32_t delta = 0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i = 0; i < 32; i++) {                         /* basic cycle start */
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0] = v0; v[1] = v1;
}

int main() {
    uint32_t v[2] = { 0xf1f5d29b,0x6e4414ec };
    uint32_t k[4] = { 3735928559, 590558003, 19088743, 4275878552 };
    decrypt(v, k);
    cout <<hex<< v[0] <<'_' << v[1] << endl;
}
```

![Untitled](Untitled.png)