---
title: 【FlareOn2】sender
date: 2023-1-19 11:55:12
tags: 
        - Reverse
        - WriteUp
categories: CTF
keywords:
    - CTF
    - buuctf
    - 逆向
    - WriteUp
    - Reverse
    - FlareOn2
description: FlareOn2 sender
cover: Untitled1.png
---
## 分析

`a1`是flag，先對flag進行了加法操作，所以之後解密時直接減回來就可

![Untitled](Untitled.png)

之後對flag進行了變表的base64加密

![Untitled](Untitled1.png)

最後會發送網路請求，也就是題目給出的那個`.pcap`檔，要用`wireshark`打開

![Untitled](Untitled2.png)

- 在`wireshark`用指令`http.request.method=="POST"`過濾掉其他無用的封包，只留下POST請求的那些
- 然後再逐一取出所有data，拼接起來後，這就是我們的密文

![Untitled](Untitled3.png)

## 解密腳本

```python
from base64 import b64decode

fake_table = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
real_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
enc_data = list("UDYs1D7bNmdE1o3g5ms1V6RrYCVvODJF1DpxKTxAJ9xuZW==")

# 變表base64要先換表
for i in range(len(enc_data)):
    enc_data[i] = real_table[fake_table.find(enc_data[i])]
enc_data = "".join(enc_data)

key = "flarebearstare"
res = list(b64decode(enc_data))
for i in range(len(res)):
    res[i] = (res[i]-ord(key[i%14]))%256
    print(chr(res[i]),end="")
print(res)
```