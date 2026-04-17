---
title: Python爬取網易云評論
date: 2022-12-26 22:18:55
tags: 
        - Python
        - 爬蟲
        - js逆向
categories: Python
keywords:
    - Python
    - 爬蟲
    - js逆向
    - 網易云
description: Python爬取網易云評論
cover: Untitled1.png
---
## 分析頁面

- 在網頁原始碼中找不到評論區的內容，**由此可知這網頁是[客戶端渲染](https://juejin.cn/post/7012492790642769934)**
- 注：`F12`與`網頁原始碼`是兩個不同的東西，`F12`中會顯示當前網頁的實時數據，所以可以看到評論區的內容

![Untitled](Untitled.png)

- 在`XHR`中找到2次響應的數據
- 可以看到請求的參數明顯經過加密，因此接下來就是要找到加密的地方

![Untitled](Untitled1.png)

![Untitled](Untitled2.png)

至此，大概可以分析出我們爬蟲的步驟：

1. 找到未加密前的參數是怎樣的
2. 找到加密函數，自己用python模擬出來
3. 對【未加密前的參數】作出自己需要的修改，然後再放到自己模擬的加密函數中進行加密
4. 發送請求

## 動調JS

對於網頁來說，動調實在是十分的方便，**只順通過很簡單的方法就可以看到函數的調用順序，根據這個順序就能很輕易地找到加密的地方**，具體操作如下：

- 在上面已經找到服務器返回的評論區的數據，即`get?csrf_token=`這個
- 點擊`發起人`→`要求呼叫堆疊`，這裡就是發送這個網路封包時的函數調用棧，點擊最上面那個

![Untitled](Untitled3.png)

然後再點擊左下角的`{}`來格式化JS代碼

![Untitled](Untitled4.png)

之後可以看到高亮的那行代碼就是發送請求的地方，然後按左邊的數字來下斷點

![Untitled](Untitled5.png)

之後按`F5`重新載入網頁，觀察作用域的數據來判斷是否停在了我需要的地方，若不是就按`繼續執行指令碼`，直到是為至

![Untitled](Untitled6.png)

然後順著`呼叫堆疊`向下找，目標是找到【未加密前的參數】和【加密函數】

![Untitled](Untitled7.png)

一個一個找，然後在一個匿名函數中找到【未加密前的參數】，它最終會將數據送到`u1x.be1x(Y1x, BH0x)`來進行加密

![Untitled](Untitled8.png)

- 進入`u1x.be1x(Y1x, BH0x)`繼續分析，因為【未加密前的參數】最終會在這個函數的某行代碼中進行加密，但有時單靠靜態分析很難直接看到是哪一行，因此可以在第1行下斷點，以單步調試的方式來判斷
- 最終發現`window.asrsea`就是加密函數

![Untitled](Untitled9.png)

可以看到`window.asrsea`傳入了4個參數，參數1就是【未加密前的參數】，參數2~4其實是定值，有兩種方法可以獲取這些定值：

1. 通過console，直接輸入參數2~4( 前提是要斷在`u1x.be1x`函數中 )
    
    ![Untitled](Untitled10.png)
    
2. 直接在具體函數內下斷點

- 之後按`Ctrl+f`搜尋`window.asrsea`函數，發現只有2處地方符合
- 看到`window.asrsea` = `d`，因此`d`就是我們的【加密函數】，而`a`、`b`、`c`都與其有關

![Untitled](Untitled11.png)

## 加密函數分析

```jsx
function a(a) {
        var d, e, b = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", c = "";
        for (d = 0; a > d; d += 1)
            e = Math.random() * b.length,
            e = Math.floor(e),
            c += b.charAt(e);
        return c
    }
    function b(a, b) {
        var c = CryptoJS.enc.Utf8.parse(b)
          , d = CryptoJS.enc.Utf8.parse("0102030405060708")
          , e = CryptoJS.enc.Utf8.parse(a)
          , f = CryptoJS.AES.encrypt(e, c, {
            iv: d,
            mode: CryptoJS.mode.CBC
        });
        return f.toString()
    }
    function c(a, b, c) {
        var d, e;
        return setMaxDigits(131),
        d = new RSAKeyPair(b,"",c),
        e = encryptedString(d, a)
    }
 //////////////////    加密函數    //////////////////
    function d(d, e, f, g) { //d是【未加密前的參數】，e、f、g是已知的定值
        var h = {}
          , i = a(16); //a會返回16個隨機的字符串，即i是隨機的
				
				//這裡對第1個函數進行了2次AES
        return h.encText = b(d, g), //b是AES加密，CBC模式
        h.encText = b(h.encText, i),
				//這裡對第2個參數進行了RSA加密
				//而i是一個隨機的字符串，e、f是固定的
				//因此只需要固定i，那麼encSecKey就是固定的
				//可以動調獲取i和encSecKey的值，然後直接寫死在爬蟲程序中就可以
        h.encSecKey = c(i, e, f),
        h
    }
```

## 最終代碼

```python
import requests
from Cryptodome.Cipher import AES
import json
from base64 import b64encode

url = "https://music.163.com/weapi/comment/resource/comments/get?csrf_token="

# 原始請求參數
data = {
    "cursor": -1,
    "offset": 0,
    "orderType": 1,
    "pageNo": 1,
    "pageSize": 20,
    "rid": "A_PL_0_2105681544",
    "threadId": "A_PL_0_2105681544"
}

# 固定的參數
encSecKey = "d408e6881677cf32231835eb33caa8d6c48ab2769efa209eaa2178df039c899e0083959c5084d2a017c9548962608b1ac29f69deb3906fe4bb128d848b40df8755fd28a9b657c9bf98f2ef99877d87611167db0b1b2737effd5d7c4fa0db6fd1c055532f3ba62a1e39b73266e355c4d70d3f3dfef43d9a9d5c758001f70bb7a6"
i = "TfyOQ9mmmJOZEI7g"
e = "010001"
f = "00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7"
g = "0CoJUm6Qyw8W8jud"

# data需為字符串，這樣才能加密
def getEncText(data):
    first = myEnc(data,g)
    return myEnc(first,i)

# AES加密的內容必須為16的倍數，並需按如下規則進行處理：
# 當data長度為12時，16-12=4，必須補充4個chr(4)，如此類推
# 特別地，當data正好為16時，也需要補充
def to_16(data):
    pad = 16 - len(data)%16
    data += pad*chr(pad)
    return data

def myEnc(data,key):
    data = to_16(data)
    cipher = AES.new(key = key.encode("utf-8"),iv=b"0102030405060708", mode = AES.MODE_CBC) # 加密參數都要求是bytes類型
    ciphertext = cipher.encrypt(data.encode("utf-8"))# 加密參數都要求是bytes類型
    # 不能直接轉成str，要先base64後加轉成str
    b64_enc = b64encode(ciphertext)
    return str(b64_enc,"utf-8")

if __name__ == "__main__":
    resp = requests.post(url=url,data={
        "params":getEncText(json.dumps(data)),
        "encSecKey":encSecKey
    })
    print(resp.text)
```