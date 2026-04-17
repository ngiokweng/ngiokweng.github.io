---
title: 【js逆向】yrx內部平台第5題
date: 2023-7-11 22:11:12
tags: 
        - js逆向
        - Python
        - 爬蟲
categories: js逆向
keywords:
    - js逆向
    - Python
    - 逆向
    - 爬蟲
description: js逆向 yrx
cover: Untitled1.png
---

## 無限debugger

這題有個無限debugger，用下面這個腳本暫時過一過，能分析頁面邏輯就行

```jsx
var Func = Function;

Function = function(){
    if(arguments[0].indexOf('debugger')!=-1)return function(){};
    return Func.apply(this,arguments);
}
```

## 定位加密函數

- 通過hook `XMLHttpRequest.prototype.open`，找到加密參數的位置
- 然後會跟到`_yrxyA$`這個函數，接下來就是要想辦法將它扣出來了

```jsx
function _yrxyA$(_yrx7jl, _yrxcze) {
        try {
            if (typeof _yrx7jl !== _yrxQ9C[6])
                _yrx7jl += ''
        } catch (_yrxrqQ) {
            return _yrx7jl
        }
        if (!(_yrxCJw & 1024)) {
            _yrx7jl = _yrxR2F(_yrx7jl)
        }
        var _yrx$Kn = _yrxtSa(_yrx7jl);
        if (_yrx$Kn === null) {
            return _yrx7jl
        }
        if (_yrx$Kn._yrxKni > 3) {
            return _yrxtY2(_yrx$Kn)
        }
        var _yrxmEu = _yrxWKg(_yrxyHJ(_yrx5XG(_yrx$Kn._yrx2ad + _yrx$Kn._yrxAmM)));
        var _yrx7jl = _yrx$Kn._yrxCiX + _yrx$Kn._yrxAmM;
        if (_yrx$Kn._yrxAmM === '')
            _yrx7jl = _yrx7jl + '?';
        else
            _yrx7jl = _yrx7jl + '&';
        var _yrx2LR = _yrx$Kn._yrxiv8 + _yrx7jl;
        _yrx2LR += _yrxBXT(779, _yrx$Kn._yrxQZs, _yrxmEu, _yrxcze);
        _yrx2LR += _yrx$Kn._yrxcFt;
        return _yrx2LR
    }
```

## 補環境

我比較懶，是直接把全部代碼扣下來，然後再補環境，具體思路&內容大概如下：

- 補環境時如果遇到代碼報錯 / 某些值不知怎麼來的，這時可以先基本判斷一下這些代碼有無用
- 若覺得無用，可以找到函數調用的源頭，將函數調用的入口注釋掉( 同樣要留下記號 )
- 遇到某些值不知怎麼來的時候，可以先與網頁的進行對比，若不變就可將值固定
- 有個地方會取`meta`標籤的`content`屬性，而這個值可以固定，改一改代碼將這個固定的值直接返回就可以

**總而言之，遇到問題先用最簡單的方法處理一次，報錯再說~**

### 動態參數分析

- 這時補好的環境還不能用，因為有幾個值是動態變化的
- 然後就只能慢慢一步一步地跟，看看哪裡不一樣了
- 最終會找到以下這個函數，它有兩處地方會改變，分別是`1689054205`和`'F' + 'g' + 'D' + 'd'`
- `_yrxCxm`就是`window`，而`_yrxCxm['F' + 'g' + 'D' + 'd']`這個值是由這個接口`/api/challenge5`返回的( 第1次請求這個接口不需要任何的加密函數，可以直接返回結果 )

```jsx
function _yrxVhD(_yrxtJ1) {
    return 1689054205 + _yrxCxm['F' + 'g' + 'D' + 'd']
}
```

### 動態參數處理

- 這時要做的就只剩下兩件事：
    1. 找到上述代碼的生成邏輯
    2. 將動態變化的值，`replace`到我補好的環境中
- 由於在以下這個地方時，`XMLHttpRequest.prototype.open`就已經被重寫了，因此我的想法是從這點入手，找到重寫`XMLHttpRequest.prototype.open`的地方，從而找到一切

![Untitled](Untitled.png)

- 我的做法是在”合適”的地方hook，這樣只要`XMLHttpRequest.prototype.open`被重寫時就能立刻定位到
    
    ```jsx
    let _val = XMLHttpRequest.prototype.open;
    
    Object.defineProperty(XMLHttpRequest.prototype,"open",{
        get:function(){
            console.log("getting",_val)
            return _val;
        },
        set:function(val) {
            debugger;
            console.log("setting",val)
            _val = val;
            return val;
        }
    })
    ```
    
- 最終成功被我定位到代碼生成的地方
- `$_ts[yuanrenxue_166('70', '\x5e\x34\x24\x4d')]`是由`/challenge/5/rsnkw2ksph`返回的密文
- `yuanrenxue_59`在這段代碼上方的某處，每次都會變
- `yuanrenxue_18` 就是最終解密後的代碼
    
    ```jsx
    for (let yuanrenxue_229 = 0x0; yuanrenxue_229 < $_ts[yuanrenxue_166('70', '\x5e\x34\x24\x4d')][yuanrenxue_166('71', '\x32\x4c\x76\x4e')]; yuanrenxue_229++) {
        yuanrenxue_36 += String[yuanrenxue_166('72', '\x70\x71\x4d\x73')]($_ts[yuanrenxue_166('73', '\x73\x36\x5a\x49')][yuanrenxue_229][yuanrenxue_166('74', '\x32\x73\x64\x45')]() - yuanrenxue_229 % yuanrenxue_59 - 0x32)
    }
    yuanrenxue_18 = atob(yuanrenxue_36);
    ```
    
- 上述這段代碼可以用python重寫一下
    
    ```python
    def decode(enc,sub_num):
        yuanrenxue_36 = ""
        for yuanrenxue_229 in range(len(enc)):
            yuanrenxue_36 += chr(ord(enc[yuanrenxue_229]) - yuanrenxue_229 % sub_num - 0x32)
    
        return base64.b64decode(yuanrenxue_36)
    ```
    

最後順一下邏輯，就基本能出結果了~

![Untitled](Untitled1.png)