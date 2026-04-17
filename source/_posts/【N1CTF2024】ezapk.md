---
title: 【N1CTF2024】ezapk
date: 2024-11-10 19:24:24
tags:
- Reverse
- Android逆向
categories: Android逆向
keywords:
- Android逆向
description: N1CTF2024
cover: image1.png
---

## 前言

久違的看看安卓題，~~順便水一篇文章~~，有任何問題歡迎指出！

## 分析

### java層

拉入jadx，很容易可以定位到關鍵邏輯，經典的加密對比。

![image.png](image.png)

加密函數`enc`在native層，而且加載了2個so。

嘗試分別將2個so都拉入ida，但都未發現`enc`，顯然是動態注冊的。

![image.png](image1.png)

![image.png](image2.png)

網上抄的一個frida腳本，用來hook動態注冊的native函數

```jsx
// com.n1ctf2024.ezapk
function find_RegisterNatives(params) {
    let symbols = Module.enumerateSymbolsSync("libart.so");
    let addrRegisterNatives = null;
    for (let i = 0; i < symbols.length; i++) {
        let symbol = symbols[i];
        
        //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
        if (symbol.name.indexOf("art") >= 0 &&
                symbol.name.indexOf("JNI") >= 0 && 
                symbol.name.indexOf("RegisterNatives") >= 0 && 
                symbol.name.indexOf("CheckJNI") < 0) {
            addrRegisterNatives = symbol.address;
            console.log("RegisterNatives is at ", symbol.address, symbol.name);
            hook_RegisterNatives(addrRegisterNatives)
        }
    }

}

function hook_RegisterNatives(addrRegisterNatives) {

    if (addrRegisterNatives != null) {
        Interceptor.attach(addrRegisterNatives, {
            onEnter: function (args) {
                console.log("[RegisterNatives] method_count:", args[3]);
                let java_class = args[1];
                let class_name = Java.vm.tryGetEnv().getClassName(java_class);
                //console.log(class_name);

                let methods_ptr = ptr(args[2]);

                let method_count = parseInt(args[3]);
                for (let i = 0; i < method_count; i++) {
                    let name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
                    let sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize));
                    let fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));

                    let name = Memory.readCString(name_ptr);
                    let sig = Memory.readCString(sig_ptr);
                    let symbol = DebugSymbol.fromAddress(fnPtr_ptr)
                    console.log("[RegisterNatives] java_class:", class_name, "name:", name, "sig:", sig, "fnPtr:", fnPtr_ptr,  " fnOffset:", symbol, " callee:", DebugSymbol.fromAddress(this.returnAddress));
                }
            }
        });
    }
}

setImmediate(find_RegisterNatives);
```

發現是在`libnative1.so!0x1b148`

![image.png](image3.png)

### native層

`0x1b148`函數如下，重命名成`enc`，做了一些奇奇怪怪的操作，等等再分析

![image.png](image4.png)

在此之前，由於比較好奇另一個so `libnative2.so`有什麼用，於是順手查看了`.init_array`段，看看有沒有偷偷在做壞事。( 因為在java層沒有發現任何對`libnative2.so`函數的調用，只有調用`libnative1.so`的，因此合理懷疑對`libnative2.so`的操作是在`libnative1.so`中進行的，而`.init_array`就是一個很好的時機。 )

`sub_1B540`是`.init_array`段最後一個函數，果然發現了`libnative2.so`的字樣。

![image.png](image5.png)

`sub_1B540`一開始先從`/proc/self/maps`裡獲取`libnative.so`的基址

![image.png](image6.png)

然後調用`sub_1B000`將libnative2.so的一些信息初始化，保存在`libnative2_base`

![image.png](image7.png)

`sub_1B000`的實現挺像linker加載so的流程中的`prelink_image`。

![image.png](image8.png)

`sub_1B540`最後部份如下，大概是將`libnative2.so`裡的`rand`函數返回值固定為`0xE9`。

![image.png](image9.png)

![image.png](image10.png)

看完`.init_array`後，可以回到`enc`函數了( 其實上面的那些東西看不看都沒有所謂，單純是我好奇想看看，純動調其實就能解決這題 )。

動調後會發現，第1個紅框大概是在取`libnative2.so`某個函數的offset，然後第2個紅框調用該函數對輸入進行加密( 通過base + offset得到函數的具體地址 )。

![image.png](image11.png)

一步一步調試完後會發現，總共從`libnative2.so`裡取了3個加密函數。

第1個的offset是`0x106C`，只是簡單的異或，異或的值是上述分析的`0xE9`。

![image.png](image12.png)

第2個的offset是`0x12C0`，一眼RC4。

![image.png](image13.png)

第3個的offset是`0x1AB0`，一眼base64。

![image.png](image14.png)

### 解密結果

最終結果：`MysT3r10us_C0d3_2024N1CTF!`

![image.png](image15.png)

## 結語

這題目挺好的，感覺我以往遇到的題更偏向於算法的部份，而這題對算法分析的要求不高，反而多了一些android逆向實際可能會遇到的東西，挺有意思的。