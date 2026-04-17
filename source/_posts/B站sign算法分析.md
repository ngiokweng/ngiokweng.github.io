---
title: B站sign算法分析
date: 2024-05-26 16:40:10
tags:
- Android逆向
- ollvm
categories: Android逆向
keywords:
- Android逆向
- ollvm
description: B站sign算法分析
cover: Untitled.png
---

## Target

目標是如下的`sign`參數，很多接口都需要這個參數，隨即找一個來分析就可以

![Untitled](Untitled.png)

## 關鍵點定位

### 方法一：字符串搜索

不能直接搜`sign`，因為會出現很多結果，難以肉眼看出。

要嘗試這樣搜索：`"sign`、`sign"`、`sign=`、`&sign`

![Untitled](Untitled1.png)

最終可以定位到`com.bilibili.nativelibrary.LibBili`類的`s`函數，是一個native方法，在`libbili.so`中。

參數是自定義的類型`SortedMap`，其實傳入`TreeMap`就可以

![Untitled](Untitled2.png)

### 方法二：hook HashMap

這個方法是從這篇文章學來的 → [https://blog.csdn.net/xmx_000/article/details/134123902](https://blog.csdn.net/xmx_000/article/details/134123902)

原理：

猜測`sign`值大機率是其餘參數的簽名，而且請求參數的鍵值對通常都會以`HashMap`( 其他Map都有可能？ )來保存，因此hook `HashMap`再打印調用棧就能快速定位到指定位置。

這裡選擇用於判斷的鍵值是`ad_extra`而不是`sign`( `ad_extra`是接口其中一個請求參數 )，因為`sign`這個詞太常見，選擇一個較為少見的參數作為過濾條件顯然會更好。

對我的手機來說( Pixel1XL )，若直接在spawn時直接hook `HashMap`的話，會卡住很久，解決方案是等APP加載後再手動調用hook函數`findSignFunc`，最後再想辦法觸發hook。

```jsx
function findSignFunc() {
    Java.perform(function () {
        function showStacks() {
            console.log(
                Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new())
            );
        }

        var hashMap = Java.use("java.util.HashMap");
        hashMap.put.implementation = function (a, b) {
            if (a.equals("ad_extra")) {
                showStacks();
                console.log("hashMap.put: ", a, b);
            }
            return this.put(a, b);
        }
    }
    )
}
```

調用棧打印如下：

![Untitled](Untitled3.png)

定位到`com.bilibili.okretro.interceptor.DefaultRequestInterceptor.addCommonParamToUrl`，發現目標

![Untitled](Untitled4.png)

## native層分析

IDA打開`libbili.so`，搜索`Java_`什麼都沒有，顯然是動態注冊的。

用大神的腳本來hook：https://github.com/lasting-yang/frida_hook_libart/blob/master/hook_RegisterNatives.js

打印了很多，搜索`com.bilibili.nativelibrary.LibBili`來定位，最終找到函數offset是`0x9050`

![Untitled](Untitled5.png)

IDA按`G`，跳到`0x9050`，很熟悉的ollvm，這時要麼想辦法反ollvm混淆，要麼只能配合指令trace來硬分析。前者有心無力，只能用後者方案。

![Untitled](Untitled6.png)

## 指令trace

使用[stalker](https://github.com/bmax121/sktrace)進行指令trace：[stalker與trace分析還原ollvm](https://www.notion.so/stalker-trace-ollvm-410ec5f5244c45cdaabe8d7e12838ce6?pvs=21) 

構建的frida主動調用如下，參數傳入`"ts"`，因此每次結果都是固定的值：`7e54b72b0c9418f66fca3f37234b0055`。

注：trace過程很漫長，要等20~30分鐘左右

```jsx
function callSignQuery() {
    console.log("======================== callSignQuery ========================")
    Java.perform(function () {
        let LibBili = Java.use("com.bilibili.nativelibrary.LibBili");
        let TreeMap = Java.use("java.util.TreeMap");
        let sortedMap = TreeMap.$new();
        sortedMap.put("ad_extra", "E86F4CFF1F8FA890A75155EEAA51E6AE4FA9DBE62FCE708186D0CE5EF37B86948620D8BA1D991685B1288E2EDE09C6D52F8C2D33D59872EAE1EB776D11F71523CE1AF2112D8A950B98F6A1A48F848BC6871A849C3ED14308F46431A85625726A929A8906FA0C16FEE2CEB33209AE6F1E0C6856961045F53A0FE3470E4E223F4831A8E8F49BB70BD66C75C477BFCB486A1746726BFC85AEFF972C3253A72BACE4F4BFBAE5FCDC4F7004849F8AA2B8AC5877769C453EB2784D47B64F834DB3F4CA4FD5E575D8311D71676146980E1018210BCB3B78165FB5971258E26B90B5BDE6D67D0D8A0457221297845A45D7309FD0BE9DF2B562088048075E3F965D2E4D3DB227F27FB5F62528B2D8578E23010600C648076F77BD43F073D7FF53FDACB3946E0BA5EB7FF49FA485ED5EC7FD56E836BDA4B844786384EA943202BC6B477C4E73EF6702720D86B83CBC48C4D4790B5D736EE8701B560A4EC5D45B9E1D48EF2B6634FDAAF660DAD595471439CBC20CE6553523EF555A4345CA05A4289AA5A817AFC7DDFE8FB1AA267BE0ACF55B38FE619BC345AE06E12699A1FF5799201210C4134A2098A62BD2ABF6F2F33C2DA61EADB84EF40F3932EA9274387827D21CAE62895E33349081BBA87B524FB6793728F0B0145DF5DBEB062AA6B9BB0EB1FFBDAE8D3804021D7282890FAB1B0B52966C63818E0451ED0E910D2193CAF907C5B10A24098AABE6159A63354F02E314DFECF72BB544E75ABEA2AF7B467155FFAAFD70724FDDE7698170F9B036CFA8DE25E0B63C2E2152D154D8F08489F105646E3C77D614C89C4D12A06D383445C3758332BCA07E8CCCFD61D1FCE8F65A897E48D356632641C222923FBA0C1F29E89EC2EBD30FE97DBF359FABDFDE889762A5485B006A37C612EE22D3AFD695FB17625DC1B66AED0282F0B14AF644C8345E73A5A309");
        sortedMap.put("appkey", "1d8b6e7d45233436");
        sortedMap.put("auto_refresh_state", "1");
        sortedMap.put("autoplay_card", "11");
        sortedMap.put("autoplay_timestamp", "0");
        sortedMap.put("build", "7770300");
        sortedMap.put("c_locale", "zh-Hant_MO");
        sortedMap.put("channel", "bili");
        sortedMap.put("column", "2");
        sortedMap.put("column_timestamp", "1715257334");
        sortedMap.put("device_name", "Pixel XL");
        sortedMap.put("device_type", "0");
        sortedMap.put("disable_rcmd", "0");
        sortedMap.put("flush", "0");
        sortedMap.put("fnval", "400");
        sortedMap.put("fnver", "0");
        sortedMap.put("force_host", "0");
        sortedMap.put("fourk", "1");
        sortedMap.put("guidance", "0");
        sortedMap.put("https_url_req", "0");
        sortedMap.put("idx", "0");
        sortedMap.put("inline_danmu", "2");
        sortedMap.put("inline_sound", "1");
        sortedMap.put("inline_sound_cold_state", "2");
        sortedMap.put("interest_id", "0");
        sortedMap.put("login_event", "1");
        sortedMap.put("mobi_app", "android");
        sortedMap.put("network", "wifi");
        sortedMap.put("open_event", "cold");
        sortedMap.put("platform", "android");
        sortedMap.put("player_net", "1");
        sortedMap.put("pull", "true");
        sortedMap.put("qn", "32");
        sortedMap.put("qn_policy", "1");
        sortedMap.put("recsys_mode", "0");
        sortedMap.put("s_locale", "zh-Hant_MO");
        sortedMap.put("splash_id", "");
        sortedMap.put("statistics", "{\"appId\":1,\"platform\":3,\"version\":\"7.77.0\",\"abtest\":\"\"}");
        sortedMap.put("ts", "1716130159");
        sortedMap.put("video_mode", "1");
        sortedMap.put("voice_balance", "1");

        let res = LibBili.signQuery(sortedMap);
        let sign = res.toString().split("&sign=")[1]
        console.log(sign)
    })
}
```

trace生成的日志用010Editor打開，會更方便分析。

直接搜索`7e54b72b0c9418f66fca3f37234b0055`，發現什麼都沒有

![Untitled](Untitled7.png)

改為搜索`0x7e,0x54`，能搜到一個結果

![Untitled](Untitled8.png)

然後可以定位到這裡，嘗試在此開始向上分析，但我發現很難向上分析，有種無從下手的感覺。

![Untitled](Untitled9.png)

改變思路，參考這篇文章：[https://blog.csdn.net/cswenrou/article/details/132666942](https://blog.csdn.net/cswenrou/article/details/132666942)

易知`7e54b72b0c9418f66fca3f37234b0055`長度是32，符合md5的長度，因此猜測`7e54b72b0c9418f66fca3f37234b0055`是由`7e54b72b`、`0c9418f6`、`6fca3f37`、`234b0055`"拼接"而來( md5結果保存在內存中，占16字節，每次取一個int大小，即4字節，內存分佈如下圖 )

![Untitled](Untitled10.png)

綜上所述，我們可以嘗試搜索`0x2bb7547e` ( 小端形式 )，最終定位到這裡。

![Untitled](Untitled11.png)

在IDA定位到上述指令，地址為：`0x7947bb1d90 - 0x7947b9f000 = 0x12D90`。

該地址在`func2_1`( 我自己重命名的 )這個函數中。

![Untitled](Untitled12.png)

![Untitled](Untitled13.png)

這時可以直接用frida hook `func2_1`函數，觀察輸入和輸出，可能會有意想不到的收獲。

它的結果會暫存在第一個參數`a1`中，因此在enter時要保存`args[0]`，然後在leave時再打印。

注入指令：`frida -U -f  tv.danmaku.bili -l .\tmp_script.js --no-pause > dump.log`

```jsx
function hook_dlopen_anti(soName = '') {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                if (path.indexOf('libmsaoaidsec.so') >= 0) {
                    ptr(pathptr).writeUtf8String("");
                }
            }
        }
    });
}

function callSignQuery() {
    console.log("======================== callSignQuery ========================")
    Java.perform(function () {
        let LibBili = Java.use("com.bilibili.nativelibrary.LibBili");
        let TreeMap = Java.use("java.util.TreeMap");
        let sortedMap = TreeMap.$new();
        sortedMap.put("ad_extra", "E86F4CFF1F8FA890A75155EEAA51E6AE4FA9DBE62FCE708186D0CE5EF37B86948620D8BA1D991685B1288E2EDE09C6D52F8C2D33D59872EAE1EB776D11F71523CE1AF2112D8A950B98F6A1A48F848BC6871A849C3ED14308F46431A85625726A929A8906FA0C16FEE2CEB33209AE6F1E0C6856961045F53A0FE3470E4E223F4831A8E8F49BB70BD66C75C477BFCB486A1746726BFC85AEFF972C3253A72BACE4F4BFBAE5FCDC4F7004849F8AA2B8AC5877769C453EB2784D47B64F834DB3F4CA4FD5E575D8311D71676146980E1018210BCB3B78165FB5971258E26B90B5BDE6D67D0D8A0457221297845A45D7309FD0BE9DF2B562088048075E3F965D2E4D3DB227F27FB5F62528B2D8578E23010600C648076F77BD43F073D7FF53FDACB3946E0BA5EB7FF49FA485ED5EC7FD56E836BDA4B844786384EA943202BC6B477C4E73EF6702720D86B83CBC48C4D4790B5D736EE8701B560A4EC5D45B9E1D48EF2B6634FDAAF660DAD595471439CBC20CE6553523EF555A4345CA05A4289AA5A817AFC7DDFE8FB1AA267BE0ACF55B38FE619BC345AE06E12699A1FF5799201210C4134A2098A62BD2ABF6F2F33C2DA61EADB84EF40F3932EA9274387827D21CAE62895E33349081BBA87B524FB6793728F0B0145DF5DBEB062AA6B9BB0EB1FFBDAE8D3804021D7282890FAB1B0B52966C63818E0451ED0E910D2193CAF907C5B10A24098AABE6159A63354F02E314DFECF72BB544E75ABEA2AF7B467155FFAAFD70724FDDE7698170F9B036CFA8DE25E0B63C2E2152D154D8F08489F105646E3C77D614C89C4D12A06D383445C3758332BCA07E8CCCFD61D1FCE8F65A897E48D356632641C222923FBA0C1F29E89EC2EBD30FE97DBF359FABDFDE889762A5485B006A37C612EE22D3AFD695FB17625DC1B66AED0282F0B14AF644C8345E73A5A309");
        sortedMap.put("appkey", "1d8b6e7d45233436");
        sortedMap.put("auto_refresh_state", "1");
        sortedMap.put("autoplay_card", "11");
        sortedMap.put("autoplay_timestamp", "0");
        sortedMap.put("build", "7770300");
        sortedMap.put("c_locale", "zh-Hant_MO");
        sortedMap.put("channel", "bili");
        sortedMap.put("column", "2");
        sortedMap.put("column_timestamp", "1715257334");
        sortedMap.put("device_name", "Pixel XL");
        sortedMap.put("device_type", "0");
        sortedMap.put("disable_rcmd", "0");
        sortedMap.put("flush", "0");
        sortedMap.put("fnval", "400");
        sortedMap.put("fnver", "0");
        sortedMap.put("force_host", "0");
        sortedMap.put("fourk", "1");
        sortedMap.put("guidance", "0");
        sortedMap.put("https_url_req", "0");
        sortedMap.put("idx", "0");
        sortedMap.put("inline_danmu", "2");
        sortedMap.put("inline_sound", "1");
        sortedMap.put("inline_sound_cold_state", "2");
        sortedMap.put("interest_id", "0");
        sortedMap.put("login_event", "1");
        sortedMap.put("mobi_app", "android");
        sortedMap.put("network", "wifi");
        sortedMap.put("open_event", "cold");
        sortedMap.put("platform", "android");
        sortedMap.put("player_net", "1");
        sortedMap.put("pull", "true");
        sortedMap.put("qn", "32");
        sortedMap.put("qn_policy", "1");
        sortedMap.put("recsys_mode", "0");
        sortedMap.put("s_locale", "zh-Hant_MO");
        sortedMap.put("splash_id", "");
        sortedMap.put("statistics", "{\"appId\":1,\"platform\":3,\"version\":\"7.77.0\",\"abtest\":\"\"}");
        sortedMap.put("ts", "1716130159");
        sortedMap.put("video_mode", "1");
        sortedMap.put("voice_balance", "1");

        let res = LibBili.signQuery(sortedMap);
        let sign = res.toString().split("&sign=")[1]
        console.log(sign)
    })
}

function hook_dlopen(soName) {
    Interceptor.attach(Module.findExportByName(null, "dlopen"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    if (path.indexOf(soName) >= 0) {
                        this.is_can_hook = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.is_can_hook) {
                    console.log("hook start...");
                    hook_func(soName)
                }
            }
        }
    );

    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    if (path.indexOf(soName) >= 0) {
                        this.is_can_hook = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.is_can_hook) {
                    console.log("hook start...");
                    hook_func(soName)
                }
            }
        }
    );
}

function hook_func(soName) {
    var base = Module.findBaseAddress(soName);

    // func2$fn1 (0x106C4)
    Interceptor.attach(base.add(0x106C4), {
        onEnter(args) {
            console.log("[0x106C4] args[0]: ", hexdump(args[0]));
            console.log("[0x106C4] args[1]: ", args[1].readCString());
            this.arg0 = args[0]

        },
        onLeave(retval) {
            console.log("[0x106C4] ret arg0: ", hexdump(this.arg0));
        }
    })

    console.log("hook done")
}

function main() {
    hook_dlopen_anti()
    hook_dlopen("libbili.so")
}

setImmediate(main)

setTimeout(callSignQuery, 20000)
```

只保留`==== callSignQuery ===`以下的日志，其他刪掉。

![Untitled](Untitled14.png)

通過觀察輸入、輸出可以得出以下結論：

1. 第一次調用時的`args[0]`是01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10，通過在IDA向上跟蹤，可以確定是固定的。同時也符合MD5算法的初始化狀態。
2. `args[1]`是我們的輸入，Java層調用`SignQuery`時傳入的參數是Map類型的，這裡的輸入是已經處理過的字符串，處理的邏輯顯然是像這樣拼接→`key1=value1&key2=value2`，長度為64
3. 每輪加密的中間結果會暫存在`args[0]`中，這點也和md5對上了

![Untitled](Untitled15.png)

注：MD5算法的解釋

![Untitled](Untitled16.png)

## C++算法還原

環境：visual studio 2019

**在正式還原前，記得先關閉SDL檢查，原因如下：**

我一開始沒有關閉SDL檢查，然後直接從IDA copy C代碼來還原，修修改改後執行發現一堆這種錯誤：`一元減號運算子套用 unsigned 類型,所得的結果也會是 unsigned`。我不以為意，直接將所有`unsigned int`類型改為`int`，結果可以順利執行不報錯了，但加密結果顯然不符合預期，經過不斷排查，最終發現是類型問題，真的不能亂改啊！！！

若我一開始就關了SDL檢查，就不會報這個錯`一元減號運算子套用 unsigned 類型,所得的結果也會是 unsigned`，也不需要浪費大量時間來一個一個排查了…

![Untitled](Untitled17.png)

### 手動處理控制流

目標函數一開始有一小段的ollvm，可以配合上面的指令trace日志手動還原

![Untitled](Untitled18.png)

先找到主分發器，IDA裡的地址是`0x10800`，trace日志的地址要加上基址，得到`0x7947baf800`

![Untitled](Untitled19.png)

搜索分發器的地址`0x7947baf800`，然後從第一個開始慢慢分析( 一行一行與IDA對比，看看是不是基本塊 )。

**小技巧：在可能的情況下，先找出所有基本塊的地址，然後在trace日志中留下記號，這樣在進行上述分析時就能方便**

![Untitled](Untitled20.png)

### IDA的坑

有些變量明明被用來計算，但卻找不到它初始化的地方，如下圖的`v270`。

原因很可能是因為IDA識別錯誤，`v270`本應是某數組的其中一個元素。

在IDA中，`v269`與`v270`的內存地址是相鄰的，因此`v269`可能是數組的起始地址，一看發現果然如此，對v270的賦值也是在此間接執行的，故交叉引用才會無法定位。

![Untitled](Untitled21.png)

![Untitled](Untitled22.png)

### 半成品

暫時沒搞清楚padding的邏輯，沒動力研究了…

- `code.cpp`
    
    ```cpp
    #include <iostream>
    #include "defs.h"
    
    using namespace std;
    
    __int64 __fastcall func2_1(int* a1, char* a2)
    {
        _BOOL4 v2; // w19
        int v3; // w28
        int v4; // w30
        int v5; // w0
        int v6; // w7
        bool v7; // zf
        unsigned int v8; // w9
        unsigned int v9; // w8
        int v10; // w7
        int v11; // w19
        int v12; // w21
        int v13; // w22
        unsigned int v14; // w21
        int v15; // w22
        int v16; // w21
        int v17; // w22
        int v18; // w21
        int v19; // w22
        unsigned int v20; // w21
        int v21; // w22
        int v22; // w22
        unsigned int v23; // w8
        unsigned __int64 v24; // t2
        int v25; // w9
        int v26; // w11
        int v27; // w14
        unsigned int v28; // w12
        int v29; // w10
        int v30; // w9
        int v31; // w12
        int v32; // w17
        unsigned int v33; // w11
        int v34; // w13
        int v35; // w9
        unsigned int v36; // w11
        int v37; // w14
        int v38; // w11
        int v39; // w15
        int v40; // w17
        unsigned int v41; // w12
        unsigned int v42; // w10
        int v43; // w10
        unsigned int v44; // w9
        int v45; // w12
        unsigned int v46; // w9
        int v47; // w13
        unsigned int v48; // w16
        unsigned int v49; // w11
        unsigned int v50; // w14
        int v51; // w9
        unsigned int v52; // w10
        unsigned int v53; // w10
        int v54; // w13
        unsigned int v55; // w11
        unsigned int v56; // w11
        unsigned int v57; // w12
        unsigned int v58; // w10
        int v59; // w16
        int v60; // w15
        int v61; // w9
        unsigned int v62; // w14
        unsigned int v63; // w10
        int v64; // w10
        int v65; // w11
        int v66; // w12
        int v67; // w0
        unsigned int v68; // w9
        int v69; // w9
        int v70; // w13
        unsigned int v71; // w10
        int v72; // w15
        int v73; // w9
        int v74; // w10
        int v75; // w17
        unsigned int v76; // w16
        int v77; // w9
        int v78; // w11
        int v79; // w13
        int v80; // w12
        int v81; // w14
        int v82; // w9
        int v83; // w10
        int v84; // w14
        int v85; // w9
        int v86; // w11
        int v87; // w15
        unsigned int v88; // w12
        int v89; // w12
        int v90; // w13
        int v91; // w10
        unsigned int v92; // w9
        int v93; // w9
        int v94; // w16
        int v95; // w12
        int v96; // w11
        int v97; // w2
        unsigned int v98; // w14
        int v99; // w13
        int v100; // w10
        int v101; // w9
        unsigned int v102; // w17
        unsigned int v103; // w12
        int v104; // w9
        unsigned int v105; // w14
        int v106; // w9
        int v107; // w14
        int v108; // w3
        int v109; // w11
        unsigned int v110; // w15
        int v111; // w12
        int v112; // w10
        int v113; // w9
        int v114; // w0
        int v115; // w16
        int v116; // w17
        unsigned int v117; // w13
        int v118; // w9
        int v119; // w11
        int v120; // w9
        int v121; // w10
        int v122; // w13
        int v123; // w12
        int v124; // w9
        int v125; // w17
        int v126; // w11
        int v127; // w15
        int v128; // w12
        unsigned int v129; // w9
        int v130; // w18
        unsigned int v131; // w0
        int v132; // w11
        int v133; // w9
        int v134; // w13
        unsigned int v135; // w11
        int v136; // w10
        int v137; // w16
        int v138; // w9
        unsigned int v139; // w11
        unsigned int v140; // w17
        int v141; // w10
        int v142; // w15
        unsigned int v143; // w10
        unsigned int v144; // w11
        unsigned int v145; // w9
        unsigned int v146; // w18
        unsigned int v147; // w12
        unsigned int v148; // w9
        unsigned int v149; // w14
        unsigned int v150; // w10
        unsigned int v151; // w11
        unsigned int v152; // w17
        unsigned int v153; // w9
        unsigned int v154; // w10
        unsigned int v155; // w11
        int v156; // w10
        unsigned int v157; // w13
        int v158; // w14
        unsigned int v159; // w11
        int v160; // w9
        int v161; // w8
        int v162; // w10
        int v163; // w12
        int v164; // w14
        int v165; // w9
        int v166; // w10
        unsigned int v167; // w16
        unsigned int v168; // w11
        int v169; // w17
        int v170; // w9
        int v171; // w12
        unsigned int v172; // w8
        unsigned int v173; // w10
        int v174; // w8
        int v175; // w9
        unsigned int v176; // w15
        int v177; // w16
        int v178; // w8
        unsigned int v179; // w10
        int v180; // w9
        unsigned int v181; // w13
        int v182; // w14
        int v183; // w10
        int v184; // w9
        unsigned int v185; // w17
        int v186; // w0
        int v187; // w10
        int v188; // w12
        unsigned int v189; // w15
        unsigned int v190; // w16
        unsigned int v191; // w9
        int v192; // w9
        int v193; // w17
        unsigned int v194; // w11
        int v195; // w10
        int v196; // w1
        unsigned int v197; // w13
        int v198; // w9
        unsigned int v199; // w9
        int v200; // w2
        int v201; // w13
        unsigned int v202; // w16
        unsigned int v203; // w11
        unsigned int v204; // w18
        unsigned int v205; // w11
        unsigned int v206; // w9
        int v207; // w10
        int v208; // w10
        int v209; // w13
        unsigned int v210; // w18
        unsigned int v211; // w15
        unsigned int v212; // w11
        int v213; // w10
        int v214; // w4
        unsigned int v215; // w10
        int v216; // w0
        unsigned int v217; // w9
        unsigned int v218; // w9
        unsigned int v219; // w13
        unsigned int v220; // w9
        unsigned int v221; // w5
        int v222; // w10
        int v223; // w14
        int v224; // w17
        int v225; // w12
        unsigned int v226; // w16
        int v227; // w10
        unsigned int v228; // w4
        int v229; // w9
        unsigned int v230; // w9
        int v231; // w1
        int v232; // w9
        unsigned int v233; // w14
        unsigned int v234; // w11
        int v235; // w11
        int v236; // w18
        int v237; // w2
        unsigned int v238; // w10
        int v239; // w9
        int v240; // w9
        unsigned int v241; // w10
        unsigned int v242; // w12
        int v243; // w10
        int v244; // w13
        int v245; // w16
        int v246; // w9
        int v247; // w8
        int v248; // w1
        int v249; // w14
        int v250; // w9
        int v251; // w11
        unsigned int v252; // w10
        unsigned int v253; // w13
        unsigned int v254; // w10
        unsigned int v255; // w15
        __int64 result; // x0
        int v257; // w9
        int v258; // w15
        int v259; // w8
        int v260; // w15
        unsigned int v261; // w8
        int v262; // [xsp+F0h] [xbp-C0h]
        int v263; // [xsp+F4h] [xbp-BCh]
        unsigned int v265; // [xsp+108h] [xbp-A8h]
        unsigned int v266; // [xsp+10Ch] [xbp-A4h]
        unsigned int v267; // [xsp+110h] [xbp-A0h]
        unsigned int v268; // [xsp+114h] [xbp-9Ch]
    
        __int64 v285; // [xsp+158h] [xbp-58h]
    
        v262 = *a1;
    
        v3 = a1[1];
        v4 = a1[2];
        v5 = a1[3];
    
        v263 = v5;
    
        // nglog
        int arr[16] = { 0 };
    
        for (int i = 0; i < 64; i+=4) {
            v13 = *(unsigned __int8*)(a2 + i + 1) << 8;
            v14 = (~v13 & 0xF91793FF | v13 & 0x6E86C00) ^ ~*(unsigned __int8*)(a2 + i) & 0xF91793FF;
            v15 = *(unsigned __int8*)(a2 + i + 2) << 16;
            v16 = v14 & v15 | v14 ^ v15;
            v17 = *(unsigned __int8*)(a2 + i + 3) << 24;
            //*(&v269 + i) = (~v16 & 0x4ED11B6 | v16 & 0xFB12EE49) ^ (~v17 & 0x4ED11B6 | v17 & 0xFB12EE49) | ~(~v16 | ~v17);
            arr[i / 4] = (~v16 & 0x4ED11B6 | v16 & 0xFB12EE49) ^ (~v17 & 0x4ED11B6 | v17 & 0xFB12EE49) | ~(~v16 | ~v17);
            //v269 = (~v16 & 0x4ED11B6 | v16 & 0xFB12EE49) ^ (~v17 & 0x4ED11B6 | v17 & 0xFB12EE49) | ~(~v16 | ~v17);
            //cout <<hex<<  "v269: " << v269 << endl;
       /*     v265 = v268 + 1;
            v266 = v267 + 4;*/
        }
        //for (int i = 0; i < 16; i++) {
        //    cout << hex << arr[i] << endl;
        //}
        //cout << "============================" << endl;
    
        
        v22 = v3;
        v23 = v5 & ~(v5 ^ ~(~v3 & 0x90E603BC | v3 & 0x6F19FC43) ^ 0x90E603BC);
        HIDWORD(v24) = v262
            - 680876936
            + ((~v23 & 0x9171C6BB | v23 & 0x6E8E3944) ^ (~((v3 ^ ~v4) & v4) & 0x9171C6BB | (v3 ^ ~v4) & v4 & 0x6E8E3944) | ~(~v23 | ~((v3 ^ ~v4) & v4)))
            + arr[0];
        LODWORD(v24) = HIDWORD(v24);
        v25 = -v3 - (v24 >> 25);
        v26 = (v24 >> 25) + v3;
        v27 = ~v26;
        v28 = v5
            - 389564586
            + arr[1]
            + (((~v26 | ~v22) & 0xF74A5921 | ~(~v26 | ~v22) & 0x8B5A6DE) ^ (~(v4 & ~(v26 ^ ~v4)) & 0xF74A5921 | v4 & ~(v26 ^ ~v4) & 0x8B5A6DE) | ~(~v26 | ~v22 | ~(v4 & ~(v26 ^ ~v4))));
        v29 = arr[4] - 176418897 - v25;
        v30 = v25
            - ((~(v28 << 12) & 0xD655DBAB | (v28 << 12) & 0x29AA2454) ^ (~(v28 >> 20) & 0xD655DBAB | (v28 >> 20) & 0x29AA2454));
        v31 = -v30;
        v32 = v22 & ~(-v30 ^ ~v22);
        v33 = v4
            + 606105819
            + arr[2]
            + ((~((v26 ^ (v30 - 1)) & -v30) & 0xC0BCE83B | (v26 ^ (v30 - 1)) & -v30 & 0x3F4317C4) ^ (~v32 & 0xC0BCE83B | v32 & 0x3F4317C4) | ~(~((v26 ^ (v30 - 1)) & -v30) | ~v32));
        v34 = v30 - (arr[5] + 1200080426);
        v35 = ((~(v33 << 17) & 0x9A6B3C7D | (v33 << 17) & 0x6594C382) ^ (~(v33 >> 15) & 0x9A6B3C7D | (v33 >> 15) & 0x6594C382))
            - v30;
        v36 = v27 | ~(~(~v35 & 0x19157E3E | v35 & 0xE6EA81C1) ^ 0x19157E3E);
        HIDWORD(v24) = v3
            - 1381195320
            + arr[3]
            + 336669990
            + ((~((v31 ^ ~v35) & v35) & 0xEC900DAE | (v31 ^ ~v35) & v35 & 0x136FF251) ^ (v36 & 0xEC900DAE | ~v36 & 0x136FF251) | ~(v36 | ~((v31 ^ ~v35) & v35)));
        LODWORD(v24) = HIDWORD(v24);
        v37 = -v35 - (arr[6] - 1473231341);
        v38 = -v35 - (v24 >> 10);
        v39 = arr[7] - 45705983 - v38;
        v40 = (v24 >> 10) + v35;
        v41 = ~v31 | ~(~(~v40 & 0x68A27795 | v40 & 0x975D886A) ^ 0x68A27795);  // 1 : 0x5f6c77ff
        v42 = v29 + ((v35 ^ ~v40) & v40 & ~v41 | v41 ^ ~((v35 ^ ~v40) & v40));  // 1
        v43 = ((~(v42 << 7) & 0x2713FC1A | (v42 << 7) & 0xD8EC03E5) ^ (~(v42 >> 25) & 0x2713FC1A | (v42 >> 25) & 0xD8EC03E5))
            - v38;  // 1
        v44 = (((~v43 | ~v40) & 0x110A8687 | ~(~v43 | ~v40) & 0xEEF57978) ^ ((v43 | ~v35) & 0x110A8687 | ~(v43 | ~v35) & 0xEEF57978) | ~(~v43 | ~v40 | v43 | ~v35))
            - v34;  // 1
        v45 = arr[8] + 1770035416 + v43;    // 1
        v46 = -v43
            - ((~(v44 << 12) & 0x50A99543 | (v44 << 12) & 0xAF566ABC) ^ (~(v44 >> 20) & 0x50A99543 | (v44 >> 20) & 0xAF566ABC));
        v47 = -v46;
        v48 = v46 - 1;
        v49 = v40 & ~(v40 ^ ~((v46 - 1) & 0x19431434 | -v46 & 0xE6BCEBCB) ^ 0x19431434);
        HIDWORD(v24) = (v49 & ~((v46 - 1) | ~v43) | ((v46 - 1) | ~v43) ^ ~v49) - v37;
        LODWORD(v24) = HIDWORD(v24);
        v50 = arr[9] - 1958414417 - v46;
        v51 = (v24 >> 15) - v46;
        v52 = v39 + ((v47 ^ ~v51) & v51 & v43 & ~(v51 ^ ~v43) | (v47 ^ ~v51) & v51 ^ v43 & ~(v51 ^ ~v43));
        v53 = -v51
            - ((~(v52 << 22) & 0x2DA0E644 | (v52 << 22) & 0xD25F19BB) ^ (~(v52 >> 10) & 0x2DA0E644 | (v52 >> 10) & 0xD25F19BB));
        v54 = -v53;
        v55 = v48 | ~(~((v53 - 1) & 0xEE294D10 | -v53 & 0x11D6B2EF) ^ 0xEE294D10);
        v56 = v45
            + ((((v53 - 1) | ~v51) & 0x9F867EAC | ~((v53 - 1) | ~v51) & 0x60798153) ^ (v55 & 0x9F867EAC | ~v55 & 0x60798153) | ~((v53 - 1) | ~v51 | v55));
        v57 = arr[11] - 1990404162 - v53;
        v58 = v53
            - ((~(v56 << 7) & 0xB186CCAB | (v56 << 7) & 0x4E793354) ^ (~(v56 >> 25) & 0xB186CCAB | (v56 >> 25) & 0x4E793354));
        v59 = -v58;
        v60 = arr[10] - 792672126 + v51;
        HIDWORD(v24) = v50 + ((v54 ^ (v58 - 1)) & -v58 & ~(-v58 | ~v51) | (-v58 | ~v51) ^ ~((v54 ^ (v58 - 1)) & -v58));
        LODWORD(v24) = HIDWORD(v24);
        v61 = (v24 >> 20) - v58;
        v62 = arr[12] + 1804603682 - v58;
        v63 = v54 & ~(v54 ^ ~(~v61 & 0x6E334C99 | v61 & 0x91CCB366) ^ 0x6E334C99);
        HIDWORD(v24) = v60
            + (((~v61 | ~v59) & 0x50F60E2A | ~(~v61 | ~v59) & 0xAF09F1D5) ^ (~v63 & 0x50F60E2A | v63 & 0xAF09F1D5) | ~(~v61 | ~v59 | ~v63))
            + 792630063;
        LODWORD(v24) = HIDWORD(v24);
        v64 = (v24 >> 15) + v61;
        HIDWORD(v24) = v57
            + ((~((v61 ^ ~v64) & v64) & 0x4F7C4933 | (v61 ^ ~v64) & v64 & 0xB083B6CC) ^ (~(v59 & ~(v64 ^ ~v59)) & 0x4F7C4933 | v59 & ~(v64 ^ ~v59) & 0xB083B6CC) | ~(~((v61 ^ ~v64) & v64) | ~(v59 & ~(v64 ^ ~v59))));
        LODWORD(v24) = HIDWORD(v24);
        v65 = (v24 >> 10) + v64;
        v66 = 1502002290 - arr[14] - v64;
        v67 = arr[13] - 1439979653 + v61;
        v68 = v61 & ~(v61 ^ ~(~v65 & 0xD133BB9F | v65 & 0x2ECC4460) ^ 0xD133BB9F);
        HIDWORD(v24) = v62
            + ((~((v64 ^ ~v65) & v65) & 0x6D1B1A72 | (v64 ^ ~v65) & v65 & 0x92E4E58D) ^ (~v68 & 0x6D1B1A72 | v68 & 0x92E4E58D) | ~(~((v64 ^ ~v65) & v65) | ~v68));
        LODWORD(v24) = HIDWORD(v24);
        v69 = -v65 - (v24 >> 25);
        v70 = (v24 >> 25) + v65;
        v71 = v67 + (~(~v70 | ~v65) & ~(v70 | ~v64) | (~v70 | ~v65) ^ (v70 | ~v64)) + 1399638552;
        v72 = arr[1] - 909585457 - v69;
        v73 = v69
            - ((~(v71 << 12) & 0xD8246177 | (v71 << 12) & 0x27DB9E88) ^ (~(v71 >> 20) & 0xD8246177 | (v71 >> 20) & 0x27DB9E88));
        v74 = arr[6] - 1069501632 - v73;
        v75 = -v73;
        v76 = ~((v73 - 1) & 0xCFE245AF | -v73 & 0x301DBA50) ^ 0xCFE245AF;
        HIDWORD(v24) = ((v76 ^ ~v65) & v65 & ~((v73 - 1) | ~v70) | ((v73 - 1) | ~v70) ^ ~((v76 ^ ~v65) & v65)) - v66;
        LODWORD(v24) = HIDWORD(v24);
        v77 = (v24 >> 15) - v73;
        HIDWORD(v24) = arr[15]
            + 1236535329
            + v65
            + ((v75 ^ ~v77) & v77 & (v70 ^ v77) & v70 | (v75 ^ ~v77) & v77 ^ (v70 ^ v77) & v70);
        LODWORD(v24) = HIDWORD(v24);
        v78 = (v24 >> 10) + v77;
        v79 = -v78 - (arr[0] - 373897302);
        HIDWORD(v24) = v72 + ((v76 ^ ~v77) & v77 & ~(~v78 | ~v75) | (~v78 | ~v75) ^ ~((v76 ^ ~v77) & v77)) + 743788947;
        LODWORD(v24) = HIDWORD(v24);
        v80 = (v24 >> 27) + v78;
        v81 = arr[11] + 643717713 + v77;
        HIDWORD(v24) = v74 + ((v78 ^ v77) & v78 & ~(~v80 | ~v77) | (~v80 | ~v77) ^ ~((v78 ^ v77) & v78));
        LODWORD(v24) = HIDWORD(v24);
        v82 = -v80 - (v24 >> 23);
        v83 = (v24 >> 23) + v80;
        HIDWORD(v24) = v81
            + ((~((v78 ^ ~v83) & v83) & 0x22E7CE11 | (v78 ^ ~v83) & v83 & 0xDD1831EE) ^ (~(v80 & ~(v78 ^ ~v80)) & 0x22E7CE11 | v80 & ~(v78 ^ ~v80) & 0xDD1831EE) | ~(~((v78 ^ ~v83) & v83) | ~(v80 & ~(v78 ^ ~v80))));
        LODWORD(v24) = HIDWORD(v24);
        v84 = arr[10] + 38016083 - v82;
        v85 = (v24 >> 18) - v82;
        v86 = arr[15] - 660478335 + v85;
        v87 = v80 - (701558691 - arr[5]);
        v88 = (v83 & ~(v80 ^ ~v83) & ~(~v85 | ~v80) | (~v85 | ~v80) ^ ~(v83 & ~(v80 ^ ~v83))) - v79;
        v89 = ((~(v88 << 20) & 0xA243D95D | (v88 << 20) & 0x5DBC26A2) ^ (~(v88 >> 12) & 0xA243D95D | (v88 >> 12) & 0x5DBC26A2))
            + v85;
        v90 = arr[4] - 405537848 + v89;
        HIDWORD(v24) = v87
            + ((~(v89 & ~(v89 ^ v83)) & 0x3FF91745 | v89 & ~(v89 ^ v83) & 0xC006E8BA) ^ ((v83 | ~v85) & 0x3FF91745 | ~(v83 | ~v85) & 0xC006E8BA) | ~(v83 | ~v85 | ~(v89 & ~(v89 ^ v83))));
        LODWORD(v24) = HIDWORD(v24);
        v91 = (v24 >> 27) + v89;
        v92 = v84
            + ((~((v85 ^ ~v91) & v91) & 0x58C2629D | (v85 ^ ~v91) & v91 & 0xA73D9D62) ^ (~(v89 & ~(v85 ^ ~v89)) & 0x58C2629D | v89 & ~(v85 ^ ~v89) & 0xA73D9D62) | ~(~((v85 ^ ~v91) & v91) | ~(v89 & ~(v85 ^ ~v89))));
        v93 = ((~(v92 << 9) & 0xEEFAE8E6 | (v92 << 9) & 0x11051719) ^ (~(v92 >> 23) & 0xEEFAE8E6 | (v92 >> 23) & 0x11051719))
            + v91;
        v94 = arr[14] - 1019803690 + v93;
        v95 = (v89 ^ ~v93) & v93 & v91 & ~(v89 ^ ~v91) | (v89 ^ ~v93) & v93 ^ v91 & ~(v89 ^ ~v91);
        v96 = ((~((v86 + v95) << 14) & 0x8FBCE0B0 | ((v86 + v95) << 14) & 0x70431F4F) ^ (~((unsigned int)(v86 + v95) >> 18) & 0x8FBCE0B0 | ((unsigned int)(v86 + v95) >> 18) & 0x70431F4F))
            + v93;
        v97 = arr[9] - 1645529321 + v91;
        HIDWORD(v24) = v90
            + ((~(v96 & ~(v96 ^ v91)) & 0x9A0A9844 | v96 & ~(v96 ^ v91) & 0x65F567BB) ^ ((v91 | ~v93) & 0x9A0A9844 | ~(v91 | ~v93) & 0x65F567BB) | ~(v91 | ~v93 | ~(v96 & ~(v96 ^ v91))));
        LODWORD(v24) = HIDWORD(v24);
        v98 = v96 & ~(v96 ^ ~(~v93 & 0x7DC89236 | v93 & 0x82376DC9) ^ 0x7DC89236);
        v99 = v96 - (187363961 - arr[3]);
        v100 = (v24 >> 12) + v96;
        v101 = (v93 ^ ~v100) & v100;
        v102 = ~v101 & 0xB0FD0F2 | v101 & 0xF4F02F0D;
        v103 = ~v100 | ~(~(~v96 & 0xD3C6D974 | v96 & 0x2C39268B) ^ 0xD3C6D974);
        v104 = ~v101 | ~v98;
        v105 = v102 ^ (~v98 & 0xB0FD0F2 | v98 & 0xF4F02F0D);
        v106 = ((~(32 * (v97 + (v105 | ~v104) - 2080991537)) & 0xD18FD77E | (32 * (v97 + (v105 | ~v104) - 2080991537)) & 0x2E702881) ^ (~((v97 + (v105 | ~v104) - 2080991537) >> 27) & 0xD18FD77E | ((v97 + (v105 | ~v104) - 2080991537) >> 27) & 0x2E702881))
            + v100;
        v107 = 1444681467 - arr[13] - v106;
        HIDWORD(v24) = v94
            + ((~((v96 ^ ~v106) & v106) & 0xD0AF1BE2 | (v96 ^ ~v106) & v106 & 0x2F50E41D) ^ (v103 & 0xD0AF1BE2 | ~v103 & 0x2F50E41D) | ~(v103 | ~((v96 ^ ~v106) & v106)));
        LODWORD(v24) = HIDWORD(v24);
        v108 = -1163531501 - arr[8] - v100;
        v109 = (v24 >> 23) + v106;
        v110 = v106 ^ ~(~v100 & 0xF9B2BAEC | v100 & 0x64D4513) ^ 0xF9B2BAEC;
        v111 = arr[2] - 51403784 + v109;
        HIDWORD(v24) = v99 + ((v100 ^ ~v109) & v109 & v106 & ~v110 | (v100 ^ ~v109) & v109 ^ v106 & ~v110);
        LODWORD(v24) = HIDWORD(v24);
        v112 = (v24 >> 18) + v109;
        HIDWORD(v24) = ((~((v106 ^ ~v112) & v112) & 0x8EFC7C88 | (v106 ^ ~v112) & v112 & 0x71038377) ^ (~(v109 & ~(v106 ^ ~v109)) & 0x8EFC7C88 | v109 & ~(v106 ^ ~v109) & 0x71038377) | ~(~((v106 ^ ~v112) & v112) | ~(v109 & ~(v106 ^ ~v109))))
            - v108;
        LODWORD(v24) = HIDWORD(v24);
        v113 = -v112 - (v24 >> 12);
        v114 = arr[7] + 1603982798 + v112 + 131345675;
        v115 = arr[12] - 1969665849 - v113 + 43058115;
        v116 = (v24 >> 12) + v112;
        v117 = ~v116 | ~(~(~v112 & 0xCB7311F1 | v112 & 0x348CEE0E) ^ 0xCB7311F1);
        HIDWORD(v24) = (((~v116 | ~v109) & 0x48D78C3A | ~(~v116 | ~v109) & 0xB72873C5) ^ ((v109 | ~v112) & 0x48D78C3A | ~(v109 | ~v112) & 0xB72873C5) | ~(~v116 | ~v109 | v109 | ~v112))
            - v107;
        LODWORD(v24) = HIDWORD(v24);
        v118 = v113 - (v24 >> 27);
        v119 = -v118;
        HIDWORD(v24) = v111 + (~((v118 - 1) | ~v112) & ~v117 | ((v118 - 1) | ~v112) ^ v117);
        LODWORD(v24) = HIDWORD(v24);
        v120 = (v24 >> 23) - v118;
        v121 = -v120 - (arr[8] - 2022574463);
        v122 = v120 & ~(v119 ^ ~v120);
        HIDWORD(v24) = v114
            + ((v116 ^ ~v120) & v120 & v119 & ~(v116 ^ ~v119) | (v116 ^ ~v120) & v120 ^ v119 & ~(v116 ^ ~v119));
        LODWORD(v24) = HIDWORD(v24);
        v123 = (v24 >> 18) + v120;
        v124 = v120 & ~v123 | v123 & ~v120;
        v125 = v119 - (378558 - arr[5]);
        HIDWORD(v24) = v115
            + ((~((v119 ^ ~v123) & v123) & 0xA14DAC01 | (v119 ^ ~v123) & v123 & 0x5EB253FE) ^ (~v122 & 0xA14DAC01 | v122 & 0x5EB253FE) | ~(~((v119 ^ ~v123) & v123) | ~v122));
        LODWORD(v24) = HIDWORD(v24);
        v126 = (v24 >> 12) + v123;
        v127 = arr[11] + 409941718 + v123;
        v128 = v123 & ~v126 | v126 & ~v123;
        v129 = v125 + ((~v124 & 0xE6B2D397 | v124 & 0x194D2C68) ^ (~v126 & 0xE6B2D397 | v126 & 0x194D2C68));
        v130 = ~v126 & 0x1E2CD199;
        v131 = v126 & 0xE1D32E66;
        v132 = -v126;
        HIDWORD(v24) = v129;
        LODWORD(v24) = v129;
        v133 = (v24 >> 28) - v132;
        v134 = v132 + 35309556 - arr[14];
        v135 = (~v133 & 0x1E2CD199 | v133 & 0xE1D32E66) ^ (v130 | v131);
        HIDWORD(v24) = (v133 & ~v128 | v128 & ~v133) - v121;
        LODWORD(v24) = HIDWORD(v24);
        v136 = (v24 >> 21) + v133;
        v137 = -v133 - (arr[1] - 1530992060);
        v138 = v133 & ~v136 | v136 & ~v133;
        v139 = v127 + (v136 & ~v135 | v135 & ~v136) + 1429088844;
        v140 = ~v136 & 0x460760C8 | v136 & 0xB9F89F37;
        v141 = -v136;
        v142 = arr[4] + 1272893353 - v141;
        v143 = ((~(v139 << 16) & 0xA1C35252 | (v139 << 16) & 0x5E3CADAD) ^ (~HIWORD(v139) & 0xA1C35252 | HIWORD(v139) & 0x5E3CADAD))
            - v141;
        v144 = (~v143 & 0x460760C8 | v143 & 0xB9F89F37) ^ v140;
        v145 = ((~v138 & 0x7F6744A4 | v138 & 0x8098BB5B) ^ (~v143 & 0x7F6744A4 | v143 & 0x8098BB5B)) - v134;
        v146 = ~v143 & 0xBA072077 | v143 & 0x45F8DF88;
        v147 = arr[7] - 155497632 + v143;
        v148 = ((~(v145 << 23) & 0xB95B6FF6 | (v145 << 23) & 0x46A49009) ^ (~(v145 >> 9) & 0xB95B6FF6 | (v145 >> 9) & 0x46A49009))
            + v143;
        v149 = ~v148 & 0xEF519A09 | v148 & 0x10AE65F6;
        v150 = (v148 & ~v144 | v144 & ~v148) - v137;
        v151 = (~v148 & 0xBA072077 | v148 & 0x45F8DF88) ^ v146;
        v152 = v148 - (1094730640 - arr[10]);
        v153 = ((~(16 * v150) & 0xB9BBDD44 | (16 * v150) & 0x464422BB) ^ (~(v150 >> 28) & 0xB9BBDD44 | (v150 >> 28) & 0x464422BB))
            + v148;
        v154 = (~v151 & 0xF356B5FA | v151 & 0xCA94A05) ^ (~v153 & 0xF356B5FA | v153 & 0xCA94A05);
        v155 = (~v153 & 0xEF519A09 | v153 & 0x10AE65F6) ^ v149;
        HIDWORD(v24) = v142 + v154;
        LODWORD(v24) = v142 + v154;
        v156 = -v153 - (v24 >> 21);
        v157 = v153 - (-681279174 - arr[13]);
        v158 = (v24 >> 21) + v153;
        v159 = v147 + (v158 & ~v155 | v155 & ~v158);
        v160 = v153 & ~v158 | v158 & ~v153;
        v161 = v156 - (arr[0] - 358537222);
        v162 = ((~(v159 << 16) & 0x76559B23 | (v159 << 16) & 0x89AA64DC) ^ (~HIWORD(v159) & 0x76559B23 | HIWORD(v159) & 0x89AA64DC))
            - v156;
        v163 = v158 & ~v162 | v162 & ~v158;
        HIDWORD(v24) = v152 + ((~v160 & 0x2847F7C6 | v160 & 0xD7B80839) ^ (~v162 & 0x2847F7C6 | v162 & 0xD7B80839));
        LODWORD(v24) = HIDWORD(v24);
        v164 = arr[3] - 722521979 + v162;
        v165 = (v24 >> 9) + v162;
        v166 = v162 & ~v165 | v165 & ~v162;
        v167 = ~v165 & 0x6A52FA09 | v165 & 0x95AD05F6;
        v168 = v157 + ((~v163 & 0x6D9C7248 | v163 & 0x92638DB7) ^ (~v165 & 0x6D9C7248 | v165 & 0x92638DB7));
        v169 = arr[6] - 1976364952 + v165 + 2052394141;
        v170 = ((~(16 * v168) & 0xFB910474 | (16 * v168) & 0x46EFB8B) ^ (~(v168 >> 28) & 0xFB910474 | (v168 >> 28) & 0x46EFB8B))
            + v165;
        v171 = -v170 - (arr[9] - 640364487);
        v172 = (v170 & ~v166 | v166 & ~v170) - v161;
        v173 = (~v170 & 0x6A52FA09 | v170 & 0x95AD05F6) ^ v167;
        v174 = ((~(v172 << 11) & 0x4C787E99 | (v172 << 11) & 0xB3878166) ^ (~(v172 >> 21) & 0x4C787E99 | (v172 >> 21) & 0xB3878166))
            + v170;
        v175 = v170 & ~v174 | v174 & ~v170;
        v176 = ~v174 & 0x1C7D2C71 | v174 & 0xE382D38E;
        HIDWORD(v24) = v164 + ((~v173 & 0x78D4F305 | v173 & 0x872B0CFA) ^ (~v174 & 0x78D4F305 | v174 & 0x872B0CFA));
        LODWORD(v24) = HIDWORD(v24);
        v177 = arr[12] + 1212671722 + v174;
        v178 = (v24 >> 16) + v174;
        v179 = (~v178 & 0x1C7D2C71 | v178 & 0xE382D38E) ^ v176;
        HIDWORD(v24) = v169 + ((~v175 & 0x1F919C73 | v175 & 0xE06E638C) ^ (~v178 & 0x1F919C73 | v178 & 0xE06E638C));
        LODWORD(v24) = HIDWORD(v24);
        v180 = (v24 >> 9) + v178;
        v181 = (~v180 & 0xD6D28D54 | v180 & 0x292D72AB) ^ (~v178 & 0xD6D28D54 | v178 & 0x292D72AB);
        v182 = arr[2] + v180 - 995338651;
        HIDWORD(v24) = (v180 & ~v179 | v179 & ~v180) - v171;
        LODWORD(v24) = HIDWORD(v24);
        v183 = (v24 >> 28) + v180;
        v184 = v180 & ~v183 | v183 & ~v180;
        v185 = ~v183 & 0xEBA85B8C | v183 & 0x1457A473;
        v186 = arr[0] - 1804540663 + v183;
        HIDWORD(v24) = v177
            + 2074585487
            + ((~v181 & 0xE59523F9 | v181 & 0x1A6ADC06) ^ (~v183 & 0xE59523F9 | v183 & 0x1A6ADC06))
            + 585894252;
        LODWORD(v24) = HIDWORD(v24);
        v187 = -v183 - (v24 >> 21);
        v188 = -v187;
        v189 = ((v187 - 1) & 0xEBA85B8C | -v187 & 0x1457A473) ^ v185;
        v190 = -v187 & 0xFA0D9192 | (v187 - 1) & 0x5F26E6D;
        v191 = arr[15]
            + 530742520
            + v178
            + ((~v184 & 0x400A16AD | v184 & 0xBFF5E952) ^ ((v187 - 1) & 0x400A16AD | -v187 & 0xBFF5E952));
        v192 = ((~(v191 << 16) & 0x3B904F48 | (v191 << 16) & 0xC46FB0B7) ^ (~HIWORD(v191) & 0x3B904F48 | HIWORD(v191) & 0xC46FB0B7))
            - v187;
        v193 = v187 - (arr[7] + 1126891415);
        v194 = ~(~v192 & 0x5D420F8C | v192 & 0xA2BDF073) ^ 0x5D420F8C;
        HIDWORD(v24) = v182 + (v192 & ~v189 | v189 & ~v192);
        LODWORD(v24) = HIDWORD(v24);
        v195 = (v24 >> 9) + v192;
        v196 = arr[14] - 1416354905 + v192;
        v197 = (~v195 & 0xFA0D9192 | v195 & 0x5F26E6D) ^ v190;
        v198 = v186 + 2059638174 + (v192 & ~(v197 | ~(v188 | ~v195)) | (v197 | ~(v188 | ~v195)) & ~v192);
        v199 = -v195
            - ((~((v198 - 453728355) << 6) & 0x44345B14 | ((v198 - 453728355) << 6) & 0xBBCBA4EB) ^ (~((unsigned int)(v198 - 453728355) >> 26) & 0x44345B14 | ((unsigned int)(v198 - 453728355) >> 26) & 0xBBCBA4EB));
        v200 = -v195 - (arr[5] - 57434055);
        v201 = -v199;
        v202 = arr[12] + 1700485571 - v199;
        v203 = ((v199 - 1) & 0x8BAAF2B9 | -v199 & 0x74550D46) ^ (~v194 & 0x8BAAF2B9 | v194 & 0x74550D46) | ~((v199 - 1) | ~v194);
        v204 = (v199 - 1) & 0xFA18E3FD | -v199 & 0x5E71C02;
        v205 = (v195 & ~v203 | v203 & ~v195) - v193;
        v206 = ((~(v205 << 10) & 0xE9EC6D8C | (v205 << 10) & 0x16139273) ^ (~(v205 >> 22) & 0xE9EC6D8C | (v205 >> 22) & 0x16139273))
            - v199;
        v207 = v206 & ~v195 | v195 ^ ~v206;
        HIDWORD(v24) = v196 + ((~v207 & 0xFA18E3FD | v207 & 0x5E71C02) ^ v204);
        LODWORD(v24) = HIDWORD(v24);
        v208 = (v24 >> 17) + v206;
        v209 = v208 & ~v201 | v201 ^ ~v208;
        v210 = ~v208 & 0x3A9876B | v208 & 0xFC567894;
        v211 = ~(~v208 & 0xC13A8FAF | v208 & 0x3EC57050) ^ 0xC13A8FAF;
        v212 = ((~v209 & 0x4F7DD662 | v209 & 0xB082299D) ^ (~v206 & 0x4F7DD662 | v206 & 0xB082299D)) - v200;
        v213 = -v208;
        v214 = arr[10] - 1051523 - v213;
        v215 = ((~(v212 << 21) & 0x1214B32D | (v212 << 21) & 0xEDEB4CD2) ^ (~(v212 >> 11) & 0x1214B32D | (v212 >> 11) & 0xEDEB4CD2))
            - v213;
        v216 = -v206;
        v217 = (~v215 & 0xB42DA829 | v215 & 0x4BD257D6) ^ (v206 & 0xB42DA829 | ~v206 & 0x4BD257D6) | ~(v206 | ~v215);
        v218 = v202 + ((~v217 & 0x3A9876B | v217 & 0xFC567894) ^ v210);
        v219 = ~v215 & 0x70929270 | v215 & 0x8F6D6D8F;
        v220 = ((~(v218 << 6) & 0xB8B24109 | (v218 << 6) & 0x474DBEF6) ^ (~(v218 >> 26) & 0xB8B24109 | (v218 >> 26) & 0x474DBEF6))
            + v215;
        v221 = arr[1] + 671671456 + v215;
        HIDWORD(v24) = arr[3]
            - 1894986606
            - v216
            + ((~(v220 & v211 | v220 ^ v211) & 0x843CDF5A | (v220 & v211 | v220 ^ v211) & 0x7BC320A5) ^ (~v215 & 0x843CDF5A | v215 & 0x7BC320A5));
        LODWORD(v24) = HIDWORD(v24);
        v222 = -v220 - (v24 >> 22);
        v223 = (v24 >> 22) + v220;
        v224 = arr[15] - 30611744 - v222;
        v225 = v223 & (~v219 ^ 0x70929270) | v223 ^ ~v219 ^ 0x70929270;
        v226 = ~(~v223 & 0xEB7AD15F | v223 & 0x14852EA0) ^ 0xEB7AD15F;
        HIDWORD(v24) = v214 + (v220 & ~v225 | v225 & ~v220);
        LODWORD(v24) = HIDWORD(v24);
        v227 = (v24 >> 17) - v222;
        v228 = arr[8] - 2010626568 + v220;
        v229 = v227 & ~v220 | v220 ^ ~v227;
        v230 = v221 + 1568373041 + (v223 & ~v229 | v229 & ~v223);
        v231 = arr[6] + v227 - 1560198380;
        v232 = ((~(v230 << 21) & 0x87998335 | (v230 << 21) & 0x78667CCA) ^ (~(v230 >> 11) & 0x87998335 | (v230 >> 11) & 0x78667CCA))
            + v227;
        v233 = ~(~v232 & 0x6D89B524 | v232 & 0x92764ADB) ^ 0x6D89B524;
        v234 = (~v232 & 0xF5D3398E | v232 & 0xA2CC671) ^ (~v226 & 0xF5D3398E | v226 & 0xA2CC671) | ~(~v232 | ~v226);
        HIDWORD(v24) = v228 + (v227 & ~v234 | v234 & ~v227) - 411027369;
        LODWORD(v24) = HIDWORD(v24);
        v235 = -v232 - (v24 >> 26);
        v236 = (v24 >> 26) + v232;
        v237 = -v232 - (arr[13] + 1309151649);
        v238 = (~v236 & 0xC37CC8D0 | v236 & 0x3C83372F) ^ (v227 & 0xC37CC8D0 | ~v227 & 0x3C83372F) | ~(v227 | ~v236);
        v239 = v224 - 1729457421 + (v232 & ~v238 | v238 & ~v232);
        v240 = ((~((v239 + 1729457421) << 10) & 0x9C2EC1AA | ((v239 + 1729457421) << 10) & 0x63D13E55) ^ (~((unsigned int)(v239 + 1729457421) >> 22) & 0x9C2EC1AA | ((unsigned int)(v239 + 1729457421) >> 22) & 0x63D13E55))
            - v235;
        v241 = (~v240 & 0xEDBFF996 | v240 & 0x12400669) ^ (~v233 & 0xEDBFF996 | v233 & 0x12400669) | ~(~v240 | ~v233);
        v242 = ~(~v240 & 0xFE23DB05 | v240 & 0x1DC24FA) ^ 0xFE23DB05;
        HIDWORD(v24) = v231 + (v236 & ~v241 | v241 & ~v236);
        LODWORD(v24) = HIDWORD(v24);
        v243 = (v24 >> 17) + v240;
        v244 = v243 & ~v236 | v236 ^ ~v243;
        v245 = -v240;
        HIDWORD(v24) = (v240 & ~v244 | v244 & ~v240) - v237;
        LODWORD(v24) = HIDWORD(v24);
        v246 = -v243 - (v24 >> 11);
        v247 = arr[2] + 718787259 + v243;
        v248 = (v24 >> 11) + v243;
        v249 = arr[9] - 343485551 - v246;
        HIDWORD(v24) = arr[4] - 145523070 - v235 + (v243 & ~(v248 & v242 | v248 ^ v242) | (v248 & v242 | v248 ^ v242) & ~v243);
        LODWORD(v24) = HIDWORD(v24);
        v250 = v246 - (v24 >> 26);
        v251 = -v250;
        v252 = ((v250 - 1) & 0x834F1845 | -v250 & 0x7CB0E7BA) ^ (v243 & 0x834F1845 | ~v243 & 0x7CB0E7BA) | ~(v243 | (v250 - 1));
        v253 = ~((v250 - 1) & 0xA3ABA81F | -v250 & 0x5C5457E0) ^ 0xA3ABA81F;
        v254 = arr[11] - 1120210379 - v245 + (v248 & ~v252 | v252 & ~v248);
        v255 = v254 << 10;
        v254 >>= 22;
        result = ~v254 & 0x842418CE;
        v257 = v250 - ((~v255 & 0x842418CE | v255 & 0x7BDBE731) ^ (result | v254 & 0x7BDBE731));
        v258 = -v257 & ~v248 | v248 ^ (v257 - 1);
        HIDWORD(v24) = v247 + (v251 & ~v258 | v258 & ~v251);
        LODWORD(v24) = HIDWORD(v24);
        v259 = (v24 >> 17) - v257;
        v260 = v259 + v3;
        a1[2] = v259 + v4;
        a1[3] = v263 - v257;
        v261 = v249
            + (-v257 & ~((~v259 & 0xF1F0C7FF | v259 & 0xE0F3800) ^ (~v253 & 0xF1F0C7FF | v253 & 0xE0F3800) | ~(~v259 | ~v253)) | ((~v259 & 0xF1F0C7FF | v259 & 0xE0F3800) ^ (~v253 & 0xF1F0C7FF | v253 & 0xE0F3800) | ~(~v259 | ~v253)) & (v257 - 1));
        *a1 = v251 + v262;
        a1[1] = v260
            + ((~(v261 << 21) & 0x3E3C1AF9 | (v261 << 21) & 0xC1C3E506) ^ (~(v261 >> 11) & 0x3E3C1AF9 | (v261 >> 11) & 0xC1C3E506));
        return result;
        
    }
    int main(void){
    
        unsigned char hexData[89] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0xA8, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x5F, 0x65, 0x78, 0x74, 0x72, 0x61,
            0x3D, 0x45, 0x38, 0x36, 0x46, 0x34, 0x43, 0x46, 0x46, 0x31, 0x46, 0x38, 0x46, 0x41, 0x38, 0x39,
            0x30, 0x41, 0x37, 0x35, 0x31, 0x35, 0x35, 0x45, 0x45, 0x41, 0x41, 0x35, 0x31, 0x45, 0x36, 0x41,
            0x45, 0x34, 0x46, 0x41, 0x39, 0x44, 0x42, 0x45, 0x36, 0x32, 0x46, 0x43, 0x45, 0x37, 0x30, 0x38,
            0x31, 0x38, 0x36, 0x44, 0x30, 0x43, 0x45, 0x35, 0x00
        };
        char a2[] = "appkey=1d8b6e7d45233436&build=7770300&c_locale=zh-Hant_MO&channel=bili&disable_rcmd=0&mobi_app=android&platform=android&s_locale=zh-Hant_MO&statistics=%7B%22appId%22%3A1%2C%22platform%22%3A3%2C%22version%22%3A%227.77.0%22%2C%22abtest%22%3A%22%22%7D&ts=1716716480";
        char* tmp = a2;
        int len = strlen(a2) / 64;
        cout << "len = " << len << endl;
    
        for (int j = 0; j < len; j++) {
            cout << tmp << endl;
            func2_1((int*)hexData, tmp);
    
            for (int i = 0; i < 16; i++) {
                cout << hex << (int)hexData[i] << endl;
            }
    
            tmp += 64;
            
        }
    
    	return 0;
    }
    ```