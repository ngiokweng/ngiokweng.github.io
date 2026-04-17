---
title: LIAPP手遊保護分析
date: 2024-11-28 19:59:08
tags:
- Android逆向
categories: Android逆向
keywords:
- LIAPP
description: LIAPP
cover: image1.png
---

> packagename：bmV0LmdhbWVkdW8udGJk
聲明：本文內容僅供學習交流之用
> 

## 前言

淺淺記錄一次對LIAPP的分析過程。

## 初見反調試

直接打開APP會提示`debuggable`。

![image.png](image.png)

用frida注入後會提示`ng1ok-64.so` ( 一般的frida應該是`frida-agent-64.so` )

![image.png](image1.png)

用frida hook `dlopen`，發現在閃退前只加載了`libdyzzwwc.so`，顯然anti frida的邏輯就在這個so中。

![image.png](image2.png)

查看`libdyzzwwc.so`的.init_array，看上去有點奇怪。

![image.png](image3.png)

手動按`D`幫助IDA重新解析，發現靜態分析.init_array只能看到有一個初始化函數，相關檢測邏輯大概就在這裡。

將`sub_B8080`重命名為`init_array_func1`。

![image.png](image4.png)

進入`init_array_func1`，會發現有些函數調用IDA靜態分析時無法識別，像下圖這樣。

遇到這種情況時，只好動調看看了。

![image.png](image5.png)

## 動調分析init_array

注：一些函數是經過我重命名的，並非原本就是這樣。

在動調前要先弄清楚主要的目的：

1. 嘗試找到檢測邏輯。
2. 熟悉代碼( 相信代碼，代碼就會幫助你 )。
3. 尋找字符串解密函數 / 處理字符串的函數。

### init_array_func1

從`init_array_func1`下斷點開始進行動調，一開始先判斷了`v1`中是否包含`.sandbox`，不清楚具體檢測的是什麼，或許是一些沙箱環境？

我的環境不會走這條if分支，繼續向下看。

![image.png](image6.png)

注：`v1`如下，是從`/proc/self/environ`裡取的值，while循環會遍歷這其中的所有元素

![image.png](image7.png)

然後`v1`是否包含`com.lbe.parallel`，查了下這個APP，相關描述是`"使用 Parallel Space 輕鬆地複製和運行同一應用程式的多個帳戶"`，大概是一個APP多開工具，看來這個工具也是不允許的。

![image.png](image8.png)

跳過中間的一些不太重要的邏輯，看到最後調用了幾個函數，逐一看看。

![image.png](image9.png)

首先看`check_blackdex`，檢查了`blackdex`，這是一個著名的脫殼工具，被檢測到後會調用`kill_func`。

![image.png](image10.png)

繼續看`check_something`，中間幾個`5C85F0A264`指向`app_process64`某處，不用理會。

重點是`do_something1`和`do_something2`。

![image.png](image11.png)

先看`do_something1`，一開始先打開了`/proc/self/maps`，算是比較經典的檢測點。

![image.png](image12.png)

將從maps裡獲取的內容傳入`check1`函數。

![image.png](image13.png)

`check1`檢測的東西如下( 只顯示一部份 )，包括frida、xposed等等。由於我魔改的`frida-agent.so`放在了`/data/local`目錄下，因此被檢測出來了。

當maps中存在以下字符串時代表檢測到，會返回`-1`，反之返回`0`代表檢測不到。

![image.png](image14.png)

![image.png](image15.png)

![image.png](image16.png)

看完`check1`函數，回到`do_something1`繼續向下看，會發現另一層檢測邏輯。

首先通過`scandir`獲取`/proc/<pid>/task`下所有目錄。

![image.png](image17.png)

然後遍歷這些線程目錄，讀取`/proc/<tid>/comm`的內容。

![image.png](image18.png)

接著判斷`/proc/<tid>/comm`的內容是否與以下字符串相等，是則代表被檢測到。

可以看到`pool-frida`、`gum-js-loop`、`gbus`、`gamin`這些熟悉的frida特徵。

![image.png](image19.png)

![image.png](image20.png)

回到`check_something`函數，繼續看`do_something2`。

一開始先打開了`/proc/<tid>/maps`，然後調用`check_maybe_io_redirect`進行一些檢查，arg0是`fopen`返回的`fp`，arg1是`"/proc/<tid>/maps"`。

深入`check_maybe_io_redirect`看看具體做了什麼。

![image.png](image21.png)

`check_maybe_io_redirect`中調用了`check_fd`。

![image.png](image22.png)

`check_fd`的檢測邏輯如下：

1. 通過`sprintf`構造一個諸如`"/proc/16875/fd/38"`的字符串，其中的`38`就是上述`fopen`的返回值。
2. 調用`readlink`將`/proc/16875/fd/38`符號鏈接的內容( 類似`/proc/16875/maps` )存儲到`buf1`中。
3. 對比傳入的`proc_maps`和`buf1`，正常來說它們要是相等的，都是`/proc/<pid>/maps`

![image.png](image23.png)

注：`cmp_func1`類似`strcmp`，相等才返回`0`。

![image.png](image24.png)

綜上分析，感覺大概是在檢測IO重定向？我沒有進一步測試，所以也不太確定。

回到`do_something2`函數繼續看，中間是一大段對proc_maps的判斷和操作，感覺不太重要。

![image.png](image25.png)

最後又調用了一次`check_maybe_io_redirect`，然後保存了base.apk的一些信息。

![image.png](image26.png)

至此分析完`init_array_func1`的一些較為重要的函數。

### init_array_func2

在靜態分析時只能看到有一個.init_array函數，實際上有2個，在執行完`init_array_func1`後單步慢慢走就能走到`init_array_func2` ( 或者在linker打斷點也可以 )。

只調用了一個函數，直接進去看看。

![image.png](image27.png)

一開始是一段字符串解密邏輯，解密結果是`/linker`，然後調用`like_strcpy`賦給`v24`。

然後會調用`like_dlopen`，它會打開一個新的linker並進行一些初始化。

![image.png](image28.png)

進入`like_dlopen`看看它是如何實現的。

`get_linker_startaddr`中會獲取原`linker`的起始地址( 存放在`*((_QWORD *)a1 + 3)` )，然後調用`openat + mmap`將新的linker映射進內存。

![image.png](image29.png)

之後是一個while循環，通過與linker的原文件對比( 用010來進行字節對比 )發現，這是在遍歷setion header tables，並根據`s_type`進行一些初始化。所以結果都保存在`a1 + x`。

![image.png](image30.png)

![image.png](image31.png)

![image.png](image32.png)

總的來說`like_dlopen`像是一個簡易版的`dlopen`。

回到上一層，在`like_dlopen`後調用了數個`like_dlsym`獲取一些符號，並保存在不同的全局變量中。其中的`g_solist`、`g_soinfo_get_realpath_func`、`g_soinfo_get_soname`在之後的分析中會出現。

而具體`like_dlsym`的實現就不看了，是一堆很抽象的計算，反正從結果來看它類似`dlsym`。

![image.png](image33.png)

![image.png](image34.png)

![image.png](image35.png)

![image.png](image36.png)

![image.png](image37.png)

最終調用一個函數清理一開始`open + mmap`映射進內存的那個linker，然後就返回了。

![image.png](image38.png)

總的來說`init_array_func2`裡做了一堆與linker相關的操作，獲取了一些linker函數，大概會在之後的一些檢測點。

## 字符串函數

通過上述對.init_array函數的分析，可以發現一些經常出現與字符串有關的函數`like_strcpy`、`a1_contain_a2`、`cmp_func1`、`cmp_func2`等等。

其中的`like_strcpy`通常會在字符串解密邏輯執行後調用，可以算是最接近解密字符串的一個函數，因此嘗試hook `like_strcpy`看看。

在此之前先解決frida檢測的問題，從上述分析可以知道是如何檢測的，因此我一開始的想法是hook `fgets`抹寫`/data/local`特徵，同時`fgets`也是本例.init_array中執行時機較早的函數，因此可以以`fgets`為跳板去hook其他在.init_array時機執行的函數( 如`like_strcpy` )。

```jsx
function addr_in_so(addr){
    var process_Obj_Module_Arr = Process.enumerateModules();
    for(var i = 0; i < process_Obj_Module_Arr.length; i++) {
        if(addr>process_Obj_Module_Arr[i].base && addr<process_Obj_Module_Arr[i].base.add(process_Obj_Module_Arr[i].size)){
            console.log(addr.toString(16),"is in",process_Obj_Module_Arr[i].name,"offset: 0x"+(addr-process_Obj_Module_Arr[i].base).toString(16));
        }
    }
}

let hooked = false;
function hook_fgets() {
    Interceptor.attach(Module.findExportByName(null, "fgets"), {
        onEnter: function(args) {
            this.res = args[0];
        },
        onLeave: function() {
            let res = this.res.readCString();
            // 1. bypass anti-frida
            if (res.indexOf("/data/local/ng1ok/ng1ok_server/ng1ok-64.so") != -1) {
                Memory.writeUtf8String(this.res, " ");
                if(!hooked) {
                    hooked = true;
                    // 2. hook .init_array
                    start_hook();
                }
            }
        }
    })
}

function start_hook() {

    function hook_like_strcpy(base) {
        let count = 0;
        Interceptor.attach(base.add(0xE384), {
            onEnter: function(args) {
                console.log("a1: ", args[1].readCString());
            }
        })
    }

    let base = Module.findBaseAddress("libdyzzwwc.so");
    console.log("base: ", base);
    hook_like_strcpy(base);
}

function main() {
    hook_fgets();
}

setImmediate(main);
```

結果是雖然frida不會再直接`Process terminated`，但依會彈窗提示，代表仍然有其他的frida檢測邏輯。

![image.png](image39.png)

`hook_like_strcpy`打印了很多東西，只列出一些我看到且認為比較重要的：

```jsx
// 1. 有點像完整性檢測
a1:  /libAdaptivePerformanceAndroid.so/libAdaptivePerformanceHint.so/libAdaptivePerformanceThermalHeadroom.so/libAndroidCpuUsage.so/libEncryptorP.so/libFirebaseCppAnalytics.so/libFirebaseCppApp-11_9_0.so/lib_burst_generated.so/libapminsighta.so/libapminsightb.so/libapplovin-native-crash-reporter.so/libbuffer_pg.so/libdyzzwwc.so/libfile_lock_pg.so/libil2cpp.so/libmain.so/libnative-googlesignin.so/libnms.so/libtobEmbedPagEncrypt.so/libunity.so
a1:  .
a1:  .
a1:  null:0:0:0:29256:0:d7db4753:5.1.1.139:null:10:10
a1:  null
a1:  5.1.1.139
a1:  d7db4753

// 2. root
a1:  /system/xbin/su
a1:  /system/bin/su
a1:  /sbin/su
a1:  /cache/su
a1:  /data/local/bin/su
a1:  /data/local/su
a1:  /data/local/xbin/su
a1:  /data/su
a1:  /system/bin/su
a1:  /system/xbin/bstk/su

// 3. magisk
a1:  /system/bin/magisk
a1:  /system/bin/magiskinit
a1:  /system/bin/magiskpolicy

// 4. android屬性?
a1:  /dev/__properties__/property_info

// 5. maybe frida?
a1:  ng1ok-64.so
a1:  FF130916
a1:  /proc/self/net/unix
a1:  7c3551fe3618

// 6. others
a1:  USB Connected
a1:  Alertdialog
a1:  debuggable
```

## 另一處anti-frida

注：其實只要hook `check1`讓其固定返回`0`就能完全bypass，但由於我比較好奇另一個frida檢測的實現邏輯，因此才進行了接下來的操作。

同上面那樣hook `like_strcpy`，在遇到`"ng1ok-64.so"`時打印調用棧。

```jsx
function hook_like_strcpy(base) {
    let count = 0;
    Interceptor.attach(base.add(0xE384), {
        onEnter: function(args) {
            if(args[1].readCString().indexOf("ng1ok-64.so") != -1) {
                console.log("a1: ", args[1].readCString());
                Thread.backtrace(this.context, Backtracer.FUZZY).map(addr_in_so);
            }
        }
    })
}
```

打印調用棧如下：

```bash
a1:  /data/local/ng1ok/ng1ok_server/ng1ok-64.so
7a0dd2b20c is in libdyzzwwc.so offset: 0x1720c
7a0dd37864 is in libdyzzwwc.so offset: 0x23864
7a7bbd1974 is in libart.so offset: 0x5ab974   
7a211ff25c is in ng1ok-64.so offset: 0x8e925c 
7a211ff25c is in ng1ok-64.so offset: 0x8e925c 
7a2120830c is in ng1ok-64.so offset: 0x8f230c
7a0dd38624 is in libdyzzwwc.so offset: 0x24624
7a2120851c is in ng1ok-64.so offset: 0x8f251c
7a0dd3819c is in libdyzzwwc.so offset: 0x2419c
7a0dd3819c is in libdyzzwwc.so offset: 0x2419c
7afe1af0a4 is in libdl.so offset: 0x10a4
7a0dd380e0 is in libdyzzwwc.so offset: 0x240e0
7a0dd66310 is in libdyzzwwc.so offset: 0x52310
7a7b766354 is in libart.so offset: 0x140354
a1:  ng1ok-64.so
7a0dd37a9c is in libdyzzwwc.so offset: 0x23a9c
7a0dd38624 is in libdyzzwwc.so offset: 0x24624
7a2120851c is in ng1ok-64.so offset: 0x8f251c
7a0dd3819c is in libdyzzwwc.so offset: 0x2419c
7a0dd3819c is in libdyzzwwc.so offset: 0x2419c
7afe1af0a4 is in libdl.so offset: 0x10a4
7a0dd380e0 is in libdyzzwwc.so offset: 0x240e0
7a0dd66310 is in libdyzzwwc.so offset: 0x52310
7a7b766354 is in libart.so offset: 0x140354
7afcf0da18 is in libc.so offset: 0xdea18
7a0dd2c0f0 is in libdyzzwwc.so offset: 0x180f0
7a0dd50ee0 is in libdyzzwwc.so offset: 0x3cee0
7afcebe0ac is in libc.so offset: 0x8f0ac
5c85f0a570 is in app_process64 offset: 0x5570
a1:  ng1ok-64.so
7a0dd37d1c is in libdyzzwwc.so offset: 0x23d1c
7a0dd38624 is in libdyzzwwc.so offset: 0x24624
7a2120851c is in ng1ok-64.so offset: 0x8f251c
7a0dd3819c is in libdyzzwwc.so offset: 0x2419c
7a0dd3819c is in libdyzzwwc.so offset: 0x2419c
7afe1af0a4 is in libdl.so offset: 0x10a4
7a0dd380e0 is in libdyzzwwc.so offset: 0x240e0
7a0dd66310 is in libdyzzwwc.so offset: 0x52310
7a7b766354 is in libart.so offset: 0x140354
7afcf0da18 is in libc.so offset: 0xdea18
7a0dd2c0f0 is in libdyzzwwc.so offset: 0x180f0
7a0dd386cc is in libdyzzwwc.so offset: 0x246cc
7afcf12730 is in libc.so offset: 0xe3730
a1:  ng1ok-64.so
7a0dd633e4 is in libdyzzwwc.so offset: 0x4f3e4
7a7b766354 is in libart.so offset: 0x140354
a1:  /data/local/ng1ok/ng1ok_server/ng1ok-64.so
7a0dd36328 is in libdyzzwwc.so offset: 0x22328
7a0dd388d0 is in libdyzzwwc.so offset: 0x248d0
a1:  /data/local/ng1ok/ng1ok_server/ng1ok-64.so
7a0dd633e4 is in libdyzzwwc.so offset: 0x4f3e4
7a7b766354 is in libart.so offset: 0x140354
```

可以看到有一堆不同的地方，一開始還以為有那麼多不同的frida檢測邏輯，打算一個一個替換看看。

```jsx
function hook_like_strcpy(base) {
    let count = 0;
    Interceptor.attach(base.add(0xE384), {
        onEnter: function(args) {
            if(args[1].readCString().indexOf("ng1ok-64.so") != -1) {
                if(count++ == 0) {
                    Memory.writeUtf8String(args[1], "tteesstt");
                }
                console.log("a1: ", args[1].readCString());
                Thread.backtrace(this.context, Backtracer.FUZZY).map(addr_in_so);
            }
        }
    })
}
```

誰知道在替換第一個後，就只剩一個調用棧了。

而且APP顯示的檢測點也從`ng1ok-64.so`變成`debuggable`。

```jsx
a1:  tteesstt
7a0ee2c20c is in libdyzzwwc.so offset: 0x1720c
7a0ee38864 is in libdyzzwwc.so offset: 0x23864
7a7bbd1974 is in libart.so offset: 0x5ab974   
7a211ff25c is in ng1ok-64.so (deleted) offset: 0x8e925c
7a211ff25c is in ng1ok-64.so (deleted) offset: 0x8e925c
7a2120830c is in ng1ok-64.so (deleted) offset: 0x8f230c
7a0ee39624 is in libdyzzwwc.so offset: 0x24624
7a2120851c is in ng1ok-64.so (deleted) offset: 0x8f251c
7a0ee3919c is in libdyzzwwc.so offset: 0x2419c
7a0ee3919c is in libdyzzwwc.so offset: 0x2419c
7afe1af0a4 is in libdl.so offset: 0x10a4
7a0ee390e0 is in libdyzzwwc.so offset: 0x240e0
7a0ee67310 is in libdyzzwwc.so offset: 0x52310
7a7b766354 is in libart.so offset: 0x140354
```

看到上述調用棧`libdyzzwwc.so offset: 0x240e0`調用了`libdl.so offset: 0x10a4`，動調看看。

發現調用了`dl_iterate_phdr`，這個函數的作用大概是會遍歷所依賴的共享庫，對每個對象都調用一次回調。

要單步`F7`才能慢慢跟到`callback_func`裡面。

![image.png](image40.png)

然後會跟到`linker64`的`dl__Z18do_dl_iterate_phdrPFiP12dl_phdr_infomPvES1`，在這裡調用上述的`callback_func`。

![image.png](image41.png)

跟入`callback_func`，不知為何`F5`的結果與匯編的結果不一致( 大概是IDA對某些函數錯誤的分析所導致的連鎖效應 )，只能從匯編視圖繼續跟。

![image.png](image42.png)

`x0`為`"/system/bin/linker64"`，`x1`為`libdl.so`，`cmp_func1`類似`strcmp`，相等才會返回`0`

![image.png](image43.png)

`x0`為`"/system/bin/linker64"`，`x1`為`/data/app`，`cmp_func2`同樣類似`strcmp`。

![image.png](image44.png)

`x0`為`"/system/bin/linker64"`，`x1`為packagename，`x0`包含`x1`時才為true，否則會走到`check_smaps`函數。

![image.png](image45.png)

跟了一會可以總結出，`x0`就是`dl_iterate_phdr`遍歷時傳給`callback_func`的共享庫名字。

`callback_func`的大概邏輯就是將除了`libdl.so`、以`/data/app/`開頭、包含packagename的so都過濾後，然後調用`check_smaps`檢查。

![image.png](image46.png)

而`check_smaps`會調用`check1`。

![image.png](image47.png)

再來回顧下`check1`，裡面有一段這樣的檢測，而由於我魔改的`frida-agent-<arch>.so`放在了`/data/local`目錄下，所以才會被檢測到。

![image.png](image48.png)

試下直接將`check1`固定返回`0`，看看可否bypass。

```jsx
function hook_check1(base) {
    // 1643C
    Interceptor.attach(base.add(0x1643C), {
        onEnter: function(args) {
        },
        onLeave: function(retval) {
            if(retval.toInt32() != 0) {
                console.log(`bypass check1 (before retval: ${retval})`)
                retval.replace(0);

            }
        }
    })
}

```

成功，不再顯示`ng1ok-64.so`，而是顯示`debuggable`。

![image.png](image49.png)

小結：

除了`fopen("/proc/<pid>/maps") + fgets`這套組合技外，還可以通過`dl_iterate_phdr`來實現類似遍歷`/proc/<pid>/maps`的效果，因此我一開始hook `fgets`時才無法bypass。

## debuggable檢測

會觸發這個檢測是大概是因為我的手機環境是自定制的AOSP，我設置了所有APP默認有debuggable權限。

為了驗證是否如我所想，我將APP debuggable權限改成了可切換的模式。

![image.png](image50.png)

可以看到，關閉debuggable的狀態下是可以正常進入遊戲的。

![image.png](image51.png)

但關了debuggable權限後就無法動調了，這很不好。嘗試過找具體的檢測代碼，想針對性地bypass，但沒找到。

最終的解決方案是patch掉導致APP閃退的函數來bypass，後文會說明是哪個函數。

## .init_array之外的檢測函數

在動調.init_array函數的過程中，會對其中用到的一些函數下斷點。

某次調試完.init_array後按`F9`繼續運行，發現斷在了某個地方，向上回溯能來到另一個超大的檢測函數，我將其命名為`after_initarray_check2`。

一開始沒有細究`after_initarray_check2`是誰調用的，後來想了想明顯是Java層調用的native函數。

將APP拉入jadx，查找`dyzzwwc`。

![image.png](image52.png)

其中只有一個native函數，顯然就是它。

同時會發現Java層做了一些混淆，但目前並不需要分析Java層，因此也無所謂了。

![image.png](image53.png)

之後各種檢測的上層調用棧都是`after_initarray_check2`，因此這裡先小小分析一下它的來源。

## N個線程檢測函數

在動調`after_initarray_check2`時，會發現IDA越來越卡，而且經常亂跳，經常crash，經常卡住不動。

一開始還以為是IDA的老問題( IDA動調有時候是真的卡… )，但漸漸感到不太對，直到在某處看到`pthread_create`才恍然大悟，猜測大概是`after_initarray_check2`啟動了一堆線程。

![image.png](image54.png)

hook了`pthread_create`後發現果然如此，創建了N個線程，數了下總共有`11`個不同的線程回調函數。

後面會繼續分析這些線程到底在檢測什麼，現在先嘗試bypass，目的是讓frida可以正常hook APP( 並且解決`debuggable`檢測 )而不閃退。

```cpp
so_name libdyzzwwc.so offset 0x2d4c4 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd444c4
so_name libdyzzwwc.so offset 0x11368 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd28368
so_name libdyzzwwc.so offset 0x25fa8 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd3cfa8
so_name libdyzzwwc.so offset 0x44834 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd5b834
so_name libdyzzwwc.so offset 0x15f30 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd2cf30
so_name libdyzzwwc.so offset 0x45a68 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd5ca68
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0x332a4 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd4a2a4
so_name libdyzzwwc.so offset 0x112e4 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd282e4
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0x39e18 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd50e18
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0xf2d0 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd262d0
so_name libdyzzwwc.so offset 0x2466c path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd3b66c
so_name libdyzzwwc.so offset 0x112e4 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd282e4
so_name libdyzzwwc.so offset 0x112e4 path /data/app/net.gameduo.tbd-BHl5bEYewEh0AB6f_qEItw==/lib/arm64/libdyzzwwc.so parg2 0x7a0dd282e4
```

### bypass all

APP啟動了那麼多的線程，相關的檢測邏輯大概都在其中，因此嘗試直接patch掉所有線程。

結果是APP雖然不會再彈出Alert Dialog，但會在進度條加載到某個時刻時閃退。

嘗試hook動調時發現的`kill_func`，看看會否觸發，順便打印調用棧。

```jsx
function hook_exit(base) {
    // 0x10CFC
    Interceptor.attach(base.add(0x10CFC), {
        onEnter: function() {
            console.log("call kill func");
            Thread.backtrace(this.context, Backtracer.FUZZY).map(addr_in_so);
        }
    })
}
```

的確會觸發，跳到對應位置繼續分析

```bash
call kill func
7a0dc27fa0 is in libdyzzwwc.so offset: 0x10fa0
7a0dc65738 is in libdyzzwwc.so offset: 0x4e738
7a7b766354 is in libart.so offset: 0x140354
7a7b75d5bc is in libart.so offset: 0x1375bc
7a7b76bfb0 is in libart.so offset: 0x145fb0
7a7b90cc94 is in libart.so offset: 0x2e6c94
7a7b908cb4 is in libart.so offset: 0x2e2cb4
7a7b908b70 is in libart.so offset: 0x2e2b70
7a7bbd7150 is in libart.so offset: 0x5b1150
7a7b757c98 is in libart.so offset: 0x131c98
7a7bbd4564 is in libart.so offset: 0x5ae564
7a7b757998 is in libart.so offset: 0x131998
7a7bbd4564 is in libart.so offset: 0x5ae564
7a7bbd4788 is in libart.so offset: 0x5ae788
7a2111fcb0 is in ng1ok-64.so offset: 0x7eecb0
7a7b757998 is in libart.so offset: 0x131998
```

發現是`pthread_func9`( 我命名的第9個檢測線程 )創建失敗所導致。

![image.png](image55.png)

嘗試讓`pthread_func9`順利創建

```jsx
// 在hook pthread_create中放行pthread_func9
if(offset == 0x112E4) { // 0x112E4: offset of pthread_func9
    console.log("pass pthread_func9");
    return pthread_create(parg0, parg1, parg2, parg3)
}
```

之後雖然能順利進入遊戲，但過一陣子同樣閃退。

```jsx
call kill func
7a0dc142dc is in libdyzzwwc.so offset: 0x112dc
7a0dc14368 is in libdyzzwwc.so offset: 0x11368
7afcf12730 is in libc.so offset: 0xe3730
7afceb3008 is in libc.so offset: 0x84008
```

由此可知各個檢測線程存在一定程度上的耦合，牽一髮則動全身。

最終的通用bypass手段是從`kill_func`入手( 猜測所有閃退都會調用`kill_func` )，嘗試直接patch掉`kill_func`，讓它固定返回`0`，成功讓APP與frida都不再閃退。

```jsx
function patch_exit(base) {
    // 0x10CFC
    Interceptor.replace(base.add(0x10CFC), new NativeCallback(() => {
        console.log("call kill func");
        return 0;
    }, "int", []))
}
```

至此我遇到的2個反調試都已成功繞過，但我同樣比較好奇其他檢測線程干了什麼，因此下文會繼續分析看看其他線程( 不會全部線程都分析 )。

### 調試線程前置

1. 通過frida + IDA來動調( 而不是`adb shell am start -D -n XXX` 那種方式 )，這樣做的目的是：
    1. 可以選擇只讓哪個線程被成功創建，然後就可以單獨分析該線程。
    2. 需要frida hook `kill_func`來防止閃退。
    
    ```jsx
    function hook_pthread() {
    
        var pthread_create_addr = Module.findExportByName(null, 'pthread_create');
        console.log("pthread_create_addr,", pthread_create_addr);
    
        var pthread_create = new NativeFunction(pthread_create_addr, "int", ["pointer", "pointer", "pointer", "pointer"]);
    
        Interceptor.replace(pthread_create_addr, new NativeCallback(function (parg0, parg1, parg2, parg3) {
            var so_name = Process.findModuleByAddress(parg2).name;
            var so_path = Process.findModuleByAddress(parg2).path;
            var so_base = Module.getBaseAddress(so_name);
            var offset = parg2 - so_base;
            // if(so_name.indexOf("libdyzzwwc.so") != -1)
            //     console.log("so_name", so_name, "offset", ptr(offset), "path", so_path, "parg2", parg2);
            var PC = 0;
            if ((so_name.indexOf("libdyzzwwc.so") > -1)) {
                // console.log("find thread func offset", so_name, offset);
    
                // if(offset == 0x112E4) {  // maybe the Alert Dialog
                //     console.log("ignore to patch: pthread_func9");
                //     return pthread_create(parg0, parg1, parg2, parg3)
                // }
    
                // if(offset == 0x332A4) {
                //     console.log("ignore to patch: pthread_func8_check_app_debuggable");
                //     return pthread_create(parg0, parg1, parg2, parg3)
                // }
    
                // if(offset == 0x2D4C4) {  // nothing
                //     console.log("ignore to patch: pthread_func1");
                //     return pthread_create(parg0, parg1, parg2, parg3)
                // }
    
                // if(offset == 0x112A0) {  // nothing
                //     console.log("ignore to patch: pthread_func2");
                //     return pthread_create(parg0, parg1, parg2, parg3)
                // }
    
                // if(offset == 0x25FA8) {  // nothing
                //     console.log("ignore to patch: pthread_func3");
                //     return pthread_create(parg0, parg1, parg2, parg3)
                // }
                
                // if(offset == 0x44834) {  // nothing
                //     console.log("ignore to patch: pthread_func4");
                //     return pthread_create(parg0, parg1, parg2, parg3)
                // }
    
                // if(offset == 0x15F30) {  // nothing
                //     console.log("ignore to patch: pthread_func5");
                //     return pthread_create(parg0, parg1, parg2, parg3)
                // }
    
                // if(offset == 0x45A68) {  // detect: net.gameduo.tbd.apk
                //     console.log("ignore to patch: pthread_func6");
                //     return pthread_create(parg0, parg1, parg2, parg3)
                // }
    
                // if(offset == 0xF2D0) {  // nothing
                //     console.log("ignore to patch: pthread_func7");
                //     return pthread_create(parg0, parg1, parg2, parg3)
                // }
      
                // if(offset == 0x39E18) {  // shamiko??
                //     // 前置: pthread_func6、pthread_func7、pthread_func9
                //     console.log("ignore to patch: pthread_func10");
                //     return pthread_create(parg0, parg1, parg2, parg3)
                // }
      
                if(offset == 0x2466C) {  // nothing
                    console.log("ignore to patch: pthread_func11");
                    return pthread_create(parg0, parg1, parg2, parg3)
                }
    
                
            } else {
                PC = pthread_create(parg0, parg1, parg2, parg3);
                // console.log("ordinary sequence", PC)
            }
            return PC;
        }, "int", ["pointer", "pointer", "pointer", "pointer"]))
    
    }
    ```
    
2. patch `nanosleep`，對本例來說，它會導致動調時卡住不動，大概也是由某個反調試邏輯觸發的，直接讓其固定返回`0`就可以。
    
    ```jsx
    function hook_nanosleep() {
        Interceptor.replace(Module.findExportByName(null, "nanosleep"), new NativeCallback(() => {
            return 0;
        }, "int", ["pointer", "pointer"]))
    }
    ```
    
3. 最好是在對應的`pthread_create`和對應的線程回調函數裡都下斷點，只在線程的回調函數裡下斷點可能會失敗。
    
    ![image.png](image56.png)
    
4. 斷在對應的`pthread_create`後，最好先暫時其他線程，這樣會比較好調，防止其他線程的干擾。IDA Python腳本：一鍵暫停其他線程
    
    ```python
    import idc;
    def suspend_other_thread():
        current_thread = idc.get_current_thread()
        thread_count = idc.get_thread_qty()
        for i in range(0, thread_count):
            other_thread = idc.getn_thread(i)
            if other_thread != current_thread:
                idc.suspend_thread(other_thread)
    suspend_other_thread()
    ```
    

### pthread_func6

function offset：`0x45A68`

`pthread_func6`一開始先調用`check_fingerprint3`函數進行第一部份的檢測，進入看看。

![image.png](image57.png)

`check_fingerprint3`裡調用`check_su`檢查了一些常規的su路徑。

![image.png](image58.png)

`check_su`會先構造各種可能的su路徑，如`/system/xbin/su`，然後傳入`check_su_path_exist`

![image.png](image59.png)

`check_su_path_exist`( 其實叫做`check_path_exist`會好點，因為這個函數不只用來檢測su路徑 )會創建`pthread_func7`來檢測。

`pthread_func7`具體實現下一小節再看。

![image.png](image60.png)

回到`check_fingerprint3`繼續向下看。

檢查`ro.build.fingerprint`是否包含`userdebug`。

![image.png](image61.png)

比較`ro.product.model`與`Custom Phone`是否相同。

![image.png](image62.png)

檢查magisk特徵

![image.png](image63.png)

獲取環境變量，遍歷其中的所有路徑，傳入`trav_dir_and_check_su`函數。

![image.png](image64.png)

注：`trav_dir_and_check_su`函數實現如下，通過`scandir`來遍歷指定目錄，然後檢查其中是否包含`su`文件。

![image.png](image65.png)

連`/sdcard/Download/boot.img`都不放過？

![image.png](image66.png)

又是一些magisk特徵：

`/system/bin/magisk`、`/system/bin/magiskinit`、`/system/bin/magiskpolicy`、`/system/bin/resetprop`

![image.png](image67.png)

![image.png](image68.png)

![image.png](image69.png)

最後又有一些su檢測

![image.png](image70.png)

看完`check_fingerprint3`後，回到`pthread_func6`繼續向下看( 只發現一處特別可疑的地方 )。

循環遍歷solist ( 由`g_solist`賦值 )，調用`soinfo_get_realpath` ( 實際調用的是`g_soinfo_get_realpath_func` )、`soinfo_get_soname` ( 實際調用的是`g_soinfo_get_soname` )來獲取`realpath`和`soname`，然後判斷其中是否包含zygisk的特徵。

![image.png](image71.png)

![image.png](image72.png)

小結：

`pthread_func6`總的來說就是一個root檢測。

### pthread_func7

function offset：`0xF2D0`

`pthread_func7`中會通過各種手段嘗試打開/訪問傳入來的路徑，如果能順利執行就代表被檢測到。

用到的API包括：`fopen`、`openat`、`scandir`、`lstat`、`stat`、`access`、`readlink`。

![image.png](image73.png)

![image.png](image74.png)

### pthread_func10

function offset：`0x39E18`

一開始調用了`sub_7869BC4880`，動調時沒有看出它在干什麼。

![image.png](image75.png)

但在靜態分析時手動解密了`sub_7869BC4880`中的一些字符串，大概是一些模擬器的特徵檢測。

![image.png](image76.png)

回到`pthread_func10`繼續向下看。

調用了`check_BlueStacks_emu`，它專門檢測了BlueStacks模擬器。

![image.png](image77.png)

具體檢測了以下特徵：( 將以下字符串作為參數傳入`check_su_path_exist` )

```python
"com.bluestacks.bstfolder"
"/data/data/com.bluestacks.home"
"/data/data/com.bluestacks.launcher"
"/sdcard/Android/data/com.bluestacks.home"
"/system/bin/bstfolderd"
"/system/bin/bstfolder"
"/system/bin/bstsyncfs"
"/sys/module/bstsensor"
"/sys/module/bstpgaipc"
"/system/xbin/bstk/su"
"/system/xbin/bstk"
```

繼續向下看，又檢測了一些特徵，不認識。

![image.png](image78.png)

檢測夜神模擬器

![image.png](image79.png)

具體檢測了以下特徵：

```python
"/system/bin/nox-vbox-sf"
"/data/data/com.bignox.appcenter"
```

檢測雷電模擬器

![image.png](image80.png)

具體檢測了以下特徵：

```python
"/system/app/LDAppStore/LDAppStore.apk"
```

檢測KoPlayer

![image.png](image81.png)

檢測一些虛擬機特徵：

```python
"/system/bin/androidVM-vbox-sf"
"/system/bin/androidVM-prop"
"/sys/module/vboxpcismv"
"/sys/module/nemusf"
"/system/bin/genybaseband"
"/sys/module/vboxsf"
```

檢測Android指紋中是否包含：

```python
"Android SDK built"
"sdk_gphone"
"Android/sdk_"
"Android/vbox86"
"google/sdk_"
```

調用`check_android_prop`檢測了一些android屬性

![image.png](image82.png)

具體獲取了以下android屬性：

```python
"Dapexd.status"
"vm.cleaner.status"
"Xsystem.slide-out.enabled"
"sys.powerboot.adbd"
"init.svc.vmcd"
"nit.svc.sh_boot"
"siq.display.config"
"ro.boottime.apexd"
"ro.com.cph.cloud_app_engine" (云手機特徵)
"ro.global.scene"
```

小結：

`pthread_func10`總的來說就是一個模擬器/虛擬機檢測，除此之外大概還檢測了`shamiko`，但我動調時走不到相應的檢測邏輯，故沒有分析其具體實現。

## il2cpp dump

繞過相關反調試後，終於可以開始我們的「正文」了，沒想到這部份是最簡單的…

這個手遊是經典的Unity + il2cpp，它的`libil2cpp.so`沒有加密，但`global-metadata.dat`明顯加密了。

![image.png](image83.png)

在`libil2cpp.so`搜`"global-metadata.dat"`定位到其加載函數`sub_A6D2B0`。

![image.png](image84.png)

frida dump腳本：

```jsx
function dump_bin(name, addr, size) {
    var file_path = "/data/data/net.gameduo.tbd" + "/" + name + ".bin";
    console.log("dump path: ", file_path);
    var file_handle = new File(file_path, "wb");
    if (file_handle && file_handle != null) {
        Memory.protect(ptr(addr), size, 'rwx');
        var libso_buffer = ptr(addr).readByteArray(size);
        file_handle.write(libso_buffer);
        file_handle.flush();
        file_handle.close();
        console.log("[dump]:", file_path);
    }
}
function get_size(addr) {
    const metadataHeader = addr;
    let fileOffset = 0x10C;
    let lastCount = 0;
    let lastOffset = 0;
    while (true) {
        lastCount = Memory.readInt(ptr(metadataHeader).add(fileOffset));
        if (lastCount !== 0) {
            lastOffset = Memory.readInt(ptr(metadataHeader).add(fileOffset-4));
            console.log("fileOffset : ", ptr(fileOffset))
            break;
        }
        fileOffset -= 8;
        if(fileOffset <= 0)
        {
            console.log("get size failed!");
            break;
        }
    }
    return lastOffset + lastCount;
}
function dump_gm(base) {
    Interceptor.attach(base.add(0xA6D2B0),{
        onEnter(args){
            console.log("[libil2cpp] arg0: ", args[0].readCString());
        },
        onLeave(retval){
            dump_bin("global-meta", retval, get_size(retval));
        }
    })
}
```

dump下來的global-metadata可以直接用在Il2cppDumper。

最後，隨便找了個函數來hook，成功修改了升級所需的經驗。

![image.png](image85.png)

## 結語

淺淺過了一遍LIAPP這個保護，能看出來它花了大量功夫在反調試上，與常規防護不同的是它沒有一個固定的字符串解密函數，導致逆向時無法一步到位發現所有可疑的地方，所幸在不同的字符串解密邏輯後都跟了固定幾個字符串處理函數，大大方便了逆向工作。除此之外它應該還有一些風控的邏輯，但我沒有分析到就不談了。

令人費解的是它對gm文件的保護程度簡直弱到可怕，可以說是即dump即用了。

花了幾天時間來研究，若單純以破解為目的其實只需要1~2天就可以，比較費時間的是研究它的檢測原理，總的來說也是收獲了不少。

最後，文中若是有寫錯的地方還望指出，也歡迎技術交流！！！