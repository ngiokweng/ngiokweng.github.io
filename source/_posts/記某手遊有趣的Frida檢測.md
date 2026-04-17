---
title: 記某手遊有趣的Frida檢測
date: 2026-01-03 17:20:50
tags:
- Android逆向
- Frida檢測
categories: Android逆向
keywords:
- Android逆向
- Frida檢測
description: frida detect
cover: image1.png
---

## 0. 前言

前段時間群友分享了一個cocos2djs樣本，似乎用到了魔改的v8引擎，嘗試分析了一下，遺憾倒在了v8的環境上( 嘗試了幾種編譯配置，都無法編譯出樣本中使用的v8環境 )，只能放棄。

無奈之下只好找別的樣本來看，打開應用商店，隨便下載了個遊戲，不曾想看到了兩個挺有意思的frida檢測，故寫下此文與各位分享一二。

## 1. 分析

### hook檢測

僅以frida啟動( 不注入腳本 )遊戲，會因SIGSEGV異常而閃退，fault addr為`0x97c`。

```bash
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x97c
Cause: null pointer dereference
    x0  0000000000000000  x1  000000005b93db5d  x2  0000000038e13d9b  x3  0000000087f8886f
    x4  00000072c9b31de0  x5  00000000b6a2897e  x6  0000000084e98181  x7  00000000b87799a1
    x8  00000000b6a2897e  x9  000000000000097c  x10 00000000e4e0ce0c  x11 00000000df4bca4f
    x12 00000000b87799a2  x13 00000000b2c86410  x14 00000000a027565c  x15 0000000092d1a39f
    x16 0000000088593d27  x17 000000006d65dbde  x18 00000072c91a2000  x19 0000000000000fff
    x20 00000000b6a2897e  x21 00000072c9426710  x22 00000000e4e0ce0b  x23 00000000b2c8640f
    x24 0000000074e73510  x25 00000072c9b3210c  x26 00000072c9b320e0  x27 000000005b93db5c
    x28 000000000000097c  x29 00000072c9426790
    sp  0000000000000000  lr  0000000000000000  pc  000000000000097c

backtrace:
      #00 pc 000000000000097c  <unknown>
      #01 pc 0000000000000000  <unknown>
```

遊戲閃退有以下規律：

- 先啟動frida server，再手動打開遊戲，會閃退。
- 關了frida server，再手動打開遊戲，不會閃退。
- 打開遊戲後，再啟動frida server，不會閃退。

由此猜測它在遊戲啟動之初檢測了一次maps特徵( 或其他少見的frida特徵？ )。

hook `pthread_create()`會發現更快地閃退，而且fault addr變為了`0x10dc`。

```cpp
backtrace:
      #00 pc 00000000000010dc  <unknown>
      #01 pc 0000000000000000  <unknown>
```

大概是檢測了`pthread_create()`函數有沒有被hook。

對該函數下硬斷(讀)，果然有觸發：

```cpp
from kernel: log = HWBP
#0 :    Offset: 0x1c3158     | Path: /data/app/com.pearlabyss.blackdesertm.gl-vSTUZ2GFrGI8BORwxdSkyw==/lib/arm64/libAppGuard.so
#1 :    Offset: 0x293640     | Path: /data/app/com.pearlabyss.blackdesertm.gl-vSTUZ2GFrGI8BORwxdSkyw==/lib/arm64/libAppGuard.so
#2 :    Offset: 0x32e8c      | Path: /data/app/com.pearlabyss.blackdesertm.gl-vSTUZ2GFrGI8BORwxdSkyw==/lib/arm64/libAppGuard.so
#3 :    Offset: 0x385108     | Path: /apex/com.android.runtime/lib64/libart.so
#4 :    Offset: 0x5610       | Path: /apex/com.android.runtime/lib64/libopenjdkjvm.so
#5 :    Offset: 0xb9af8      | Path: /system/framework/arm64/boot.oat
#6 :    Offset: 0x3dc059     | Path: /apex/com.android.runtime/javalib/core-oj.jar
[BM_PERF_CALLCHAIN_USER] waiting kernel data....
```

先看第一個觸發點( `0x1c3158` )，明顯是在對比什麼東西，大概是前N字節？

記當前所屬函數為`is_lib_func_hooked_1C2144()`。

![image.png](image.png)

trace看看`is_lib_func_hooked_1C2144()`的實現方式。

首先遍歷maps獲取目標lib的全路徑。

![image.png](image1.png)

然後解析目標lib的shdr，獲取符號表和字符串表，遍歷查找指定符號的偏移。

![image.png](image2.png)

得到指定符號在內存的地址後，會又一次遍歷maps找到該地址所屬內存段，賦予這段內存rx權限( 確保能讀，因為原權限可能會像是`--x`這樣的 )。

![image.png](image3.png)

最後對比前`0x10`字節，不相同代表被hook了。

![image.png](image4.png)

往上追一層，來到這裡，發現了`is_lib_func_hooked_1C2144()`前面有明顯的字符串解密函數，記為`decrypt_str()`( 後續分析可以從它入手 )

![image.png](image5.png)

hook `is_lib_func_hooked_1C2144()`可知，除了`pthread_create()`外，還檢測了`libart.so`的一些函數，測試後可知返回值的含義：

- `0`：目標函數沒有被hook
- `1`：目標函數被hook了
- `-1`：應該是沒有找到目標函數

```cpp
[is_lib_func_hooked_1C2144] lib:  libc.so        
[is_lib_func_hooked_1C2144] func:  pthread_create
[is_lib_func_hooked_1C2144] retval:  0x0
[is_lib_func_hooked_1C2144] lib:  libart.so
[is_lib_func_hooked_1C2144] func:  _ZN3art6mirror9ArtMethod14RegisterNativeEPNS_6ThreadEPKvb
[is_lib_func_hooked_1C2144] retval:  0xffffffff
[is_lib_func_hooked_1C2144] lib:  libart.so
[is_lib_func_hooked_1C2144] func:  _ZN3art6mirror9ArtMethod16UnregisterNativeEPNS_6ThreadE
[is_lib_func_hooked_1C2144] retval:  0xffffffff
[is_lib_func_hooked_1C2144] lib:  libart.so
[is_lib_func_hooked_1C2144] func:  _ZN3art9ArtMethod14RegisterNativeEPKvb
[is_lib_func_hooked_1C2144] retval:  0xffffffff
[is_lib_func_hooked_1C2144] lib:  libart.so
[is_lib_func_hooked_1C2144] func:  _ZN3art9ArtMethod16UnregisterNativeEv
[is_lib_func_hooked_1C2144] retval:  0x0
[is_lib_func_hooked_1C2144] lib:  libart.so
[is_lib_func_hooked_1C2144] func:  _ZN3art9ArtMethod14RegisterNativeEPKv
[is_lib_func_hooked_1C2144] retval:  0x0
[is_lib_func_hooked_1C2144] lib:  libart.so
[is_lib_func_hooked_1C2144] func:  _ZN3art11ClassLinker14RegisterNativeEPNS_6ThreadEPNS_9ArtMethodEPKv
[is_lib_func_hooked_1C2144] retval:  0xffffffff
[is_lib_func_hooked_1C2144] lib:  libart.so
[is_lib_func_hooked_1C2144] func:  _ZN3art11ClassLinker16UnregisterNativeEPNS_6ThreadEPNS_9ArtMethodE
[is_lib_func_hooked_1C2144] retval:  0xffffffff
[is_lib_func_hooked_1C2144] lib:  libart.so
[is_lib_func_hooked_1C2144] func:  _ZN3art11ClassLinker22FixupStaticTrampolinesENS_6ObjPtrINS_6mirror5ClassEEE
[is_lib_func_hooked_1C2144] retval:  0x0
[is_lib_func_hooked_1C2144] lib:  libart.so
[is_lib_func_hooked_1C2144] func:  _ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6ThreadENS_6ObjPtrINS_6mirror5ClassEEE
[is_lib_func_hooked_1C2144] retval:  0xffffffff
[is_lib_func_hooked_1C2144] lib:  libart.so
[is_lib_func_hooked_1C2144] func:  _ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6mirror5ClassE
[is_lib_func_hooked_1C2144] retval:  0xffffffff
```

### Frida檢測(一)

hook `decrypt_str()`發現如下字串：

```
[decrypt_str] retval:  /memfd:
[decrypt_str] retval:  00000000 00:00 0
```

打印調用棧如下，看似有2處不同的調用棧，其實應該是同一個。

`0x1b49b8`所屬函數是`sub_1B4214()`，trace這個函數，看看它的調用流。( 日志記為`trace_1B4214.log` )

```cpp
[decrypt_str] res: /memfd: (a0: 0ohnhg;)
called from:
0x71a57c7aa8 libAppGuard.so!0x1baaa8
0x71a57c19b8 libAppGuard.so!0x1b49b8
0x71a57c1178 libAppGuard.so!0x1b4178
0x71a57bfa14 libAppGuard.so!0x1b2a14
0x71a57f8964 libAppGuard.so!0x1eb964
0x7296a41730 libc.so!_ZL15__pthread_startPv+0x28
0x72969e2008 libc.so!__start_thread+0x44

[decrypt_str] res: /memfd: (a0: 0ohnhg;)
called from:
0x71a57c21e4 libAppGuard.so!0x1b51e4
0x71a57c9960 libAppGuard.so!0x1bc960
0x71a57c19b8 libAppGuard.so!0x1b49b8
0x71a57c1178 libAppGuard.so!0x1b4178
0x71a57bfa14 libAppGuard.so!0x1b2a14
0x71a57f8964 libAppGuard.so!0x1eb964
0x7296a41730 libc.so!_ZL15__pthread_startPv+0x28
0x72969e2008 libc.so!__start_thread+0x44

[decrypt_str] res: /memfd: (a0: 0ohnhg;)
```

在`trace_1B4214.log`會發現它又遍歷了`/proc/self/maps`，而且是通過`read()`系統調用來逐字節讀取maps的每一行，記每行為`maps_line`。

![image.png](image6.png)

然後調用`access()`來判斷`maps_line`中的文件路徑是否存在，如果不存在且路徑中包含`memfd`，則調用`syscall(0x10e)`( `process_vm_readv()` )來判斷前4字節是否elf文件的魔數。

注：為方便記憶，將`sub_1B4214()`記為`check_memfd()`

![image.png](image7.png)

注：從`sub_1bfebc()` ( 上圖中`syscall(0x10e)`的外外層函數 )的輸出可知是在校驗elf魔數。

```jsx
[hook_1bfebc] this.a1:               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
73ea1b0954  7f 45 4c 46 2f 6d 65 6d 66 64 3a 00 30 09 1b ea  .ELF/memfd:.0...
73ea1b0964  73 00 01 01 59 09 1b ea 73 00 00 00 01 01 01 01  s...Y...s.......
73ea1b0974  2f 00 00 00 06 00 00 00 00 00 00 00 a1 0d 1b ea  /...............
73ea1b0984  73 00 00 00 01 01 01 01 2f 00 00 00 a0 0d 1b ea  s......./.......
73ea1b0994  73 00 00 00 2f 00 00 00 3a 00 00 00 5f 09 1b ea  s.../...:..._...
73ea1b09a4  73 00 00 00 a7 0d 1b ea 73 00 00 00 01 00 00 00  s.......s.......
73ea1b09b4  00 00 00 00 a6 0d 1b ea 73 00 00 00 30 30 30 30  ........s...0000
73ea1b09c4  30 30 30 30 20 30 30 3a 30 30 20 30 00 03 ed a9  0000 00:00 0....
73ea1b09d4  00 00 00 00 df c7 bb 20 ed 42 90 77 b7 0d 1b ea  ....... .B.w....
73ea1b09e4  73 00 00 00 df c7 bb 20 ed 42 90 77 26 7d 4c 28  s...... .B.w&}L(
73ea1b09f4  00 00 00 00 e6 e6 3c 04 00 00 00 00 66 f3 08 49  ......<.....f..I
73ea1b0a04  00 00 00 00 6e e4 30 32 00 00 00 00 14 53 58 b9  ....n.02.....SX.
73ea1b0a14  00 00 00 00 b5 a2 05 a0 00 00 00 00 14 28 8d c7  .............(..
73ea1b0a24  00 00 00 00 da 2a ae d3 00 00 00 00 b6 a2 05 a0  .....*..........
73ea1b0a34  00 00 00 00 a4 8d 79 9b 00 00 00 00 b0 0c 1b ea  ......y.........
73ea1b0a44  73 00 00 00 60 f9 76 eb 73 00 00 00 00 00 00 00  s...`.v.s.......  len =  4
```

嘗試bypass，具體思路是在frida注入時提前遍歷maps文件，判斷路徑是否包含`memfd`，且前4字節是否elf魔數，均成立的情況下，把前4字節置空。

```jsx
function bypass_memfd_check() {
    console.log("[*] 开始读取 /proc/self/maps");
    
    try {
        // 打开当前进程的 maps 文件
        const mapsFile = new File("/proc/self/maps", "r");
        let lineCount = 0;
        
        // 逐行读取
        while (!mapsFile.eof) {
            const line = mapsFile.readLine();
            if (!line) break;
            
            // 解析格式: "起始-结束 权限 偏移 设备 inode 路径名"
            // 示例: "7f8b3d5000-7f8b3f6000 r-xp 00000000 b3:18 8193  /system/lib64/libc.so"
            const parts = line.trim().split(/\s+/);
            
            if (parts.length >= 6) {
                const addressRange = parts[0];        // "7f8b3d5000-7f8b3f6000"
                const pathname = parts.slice(5).join(' '); // 合并路径名中的空格
                const perm = parts[1].substring(0, 3);

                // 提取起始地址
                const startAddr = ptr("0x" + addressRange.split('-')[0]);
                const endAddr = ptr("0x" + addressRange.split('-')[1]);
                if (pathname.indexOf("memfd") != -1) {
                    console.log(`[${lineCount++}] 起始地址: 0x${startAddr} → ${pathname}`);
                    Memory.protect(startAddr, endAddr - startAddr, "rwx");
                    if (startAddr.readU32() == 0x464c457f) {
                        console.log("bypass ", startAddr)
                        startAddr.writeU32(0);
                    }
                }

                Memory.protect(startAddr, endAddr - startAddr, perm);
            }
        }
        
        mapsFile.close();
        console.log(`[*] 共读取 ${lineCount} 条映射记录`);
        
    } catch (e) {
        console.error("[!] 读取失败:", e);
        console.error("    可能原因: 权限不足或 SELinux 限制");
    }
}

```

結果仍會閃退，但並非沒有效果，因為hook `check_memfd()`會發現：

- 在沒有`bypass_memfd_check()`時，`check_memfd()`返回`1`
- 在`bypass_memfd_check()`後，`check_memfd()`返回`0`。

```jsx
function hook_check_memfd() {
    Interceptor.attach(base.add(0x1B4214), {
        onEnter : function (args) {
        },
        onLeave : function (retval) {
           console.log("[check_memfd] retval: ", retval)
        }
    })
}
```

由此可知仍有其他地方在檢測frida。

### Frida檢測(二)

在`bypass_memfd_check()`的情況下重新trace多次`pthread_func_1eb750()`。

trace到`sub_1b20f4()`時會執行得很慢很慢，hook `sub_1b20f4()`會發現只有enter沒有leave，即另一處檢測邏輯大概就在其中。

用frida stalker看看`sub_1b20f4()`調用過的`bl`指令( 只列出最後幾個 )，最後一個是在`0x1b29f0`，調用的函數是`sub_251798()`。

```jsx
0x1b3a8c: bl #0x73ea5dd380  
0x1b3a94: bl #0x73ea5dcd30  
0xf0cd4fe4: bl #0x74db2c3900
0x1b3ab0: bl #0x73ea5dd6c0  
0x1b39c8: bl #0x73ea5dd520
0x1b39e8: bl #0x73ea5dd380
0x1b3a04: bl #0x73ea5dd6c0
0x1b3de8: bl #0x73ea5dd2a0
// crash前最後一處函數調用
0x1b29f0: bl #0x73ea800798
```

![image.png](image8.png)

嘗試trace `sub_251798()`，卻會在一處`br x28`執行後crash，輸出`x28`的值發現正是`0x97c`。

即`sub_251798()`相當於一個退出函數( 記為`br_to_0x97c()` )，真正的檢測函數應該在它前面。

![image.png](image9.png)

`br_to_0x97c()`前面的3個函數調用如下，它們都屬於`sub_1B2BF8()`。

```jsx
0x1b39e8: bl #0x73ea5dd380
0x1b3a04: bl #0x73ea5dd6c0
0x1b3de8: bl #0x73ea5dd2a0
```

hook `sub_1B2BF8()`，將retval替換為`0`( 原本是`1` )，結果不再閃退。

由此可以確定`sub_1B2BF8()`就是另一處的frida檢測函數。

```jsx
Interceptor.attach(base.add(0x1B2BF8), {
    onEnter: function (args) {
        console.log("[hook_test2] call")
    
    },
    onLeave: function (retval) {
        retval.replace(0)
        console.log("[hook_test2] retval: ", retval)
    }
})
```

看看它的檢測原理。

trace後發現一堆socket操作，它會嘗試與本地的`127.0.0.1:20000 ~ 127.0.0.1:<port_max>`發起socket連接。

![image.png](image10.png)

注：端口是通過`sockaddr.sa_data`來設置，如上圖的`connect()`的sa_data前4字節是`0x4e20`，即十進制的`20000`。

![image.png](image11.png)

每個端口對應2個`socket()`，當第1個socket_fd連接成功後，會對其發送`"\x00"`和`"AUTH\r\n"`，用於檢測舊版frida( D-Bus檢測 )。

![image.png](image12.png)

然後會連接第2個socket_fd，對其發送協議升級的請求，如果接收的內容包含`Sec-WebSocket-Accept`則代表成功檢測到frida。

注：frida15及之後開始引入WebSocket支援，因此上述檢測針對frida15及之後的版本。

![image.png](image13.png)

而由於我啟動frida-server習慣用`23940`端口，因此會被檢測到，換個小於20000的端口即可繞過。

```jsx
./frida-server -l 0.0.0.0:23940
```

## 2. 結語

該樣本沒有加固，只有一些fla和bcf混淆，整體算是比較簡單的樣本，但它的frida檢測思路還是挺有趣的。

最後祝各位讀者新年快樂！！！！！！！！！！！！！！！！