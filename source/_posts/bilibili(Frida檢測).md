---
title: bilibili(Frida檢測)
date: 2024-05-13 13:40:45
tags:
- Android逆向
- Frida檢測
categories: Android逆向
keywords:
- Android逆向
- Frida檢測
description: bilibili(Frida檢測)
cover: Untitled.png
---

> 注：本文使用了自編譯魔改的Frida！！！
> 

## 分析

通過hook `dlopen`，打印加載的so，發現到`libmsaoaidsec.so`後frida就閃退，由此可知`libmsaoaidsec.so`中有檢測frida的邏輯。

![Untitled](Untitled.png)

通常很多檢測frida的邏輯都會使用`fopen`函數打開`/proc/self/`中的文件( 如`/proc/self/maps` )，以此來尋找是否存在frida的特徵。

而fopen底層的系統調用號是`__NR_openat`，嘗試使用https://github.com/ngiokweng/Frida-Seccomp來監控該系統調用。

## Hook驗證猜想

在保存的log裡搜索`libmsaoaidsec.so`，目標是調用棧中出現`libmsaoaidsec.so`的那些。

第一個打開了：`/proc/15547/cmdline`

第二個打開了：`/proc/self/maps`

第一個大機率不是檢測點，而是其他某些操作？因為不論是在注入frida前後，它的內容都不會變。

而第二個則大機率是檢測點，通過hook來驗證下。

![Untitled](Untitled1.png)

![Untitled](Untitled2.png)

由於`0x18a34`是由`.init_proc`裡的函數調用的，因此不能直接hook，而是要先hook `.init_proc`，再hook `0x18a34`。

或者通過[方法二( 取巧 )：](https://www.notion.so/c995f7fa39ad4444880dcc4097085f18?pvs=21) 這種取巧的方式來hook `.init_proc`裡調用的函數。

```jsx
let flag = false;
function hook_libmsaoaidsec(offset){
    let baseAddr = Module.findBaseAddress("libmsaoaidsec.so")

    Interceptor.attach(baseAddr.add(0x18a34), {
        onEnter: function(){
            console.log("[0x18a34] call");
        },
        onLeave: function(){
            console.log("[0x18a34] leave")

        }
    })

}

function hook_constructor() {
    if (Process.pointerSize == 4) {
        var linker = Process.findModuleByName("linker");
    } else {
        var linker = Process.findModuleByName("linker64");
    }
 
    var addr_call_function =null;
    var addr_g_ld_debug_verbosity = null;
    var addr_async_safe_format_log = null;
    if (linker) {
        //console.log("found linker");
        var symbols = linker.enumerateSymbols();
        for (var i = 0; i < symbols.length; i++) {
            var name = symbols[i].name;
            if (name.indexOf("call_function") >= 0){
                addr_call_function = symbols[i].address;
               // console.log("call_function",JSON.stringify(symbols[i]));
            }
            else if(name.indexOf("g_ld_debug_verbosity") >=0){
                addr_g_ld_debug_verbosity = symbols[i].address;
 
                ptr(addr_g_ld_debug_verbosity).writeInt(2);
 
            } else if(name.indexOf("async_safe_format_log") >=0 && name.indexOf('va_list') < 0){
               // console.log("async_safe_format_log",JSON.stringify(symbols[i]));
                addr_async_safe_format_log = symbols[i].address;
 
            }
 
        }
    }
    if(addr_async_safe_format_log){
        Interceptor.attach(addr_async_safe_format_log,{
            onEnter: function(args){
                this.log_level  = args[0];
                this.tag = ptr(args[1]).readCString()
                this.fmt = ptr(args[2]).readCString()
                if(this.fmt.indexOf("c-tor") >= 0 && this.fmt.indexOf('Done') < 0){
                    this.function_type = ptr(args[3]).readCString(), // func_type
                    this.so_path = ptr(args[5]).readCString();
                    var strs = new Array(); //定义一数组
                    strs = this.so_path.split("/"); //字符分割
                    this.so_name = strs.pop();
                    this.func_offset  = ptr(args[4]).sub(Module.findBaseAddress(this.so_name))
                     console.log("func_type:", this.function_type,
                        '\nso_name:',this.so_name,
                        '\nso_path:',this.so_path,
                        '\nfunc_offset:',this.func_offset
                     );
                   // hook代码在这加
                   if(this.so_name == "libmsaoaidsec.so"){
                    hook_libmsaoaidsec(this.func_offset) // .init_proc
                   }
                }
            },
            onLeave: function(retval){
            }
        })
    }
 
 
}

```

會發現`0x18a34`只有call沒有leave

![Untitled](Untitled3.png)

在IDA中查看`0x18a34`如下，但沒有看明白具體檢測了maps的什麼…

![Untitled](Untitled4.png)

## Bypass方案

### 1、IO重定向maps

複製一份正常的maps保存到`/data/app/<pkg>`下

```bash
cp /proc/`pidof tv.danmaku.bili`/maps /data/app/tv.danmaku.bili-tk5wLG_ePdtCr4YILKNN1w==/bili_maps
```

hook替換成正常的maps

```jsx
var idx = 0;
function test(){
    let open = Module.getExportByName("libc.so", "open"); // open是標準的C庫函數, .c裡會調用這個

    Interceptor.attach(open,
        {
            onEnter: function (args) {
                let fileName = args[0].readCString();
                if(fileName.indexOf("/proc/self/maps") != -1){

                    if(idx == 1 || idx == 2){
                        Memory.protect(args[0], 4096, 'rwx');
                        Memory.writeUtf8String(args[0],"/data/app/tv.danmaku.bili-tk5wLG_ePdtCr4YILKNN1w==/bili_maps")
                        console.log("io 重定向....")
                        console.log("idx: " + idx)
                    }
                    idx++;
            
                }
            },
            onLeave: function (retval) {
            }
        }
    );
    
}

```

### 2、不加載`libmsaoaidsec.so`

來源：[http://www.yxfzedu.com/article/10603](http://www.yxfzedu.com/article/10603)

看來`libmsaoaidsec.so`裡都是檢測的邏輯，沒有包含業務代碼，因此不加載也不影響APP正常運行。

```jsx
function hook_dlopen_anti(soName = '') {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                if(path.indexOf('libmsaoaidsec.so') >= 0){
                    ptr(pathptr).writeUtf8String("");
                }
                console.log('path: ',path)
            }
        }
    });
}

```