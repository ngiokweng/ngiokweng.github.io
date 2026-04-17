---
title: 【Unity+lua手遊逆向】道友掛機嗎
date: 2024-05-16 20:14:47
tags:
- Android逆向
- Lua逆向
- Unity逆向
categories: Android逆向
keywords:
- Android逆向
- Lua逆向
- Unity逆向
description: Unity+lua手遊逆向, 道友掛機嗎
cover: Untitled.png
---

## 分析

查看lib目錄，發現`libil2cpp.so`、`libunity.so`、`libtolua.so`，由此可以判斷是Unity + lua的組合。

第一步必然是要將`dump.cs`搞下來，以下兩種方式都可以：

1. [常規操作](https://www.notion.so/3e49320f79ad4faf80cfe69c749eef46?pvs=21) ( 這樣方式可以獲得更多信息 )
2. [frida-il2cpp-bridge](https://www.notion.so/frida-il2cpp-bridge-ecc993ed33374fc789b32886eb4ce5d3?pvs=21) ( 只能dump下來`dump.cs` )

![Untitled](Untitled.png)

配合`dump.cs`的信息嘗試trace `libil2cpp.so`的一些類和方法，但發現具體邏輯應該是調用lua腳本實現的。

嘗試尋找APK目錄下是否存在lua腳本，發現`/assests/lua`。

![Untitled](Untitled1.png)

在`assets`目錄下有一些`.assetbundle`文件，這些是Unity的一些資源打包成`assetbundle` ( 簡稱ab包 )的形式。

`.assetbundle`文件開頭是`"UnityFS"`標誌。 ( 後面會用到這點 )

![Untitled](Untitled2.png)

進入lua目錄，也有一堆`.assetbundle`文件，但是用010Editor來查看會發現與上述正常的`.assetbundle`文件完全不一致。

因此合理懷疑這些就是被加密打包後的lua腳本。

![Untitled](Untitled3.png)

![Untitled](Untitled4.png)

## 解密lua腳本

### 思路一：hook open

`lua.assetbundle`等加密打包後的lua腳本，在加載前必然需要解密，理論上也很大機率會調用如`open`函數來打開文件。

hook libc的`open`函數，保險起見兩個版本都要hook。

```jsx
function test() {
    let __open_2 = Module.getExportByName("libc.so", "__open_2");  // __open_2 是 Android NDK 提供的函數, .cpp裡會調用這個
    let open = Module.getExportByName("libc.so", "open"); // open是標準的C庫函數, .c裡會調用這個

    Interceptor.attach(open,
        {
            onEnter: function (args) {
                let fileName = args[0].readCString();
                if(fileName.indexOf("lua.assetbundle") != -1){
                    console.log("[open] ", fileName);
                    console.log('[open] called from:\n' +
        Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
                }
            },
            onLeave: function (retval) {
            }
        }
    );
    
    Interceptor.attach(__open_2,
        {
            onEnter: function (args) {
                let fileName = args[0].readCString();
                if(fileName.indexOf("lua.assetbundle") != -1){
                    console.log("[__open_2] ", fileName)
                }
            },
            onLeave: function (retval) {
            }
        }
    )
}

function main(){
    test()
}

setImmediate(main)

```

打印如下，的確是調用`open`來打開。

```jsx
[open]  /storage/emulated/0/Android/data/com.wycx.tw/files/tgame_android/lua/lua.assetbundle
[open] called from:
0x782aeeb2dc libil2cpp.so!0x14202dc
0x782aeeb2dc libil2cpp.so!0x14202dc
0x782aeffa14 libil2cpp.so!0x1434a14
0x782a759bd4 libil2cpp.so!0xc8ebd4
0x782a75a1c8 libil2cpp.so!0xc8f1c8
0x782a228e7c libil2cpp.so!0x75de7c
0x782a229aec libil2cpp.so!0x75eaec
0x782a21e7d4 libil2cpp.so!0x7537d4
0x782a21e65c libil2cpp.so!0x75365c
0x782a0d70a0 libil2cpp.so!0x60c0a0
0x782ade6528 libil2cpp.so!0x131b528
0x782a076378 libil2cpp.so!0x5ab378
0x782aee9738 libil2cpp.so!0x141e738
0x782e217d30 libunity.so!0x490d30
0x782e220888 libunity.so!0x499888
0x782e225ff0 libunity.so!0x49eff0
```

然後就是慢慢分析調用棧，最終會在`0x75de7c`那一層找到如下十分可疑的地方，

![Untitled](Untitled5.png)

hook驗證猜想，在`DDUtil__packXor`的leave時機打印

```jsx
let hasHook = false;
let savepath = "/sdcard/dumpLua"

function hook_dlopen(soName, callback) {
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
                if (this.is_can_hook && !hasHook) {
                    console.log("hook start...");
                    callback();
                    hasHook = true;
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
                if (this.is_can_hook && !hasHook) {
                    console.log("hook start...");
                    callback();
                    hasHook = true;
                }
            }
        }
    );
}

let fileIdx = 0;

function hook_DDUtil__packXor(){
    let baseAddr = Module.findBaseAddress("libil2cpp.so")
    console.log("base: ", baseAddr)

    // DDUtil__packXor
    Interceptor.attach(baseAddr.add(0x6224C0),{
        onEnter: function(args){
            this.args1 = args[1];
            this.size = args[2].toUInt32()

            
        },
        onLeave: function(retval){
            console.log("[DDUtil__packXor] args1: ", hexdump(this.args1));

        }
    })
    
}

function onIl2CppLoaded(){
    hook_DDUtil__packXor();

    console.log("hook success");
}

function main() {
    hook_dlopen("libil2cpp.so", onIl2CppLoaded)
}

setImmediate(main)
```

可以看到明顯的`.assetbundle`特徵。

![Untitled](Untitled6.png)

進一步驗證，先將解密後的`.assetbundle`文件dump下來

```jsx
// this.args1是System_Byte_array結構, Process.pointerSize * 4 取其items屬性
let buf = this.args1.add(Process.pointerSize * 4);

let path = savepath + '/' + fileIdx + '.assetbundle';
fileIdx++;
let dexFile = new File(path,"wb");

dexFile.write(Memory.readByteArray(buf, this.size));
dexFile.flush();
dexFile.close();

console.log("decode assetbundle ->", path);
```

注：像`System_Byte_array`這樣的結構，可以在`il2cpp.h`裡查看( 由`il2cppdumper` dump出來的 )

[il2cpp.rar](%E3%80%90Unity+lua%E9%80%86%E5%90%91%E3%80%91%E9%81%93%E5%8F%8B%E6%8E%9B%E6%A9%9F%E5%97%8E%20713636415f324da3ac3e4e14cd9834d1/il2cpp.rar)

查看結構後，就能手動計算出具體屬性的內存偏移，然後通過這樣的方式在內存中手動定位`this.args1.add(Process.pointerSize * 4)`

![Untitled](Untitled7.png)

![Untitled](Untitled8.png)

使用https://github.com/Perfare/AssetStudio 工具，將dump下來的文件拉入`AssertStudio`，在`Asset List`裡查看。

可以看到明文的Lua腳本，右鍵可以直接導出。

這樣就完全可以確定`DDUtil__packXor`就是解密函數

![Untitled](Untitled9.png)

分析`DDUtil__packXor`邏輯，其實就是簡單的異或解密。

hook `System_String__get_Chars`看具體異或值是什麼。

![Untitled](Untitled10.png)

```jsx
// 在 hook DDUtil__packXor的 onEnter裡進行如下hook
Interceptor.attach(baseAddr.add(0x9B39D0),{
    onEnter: function(args){

    },
    onLeave: function(retval){
        console.log("xor val: ", retval)
    }
})
```

發現是循環異或`[0x6b,0x6c,0x77,0x6b,0x6a]`這幾個值

如何確定哪個值是第一個？將dump下來的文件與原文件的第一個字節進行異或，會發現是`0x6b`

![Untitled](Untitled11.png)

解密腳本：

```python

import os

xorTable = [0x6b,0x6c,0x77,0x6b,0x6a]
def decrypt(fileName, outputPath):
    tidx = 0
    with open(fileName, mode="rb") as f:
        cipherBytes = f.read()
    
    plainBytes = b""
    for byte in cipherBytes:
        plainBytes = plainBytes + bytes([byte ^ xorTable[tidx%5]])
        tidx = tidx + 1

    with open(outputPath, mode="wb") as f:
        f.write(plainBytes)

    

if __name__ == "__main__":
    # decrypt("lua.assetbundle")

    targetDir = "./lua"
    outputDir = "./output"
    fileNames = os.listdir(targetDir)

    for fileName in fileNames:
        if not fileName.endswith(".assetbundle"):
            continue

        decrypt(f"{targetDir}/{fileName}", f"{outputDir}/{fileName}")
        print(f"{targetDir}/{fileName} 解密完成!!")
```

### 思路二：利用`stringliteral.json`

`stringliteral.json`這是`il2cppdumper`工具dump出來的，保存了所有字符串常量。

直接搜加密文件的文件名，就能直接定位到這個字符串出現的地址( offset )，從這裡開始分析可以更快找到解密函數。

![Untitled](Untitled12.png)

## 替換Lua腳本

### 方法一：不落地替換

思路：[https://gslab.qq.com/portal.php?mod=view&aid=173](https://gslab.qq.com/portal.php?mod=view&aid=173)

沿著lua引擎加載腳本的函數鏈進行分析，找到Lua腳本的加載時機，目標是在加載前實現替換。

**`luaL_loadbuffer`**是一個走得比較頻繁的點，嘗試在`il2cpp.so`裡找，果然發現了該函數。

![Untitled](Untitled13.png)

![Untitled](Untitled14.png)

以下是dump的腳本，在加載前將要被加載的`buff`保存下來，看看是否正常。

注：相關數據結構的偏移同上所述是在`il2cpp.h`裡查看的

```jsx
function getString(sPtr){
    let fields = sPtr.add(Process.pointerSize * 2);
    let start_char = fields.add(4).readUtf16String();

    return start_char;

}

let fileIdx = 0;
function dumpLua() {
    let baseAddr = Module.findBaseAddress("libil2cpp.so")

    // luaL_loadbuffer
    Interceptor.attach(baseAddr.add(0xD9DC4C),{
        onEnter(args){
            let max_length = args[2].add(Process.pointerSize * 3).readU32();
            let buf = args[2].add(Process.pointerSize * 4);
            let name = getString(args[4]);
            name = name.replaceAll('/','_')

            console.log(name)

            let path = savepath + '/' + name;
            fileIdx++;
            let dexFile = new File(path, "wb");

            dexFile.write(Memory.readByteArray(buf, max_length));
            dexFile.flush();
            dexFile.close();

            console.log("lua ->",path);
        },
        onLeave(retval){

        }
    })

}
```

dump出來的東西有2種，一是像如下這樣的數據：

![Untitled](Untitled15.png)

另一種是Lua腳本：

![Untitled](Untitled16.png)

如此一來便確定了是正常的( 即是明文，無需再解密 )。

替換lua的邏輯如下，參考了[這位大佬](https://floe-ice.cn/archives/674)的博客。

注：APP要有讀取`/sdcard`的權限

```jsx
function getReplaceData(path, origBuff){
    /**
    * struct Il2CppObject
    {
        Il2CppClass *klass;
        void *monitor;
    };

    struct System_Byte_array {
        Il2CppObject obj;
        Il2CppArrayBounds *bounds;
        il2cpp_array_size_t max_length;
        uint8_t m_Items[65535];
    };
    */
    var fopenPtr = Module.findExportByName("libc.so", "fopen");
    var fopen = new NativeFunction(fopenPtr, 'pointer', ['pointer', 'pointer']);
    var fclosePtr = Module.findExportByName("libc.so", "fclose");
    var fclose = new NativeFunction(fclosePtr, 'int', ['pointer']);
    var fseekPtr = Module.findExportByName("libc.so", "fseek");
    var fseek = new NativeFunction(fseekPtr, 'int', ['pointer', 'int', 'int']);
    var ftellPtr = Module.findExportByName("libc.so", "ftell");
    var ftell = new NativeFunction(ftellPtr, 'int', ['pointer']);
    var freadPtr = Module.findExportByName("libc.so", "fread");
    var fread = new NativeFunction(freadPtr, 'int', ['pointer', 'int', 'int', 'pointer']);

    let newLuaPath = Memory.allocUtf8String(path);

    let openMode = Memory.allocUtf8String('rb');
    let file = fopen(newLuaPath, openMode);
    if (file != null) {
		    // 獲取newBuffer的大小
        fseek(file, 0, 2);
        let newSize = ftell(file);
        // reset
        fseek(file, 0, 0);
        
        let newBuffer = Memory.alloc(newSize + 1 + Process.pointerSize * 4);
        // 先將原buff的前Process.pointerSize * 4字節copy到newBuffer ( 具體原因看System_Byte_array結構 ) 
        newBuffer.writeByteArray(origBuff.readByteArray(Process.pointerSize * 4))
        // 將我們修改後的lua腳本寫入newBuffer
        fread(newBuffer.add(Process.pointerSize * 4), newSize, 1, file);

        fclose(file);

        return {
            "buff": newBuffer,
            "size": newSize
        }

    }
    return null;
}

function hookLuaLoad() {
    let baseAddr = Module.findBaseAddress("libil2cpp.so")
    let sleep = new NativeFunction(Module.getExportByName(null, "sleep"), "void", ["int"]);

    let luaL_loadbuffer_addr = baseAddr.add(0xD9DC4C);
    let luaL_loadbuffer = new NativeFunction(luaL_loadbuffer_addr, "int", ["pointer", "int64", "pointer", "int", "pointer", "pointer"])

    Interceptor.replace(luaL_loadbuffer_addr, new NativeCallback(function(thiz, luaState, buff, size, name, method){
        
        let cName = getString(name);

        if(cName.indexOf("JingJieLevelDef") != -1){
            console.log(cName);
            let rData = getReplaceData('/sdcard/tmp/Table_JingJieLevelDef.lua', buff)
            buff = rData["buff"]
            size = rData["size"]

        }

        if(cName.indexOf("@UI/Main/MainPanel") != -1){
            console.log(cName);
            let rData = getReplaceData('/sdcard/tmp/@UI_Main_MainPanel', buff)
            buff = rData["buff"]
            size = rData["size"]

        }

        if(cName.indexOf("@UI/Main/DuJiePanel") != -1){
            console.log(cName);
            let rData = getReplaceData('/sdcard/tmp/@UI_Main_DuJiePanel', buff)
            buff = rData["buff"]
            size = rData["size"]

        }

        if(cName.indexOf("LunHuiPanel") != -1){
            console.log(cName);
            let rData = getReplaceData('/sdcard/tmp/@UI_LiLian_LunHuiPanel', buff)
            buff = rData["buff"]
            size = rData["size"]

        }

        if(cName.indexOf("PlayerLevelMgr") != -1){
            console.log(cName);
            let rData = getReplaceData('/sdcard/tmp/@UI_Manager_PlayerLevelMgr', buff)
            buff = rData["buff"]
            size = rData["size"]

        }
        
        if(cName.indexOf("Network") != -1){
            console.log(cName);
            let rData = getReplaceData('/sdcard/tmp/@Logic_Network', buff)
            buff = rData["buff"]
            size = rData["size"]

        }

        return luaL_loadbuffer(thiz, luaState, buff, size, name, method);

    }, "int", ["pointer", "int64", "pointer", "int", "pointer", "pointer"]))

}

```

能成功替換lua腳本後，嘗試修改遊戲的【渡劫】邏輯，目標是不需要消耗經驗就可以直接渡劫。

通過在dump出的lua腳本中不斷搜索相關的字符串，最終定位到以下lua函數，易知有網路請求( socket )，因此只在本地修改純粹是在搞笑…

![Untitled](Untitled17.png)

只能通過分析協議 & 攔截Socket通信的方式才可能實現修改，有機會再嘗試下……

![Untitled](Untitled18.png)

### 方法二：落地替換

參考這篇文章：[https://blog.csdn.net/linxinfa/article/details/122390621](https://blog.csdn.net/linxinfa/article/details/122390621)

利用**Unity Addressables**來將`lua`腳本打包成`.assetbundle`，然後加密打包後的`.assetbundle`文件，再重打包進AP裡。

結果最後會進不去遊戲的主界面，進度條卡死在外面…

注：lua腳本的後綴要是`.bytes`才能順利打包

## 參考/更多資料

frida-il2cpp-bridge：

- [https://www.bilibili.com/video/BV1Qz421o7uq/?vd_source=999a37555f77c5995df6185262c99be3](https://www.bilibili.com/video/BV1Qz421o7uq/?vd_source=999a37555f77c5995df6185262c99be3)
- [http://www.yxfzedu.com/article/7047](http://www.yxfzedu.com/article/7047)
- [https://www.bilibili.com/read/cv25789570/](https://www.bilibili.com/read/cv25789570/)
- [https://blog.csdn.net/Pisces50002/article/details/138419682](https://blog.csdn.net/Pisces50002/article/details/138419682)
- [https://wkr.moe/study/884.html](https://wkr.moe/study/884.html)
- **[记frida-il2cpp-bridge的使用](https://blog.csdn.net/weixin_44292683/article/details/132125663?spm=1001.2101.3001.6650.5&utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-5-132125663-blog-134367056.235%5Ev43%5Epc_blog_bottom_relevance_base5&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-5-132125663-blog-134367056.235%5Ev43%5Epc_blog_bottom_relevance_base5&utm_relevant_index=10)**
- [https://www.52pojie.cn/thread-1891741-1-1.html](https://www.52pojie.cn/thread-1891741-1-1.html)

lua：

- [https://bbs.kanxue.com/thread-257678.htm](https://bbs.kanxue.com/thread-257678.htm)
- [https://blog.csdn.net/s0201428/article/details/87882011](https://blog.csdn.net/s0201428/article/details/87882011)
- [https://bbs.kanxue.com/thread-216969.htm](https://bbs.kanxue.com/thread-216969.htm)
- [https://8biiit.github.io/2021/04/12/某三消游戏逆向/](https://8biiit.github.io/2021/04/12/%E6%9F%90%E4%B8%89%E6%B6%88%E6%B8%B8%E6%88%8F%E9%80%86%E5%90%91/)
- [https://bbs.kanxue.com/thread-266130.htm#msg_header_h2_2](https://bbs.kanxue.com/thread-266130.htm#msg_header_h2_2)
- [https://www.52pojie.cn/thread-1117641-1-1.html](https://www.52pojie.cn/thread-1117641-1-1.html)

assetbundle：

- [https://warl.top/posts/Unity-AssetBundle/](https://warl.top/posts/Unity-AssetBundle/)