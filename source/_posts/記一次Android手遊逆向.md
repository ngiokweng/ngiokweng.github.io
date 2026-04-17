---
title: 記一次Android手遊逆向
date: 2024-05-08 18:26:23
tags: 
	- Android逆向
categories: Android逆向
keywords:
    - Android逆向
description: Android逆向
cover: Untitled.png
---
## 前言

這是一款挺老的遊戲了，以前身邊很多人在玩所以我也玩了一會，在遇然得知網上有這遊戲的免費外掛後去嘗試了一下，感覺很爽，畢竟是一款半單機的遊戲，就算開掛也不太會影響別人。

在那之後有試過研究一下這外掛的原理，但當時可謂是0基礎，只能按別人影片裡的教學一步一操作地嘗試自己寫外掛，最後不出意外地失敗了。再之後又嘗試了幾次，同樣以失敗告終…

雖說一直失敗，但不得不說我對寫外掛一直都很感興趣，大學選了計算機專業很大部份原因也是因為對外掛感興趣吧。

今天總算是圓了這以前的遺憾了^^

## 前置操作

利用MT管理器的APK共存功能複製一個APK出來：安裝包提取→選擇APK→APK共存

![Untitled](Untitled.png)

**修改就只對新複製出來的那個APK進行修改，原APK不作任何修改，方便之後hook兩者來對比差異**

## 閃退分析

以前在修改這遊戲後發現會閃退，一直以為它有簽名校驗，但其實並沒有。

它真的會校驗的是`libmonsterstrike.so`這個so，如何發現的？當不進行任何修改直接重打包APK後，它不會閃退；而只要修改了`libmonsterstrike.so`任一地方後，APP會閃退，由此可知該APP會校驗`libmonsterstrike.so`有沒有被修改。

然後就要找是哪裡在檢測`libmonsterstrike.so`的完整性，通過hook `dlopen`打印加載的so路徑

```jsx
function hook_dlopen(soName, func) {
    Interceptor.attach(Module.findExportByName(null, "dlopen"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    console.log(path);
                }
            },
            onLeave: function (retval) {
            }
        }
    );
 
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    console.log(path);
                }
            },
            onLeave: function (retval) {
            }
        }
    );
}
```

會發現在加載`libmonsterstrike.so`後APP就會閃退，因此可知`libmonsterstrike.so`裡某個函數會檢測`libmonsterstrike.so`的完整性

![Untitled](Untitled1.png)

之後hook `syscall`，對比原版APP和修改了`libmonsterstrike.so`後的APP的`syscall`的區別，會發現修改版APP會比原版APP多調用了系統調用號為`220`的那個系統調用，打印其調用棧後會定位到`applicationDidFinishLaunching`這個函數

```jsx
let sysNumMaps = {}
function hook_syscall(){
    let syscall = Module.getExportByName(null, "syscall"); 

    Interceptor.attach(syscall,
        {
            onEnter: function (args) {
                if(args[0].toInt32() == 220){
                    this.print = true;
                    console.log('sys_num[220] called from:\n' +
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n') + '\n');
                }
                if(!sysNumMaps[args[0].toInt32()]){
                    sysNumMaps[args[0].toInt32()] = 1;
                    console.log("sysNumMaps: ", JSON.stringify(sysNumMaps));
                }

            },
            onLeave: function (retval) {
                if(this.print){
                    console.log("retval: ", retval);
                }
            }
        }
    );
}
```

從上述調用棧具體可以定位到`applicationDidFinishLaunching`裡的`getTimeOffset`，其實應該是`getTimeOffset`上面的`checkAllKeys`函數( `checkAllKeys`函數在下圖已被我patch掉，因此看不到 )

![Untitled](Untitled2.png)

嘗試將`checkAllKeys`用frida替換掉，看看還會不會閃退，`0x21BEA6C`是`checkAllKeys`的地址。結果是不會閃退，因此`checkAllKeys`就是那個萬惡的檢測函數，並且不包含任何業務邏輯，可以直接patch掉。

```jsx
function hook_dlopen(soName, func) {
    Interceptor.attach(Module.findExportByName(null, "dlopen"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    console.log(path);
                    if (path.indexOf(soName) >= 0) {
                        this.is_can_hook = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.is_can_hook) {
                    console.log("hook start...");
                    hook_func1(soName, func)
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
                    console.log(path);
                    if (path.indexOf(soName) >= 0) {
                        this.is_can_hook = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.is_can_hook) {
                    console.log("hook start...");
                    hook_func1(soName, func)
                }
            }
        }
    );
}

function hook_func1(soName, func) {
    var funcAddr;
    var base;
    if(typeof func == "string"){
        funcAddr = Module.findExportByName(soName, func);
    }else if(typeof func == "number"){
        base = Module.findBaseAddress(soName);
        funcAddr = base.add(func);
        
    }
    console.log("base: ", base)
    console.log("func addr: ", funcAddr)

    Interceptor.replace(funcAddr, new NativeCallback(function (a) {
        console.log("替換 checkAllKey")
         return 123;
    }, 'void', ['pointer']));

    // Interceptor.attach(funcAddr,{
    //     onEnter(args){
    //         console.log("有調用!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            
    //     },
    //     onLeave(retval){
    //         console.log("retval: ", retval)
    //     }
    // })

    console.log("hook done")
}

hook_dlopen("libmonsterstrike.so", 0x21BEA6C);

```

## 外掛功能實現

APP的主要功能在`libmonsterstrike.so`裡，並且它連符號都沒有去掉，因此可以通過搜尋關鍵字的方式來定位到相應的功能。先用frida hook來驗證，最後再修改匯編。

1. `TaskEnemy::addDamage`：加攻擊力

實際上是`TaskEnemy::addDamage`裡的`TaskActor::addDamage`，它的第2個參數可以理解成增加的傷害。

這裡的修改方式是將某處對X21的賦值改成`MOV X21, #0xFFFFFFFF`，因為`X21`會在`TaskActor::addDamage`調用前賦給`X1`，而`X1`是`TaskActor::addDamage`的第2個參數

![Untitled](Untitled3.png)

![Untitled](Untitled4.png)

1. `TaskCharBall::isStrikeAttackOk`：判斷是否有大技

修改：`W0`( `X0`的低32位 )代表返回值，因此直接將其置`1`然後返回。

注：修改後需要按`U`再按`P`來重新生成函數

![Untitled](Untitled5.png)