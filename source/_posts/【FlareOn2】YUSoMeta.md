---
title: 【FlareOn2】YUSoMeta WriteUp
date: 2022-08-28 21:18:30
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - Buuctf
    - 逆向
    - socket
    - WriteUp
description: 【FlareOn4】greek_to_me的WriteUp
cover: Untitled1.png
---

> 題目：[https://buuoj.cn/challenges#[FlareOn2]YUSoMeta](https://buuoj.cn/challenges#%5BFlareOn2%5DYUSoMeta)
> 

## 查殼

使用`ExeinfoPe`查殼，發現是.net程序加了混淆，嘗試使用提示的`.NET Generic unpacker`的工具去除混淆，發現不行

![Untitled](Untitled.png)

拉入`DIE`，發現其所使用的混淆名為Smart Assembly，可使用`de4dot`工具來去除

![Untitled](Untitled1.png)

## 使用`de4dot`去除混淆

- 下載地址：https://github.com/de4dot/de4dot
- 打開`de4dot.netframework.sln`，按如下設置，然後按生成

![Untitled](Untitled2.png)

- 進入`\Release\net45`，可以看到`de4dot.exe`
- 使用指令`de4dot.exe -d [path]`來**查看用了哪種混淆**，確定了果真是SmartAssembly

![Untitled](Untitled3.png)

- 使用指令`de4dot.exe [path] -p sa`來**去除SmartAssembly混淆**，反混淆後的檔案放在了原exe的目錄
- **選項說明`-p sa`：指定混淆類型，sa代表SmartAssembly**

![Untitled](Untitled4.png)

## 代碼分析

- 將反混淆後的程序拉入`dnSpy`進行分析
- 找到如下的關鍵地方，發現只要`test == b`時就能得到flag，易知`test`是用戶輸入，而`b`的生成又與`text`無關，因此直接動調獲取`b`的值

![Untitled](Untitled5.png)

- 得出`b = \u001DL{a\0^o\u0017[nm\u001DEn\u0017@|h\u0015^d_5C047EAE20B8A616D34B9BE06D342C54`，輸入後發現不對
- 猜測可能是因為反混淆的過程中，某些地方修復錯誤所導致，因此這時嘗試打開原文件，找到相同的地方，重新獲取一次數據

![Untitled](Untitled6.png)

取得的數據為`metaprogrammingisherd_DD9BE1704C690FB422F1509A46ABC988`

![Untitled](Untitled7.png)

輸入後，果真得到flag

![Untitled](Untitled8.png)

## 資料參考

- ****[de4dot 反混淆工具使用](https://blog.csdn.net/u012278016/article/details/104659622)****
- ****[BUUCTF [FlareOn2]YUSoMeta](https://blog.csdn.net/weixin_53349587/article/details/122310993)****