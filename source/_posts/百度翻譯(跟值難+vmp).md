---
title: 某度翻譯逆向分析
date: 2023-09-03 22:11:23
tags: 
	- Web逆向
categories: Web逆向
keywords:
    - Web逆向
description: 某度翻譯逆向分析
cover: Untitled.png
---

> 目標網站：aHR0cHM6Ly9mYW55aS5iYWlkdS5jb20vI2VuL2NodC9oZWxsbw==
> 

## 請求參數跟值

- 下個XHR斷點，一步一步跟很容易可以來到這處
- 請求參數就是`this.paramData`
- 這時一個快捷的方法是先看看`this.constructor`，看`paramData`是否在構造函數裡就已經賦值

![Untitled](Untitled.png)

- 一看發現果然如此

![Untitled](Untitled1.png)

- 然後向上一層就能找到參數生成的地方
- 慢慢調試，會發現除了`sign`外，其他參數都能固定
- 生成`sign`的函數也很容易扣，用一般webpack的扣法就能搞出來

![Untitled](Untitled2.png)

## Acs-Token跟值

- 在上述跟值的過程中就能看到`Acs-Token`賦值的地方

![Untitled](Untitled3.png)

打個條件斷點跟到這裡，再往前就是異步

![Untitled](Untitled4.png)

![Untitled](Untitled5.png)

- 在異步的地方下斷點，測試後發現代碼會走2次這裡，若第2次時再按`F8`就會去到上一步條件斷點的位置
- 因此在第2次時按`F11`

![Untitled](Untitled6.png)

然後發現`n`是生成好的`Acs-Token`，代表我們又更前了一步

![Untitled](Untitled7.png)

繼續向前跟會發現`Acs-Token`在`n.gs`的回調函數中出現

![Untitled](Untitled8.png)

- 跟進`n.gs`，來到另一個名為`acs-2060.js?_=XXXX`的代碼中，而`n.gs`就會下圖紅框的這個函數
- 根據文件名其實就可以推測`Acs-Token`的值就是在這裡生成，而`n.gs`這個函數就可以作為生成Acs-Token的入口，最終結果會在回調函數的參數生傳入

![Untitled](Untitled9.png)

## Acs-Token生成

複製整份`acs-2060.js?_=XXXX`的代碼，放到補環境框架裡，在日志可以看到，它很貼心地幫我們將入口函數導出了，直接在全局就能使用

![Untitled](Untitled10.png)

- 調用方法如下，然後就是補補環境讓它能出值就可以了
- 經測試發現它對環境的校驗並不強，能出值基本上就能用了？( 或許吧

![Untitled](Untitled11.png)

附上一張請求成功的圖^^

![Untitled](Untitled12.png)