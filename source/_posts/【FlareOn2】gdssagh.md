---
title: 【FlareOn2】gdssagh
date: 2022-12-6 22:18:55
tags: 
        - Reverse
        - WriteUp
categories: CTF
keywords:
    - CTF
    - buuctf
    - 逆向
    - WriteUp
    - Reverse
    - FlareOn2
description: 【FlareOn2】gdssagh的wp
cover: Untitled1.png
---
## 分析

- 拉入IDA，發現只打印了一句話，然後就退出了
- 但在其下方發現一大堆沒分析出來的數據，**嘗試轉為代碼，但轉完後無從下手**
- **然後再嘗試轉為數據**，發現一大堆可見字符，**且很像Base64**
- **嘗試取開頭的一小段進行Base64解密**，結果如下，由此可知這些base64字符串**其實是一張圖片**

![Untitled](Untitled.png)

- 使用[CTF-Tools工具](https://github.com/qianxiao996/CTF-Tools)，將base64轉換為圖片
- 工具**操作**：先將base64字符複制到Source中，然後`常見編碼`→`圖片轉換`→`base64->圖片`
- 然後得到下面這張圖片，看不出什麼東西，極有可能是有一些隱寫操作

![Untitled](Untitled1.png)

## `zsteg`的安裝及使用

- 參考[這篇文章](https://www.tophertimzen.com/blog/flareOn/)，**發現是[zsteg](https://github.com/zed-0xff/zsteg)的隱寫**
- 在Ubuntu安裝zsteg的方法：
    1. `sudo apt-get install rubygems`
    2. `gem install zsteg`
- 使用指令`zsteg what.jpg` 來查看`what.jpg`所隱藏的所有東西，**然後檢測到嵌入的PE32可執行文件，如下圖所示**，記下`b1,rgb,msb,xy`這串東西

![Untitled](Untitled2.png)

- 使用指令`zsteg -E b1,rgb,msb,xy what.jpg > hide.exe` 來提取上述的PE文件，並重定向到`hide.exe`中
- 使用`strings hide.exe | grep flare`來查找`hide.exe`中包含`flare`的字符串，然後就得到flag了

![Untitled](Untitled3.png)