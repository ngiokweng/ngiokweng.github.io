---
title: 【FlareOn1】Bob Doge WriteUp
date: 2022-04-10 20:17:53
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - Buuctf
    - 逆向
    - FlareOn1
    - WriteUp
    - buuctf
description: buuctf的[FlareOn1]Bob Doge 的WriteUp
cover: 3.png
---
解壓後有個`C1.exe`，但這並不是我們要分析的程序，雙擊`C1.exe`後安裝的那個`Challenge1.exe`才是要分析的程序。將其拉入`ExeinfoPe`，發現是個C#程序
![圖](1.png)
打開`Challenge1.exe`，發現只有一個Decode按鈕可按，按了之後彈出不明的東西
![圖](2.png)
![圖](3.png)
將程序拉入C#反編譯神器`dnSpy`繼續分析，找到Decode按鈕對應的代碼
![圖](4.png)
可以看出它對某數據進行了3次加密，然後展示出來，抱著好奇之心，在第一次加密完的位置打個斷點，查看其數據
![圖](5.png)
![圖](6.png)
看上去有點像flag，嘗試提交，結果成功了( 逆向果然是七分逆、三分猜 \^\.\^ )
