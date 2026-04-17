---
title: 【CTF】一道簡單的花指令
date: 2022-02-26 20:01:48
tags: 
	- Reverse
	- WriteUp
	- 花指令
categories: CTF
keywords:
    - CTF
    - 逆向
    - WriteUp
description: 一道簡單的花指令WriteUp
cover: 2.jpg
---
>題目：[點我下載](junk.zip)
## 花指令分析
紅框中的兩條代碼使程序經過時必然會跳到`loc_401034`的下一行，所以由此可知`loc_401034`處是一條無用的花指令

## 去除花指令
使用IDA的`Keypatch`插件將`loc_401034`處patch為`nop`

### 錯誤做法
像下圖一樣選取多行(雖然左邊地址都相同)進行patch會出現問題
![2](2.jpg)

### 正確做法
只選一行或直接對著`loc_401034`，然後按`Ctrl+Alt+K`(Keypatch快捷鍵)
![3](3.jpg)

- 之後在`.text:00401085`會看到與上面一模一樣的情況，以同樣手法去除花指令即可。
- 然後選取需要的區域，按`p`重新生成函數，即可`F5`查看偽代碼
- 並可直接在偽代碼中得出flag為`Kap0k{junkC0de_1s_w0derfuuuul!}`