---
title: 【HDCTF2019】Maze WriteUp
date: 2022-02-26 15:09:26
tags: 
	- Reverse
	- WriteUp
	- 花指令
categories: CTF
keywords:
    - CTF
    - Buuctf
    - 逆向
    - HDCTF2019
    - WriteUp
description: buuctf的HDCTF2019-Maze的WriteUp
cover: cover.jpg
---

>題目：https://buuoj.cn/challenges#[HDCTF2019]Maze
## 查殼和脫殼
先查殼，發現有殼，根據提示用`upx`脫殼
![1](1.jpg)
## 代碼逆向
### 分析花指令
- 脫殼後拉入IDA分析，發現`.text:0040102C`是一處無用的花指令，因為它的作用是跳到下一行(毫無意義，可以直接`nop`掉)。
- 而`.text:0040102E`處`call`指令後而跟住的`0EC85D78Bh`不是一個地址(因為對其雙擊之後沒有反應)，由此也可得知這段代碼受到了花指令的影響(部分代碼還有用處，不能直接`nop`掉)
![2](2.jpg)

### 去除花指令
1. 使用Keypatch插件，直接將`.text:0040102C`處patch為`nop`
    ![3](3.jpg)
2. 因為`.text:0040102E`處的部分代碼還有用處，不能直接`nop`掉，所以要先找出其中無用的部分。方法：在`.text:0040102E`處按`U`，將其重定義為一個一個的字節，之後就嘗試將第1個字節`0E8h`patch為`nop`( 若能重新生成為代碼就是成功。不能的話，就還原，然後將之後的每個字節都嘗試一遍 )，如下圖2所示即為成功
    ![4](4.jpg)
    ![5](5.jpg)
3. 最後選取所有紅色的部分，然後按`P`重新生成為函數，之後就可`F5`查看偽代碼
    ![6](6.jpg)

### 迷宮分析
1. 按`Shift+F12`查看字符串窗口，發現了一個十分像迷宮的字符串
   ![7](7.jpg)
2. 點進去，算了一下它的長度為70，推測是一個`10X7`的迷宮，將其整理好後如下圖2所示
   ![8](8.jpg)
   ![9](9.jpg)
3. 取得迷宮圖後，接著去main函數中分析迷宮的代碼邏輯。可以看出是以`wasd`控制上下左右的移動
   ![10](10.jpg)
4. 推測`+`為起點，`F`為終點，人腦走一次，得出`ssaaasaassdddw`
   ![11](11.jpg)
5. 嘗試提交`flag{ssaaasaassdddw}`，結果正確，

   

