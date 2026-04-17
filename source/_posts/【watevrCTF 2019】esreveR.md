---
title: 【watevrCTF 2019】esreveR WriteUp
date: 2022-08-18 23:19:48
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - Buuctf
    - 逆向
    - WriteUp
description: 【watevrCTF 2019】esreveR的WriteUp
cover: Untitled5.png
---

## 程序分析

- 程序後綴是`.com`，但不管直接拉入`ExeinfoPe`查殼
- 發現原來是64位的ELF文件，沒殼

![Untitled](Untitled.png)

- 拉入IDA分析，進入main函數，看到如下關鍵信息
- 經分析發現if語句應該為永真，即一定會進入( 可動態調試看看 )
- 在進入最後一個if之前，調用了`sub_55C1E23CB2D8`這個函數，雙擊進入查看

![Untitled](Untitled1.png)

- 發現當`sub_55C1E23CABA0`返回0時，程序就直接退出
- 所以為`sub_55C1E23CABA0`必須返回1
- 注：`xor_key4`、`key`等等的變量是我分析後重新命名而得來的

![Untitled](Untitled2.png)

![Untitled](Untitled3.png)

- 進入`sub_55C1E23CABA0`查看，結合函數傳入的參數，可以得知
    
    ```python
    input[0] = xor_key4 ^ 0xFFFFFFFF9A1391B5
    input[1] = xor_key4 ^ 0xFFFFFFFF9A1391A3
    #...
    ```
    

![Untitled](Untitled4.png)

## 動調獲取數據

- 現在只要動調獲取`xor_key1`、`xor_key2`、`xor_key3`、`xor_key4`、`key5`的值即可求得flag
- 簡單說一下方法：執行到`xor_key4`的下一句，將鼠標移到`xor_key4`的上方，看到的`0xFFFFFFFF9A1391C2`就是`xor_key4`的值。其他也如此類推

![Untitled](Untitled5.png)

## 腳本

( 我是手動一個一個拷貝上去，不知有無更快的方法= = )

```python
input = [0 for i in range(56)]
xor_key1 = 0x427D8616
xor_key2 = 0xFFFFFFFFC7F2682D
xor_key3 = 0x5CBFB3D5
xor_key4 = 0xFFFFFFFF9A1391C2
key5 = 0xC2

input[0] = xor_key4 ^ 0xFFFFFFFF9A1391B5
input[1] = xor_key4 ^ 0xFFFFFFFF9A1391A3
input[2] = xor_key4 ^ 0xFFFFFFFF9A1391B6
input[3] = xor_key4 ^ 0xFFFFFFFF9A1391A7      
input[4] = xor_key4 ^ 0xFFFFFFFF9A1391B4
input[5] = xor_key4 ^ 0xFFFFFFFF9A1391B0
input[6] = xor_key4 ^ 0xFFFFFFFF9A1391B9
input[7] = xor_key4 ^ 0xFFFFFFFF9A1391A7
input[8] = xor_key4 ^ 0xFFFFFFFF9A1391B1
input[9] = xor_key4 ^ 0xFFFFFFFF9A1391B0
input[10] = xor_key4 ^ 0xFFFFFFFF9A1391A7
input[11] = xor_key4 ^ 0xFFFFFFFF9A1391B4
input[12] = xor_key4 ^ 0xFFFFFFFF9A1391A7
input[13] = xor_key4 ^ 0xFFFFFFFF9A1391B0
input[14] = xor_key4 ^ 0xFFFFFFFF9A13919D
input[15] = xor_key4 ^ 0xFFFFFFFF9A1391B0
input[16] = xor_key4 ^ 0xFFFFFFFF9A1391A7
input[17] = xor_key4 ^ 0xFFFFFFFF9A1391B4
input[18] = xor_key4 ^ 0xFFFFFFFF9A1391A7
input[19] = xor_key4 ^ 0xFFFFFFFF9A1391B0
input[20] = xor_key3 ^ 0x5CBFB3A6
input[21] = xor_key3 ^ 0x5CBFB3B0
input[22] = xor_key3 ^ 0x5CBFB3B1
input[23] = xor_key3 ^ 0x5CBFB38A
input[24] = xor_key3 ^ 0x5CBFB3AC
input[25] = xor_key3 ^ 0x5CBFB3BA
input[26] = xor_key3 ^ 0x5CBFB3A0
input[27] = xor_key3 ^ 0x5CBFB3A1
input[28] = xor_key3 ^ 0x5CBFB3A0
input[29] = xor_key3 ^ 0x5CBFB3B7
input[30] = xor_key3 ^ 0x5CBFB3B0
input[31] = xor_key3 ^ 0x5CBFB3FB
input[32] = xor_key3 ^ 0x5CBFB3B6
input[33] = xor_key3 ^ 0x5CBFB3BA
input[34] = xor_key3 ^ 0x5CBFB3B8
input[35] = xor_key2 ^ 0xFFFFFFFFC7F26802
input[36] = xor_key2 ^ 0xFFFFFFFFC7F2685A
input[37] = xor_key2 ^ 0xFFFFFFFFC7F2684C
input[38] = xor_key2 ^ 0xFFFFFFFFC7F26859
input[39] = xor_key2 ^ 0xFFFFFFFFC7F2684E
input[40] = xor_key2 ^ 0xFFFFFFFFC7F26845
input[41] = xor_key2 ^ 0xFFFFFFFFC7F26812
input[42] = xor_key2 ^ 0xFFFFFFFFC7F2685B
input[43] = xor_key2 ^ 0xFFFFFFFFC7F26810
input[44] = xor_key2 ^ 0xFFFFFFFFC7F26864
input[45] = xor_key2 ^ 0xFFFFFFFFC7F26815
input[46] = xor_key2 ^ 0xFFFFFFFFC7F26844
input[47] = xor_key2 ^ 0xFFFFFFFFC7F26847
input[48] = xor_key2 ^ 0xFFFFFFFFC7F2684F
input[49] = xor_key2 ^ 0xFFFFFFFFC7F26819
input[50] = key5 ^ 0x98
input[51] = key5 ^ 0xA7
input[52] = xor_key1 ^ 0x427D8673
input[53] = xor_key1 ^ 0x427D8623
input[54] = xor_key1 ^ 0x427D8653
input[55] = xor_key1 ^ 0x427D866B

flag = ""
for c in input:
    flag+=chr(c)

print(flag) #watevr{esrever_reversed_youtube.com/watch?v=I8ijb4Zee5E}
```