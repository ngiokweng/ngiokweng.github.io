---
title: 【Zer0pts2020】easy strcmp
date: 2022-03-06 10:23:10
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - Buuctf
    - 逆向
    - Zer0pts2020
    - WriteUp
description: buuctf的Zer0pts2020-easy strcmp的WriteUp
cover: 3.jpg
---

## 查殼
慣例查一下，發現沒有殼
![1](1.jpg)

## 代碼分析
拉入IDA，進入`main`函數，看到是字符串的對比，而`a2[1]`是用戶輸入的字符串。通常會先將用戶輸入的字符串進行加密後，再作對比，所以先尋找加密函數
![2](2.jpg)
找到後，可以看出它是將用戶輸入的字符串每8個分成一組，然後與`qword_201060[j]`( j = 0~4 )相減
![3](3.jpg)

## 腳本解密
分析完之後就可編寫腳本進行解密。**注：字符串以小端模式存放在內存中，例如字符串`ABC`在內存中的存放順序為`43 42 41`，`41`對應`A`、`42`對應`B`、`43`對應`C`**
```c++
#include <iostream>
using namespace std;

int main() {
	long long qword_201060[5] = { 0,0x410A4335494A0942, 0x0B0EF2F50BE619F0, 0x4F0A3A064A35282B,0 };

	int i; // [rsp+18h] [rbp-8h]
	int v4; // [rsp+18h] [rbp-8h]
	int j; // [rsp+1Ch] [rbp-4h]
	char* str = "zer0pts{********CENSORED********}";
	i = strlen(str);
	v4 = (i >> 3) + 1;

	for (j = 0; j < v4; ++j) {
		long long a = *(long long*)(8 * j + str) + qword_201060[j];
		long long mask = 0xFF;
		for (int i = 0; i < 8; i++) {
			cout << (char)(a & mask);
			a >>= 8;
		}
		
	}

}
```
最後解出flag為->`zer0pts{l3ts_m4k3_4_DETOUR_t0d4y}`




