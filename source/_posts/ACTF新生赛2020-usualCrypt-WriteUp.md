---
title: ACTF新生赛2020-usualCrypt WriteUp
date: 2022-02-23 19:23:48
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - Buuctf
    - 逆向
    - ACTF新生赛2020
    - usualCrypt
    - WriteUp
description: buuctf的ACTF新生赛2020-usualCrypt的WriteUp
cover: hack.jpg
---

>題目：https://buuoj.cn/challenges#[ACTF%E6%96%B0%E7%94%9F%E8%B5%9B2020]usualCrypt

下載、解壓後，文件夾內有兩個檔案，直接把名為`base.exe`的那個拉入IDA進行分析( 另一個檔案不知有何作用 )。進入`main`函數查看偽代碼，經分析推測整體代碼邏輯為`接收輸入->加密->與特定字串對比->判斷正確與否`，進入加密函數`sub_401080`繼續分析
![1](1.jpg)
發現是base64加密，但在前面有個可疑的函數`sub_401000`，抱著好奇之心，先點進去看看
![2](2.jpg)
可以看出是將base64的索引表進行了魔改，`BASE64_table_40E0A0`為原索引表的起始地址，`byte_40E0AA`則是在起始地址+10byte的位置，而索引表進行的改動也就是簡單的位置亙換
![3](3.jpg)
返回`sub_401080`繼續分析，看到最後`return`時竟然是一個函數，點入去查看
![4](4.jpg)
第一眼看到簡直不知道是三小，但在分析過後，看到下圖紅框中的關鍵特徵，推測是將字母的大小寫亙換
![5](5.jpg)
最後，編寫如下腳本進行解密
```c++
#include<iostream>
#include<string>
using namespace std;

int main() {
	string realTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	string wrongTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	//取得魔改後的"假表"
	for (int i = 6; i < 15; i++) {
		char v1 = wrongTable[i + 10];
		wrongTable[i + 10] = wrongTable[i];
		wrongTable[i] = v1;
	}
	// 大小寫亙換
	string str = "zMXHz3TIgnxLxJhFAdtZn2fFk3lYCrtPC2l9";
	for (int i = 0; i < str.length(); i++) {
		if (str[i] >= 'a' && str[i] <= 'z') {
			str[i] = (char)(str[i] - 32);
		}
		else if (str[i] >= 'A' && str[i] <= 'Z') {
			str[i] = (char)(str[i] + 32);
		}
	}
	// 換表操作
	string decode = "";
	for (int i = 0; i < str.length(); i++) {
		decode += realTable[wrongTable.find(str[i])];
	}

	cout << decode << endl;  //將decode進行base64解密即可得出flag
}
```
將上面得出的`decode`進行base64解密即可得出flag( [解碼網站](http://www.hiencode.com/base64.html) )
![6](6.jpg)
`flag{bAse64_h2s_a_Surprise}`


