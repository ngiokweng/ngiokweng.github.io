---
title: 【CSAW CTF Qualification Round 2022】逆向---部分WriteUp
date: 2022-09-12 00:00:30
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - CASW
    - 逆向
    - WriteUp
description: CSAW CTF Qualification Round 2022 逆向部分WriteUp
cover: Untitled1.png
---

## Anya Gacha

### 分析

打開文件夾，發現是Unity遊戲

![Untitled](Untitled.png)

- 先打開遊戲看看是在干什麼
- 大概是一個抽卡遊戲，左上是金錢( 每次-10 )，按左下按鈕開始抽取

![Untitled](Untitled1.png)

- 逆Unity遊戲通常可直接找到它的`Assembly-CSharp.dll`文件( 在`\AnyaGacha_Data\Managed`目錄下 )，將其拉入`dnspy`進行分析( 32位 )
- 在開始時對一些數據進行了初始化，**這裡其中一個數據用了隨機數**

![Untitled](Untitled2.png)

- 找到按下【抽卡】按鈕所調用的函數
- 這裡首先判斷【金錢】是否>10，若是才能繼續
- 後面再對一些數據進行處理，然後調用`this.Upload()`

![Untitled](Untitled3.png)

- 進入`this.Upload()`，看到它是通過發送網路請求來驗證
- 但我看不懂要怎樣才能走到`this.succeed(text)`，而上面有提到一開始使用了隨機數來初始化數據，因此我猜測這可能與真的抽卡遊戲一樣，是概率問題
- 所以我的破解思路：不斷調用`this.Upload()`，直到成功為至

![Untitled](Untitled4.png)

### 暴力破解

在dnspy中，`右鍵`→`Edit Method`，修改`wish`函數

```csharp
public void wish()
	{
		int num = this.unmask_value(this.value);
		//...刪了一些代碼
		this.value = this.mask_value(num);
		this.counter = this.mySHA256.ComputeHash(this.counter);
		this.loading.SetActive(true);
		base.StartCoroutine(this.Upload());
	}
```

同樣方法修改`Upload`函數

```csharp
private IEnumerator Upload()
{
	WWWForm wwwform = new WWWForm();
	string str = Convert.ToBase64String(this.counter);
	wwwform.AddField("data", str);
	UnityWebRequest www = UnityWebRequest.Post(this.server, wwwform);
	Debug.Log("Posted: " + str);
	yield return www.SendWebRequest();
	if (www.result != UnityWebRequest.Result.Success)
	{
		this.wish(); //修改的地方
		Debug.Log(www.error);
	}
	else
	{
		this.loading.SetActive(false);
		string text = www.downloadHandler.text;
		if (text == "")
		{
			this.wish();  //修改的地方
			this.fail();
		}
		else
		{
			this.succeed(text);
		}
	}
	yield break;
}
```

`backfrom`這是按【返回鍵】後會調用的函數

```csharp
public void backfrom(GameObject g)
{
	g.SetActive(false);
	this.mainpage.SetActive(true);
	this.wish(); //修改的地方
}
```

- 然後保存，方法：`File→Save Module`
- 之後打開遊戲，按【make a wish】之後，狂按右上的【back】
- 理論上按下【make a wish】之後，慢慢等就會自動出flag，但不知為何出不了( 等得不夠久？ )，但只要按上述那樣改掉`backfrom`函數，**然後狂按【back】就很快會出flag**

![Untitled](Untitled5.png)

## Game

### 分析

題目描述如下圖所示：

![Untitled](Untitled6.png)

- 先拉入IDA，去`main`函數看看
- 看不出什麼，再繼續進入`level_gen()`

![Untitled](Untitled7.png)

- 要求用戶輸入1、2、3，分別對應左、中、右三條路
- 然後之後會調用`level_next`，繼續跟入去

![Untitled](Untitled8.png)

- 可以看出共有3個結果，分別是**【繼續3選1】**、**【到達某個出口】**、**【到達需要password的地方】**
- 在需要輸入password的地方輸入password後，會與`fnv_1a_32`函數的返回值進行對比，若一致就會輸出某些東西，推測與flag有關

![Untitled](Untitled9.png)

### 解題過程

記錄一下**當時在做題時**的一些**經歷**

1. 看到這樣類似走迷宮的題，本來打算先將【地圖】dump出來再分析，但試著試著突然想起題目給了個`nc rev.chal.csaw.io 5003`，代表他將數據放在了服務器上，若我在本地上直接動調會失去【地圖】數據( ~~然後我就放棄了~~ )
2. 不知道如何將服務器上的數據dump下來，之後我想了一想，**發現以我的水平，好像只能嘗試將【地圖】手動爆破出來**

**手動爆破的地圖如下圖所示：**

1. 最底下是**超始位置**，左、中、右3格對應1、2、3
2. 黃圈`P`代表要**輸入密碼**的地方( 上方**有橙色勾**的是不重複的地方，其他沒有**橙色勾**的黃圈`P`會與其中一個**有橙色勾**的地方重複 )
3. 綠色`w`是出口( 沒有什麼用 )
4. 普通白色圈代表繼續【3選1】
5. 黑色`x`代表死路

![Untitled](Untitled10.png)

- 現在要先找出所有密碼。去到驗證密碼的地方分析
- `v11`的大小是50字節，但`qmemcpy`卻只複製了`”cook”`4個字節，明顯有古怪
- 雙擊`”cook”`，發現其下還有東西，且正好可以**每10個字節1組，分成5組**
- 而由`fnv_1a_32(&v11[10 * v8]) == pass`也可以看出`fnv_1a_32`函數也是**每10個字節1組**進行處理

![Untitled](Untitled11.png)

![Untitled](Untitled12.png)

編寫腳本

```cpp
#include<iostream>
#include <Windows.h>
using namespace std;

__int64 __fastcall fnv_1a_32(unsigned __int8* a1)
{
	__int64 result; // rax
	int v2; // edx

	for (result = 2166136261LL; ; result = 16777619 * (v2 ^ (unsigned int)result))
	{
		v2 = *a1;
		if (!(BYTE)v2)
			break;
		++a1;
	}
	return result;
}

int main() {
	unsigned char aCook[] =
	{
	  0x63, 0x6F, 0x6F, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x66, 0x6C, 0x61, 0x77, 0x65, 0x64, 0x00, 0x00, 0x00, 0x00,
	  0x67, 0x72, 0x61, 0x76, 0x65, 0x6C, 0x00, 0x00, 0x00, 0x00,
	  0x6B, 0x69, 0x6E, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x76, 0x65, 0x00, 0x00
	};

	for (int i = 0; i < 50; i += 10) {
		cout << (fnv_1a_32(&aCook[i])) << endl;
	}
}
// 結果：
/*
4013828393
1118844294
3000956154
3658736598
1688072995
*/
```

由於不知道哪個密碼對應哪條路，因此只能逐一嘗試，**最終經過無數次的嘗試得出**：

1. `11`這條路徑的密碼是`4013828393`，輸出結果為：`flag{e@5+er_`
2. `1313`這條路徑的密碼是`3000956154`，輸出結果為：`p@yw@115_i5_`
3. `131221`這條路徑的密碼是`4013828393`，輸出結果為：`+he_dum6e5+_`
4. `1312221`這條路徑的密碼是`1688072995`，輸出結果為：`ide@_ever!!}`
5. `222`這條路徑的密碼是`1118844294`，輸出結果為：`e995_6ehind_`

將路徑**由小到大排列**得出flag為：`flag{e@5+er_e995_6ehind_p@yw@115_i5_+he_dum6e5+_ide@_ever!!}`