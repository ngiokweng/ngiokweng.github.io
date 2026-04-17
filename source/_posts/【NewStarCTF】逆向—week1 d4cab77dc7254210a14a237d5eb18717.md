---
title: 【NewStarCTF】逆向—week1
date: 2022-09-25 21:08:30
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - NewStarCTF
    - 逆向
    - WriteUp
description: NewStarCTF 逆向部分 第一周的WriteUp
cover: Untitled1.png
---

> 面向22級新生的題，難度友好，十分適合我這種菜G (￣▽￣)/
> 

## Hello_Reverse

在main函數找到flag的一部分，然後按`shift+f12`找到另一部分

![Untitled](Untitled.png)

![Untitled](Untitled1.png)

## Baby_Re

### 解法1

先對用戶輸入進行異或加密，然後調用`compare(s)`函數進行比較

![Untitled](Untitled2.png)

進入`compare`函數，發現只是一個直接比較

![Untitled](Untitled3.png)

雙擊`final`可以看到密文，但其中4個字節的數據被交叉引用過，疑似被修改過，按`x`跟過去看看

![Untitled](Untitled4.png)

發現它們被以下函數修改，而`FunctionName`這函數的調用時機在`main`之前

![Untitled](Untitled5.png)

IDA導出數據的技巧：選中所需數據，按`shift+e`

![Untitled](Untitled6.png)

編寫腳本解flag

```cpp
#include<iostream>
using namespace std;

int main() {
	unsigned char final[] =
	{
	  0x66, 0x6D, 0x63, 0x64, 0x7F, 0x56, 54, 0x6A, 0x6D, 0x7D,
	  0x62, 58, 0x62, 0x6A, 0x51, 0x7D, 0x65, 0x7F, 0x4D, 0x71,
	  0x71, 0x73, 38, 0x65, 0x7D, 0x46, 0x77, 0x7A, 0x75, 0x73,
	  63, 0x62
	};
	for (int i = 0; i < 32; i++) {
		cout << (char)(final[i] ^ i);
	}
  
}
```

### 解法2(懶人法)

使用`angr`讓它自己跑出來

```python
import angr
import sys

def is_good(state):
    return b'Well done! You find the secret!' in state.posix.dumps(1)  # state.posix.dumps(1)代表輸出，若輸出中包含'Well done! You find the secret!'即代表是我的目的地

def is_bad(state):
    return b'The flag is wrong! Maybe something run before main' in state.posix.dumps(1)  # state.posix.dumps(1)代表輸出，若輸出中包含'The flag is wrong! Maybe something run before main'即代表要避開的地方

def main(argv):
    bin_path = argv[1] # argv[1]是調用.py文件時傳入的參數，即【python3 mySolve.py xxx】中的xxx
    p = angr.Project(bin_path)

    init_state = p.factory.entry_state()
    sm = p.factory.simulation_manager(init_state,veritesting = True)
    sm.explore(find = is_good, avoid = is_bad) #除了傳入地址外，也能以這種方式來判斷

    if sm.found: #當sm.found不為空時
        found_state = sm.found[0]
        print("Solution: {}".format(found_state.posix.dumps(0)))

if __name__ == "__main__":
    main(sys.argv)
```

![Untitled](Untitled7.png)

## EasyRe

將`easyre.exe`拉入IDA，發現加密函數在`enc.dll`中

![Untitled](Untitled8.png)

- 將`enc.dll`拉入IDA，並找到`encode_0`函數
- 可以看到base64加密的特徵，然後返回了`sub_18001132A(a2)`，進入該函數查看

![Untitled](Untitled9.png)

是個異或加密

![Untitled](Untitled10.png)

所以該題的**加密流程**如下，只要逆向解密就能得到flag：

1. base64加密
2. 異或加密

先解密【異或加密】那部分，腳本如下：

```cpp
#include <iostream>
#include <string>
using namespace std;

int main() {
    string str = "Reverse";
    char final[100];
    memset(final, 0, sizeof(final));
    memset(final, 8, 2);
    final[2] = 14;
    final[3] = 13;
    final[4] = 40;
    final[5] = 64;
    final[6] = 17;
    final[7] = 17;
    final[8] = 60;
    final[9] = 46;
    final[10] = 43;
    final[11] = 30;
    final[12] = 61;
    final[13] = 15;
    final[15] = 3;
    final[16] = 59;
    final[17] = 61;
    final[18] = 60;
    final[19] = 21;
    final[20] = 40;
    final[21] = 5;
    final[22] = 80;
    final[23] = 70;
    final[24] = 63;
    final[25] = 42;
    final[26] = 57;
    final[27] = 9;
    final[28] = 49;
    final[29] = 86;
    final[30] = 0x24;
    final[31] = 0x1C;
    strncpy(&final[32], "?$P<,%#K", 8);
    for (int i = 0; i <40; ++i) {

        final[i] ^= str[i % str.length()];
    }
    cout << final << endl;
}
```

將上方得到的字串進行**base64解密**，即可得到**flag**( 網站：[http://www.hiencode.com/base64.html](http://www.hiencode.com/base64.html) )

![Untitled](Untitled11.png)

## Pyre

- 看到是python程序，直接逆向比較難，通常要將`.exe`→`.py`，詳細做法可參考[這篇文章](https://bbs.pediy.com/thread-264287.htm#msg_header_h2_1)
- 在這簡單地說說大致做法：
    1. 使用[pyinstxtractor.py](https://github.com/extremecoders-re/pyinstxtractor)將`.exe`→`.pyc`
    2. `.pyc`文件修復，( 下圖是修復好的版本 )
        
        ![Untitled](Untitled12.png)
        
    3. 將`.pyc`→`.py`，( [線上工具](https://tool.lu/pyc/) )

然後可以在.py文件中看到加密邏輯，直接寫腳本解flag即可

```python
str = 'REla{PSF!!fg}!Y_SN_1_0U'
flag = 23*[0]
table = [7, 8, 1, 2, 4, 5, 13, 16, 20, 21, 0, 3, 22, 19, 6, 12, 11, 18, 9, 10, 15, 14, 17]

for i in range(23):
    flag[table[i]] = str[i]

for i in range(23):
    print(flag[i],end="")
```

## 艾克体悟题

apk逆向，在模擬器打開後提示如下信息，不知道什麼意思，拉入`jadx`( apk逆向工具 )繼續分析

![Untitled](Untitled13.png)

看到flag在另一個Activity中，結合上圖可知，需要讓apk啟動`FlagActivity`( 默認是啟動`MainActivity` )，要實現這個動作需要用到`adb`

![Untitled](Untitled14.png)

可參考以下文章來連接`adb` ( **target：雷電模擬器** )

1. ****[【雷神命令】常用adb命令整理贴](https://www.ldmnq.com/forum/32.html)****
2. ****[adb 出现 adb.exe: more than one device/emulator 解决方法](https://blog.csdn.net/weixin_64094652/article/details/126032471)****

**連接adb後**，輸入`adb.exe shell am start -D -n com.droidlearn.activity_travel/.FlagActivity`，即可進入`FlagActivity`

![Untitled](Untitled15.png)

使用模擬器的自動點擊功能點擊10000次後就可得到flag

![flag.png](flag.png)