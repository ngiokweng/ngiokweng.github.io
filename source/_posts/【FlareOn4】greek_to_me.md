---
title: 【FlareOn4】greek_to_me WriteUp
date: 2022-08-15 14:17:48
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - Buuctf
    - 逆向
    - socket
    - WriteUp
description: 【FlareOn4】greek_to_me的WriteUp
cover: 1.png
---

## 靜態分析

習慣先查一下殼，沒殼

![Untitled](8.png)

拉入IDA分析，發現主要代碼在`sub_401008`，其中調用了`sub_401121`，進入查看

![Untitled](1.png)

發現是個socket，`buf`用來接收客戶端傳送過來的信息。返回`sub_401008`繼續分析

![Untitled](2.png)

- 紅框這裡取`buf[0]`對`0x40107C`處的代碼進行自解密，長度是121，可以發現`0x40107C`處的代碼正是綠框那部分，緊接著綠框後就是提示成功的信息。
- 這時可以嘗試開始解密，流程如下：
    1. 編寫腳本暴力破解`buf[0]`的值
    2. 動調代碼，查看綠框自解密後的代碼

![Untitled](3.png)

## 腳本編寫

### 提取數據

- 先獲取`0x40107C`到`0x40107C+121`的數據
- 方法：在IDA中按`G`跳到`0x40107C`，選中`0x40107C`到`0x40107C+121`的數據，按`shift+e`

![Untitled](4.png)

### 腳本代碼

```cpp
#include <iostream>
#include <Windows.h>
using namespace std;

#define HIBYTE(x)   (*((byte*)&(x)+1))

unsigned char arr[] =
{
  0x33, 0xE1, 0xC4, 0x99, 0x11, 0x06, 0x81, 0x16, 0xF0, 0x32,
  0x9F, 0xC4, 0x91, 0x17, 0x06, 0x81, 0x14, 0xF0, 0x06, 0x81,
  0x15, 0xF1, 0xC4, 0x91, 0x1A, 0x06, 0x81, 0x1B, 0xE2, 0x06,
  0x81, 0x18, 0xF2, 0x06, 0x81, 0x19, 0xF1, 0x06, 0x81, 0x1E,
  0xF0, 0xC4, 0x99, 0x1F, 0xC4, 0x91, 0x1C, 0x06, 0x81, 0x1D,
  0xE6, 0x06, 0x81, 0x62, 0xEF, 0x06, 0x81, 0x63, 0xF2, 0x06,
  0x81, 0x60, 0xE3, 0xC4, 0x99, 0x61, 0x06, 0x81, 0x66, 0xBC,
  0x06, 0x81, 0x67, 0xE6, 0x06, 0x81, 0x64, 0xE8, 0x06, 0x81,
  0x65, 0x9D, 0x06, 0x81, 0x6A, 0xF2, 0xC4, 0x99, 0x6B, 0x06,
  0x81, 0x68, 0xA9, 0x06, 0x81, 0x69, 0xEF, 0x06, 0x81, 0x6E,
  0xEE, 0x06, 0x81, 0x6F, 0xAE, 0x06, 0x81, 0x6C, 0xE3, 0x06,
  0x81, 0x6D, 0xEF, 0x06, 0x81, 0x72, 0xE9, 0x06, 0x81, 0x73,
  0x7C
};

__int16 __cdecl sub_4011E6(unsigned __int8* a1, unsigned int a2)
{
    unsigned int v2; // edx
    unsigned __int16 v3; // cx
    unsigned __int16 v5; // di
    int v6; // esi
    unsigned __int16 i; // [esp+0h] [ebp-4h]

    v2 = a2;
    v3 = 255;
    for (i = 255; v2; v3 = HIBYTE(v3) + (unsigned __int8)v3)
    {
        v5 = i;
        v6 = v2;
        if (v2 > 0x14)
            v6 = 20;
        v2 -= v6;
        do
        {
            v5 += *a1;
            v3 += v5;
            ++a1;
            --v6;
        } while (v6);
        i = HIBYTE(v5) + (unsigned __int8)v5;
    }
    return (HIBYTE(i) + (unsigned __int8)i) | ((v3 << 8) + (v3 & 0xFF00));
}

int main() {

    for (int i = 0; i < 256; i++) {
        unsigned char v2[121];
        memcpy(v2,arr,0x79);
        for (int j = 0; j < 0x79; j++) {
           v2[j]  = (i ^ v2[j]) + 0x22;
        }
        if ((unsigned __int16)sub_4011E6((unsigned __int8*)&v2, 0x79u) == 0xFB5E) {
            cout << i << endl;
            break;
        }
    }

 
}
```

最終得出結果是162，即`buf[0]`為162時才會走入提示成功的地方

## 動態調試

在此之前先寫一個socket客戶端，用來發送`buf[0]`，具體實現如下所示

```cpp
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <iostream>

// Need to link with Ws2_32.lib
#pragma comment(lib, "ws2_32.lib")

using namespace std;
int __cdecl main()
{

    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        printf("WSAStartup failed with error: %d\n", err);
        return 1;
    }

    //綁定到特定的運輸服務提供商
    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    //服務器信息
    sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(0x8AE);
    serveraddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    //連接到服務器
    connect(client, (sockaddr*)&serveraddr, sizeof(serveraddr));

    //發送數據
    char data[] = "1234";
    data[0] = 162;
    send(client, data, sizeof(data), 0);

    system("pause");
    WSACleanup();

}
```

將`greek_to_me.exe`拉入OD，在調用`0x401015`處下斷點( 通過對比可知OD與IDA中的地址一致，而`0x401015`的這個call在上方的分析中已知是啟動socket服務端 )，然後按`F9`再按`F8`

![Untitled](5.png)

之後執行socket客戶端傳入數據，然後`F8`直到`0x40107C`，可以看到一大堆`mov`指令，在數據窗口查看`[ebp-0x2B]`，然後再慢慢`F8`，即可看到flag

![Untitled](6.png)

![Untitled](7.png)