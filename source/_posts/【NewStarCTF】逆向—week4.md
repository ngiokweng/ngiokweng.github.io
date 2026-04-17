---
title: 【NewStarCTF】逆向—week4
date: 2022-10-19 11:06:01
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - NewStarCTF
    - 逆向
    - WriteUp
    - Reverse
    - week4
description: NewStarCTF 逆向部分 第4周的WriteUp
cover: Untitled1.png
---

> 太難啦 兩題沒做出來
> 

## Hash

拉入IDA，找到加密函數

![Untitled](Untitled.png)

通過查詢各個API，得知是個**sha加密**，再根據傳入的參數可知**每次加密3個字符，結果存放在`v10`中，長度為20**

![Untitled](Untitled1.png)

由於不太會python，所以只能用C++來寫爆破腳本( 正常用python來寫的話會簡單很多 )

```cpp
#include <iostream>
#include <string>
#include <Windows.h>
using namespace std;

int __cdecl enc(BYTE* pbData, DWORD dwDataLen, BYTE* a3, DWORD* a4)
{
    char v5; // al
    char LastError; // al
    int pdwDataLen[3]; // [esp+D0h] [ebp-44h] BYREF
    BYTE v8[4]; // [esp+DCh] [ebp-38h] BYREF
    int phHash[3]; // [esp+E8h] [ebp-2Ch] BYREF
    int phProv[3]; // [esp+F4h] [ebp-20h] BYREF
    int v11; // [esp+100h] [ebp-14h]
    int v12; // [esp+10Ch] [ebp-8h]

    v12 = 0;
    v11 = 0;
    phProv[0] = 0;
    phHash[0] = 0;
    *(DWORD*)v8 = 0;
    if (!CryptAcquireContextW((HCRYPTPROV*)phProv, 0, 0, 1u, 0xF0000000))
        return 0;
    if (!CryptCreateHash(phProv[0], 0x8004u, 0, 0, (HCRYPTHASH*)phHash))// 0x8004 = CALG_SHA
        CryptReleaseContext(phProv[0], 0);
    if (!CryptHashData(phHash[0], pbData, dwDataLen, 0))
    {
        CryptDestroyHash(phHash[0]);
        CryptReleaseContext(phProv[0], 0);
    }
    pdwDataLen[0] = 4;
    // 功能：檢索參2所指定的東西，放在參3
    // 參2：4代表HP_HASHSIZE(哈希值大小)
    // 參3：存放位置
    if (CryptGetHashParam(phHash[0], 4u, v8, (DWORD*)pdwDataLen, 0))// 檢索控制散列對像操作的數據。可以使用此函數檢索實際的哈希值。
    {
        if (*a4 >= *(DWORD*)v8)
        {
            // 功能：檢索參2所指定的東西，放在參3
            // 參2：2代表HP_HASHVAL(哈希值)
            // 參3：存放位置
            if (CryptGetHashParam(phHash[0], 2u, a3, a4, 0))
            {
                v11 = 1;
            }
            else
            {
                LastError = GetLastError();
                printf("\nCryptGetHashParam failed,  Error=0x%.8x", LastError);
            }
        }
        else
        {
            printf("\nOutput buffer (%d) is not sufficient, Required Size = %d", *a4);
        }
    }
    else
    {
        v5 = GetLastError();
        printf("\nCryptGetHashParam failed, Error=0x%.8x", v5);
    }
    if (phHash[0])
        CryptDestroyHash(phHash[0]);
    if (phProv[0])
        CryptReleaseContext(phProv[0], 0);
    return v11;
}

int main() {
    string table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/!@#$%^&*(){}";
    int size = table.size();
    int v9[3];
    v9[0] = 50;
    unsigned char v10[264];

    unsigned char byte_2BA000[1176] =
    {
      '\xA2',
      '\xF1',
      '~',
      '\xD1',
      '\xC6',
      '\xA8',
      '\xBC',
      '1',
      'v',
      '\x9C',
      '\xDF',
      'e',
      'M',
      '\xF4',
      '\xB8',
      '\xA9',
      '7',
      '\x04',
      ',',
      '\xB6',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\f',
      '\xA8',
      '\xA2',
      '\xED',
      '\xB0',
      '\xC1',
      '\xD3',
      'J',
      'C',
      '*',
      'Z',
      'D',
      'd',
      '\xE0',
      '\xD6',
      '\xAB',
      '\xD8',
      'G',
      '\xC8',
      '1',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\xC3',
      'Y',
      '\xD6',
      '\x9F',
      '?',
      '\b',
      '\xBB',
      '\x92',
      '\x0F',
      ',',
      ';',
      'Q',
      '\x13',
      '2',
      '\x05',
      'S',
      '4',
      'b',
      '\t',
      '>',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\xCC',
      '\\',
      '?',
      '\xE6',
      '\xE7',
      '5',
      'j',
      '&',
      '\xA1',
      '4',
      '\xCF',
      '\xF5',
      'c',
      '3',
      'I',
      '\xF5',
      '\x97',
      '\xC4',
      '\n',
      '\x9D',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      'J',
      '\xC4',
      '\xBB',
      '?',
      '\'',
      '\xF2',
      'E',
      '\xBA',
      '\x91',
      'x',
      'e',
      '\x1A',
      '\xA5',
      '\xCD',
      '\xED',
      '\xCB',
      '\xB2',
      '\x86',
      '.',
      '*',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\xA0',
      '\x1E',
      '3',
      '\xF4',
      '\xDC',
      '\xDB',
      'k',
      '\xA1',
      '\xAE',
      '\x9F',
      '4',
      '\xA9',
      '|',
      '\xF8',
      '\xF6',
      '\xDE',
      '\xEE',
      '\xDF',
      '\x1A',
      '\x8D',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\xD3',
      '\xAF',
      'p',
      '\x91',
      '*',
      '\x8C',
      '\x1B',
      '\"',
      '\xCF',
      '\xDE',
      '\xCE',
      '\a',
      '\x1B',
      '\xA3',
      'k',
      '\xC4',
      'f',
      '+',
      'X',
      '\xFA',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\x93',
      '\x95',
      '\xEA',
      '\xB1',
      '\x95',
      '\xD2',
      '[',
      'g',
      'm',
      '}',
      '\a',
      '\a',
      ']',
      '8',
      '8',
      '\xA9',
      '\xAC',
      '\x19',
      '\xDF',
      '!',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\xFD',
      '\xB4',
      '<',
      '^',
      '\xF7',
      'n',
      '\xCD',
      '\xA0',
      '\xC1',
      'f',
      '\x1D',
      'm',
      '\x19',
      '\x9B',
      '[',
      '\xFA',
      '\xC1',
      '\xDB',
      'S',
      '\x8A',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\xDA',
      '\x8E',
      '\x99',
      '\x97',
      '\xA0',
      '\x10',
      '\xBE',
      'x',
      '\xB2',
      '\x01',
      '\b',
      '\xCE',
      'y',
      '\xFE',
      '\xC1',
      '\xFB',
      '\x9C',
      'c',
      '\xD8',
      '\xDC',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\x80',
      '\x9D',
      '\xA6',
      '\'',
      '\xF1',
      '\xAD',
      '\x01',
      '\xD6',
      'X',
      'd',
      '\xC3',
      'v',
      '\xE3',
      '\x17',
      '\x9B',
      'b',
      '\xD9',
      '\xD7',
      'B',
      'a',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\x8F',
      'a',
      '\xEE',
      '!',
      '\xAC',
      'u',
      'y',
      'b',
      'i',
      '4',
      '\xE0',
      '\xFF',
      '\xB6',
      '\xA6',
      '+',
      '=',
      'J',
      '\x82',
      '\xEE',
      '\xC4',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\xE2',
      '\xA9',
      'T',
      'u',
      '\x8F',
      '\xDB',
      'a',
      '\xF8',
      'i',
      '\x99',
      '\x8E',
      '\x97',
      '\x88',
      '\xB7',
      '\xB7',
      '\xE4',
      '\x84',
      '\x80',
      '\xB8',
      '2',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\xB8',
      '\xE3',
      '4',
      '\x9B',
      '\x97',
      'S',
      '+',
      '\'',
      '\xAA',
      'b',
      '\xB8',
      'q',
      '\x8B',
      'h',
      '$',
      '\x01',
      'y',
      '\x15',
      '\x81',
      'D',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0',
      '\0'
    };

    for (int a = 0; a < 14; a++) {
        bool flag = true;
        for (int i1 = 0; i1 < size && flag; i1++) {
            for (int i2 = 0; i2 < size && flag; i2++) {
                for (int i3 = 0; i3 < size && flag; i3++) {
                    char tmp[4] = { 0 };
                    tmp[0] = table[i1];
                    tmp[1] = table[i2];
                    tmp[2] = table[i3];

                    bool flag2 = true;
                    enc((BYTE*)tmp, 3, (BYTE*)v10, (DWORD*)v9);
                    for (int k = 0; k < 20; k++) {
                        if (v10[k] != byte_2BA000[40*a+k]) {
                            flag2 = false;
                            break;
                        }
                    }
                    if (flag2) {
                        cout << tmp;
                        flag = false;
                        break;
                    }
                }
            }
        }

    }
    return 0;
}
```

python版本腳本，來源→[https://shimo.im/docs/VMAPV1GaXwfazKqg](https://shimo.im/docs/VMAPV1GaXwfazKqg)

```python
import hashlib
import random
import string

enc = ['a2f17ed1c6a8bc31769cdf654df4b8a937042cb6', '0ca8a2edb0c1d34a432a5a4464e0d6abd847c831', 'c359d69f3f08bb920f2c3b51133205533462093e', 'cc5c3fe6e7356a26a134cff5633349f597c40a9d', '4ac4bb3f27f245ba9178651aa5cdedcbb2862e2a', 'a01e33f4dcdb6ba1ae9f34a97cf8f6deeedf1a8d', 'd3af70912a8c1b22cfdece071ba36bc4662b58fa',
       '9395eab195d25b676d7d07075d3838a9ac19df21', 'fdb43c5ef76ecda0c1661d6d199b5bfac1db538a', 'da8e9997a010be78b20108ce79fec1fb9c63d8dc', '809da627f1ad01d65864c376e3179b62d9d74261', '8f61ee21ac7579626934e0ffb6a62b3d4a82eec4', 'e2a954758fdb61f869998e9788b7b7e48480b832', 'b8e3349b97532b27aa62b8718b68240179158144']

# 爆破的字符表
dict = string.ascii_letters+string.punctuation+string.digits
flag = ''
for i in range(len(enc)):
    while (1):
        str = ''.join(random.choices(dict, k=3))  # 随机生成三个字符，可以产生重复字符
        # print(str)
        if hashlib.sha1(str.encode()).hexdigest() == enc[i]:
            flag += str
            print(flag)
            break
```

## Exception

在`main`中找到加密函數，進入查看

![Untitled](Untitled2.png)

發現有個錯誤，在錯誤的地方：`右鍵`→`Synchronize with`→`IDA View-A`，然後左鍵點擊出錯那行，然後按`tab`，再按`spcae`，這樣做是為了查看選中行的匯編代碼

![Untitled](Untitled3.png)

綠色那幾行就是上面報錯那行的匯編代碼，當時做題的時候看到IDA自帶的提示：`__except at loc_4118C9`，於是就嘗試將橙框中的部分全`nop`掉，再按`f5`反匯編看看

![Untitled](Untitled4.png)

然後沒就再出錯了，看來運氣不錯。再看代碼，是個魔改的Tea加密，它在每輪加密時將`delta`的值異或了`0x12345678`，所以在解密前要先算出`sum`的值，詳看下方腳本

![Untitled](Untitled5.png)

腳本如下：

```cpp
#include <stdint.h>
#include <iostream>
using namespace std;

void decrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], i;  /* set up */
    uint32_t  sum = 0xa3aa97a0;
    uint32_t delta = 0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i = 0; i < 32; i++) {                         /* basic cycle start */
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        delta ^= 0x12345678;
        sum -= delta;
    }                                              /* end cycle */
    v[0] = v0; v[1] = v1;
}

int main() {
    unsigned char enc[] =
    {
      0xCE, 0x21, 0xE8, 0x88, 0x70, 0x9D, 0x00, 0x0B, 0x8F, 0xE6,
      0xB1, 0x91, 0x96, 0xEA, 0x31, 0x01, 0x7D, 0x9D, 0x20, 0xA3,
      0xFB, 0x7D, 0x18, 0xA9, 0xCA, 0xC5, 0x52, 0xC4, 0x53, 0x67,
      0x69, 0xA9,0
    };
    uint32_t key[] = { 1,2,3,4 };
    for (int i = 0; i < 4; i++) {
        decrypt((uint32_t*)(enc+8*i), key);
    }

    cout << enc << endl;
    return 0;
}
```

## 哈德兔的口

拉入jadx( 版本1.4.4 )，可以看到核心函數`check`和`decode`都在native層。將.apk文件解壓，在`/lib`目錄下( 會看到4個文件夾，它們的差別在於**架構**及**位數**，**反匯編後的代碼其實差不多** )找到`libcheck.so`文件

![Untitled](Untitled6.png)

拉入IDA，可以看出是很明顯的**RC4加密**

![Untitled](Untitled7.png)

分析後發現在`do_crypt`中有兩處魔改的地方：

1. 在進行RC4**加密前**，先將數據異或`0xC6`
2. 也是在RC4**加密前**，將數據異或`0x73`
3. 所以目前的解密流程應為：`RC4解密`→`異或0x73 && 異或0xC6`

![Untitled](Untitled8.png)

![Untitled](Untitled9.png)

- 分析完so層後，回到Java層找RC4加密的`key`，大機率在以下這些字串當中
- 而這些字串都調用了`decode`函數( 在so層中 )進行解密，再根據題目的名字( hard to decode )，推測`decode`函數應該很複雜，所以只能用動調的方法來獲取`decode`函數的返回值
- 本來是想直接動調so文件的，但試了很久都不行( 不知道是不是模擬器的問題 )，於是只能直接動調APK( [參考這篇](https://blog.csdn.net/weixin_44155363/article/details/107102345) )

![Untitled](Untitled10.png)

這裡使用`jeb`來動調，在返回值的下一行下斷點( `ctrl+b` )，然後修改`v0`的類型為`string`後看到`android.util.Base64`字串，這個就是解密後的字串

![Untitled](Untitled11.png)

![Untitled](Untitled12.png)

按同樣方法對其他加密字串進行解密，之然分別得到`encode`、`Hikari#a0344y3y#19301211`。分析後知**前者為Base64_encode、後者為RC4加密的key**

**所以最終的解密流程為**：`RC4解密`→`異或0x73 && 異或0xC6` →`Base64解密`

1. RC4解密 ( [解密網站](https://gchq.github.io/CyberChef/) )

![Untitled](Untitled13.png)

1. 異或0x73 && 異或0xC6

```cpp
#include <iostream>
#include <string>

using namespace std;

int main() {

    string s = "efd8cdddef86c1e7e4e3f3d3d4f28c86f8d8e7d9ec878cdeefe6f8dfd6f2cdcfed86e7d9e4e2fbdaed86e7d9e3d8fbdaed8784d9fce6f38c";
    
		// 構造C++數組
    /*cout << "unsigned char arr2[]={" << endl;
    for (int i = 0; i < s.length(); i += 2) {
        cout << "0x" << s[i] << s[i + 1] << ',';
    }
    cout << endl;
    cout << '}';*/

    unsigned char arr2[] = {
0xef,0xd8,0xcd,0xdd,0xef,0x86,0xc1,0xe7,0xe4,0xe3,0xf3,0xd3,0xd4,0xf2,0x8c,0x86,0xf8,0xd8,0xe7,0xd9,0xec,0x87,0x8c,0xde,0xef,0xe6,0xf8,0xdf,0xd6,0xf2,0xcd,0xcf,0xed,0x86,0xe7,0xd9,0xe4,0xe2,0xfb,0xda,0xed,0x86,0xe7,0xd9,0xe3,0xd8,0xfb,0xda,0xed,0x87,0x84,0xd9,0xfc,0xe6,0xf3,0x8c };
    cout << endl;

    for (int i = 0; i < 56;i++) {
        arr2[i] ^= 0xC6;
        arr2[i] ^= 0x73;
        cout << arr2[i];
    }

    return 0;
}
```

1. Base64解密

![Untitled](Untitled14.png)