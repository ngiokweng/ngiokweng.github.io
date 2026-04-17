---
title: 【HGAME2023】week2-VidarCamera
date: 2023-2-2 11:21:12
tags: 
        - Reverse
        - WriteUp
categories: CTF
keywords:
    - CTF
    - hgame2023
    - 逆向
    - WriteUp
    - Reverse
description: hgame2023 VidarCamera
cover: Untitled.png
---
## 程序分析

- 找到加密函數，發現明顯xtea算法的特點( `<<4` `>>5` )，delta為`878077251`
- 分析後可知，v[0]和v[1]一組進行xtea，然後再v[1]和v[2]一組進行xtea，如此類推，因此解密時要從後向前進行解密

![Untitled](Untitled.png)

- 裡面的語句都經過一些簡單的”混淆”，手動還原一下最核心的兩句
- 可以看到第一句代碼與原版xtea相比多了一個`^sum`

```cpp
iArr[i2] += (((key[(sum & 3)]) + sum) ^(((iArr[i] << 4) ^ (iArr[i] >>> 5)) + iArr[i])) ^ sum        
iArr[i] += (((iArr[i2] << 4) ^ (iArr[i2] >>> 5)) + iArr[i2]) ^ ((key[((sum >>> 11) & 3)]) + sum)
```

## 腳本

```cpp
#include <iostream>
#include <stdint.h>
using namespace std;

void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], delta = 878077251, sum = delta*num_rounds;
    for (i = 0; i < num_rounds; i++) {
        sum -= delta;
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + (key[(sum >> 11) & 3]));
        v0 -= ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3])) ^ sum;
    }
    v[0] = v0; v[1] = v1;
}

int main() {
    uint32_t v[] = { 637666042 ,457511012 ,-2038734351 ,578827205 ,-245529892 ,-1652281167 ,435335655,733644188,705177885 ,-596608744 };
    uint32_t key[] = { 2233,4455,6677,8899 };

    for (int i = 8; i >=0; i--) {
        decipher(33, v+i, key);
    }

    for (int i = 0; i < 40; i++) {
        char tmp = *((char*)v + i);
        cout << tmp;
    }
}
```