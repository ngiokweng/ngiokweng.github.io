---
title: 【XNUCA2018】Code_Interpreter WriteUp
date: 2022-11-09 11:05:53
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - Buuctf
    - 逆向
    - XNUCA2018
    - WriteUp
    - buuctf
description: Code_Interpreter WriteUp
cover: Untitled.png
---

- 可以看出是一道虛擬機題，要求輸入3個整數，經`encrypt()`後再做對比
- 動調後可知input1~3的值不會被`encrypt()`修改
- 再分析`encrypt()`後，知其內部通過數組越界的方式對`whereIsThisShit_`進行操作，易知`whereIsThisShit_`最終需為0

![Untitled](Untitled.png)

先將程序流程打印出來

```cpp
#include <iostream>
#include <string>
#include "defs.h"
using namespace std;

unsigned char opcode[] =
{
  0x09, 0x04, 0x04, 0x09, 0x00, 0x00, 0x08, 0x01, 0x00, 0x08,
  0x02, 0x01, 0x08, 0x03, 0x02, 0x06, 0x01, 0x04, 0x05, 0x01,
  0x15, 0x07, 0x00, 0x01, 0x04, 0x00, 0x03, 0x01, 0x6B, 0xCC,
  0x7E, 0x1D, 0x08, 0x01, 0x03, 0x04, 0x00, 0x01, 0x02, 0x0A,
  0x04, 0x00, 0x09, 0x00, 0x00, 0x08, 0x01, 0x00, 0x08, 0x02,
  0x01, 0x08, 0x03, 0x02, 0x06, 0x03, 0x08, 0x05, 0x03, 0x03,
  0x07, 0x00, 0x03, 0x03, 0x00, 0x02, 0x01, 0x7C, 0x79, 0x79,
  0x60, 0x08, 0x01, 0x03, 0x04, 0x00, 0x01, 0x02, 0x0A, 0x04,
  0x00, 0x09, 0x00, 0x00, 0x08, 0x01, 0x00, 0x08, 0x02, 0x01,
  0x08, 0x03, 0x02, 0x06, 0x01, 0x08, 0x07, 0x00, 0x01, 0x03,
  0x00, 0x02, 0x01, 0xBD, 0xBD, 0xBC, 0x5F, 0x08, 0x01, 0x03,
  0x04, 0x00, 0x01, 0x02, 0x0A, 0x04, 0x00, 0x00
};

int input_cpy[3];
unsigned int input1, input2, input3;
__int64 __fastcall encrypt(int mem[])
{
    int va1_0, i2, i;
    __int64 result; // rax
    int v2; // eax
    int v3; // eax
    int v4; // eax
    char v5; // [rsp+19h] [rbp-7h]
    unsigned __int8 v6; // [rsp+1Ah] [rbp-6h]
    unsigned __int8 v7; // [rsp+1Ah] [rbp-6h]
    unsigned __int8 v8; // [rsp+1Ah] [rbp-6h]
    unsigned __int8 v9; // [rsp+1Ah] [rbp-6h]
    unsigned __int8 v10; // [rsp+1Ah] [rbp-6h]
    unsigned __int8 v11; // [rsp+1Ah] [rbp-6h]
    unsigned __int8 v12; // [rsp+1Ah] [rbp-6h]
    unsigned __int8 v13; // [rsp+1Ah] [rbp-6h]
    int v14; // [rsp+1Ch] [rbp-4h]
    int v15; // [rsp+1Ch] [rbp-4h]
    int v16; // [rsp+1Ch] [rbp-4h]

    input_cpy[0] = input1;
    input_cpy[1] = input2;
    result = (unsigned int)input3;
    input_cpy[2] = input3;
    va1_0 = 0;
    i2 = 2;
    i = 0;
    v5 = 1;
    while (v5)
    {
        switch (opcode[i])
        {
        case 0:
            v5 = 0;
            cout << "v5 = 0; \n" << endl;
            break;
        case 1:
            v2 = ++i;
            ++i;
            v14 = (unsigned __int8)opcode[v2];
            v3 = i++;
            v15 = ((unsigned __int8)opcode[v3] << 8) + v14;
            v4 = i++;
            v16 = ((unsigned __int8)opcode[i] << 24) + ((unsigned __int8)opcode[v4] << 16) + v15;
            input_cpy[++i2] = v16;
            printf("input_cpy[%d] = %d \n", i2, v16);
            break;
        case 2:
            --i2;
            //cout << "--i2\n";
            break;
        case 3:
            v6 = opcode[++i];
            mem[v6] += mem[(unsigned __int8)opcode[++i]];
            printf("mem[%d] += mem[%d]\n",v6, opcode[i]);
            break;
        case 4:
            v7 = opcode[++i];
            mem[v7] -= mem[(unsigned __int8)opcode[++i]];
            printf("mem[%d] -= mem[%d]\n", v7, opcode[i]);
            break;
        case 5:
            v8 = opcode[++i];
            mem[v8] *= (unsigned __int8)opcode[++i];
            printf("mem[%d] *= %d\n", v8, opcode[i]);
            break;
        case 6:
            v9 = opcode[++i];
            mem[v9] = (unsigned int)mem[v9] >> opcode[++i];
            printf("mem[%d] >>= %d \n", v9 ,opcode[i]);
            break;
        case 7:
            v10 = opcode[++i];
            mem[v10] = mem[(unsigned __int8)opcode[++i]];
            printf("mem[%d] = mem[%d]\n", v10, opcode[i]);
            break;
        case 8:
            v11 = opcode[++i];
            mem[v11] = input_cpy[va1_0 + (unsigned __int8)opcode[++i]];
            printf("mem[%d] = input_cpy[%d] (%d)\n", v11, opcode[i], input_cpy[opcode[i]]);
            break;
        case 9:
            v12 = opcode[++i];
            mem[v12] ^= mem[(unsigned __int8)opcode[++i]];
            printf("mem[%d] ^= mem[%d]\n", v12, opcode[i]);
            break;
        case 10:
            v13 = opcode[++i];
            mem[v13] |= mem[(unsigned __int8)opcode[++i]];
            printf("mem[%d] |= mem[%d]\n", v13, opcode[i]);
            break;
        default:
            fprintf(stderr, "Invalid opcode. %d\n", (unsigned __int8)opcode[i]);
            exit(1);
        }
        result = (unsigned int)++i;
    }
    return result;
}

int main() {
        int mem[5]; 
        encrypt(mem);
        cout << mem[4] << endl;
    return 0;
}
```

關鍵點在`mem[4] |= mem[0]` 這裡，而`mem[4]`就是`whereIsThisShit_`，所以`mem[0]`必須為0才能使`mem[4]`為0

```python
mem[4] ^= mem[4]
mem[0] ^= mem[0]
mem[1] = input_cpy[0] (1408880469) 
mem[2] = input_cpy[1] (2073006411)
mem[3] = input_cpy[2] (494849131)
mem[1] >>= 4 # mem[1] = input_cpy[0]>>4
mem[1] *= 21 #  mem[1] = (input_cpy[0]>>4)*21
mem[0] = mem[1] # mem[0] = (input_cpy[0]>>4)*21
mem[0] -= mem[3] # mem[0] = (input_cpy[0]>>4)*21 - input_cpy[2]
input_cpy[3] = 494849131
mem[1] = input_cpy[3] (494849131) # mem[1] = 494849131
mem[0] -= mem[1] # mem[0] = (input_cpy[0]>>4)*21 - input_cpy[2] - 494849131
#key
mem[4] |= mem[0]

mem[0] ^= mem[0]
mem[1] = input_cpy[0] (1408880469) # mem[1] = input_cpy[0]
mem[2] = input_cpy[1] (2073006411) # mem[2] = input_cpy[1]
mem[3] = input_cpy[2] (494849131) # mem[3] = input_cpy[2]
mem[3] >>= 8 # mem[3] = input_cpy[2]>>8
mem[3] *= 3 # mem[3] = (input_cpy[2]>>8)*3
mem[0] = mem[3] # mem[0] = (input_cpy[2]>>8)*3
mem[0] += mem[2] #  mem[0] = (input_cpy[2]>>8)*3 + input_cpy[1]
input_cpy[3] = 1618573692
mem[1] = input_cpy[3] (1618573692) # mem[1] = 1618573692
mem[0] -= mem[1] # mem[0] = (input_cpy[2]>>8)*3 + input_cpy[1] - 1618573692
#key
mem[4] |= mem[0]

mem[0] ^= mem[0]
mem[1] = input_cpy[0] (1408880469)
mem[2] = input_cpy[1] (2073006411)
mem[3] = input_cpy[2] (494849131)
mem[1] >>= 8 # mem[1] = input_cpy[0]>>8
mem[0] = mem[1] # mem[0] = input_cpy[0]>>8
mem[0] += mem[2] # mem[0] = (input_cpy[0]>>8)+input_cpy[1]
input_cpy[3] = 1606204861 
mem[1] = input_cpy[3] (1606204861) # mem[1] = 1606204861
mem[0] -= mem[1] # mem[0] = (input_cpy[0]>>8)+input_cpy[1] - 1606204861
# key
mem[4] |= mem[0]
v5 = 0;
```

分析清楚後就可直接用z3來求解

```python
from z3 import *

s = z3.Solver()
input0 = BitVec("input0",32)
input1 = BitVec("input1",32)
input2 = BitVec("input2",32)

s.add(((input0>>4)*21 - input2 - 494849131) == 0)
s.add(((input2>>8)*3 + input1 - 1618573692) == 0)
s.add(((input0>>8)+input1 - 1606204861) == 0)
# 以下3條能防止出現多個解
s.add(input0&0xFF == 0x5E)
s.add((input1 & 0xFF0000) == 0x5E0000)
s.add(input2&0xFF == 0x5E)

if s.check() == sat:
    print(s.model())
```