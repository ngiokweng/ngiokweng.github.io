---
title: 【NPUCTF2020】EzReverse
date: 2022-11-09 23:38:30
tags: 
	- Reverse
	- WriteUp
categories: CTF
keywords:
    - CTF
    - Buuctf
    - 逆向
    - NPUCTF2020
    - WriteUp
    - buuctf
    - EzReverse
description: NPUCTF2020 EzReverse WriteUp
cover: Untitled2.png
---

- 一開始會有個簡單的花指令，去掉後才能對`main`F5
- 對每個`if`語句進行分析( 結合動調 )後發現，有點像迷宮
- `v3`是地圖，由數組大小可知地圖大小是`7*7`，若`v3[i]`是偶數則代表不能走的地方( 若走了直按failed )，反之是奇數就是可走的路，而終點在`v3[48]`
- `l`：向右，`h`：向左，`j`：向上，`k`：向下

![Untitled](Untitled.png)

![Untitled](Untitled1.png)

打印地圖，`*`代表可走，`X`代表不可走，終點是最後一個

```cpp
#include <iostream>
using namespace std;

int main() {
    long long v3[49] = { 0 };
    *v3 = 0xDFAE04FLL;
    v3[1] = 0x148983F2LL;
    v3[7] = 0x15B847LL;
    v3[2] = 0x69981A413ELL;
    v3[8] = 0x3402448LL;
    v3[3] = 0xAD765F22BLL;
    v3[9] = 0xDF641F6LL;
    v3[4] = 0x1F6653572295LL;
    v3[12] = 0x75B46D5LL;
    v3[5] = 0x1F687239D88BLL;
    v3[13] = 0x23BE14LL;
    v3[6] = 0x85354B6E0E0B4LL;
    v3[14] = 0x165457DLL;
    v3[10] = 0x574319309LL;
    v3[15] = 0x1656DA4LL;
    v3[11] = 0x22212127E16LL;
    v3[16] = 0xCE87FFLL;
    v3[18] = 0x57424EFE0LL;
    v3[17] = 0x925LL;
    v3[20] = 0xC6CE7E906LL;
    v3[19] = 0x4993CAA9LL;
    v3[27] = 0xCDD59530LL;
    v3[21] = 0xF183473LL;
    v3[28] = 0x36798A41BECAC6DLL;
    v3[22] = 0x2B5B718LL;
    v3[29] = 0x6E230828110LL;
    v3[23] = 0x17656B5LL;
    v3[30] = 0x575771C1BLL;
    v3[24] = 0x16590D6LL;
    v3[25] = 0x165DFDCLL;
    v3[26] = 0x34B2DDLL;
    v3[31] = 0xDFAB63CLL;
    v3[33] = 0x805B2D5A7LL;
    v3[35] = 0x2243C897C6BLL;
    v3[32] = 0xDF81E91LL;
    v3[36] = 0x5769A5D6ELL;
    v3[34] = 0x23CAC6LL;
    v3[39] = 0x1580F6F64FA1LL;
    v3[37] = 245646441LL;
    v3[40] = 2346463450LL;
    v3[38] = 234644640LL;
    v3[41] = 2343345620LL;
    v3[42] = 3444651LL;
    v3[43] = 23451LL;
    v3[44] = 67541LL;
    v3[45] = 34575860LL;
    v3[46] = 67856741LL;
    v3[47] = 0x21D616CFLL;
    v3[48] = 0x21D45D67LL;
    for (int i = 0; i < 49; i++) {
        if (i % 7 == 0)cout << endl;
        if ((v3[i] & 1) == 0) {
            cout << 'X';
        }
        else {
            cout << "*";
        }
    }
}
```

然後手動走一下，得出`kkkkkklljjjjljjllkkkkhkkll`

![Untitled](Untitled2.png)