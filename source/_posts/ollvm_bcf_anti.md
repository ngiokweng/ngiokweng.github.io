---
title: ollvm_bcf_anti
date: 2024-05-27 16:45:57
tags:
- Android逆向
- ollvm
categories: Android逆向
keywords:
- Android逆向
- ollvm
description: ollvm bcf anti
cover: Untitled.png
---

## 一、通過IDA Python Patch

### 思路1：直接patch用到不透明謂詞的地方

原理說明：

所謂不透明謂詞是指在跳轉前就已經確定的表達式，但IDA無法分析。

通過對不透明謂詞進行交叉引用會發現，沒有任何一處是賦值，全都是`LDR`，而且這些不透明謂詞通常會定義在`.bss`段，默認值為`0`。

![Untitled](Untitled.png)

![Untitled](Untitled1.png)

下圖的`x_70`是一個不透名謂詞，通過上述分析可以知道它其實永遠都為`0`，但可惜IDA不知道。

因此patch的目標就是直接將其賦為`0`，讓IDA可以分析出來。

![Untitled](Untitled2.png)

觀察匯編代碼可以發現，`x_70`最終通過`LDR W9, [X9]`賦給`W9`寄存器。

因此只需要將其修改成`mov w9, 0`即可

![Untitled](Untitled3.png)

最後的問題就是如何從`LDR W9, [X9]` → `mov w9, 0`？

通過IDA的`Keypatch`插件不斷修改來發現機械碼的變化規律，如下所示：

```python
# 40 B9 代表 ldr reg1, [reg2]
# 第1、2字節要合起來用小端來看(記作num)
# reg2 + 1 -> num += 0x20
# reg1 + 1 -> num += 1
LDR W0, [X0] -> 00 00 40 B9
LDR W0, [X1] -> 20 00 40 B9
LDR W1, [X1] -> 21 00 40 B9
>> 總結: num % 0x20 == 寄存器的編號

# 顯然第1個字節代表寄存器編號, 其他3個字節固定就可以
mov w7, 0 -> 07 00 80 52
mov w5, 0 -> 05 00 80 52

```

IDA Python腳本：環境—IDA_Pro7.7

```python
# 去除虚假控制流 idapython脚本
import ida_xref
import ida_idaapi
from ida_bytes import get_bytes, patch_bytes
import ida_segment

def getReg(num):
    # ldr w9, [x10], 獲取這個w9
    return num % 0x20

def do_patch(ea):
    byteArrs = bytearray(get_bytes(ea, 4))

    if byteArrs[2] == 0x40 and byteArrs[3] == 0xB9:
        reg = getReg(int.from_bytes(get_bytes(ea, 2), "little"))
        print("to_patch: ", reg.to_bytes(1,'little') + b'\x00\x80\x52')
        patch_bytes(ea, reg.to_bytes(1,'little') + b'\x00\x80\x52')

 
# 遍歷.bss段的不透明謂詞
seg = ida_segment.get_segm_by_name('.bss')
for addr in range(seg.start_ea, seg.end_ea,4):
    ref = ida_xref.get_first_dref_to(addr)
    print(hex(addr).center(20,'-'))
    # 遍歷所有交叉引用
    while(ref != ida_idaapi.BADADDR):
        do_patch(ref)
        print('patch at ' + hex(ref))
        ref = ida_xref.get_next_dref_to(addr, ref)
    print('-' * 20)
```

### 思路2：將全局變量賦值並將segment設為只讀

雙擊不透明謂詞進入對應段

![Untitled](Untitled4.png)

按`alt+s`或`Edit→Segments→Edit segment`來改變不透明謂詞所在段的讀寫屬性，設為只可讀

![Untitled](Untitled5.png)

最後，因為.bss段中的變量還未被賦值，所以需要手動patch這個段來固定其中的值。

```python
import ida_segment
import ida_bytes

seg = ida_segment.get_segm_by_name('.bss')

for ea in range(seg.start_ea, seg.end_ea,4):
    ida_bytes.patch_bytes(ea, int(2).to_bytes(4,'little'))

'''
seg.perm: 由三位二进制数表示,例如一个segment为可读,不可写,不可执行,则seg.perm = 0b100
(seg.perm >> 2)&1: Read
(seg.perm >> 1)&1: Write
(seg.perm >> 0)&1: Execute
'''
seg.perm = 0b100
```

## 二、angr符號執行

// TODO

## 參考

- [https://oacia.dev/ollvm-study/](https://oacia.dev/ollvm-study/)
- [https://bbs.kanxue.com/thread-266005.htm#msg_header_h1_3](https://bbs.kanxue.com/thread-266005.htm#msg_header_h1_3)