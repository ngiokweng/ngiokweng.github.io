---
title: 最小PE文件
date: 2023-09-25 23:18:52
tags: 
	- PE文件
categories: PE文件
keywords:
    - PE文件
description: 最小PE文件
cover: Untitled17.png
---

- 用`1`或`9`填充DOS頭、PE頭和節表中無用的部分
- 可以在這些地方見縫插針地填入所需的東西，如程序主要的代碼、Dll名稱和函數名稱等

![Untitled](Untitled.png)

- `DosStub`可以整段刪掉，如下圖
- 暫時先不修改各個RVA，最後刪完再一次過重設所有需要修改的RVA

![Untitled](Untitled1.png)

- 接下來修改可選PE頭的數據目錄表，因為只需要用到數據目錄表第`2`項的導入表，因此後面的`14`項都可以直接刪除
- 並將數據目錄表的項數設為`2`

![Untitled](Untitled2.png)

- 節表只需留下`.text`節表，`.rdata`可以直接刪除
- 可以直接刪除的原因是，數據目錄表能直接定位到導入表，因此不需要依靠`.rdata`節表也行

![Untitled](Untitled3.png)

- 分析一下`.rdata`對應的節區
- 可以先從原始文件中，找到`.rdata`對應節區的的起始位置和大小，從而在當前文件中找到`.rdata`對應節區
- 整個藍色部分就是`.rdata`對應的節區，紅框部分是IAT，這部分不重要，暫時以`9`填充，重要的是綠框部分，這是一個IDT結構的數組，以`20`個字節的`0`作為IDT數組的結尾
- IDT結構體最重要的是`OriginalFirstThunk`、`FirstThunk`和`Name`這3個屬性，後續要手動將這3個屬性指向正確的地址
- 由於只需要`MessageBoxA`這個函數，因此綠框部分只需留下`28`個字節的空間，前`20`個字節表示一個IDT結構，後`8`個字節表示IDT數組的結束
- 然後將修改後的紅框、綠框這兩部分移到文件最下方

![Untitled](Untitled4.png)

- 修改後如下圖
- 紅框部分算是一個備用空間，之後可作刪減
- 綠框部分中，上述提到的`3`個屬性要在之後手動修改

![Untitled](Untitled5.png)

- 藍框部分是程序的執行代碼 + 一些無用的字符串，可以直接刪
- 代碼部分要自己重構，然後見縫插針插入PE頭中，以節省空間

![Untitled](Untitled6.png)

- 藍框部分是PE頭
- 將其整段剪下，覆蓋到紅框

![Untitled](Untitled7.png)

- 修改後如下圖

![Untitled](Untitled8.png)

- 在PE頭裡插入`user32.dll`和`MessageBoxA`這2個字符串，插入的位置是從填充了`9`的字段中選中
- 下方保存的`user32.dll`和`MessageBoxA`現在可以刪了

![Untitled](Untitled9.png)

- 藍框是`.text`節表後幾個屬性，無用可以直接刪

![Untitled](Untitled10.png)

- 為了重構代碼，要借助OD來看

![Untitled](Untitled11.png)

- 代碼大概可重構成以下匯編結構，只保留了調用MessageBoxA的部分
- `E8`後面跟的地址由這個公式得出：`目標地址 - 當前指令地址 - 5`

```nasm
push 0x1040
// 68 40 10 00 00

push 0x4001F8
// 68 XX XX XX XX  ( XX 要改成標題字符串的絕對地址 )

push 0x40020C
// 68 XX XX XX XX  ( XX 要改成內容字符串的絕對地址 )

push 0x0
// 6A 00

call 00400264
// E8 XX 00 00 00 ( XX通過上述公式計算出來,算是個相對偏移 )

jmp dword ptr ds:[0x400274]
// FF 25 74 02 40 00    ( 74 02 40 00 是IAT,文件加載到內存時會將IAT指向函數的真實地址,即MessageBoxA的真實地址)
```

- 在PE頭中合適的位置插入代碼
- 部分指令解析：
    - `68 40 10 00 00`：push參數，可與原程序一致
    - `EB 0D`：`EB`是jmp指令的其中一個操作碼，操作數`0D`是一個偏移( `當前指令的下一條指令的起始地址 + 偏移 = 要跳轉到的地址`  )，用`EB`的目的是為了在一片不連續的空間實現連續的代碼執行流，相當於是一個橋樑
    - `68 A4 00 40 00`： push參數，`A4 00 40 00`是標題字符串在內存的絕對地址
    - `FF 25 E8 00 40 00`：`FF 25`是jmp指令另一個操作碼，`E8 00 40 00`是內存中的地址，它指向`MessageBoxA`的真實地址( 如何讓`0x4000E8`指向`MessageBoxA`的真實地址？將PE文件IDT表的`FirstThunk`設為`0xE8`即可 )

![Untitled](Untitled12.png)

IAT那部分只保留前`8`個字節就夠用，後`12`個字節可以刪

![Untitled](Untitled13.png)

- 之前在PE頭中插入的`MessageBoxA`字符串的前`2`個字節`9D 01`要刪，然後在後方補上`2`個字節`0`
- 若不這樣做會導致PE頭中的`SizeOfUninitializedData`過大，會使程序崩潰

![Untitled](Untitled14.png)

- 各種RVA、Size的修改，大致有以下這幾項要修改
    - `NumberOfSections`：節區數，改為`1`
    - `SizeOfOptionalHeader`：可選PE頭的大小，改為`70h`
    - `AddressOfEntryPoint`：程序起始位置，改為`30h`
    - `SizeOfHeaders`：這個相當於是第一個節區的起始位置，即代碼節的位置，需與`AddressOfEntryPoint`一致
    - 導入表起始地址改為`F0h`，大小改為`28h`
    - INT和IAT都指向`E8h`，`E8h`指向`1Ch`( `1Ch`指向PE頭中的MessageBoxA )，後面跟`4`個字節的`0`代表結束，文件加載到內存時 ( `MessageBoxA`的真實地址會放到IAT中，即`E8h`指向的就是`MessageBoxA`的真實地址 )
    - Dll的Name為`0Ch`

![Untitled](Untitled15.png)

- 最後，將彈框信息改成自己的姓名和學號，這裡用的是gbk編碼

![Untitled](Untitled16.png)

結果如下：

![Untitled](Untitled17.png)