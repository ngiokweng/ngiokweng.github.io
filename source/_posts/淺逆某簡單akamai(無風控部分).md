---
title: 淺逆某簡單akamai(無風控部分)
date: 2023-09-10 13:10:52
tags: 
	- Web逆向
categories: Web逆向
keywords:
    - Web逆向
description: 淺逆某簡單akamai(無風控部分)
cover: Untitled.png
---

> Target：aHR0cHM6Ly93d3cuZGlnaWtleS5jbi8=
> 

## 前言

本文參考了以下文章和視頻，感謝大佬們的分享

- [https://www.bilibili.com/video/BV1d14y1h7P9/?spm_id_from=333.880.my_history.page.click&vd_source=999a37555f77c5995df6185262c99be3](https://www.bilibili.com/video/BV1d14y1h7P9/?spm_id_from=333.880.my_history.page.click&vd_source=999a37555f77c5995df6185262c99be3)
- [https://blog.csdn.net/huangch135/article/details/130227868](https://blog.csdn.net/huangch135/article/details/130227868)

## 基本分析

- akm的目標是cookie裡的`_abck`這個值
- 當`_abck`裡的`~-1~`變成`~0~`時就算是有效

![Untitled](Untitled.png)

- 上述的`_abck`由類似`1diI9T-4eS/HLR5GidZ/XH/YkNYXGfprwm5/cEMlcQYB/TnUjFxE/ZWTA`這樣的接口返回
- 本網站屬於簡單類型的akm，因此在風控正常的情況下，第1個接口返回的cookie就已經是有效的
- 而對於其他難度的akm，則可能需要在第3次後，什至是在某些事件觸發後，才會返回有效的cookie

![Untitled](Untitled1.png)

## 第一次請求

- 從上述接口的堆棧，直接可以跟到這裡
- `Txf`就是接口請求的data，而其主要部分是`wFf`

![Untitled](Untitled2.png)

- 向上跟來到這裡，可以看到`ATf`明顯是一個環境檢測的數據，裡面保存著當前的各種環境

![Untitled](Untitled3.png)

- `ATf`環境數組具體如下，基本上每個都是環境檢測點，建議與自己的環境逐一對比
- 個人認為最主要關注的部分就是這個環境數組，只要這裡能基本一致應該就可以
- 後續的各種操作生成最終的`sensor_data`應該就沒有那麼重要了

```jsx
[
    // 0: 固定值
		"-100",
		// 1: 檢測了ua、window的一些屬性、自動化工具、Screen等
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36,uaend,12147,20030107,zh-TW,Gecko,5,0,0,0,416881,0,1920,1040,1920,1080,1920,931,1920,,cpen:0,i1:0,dm:0,cwen:0,non:1,opc:0,fc:0,sc:0,wrc:1,isc:0,vib:1,bat:1,x11:0,x12:1,8105,0.419036962209,847157403808.5,0,0,loc:",
    "-105",
		// 3: 檢測頁面input標籤的一些屬性
    "0,0,0,0,-1,888,0;0,-1,0,0,-1,-1,0;",
    "-108",
    "",
    "-101",
    "do_en,dm_en,t_en",
    "-110",
    "",
    "-117",
    "",
    "-109",
    "",
    "-102",
    "0,0,0,0,-1,888,0;0,-1,0,0,-1,-1,0;",
    "-111",
    "",
    "-114",
    "",
    "-103",
    "",
    "-106",
    "0,0",
    "-115",
		// 25: 這裡取了cookie,因此在第1次請求前,要先對頁面進行1次請求,從而獲取頁面返回的cookie
    "1,32,32,0,0,0,0,4,0,1694314807617,-999999,18125,0,0,3020,0,0,9,0,0,358649D9584BA9DE6AC5E821111B1819~-1~YAAQlBw/O81cCUmKAQAAp5YAfQrZ/fMGHSsNvloPsNh/jJ7n4XXUu6UHaA1RaKg7vczO18ylrCuF4EySkQ3t6XoOAwTJCNmqoAqcXdQ/SZ+evRynCqtSq6EuenlcO2+KeqRaC+qovOMyuUxX9M9KTDNvmU9zsmQ5fjaayV9pHOO9+O2lsN/Ihl4ODUU4/IAUv8ty5/TFT7VqCAGJmdhArhi5Bhq+y8It62D6MSGnZ4JGyz7m6TuNGx/1Wnfa03pi8u7hobrX3k7+NtZO7SrCMkQpynfZ62rz72edbZ22awJ/hOwJw+lI7KR87dOso7hrZQ5oR6Ke7vzXF0rgyETCaO+nUqVo5HsJ1ePZzv90oRMhA8SqiE4KBC8DhHYv4cxd6WyAKdqQIwHXGg==~-1~-1~-1,36758,-1,-1,30261693,PiZtE,12969,86,0,0,0,,,",
    "-112",
    "https://www.digikey.cn/",
    "-119",
    "-1",
    "-122",
		// 31: 檢則了一堆東西，如 XPathResult
    "0,0,0,0,1,0,0",
    "-123",
    "",
    "-124",
    "",
    "-126",
    "",
    "-127",
    8,
    "-128",
    ",,",
    "-131",
    ",,,",
    "-132",
    "",
    "-133",
    "",
    "-70",
    "-1",
    "-80",
    "94",
    "-90",
    "MjZkMjI4NjYzZjEzYTg4NTkyYTEyZDE2Y2Y5NTg3Y2FhYjAzODhiMjYyZDZkOWYxMjZlZDYyZjkzMzNhY2E5NA==|-1|3,1,53,178,165",
    "-116",
    0,
    "-129",
    ",,0,,,,,,,,"
]
```

技巧：以上述環境數組的第3個索引為例，要如何找到其生成位置？

1. 先確認它是哪個變量

![Untitled](Untitled4.png)

1. 通過search快速定位

![Untitled](Untitled5.png)

1. 發現是一堆switch…case，這時可以在每個`return`處下斷點

![Untitled](Untitled6.png)

1. 可以看到是由`UJ.apply(undefined, tJ)`返回，進入該函數，裡面就是對input的檢測

![Untitled](Untitled7.png)

- `sensor_data`這個請求參數可以在`XMLHttpRequest.prototype.send`裡接收

## 第二、三次請求

雖然只需第一次請求就夠，但第二、三次請求的一些檢測點還挺有意思的，簡單地說一下吧

- 在第2次請求時，在以下代碼的位置檢測了`font`相關的東西，例如不同`fontSize`和`fontFamily`的`offsetHeight`和`offsetWeight`
- 應付的方法也很簡單，就是根據`fontSize`和`fontFamily`構建字典一一對應就可以了

```jsx
var Mtf = cE.slice();
var Gtf = ff[hf.dL(pPf, Pp)][hf.pf(cG, Tk, cc, tLf)](hf.qs(VG, YI));
Gtf[hf.bP(FC, dc, jH, Qp)] = hf.Us(V4, AB),
Gtf[hf.kS.apply(null, [Ab, vI])][hf.rs(cR, DI)] = hf.lP(GM, mC, Lp, Kp);
var Ctf = hf.jL(qW, K1, HG, FC)
  , ktf = (ff[hf.dL.call(null, pPf, Pp)][hf.ss(WQf, OI)](hf.Ys.call(null, xLf, XI)))[K1]
  , ctf = ktf
  , Jtf = SE(Q1);
jE(ff[hf.jf(MM, N1, gR, fC)][hf.vs(Ec, mI)], K1) && dE(K1)() && (Jtf = SE(K1)),
Jtf && ((ctf = ff[hf.dL.apply(null, [pPf, Pp])][hf.pf(cG, Tk, vp, tLf)](hf.Ds(p3f, nI)))[hf.kS.call(null, Ab, vI)][hf.Os.call(null, JH, fPf)] = hf.Xs.call(null, TLf, HG, pc, B3f),
ktf[hf.bF.apply(null, [jC, ZI])](ctf)),
ctf ? (Etf[hf.Cz(lLf, gI)](function(wtf) {
    cE.push(nR);
    Gtf[hf.kS(Ab, II)][hf.ms.apply(null, [IV, qG, hJ, Ahf])] = wtf,
    ctf[hf.bF(jC, jI)](Gtf),
    Ctf += (((hf.jL(f3f, zJ, TJ, FC))[hf.LS.call(null, Sp, SE(SE([])), SE(SE({})), w3f)](wtf, hf.tL.call(null, nJ, QA)))[hf.LS(Sp, dPf, JH, w3f)](Gtf[hf.ns(UC, hLf)], hf.BK(NLf, PLf)))[hf.LS(Sp, kG, xb, w3f)](Gtf[hf.Zs(fR, xl)], hf.mS.apply(null, [vG, QLf])),
    ctf[hf.SP(OG, xb, QB, gJ)](Gtf);
    cE.pop();
```

- 同樣是第2次請求，這裡先執行了`Object.keys(iframe.contentWindow)`的操作，然後用`JSON.stringify`將其變成字符串，最後再將它用某種算法加密了一下，然後加上`Object.keys`返回的數組的長度

```jsx
E7f = ff[hf.tK.call(null, ZG, Ux)][hf.PF.call(null, Cb, QE)](d7f);
I7f = ((hf.jL.call(null, YPf, Lhf, OG, FC))[hf.LS.call(null, Ml, JJ, OG, w3f)](Atf(MSf(ff
```

- 第3次請求，這裡是一些CSS的檢測，有興趣可以自己來看看

```jsx
return [hf.I5.call(null, fW, Z9), hf.j5.apply(null, [ng, dk, SE(K1), NG]), hf.N5(Lk, AI), hf.x5(kV, g9), hf.d5(jC, fj), hf.E5.apply(null, [kV, Qn]), hf.M5(bH, HV), hf.G5(Ehf, khf, hB, c4), hf.C5(Chf, I9), hf.k5.apply(null, [vE, j9]), hf.c5(Yb, N9), hf.J5(cR, x9), hf.B5(xJ, Uk, Wk, kc), hf.w5.call(null, Cw, qV), hf.A5(NR, Rp, cG, Xp), hf.b5(F9, pc, SE(K1), Ec), hf.l5(Qb, d9), hf.p5.apply(null, [nB, E9]), hf.V5.call(null, gLf, M9), hf.R5(r3f, G9), hf.H5.call(null, xC, C9), hf.W5(k9, NH, cG, Pw), hf.f0(c9, hJ, SE(K1), hJ), hf.dQ(Bk, Ip, pG, Eb), hf.EQ(EJ, CM, DC, MG), hf.h0(Khf, SE(K1), Ec, rhf), hf.P0(JH, CO), hf.Q0.call(null, Cc, J9), hf.MQ.apply(null, [FC, ZG, pJ, rV]), hf.L0(pc, ng), hf.K0.call(null, OG, B9), hf.S0.apply(null, [kb, Fl]), hf.T0.call(null, EG, Il), hf.GQ(EG, VW, Vc, TPf), hf.z0(AA, w9), hf.t0.apply(null, [hV, DC, JB, xw]), hf.F0.call(null, Pff, A9), hf.q0(Rff, SE(SE(K1)), SE(K1), rW)][hf.Cz(lLf, b9)](function(HYf) {
    cE.push(Ol);
    pYf[hf.kS.call(null, Ab, l9)] = (hf.U0(gLf, p9))[hf.LS(OC, WJ, q3f, w3f)](HYf, hf.r0(Dff, U3f, SE(K1), CM));
    var WYf = (ff[hf.s0.apply(null, [Off, t3f, SE(SE(K1)), Bk])](pYf))[hf.Y0.call(null, Tk, V9)];
    VYf[HYf] = WYf;
    cE.pop();
}),
```

注：三次請求的觸發條件分別是

```jsx
1. 最開始的自執行函數
2. setTimeout-> delay為500的函數
3. setTimeout-> delay為1000的函數
```

## 實際請求

總體流程如下：

![Untitled](Untitled8.png)

效果如下：

- `curl_cffi`是用來躲避TLS檢測，注意*`impersonate*="chrome101"`要與js環境的ua和appVersion一致
- `node_vm2`太經典了就不多說啦

![Untitled](Untitled9.png)