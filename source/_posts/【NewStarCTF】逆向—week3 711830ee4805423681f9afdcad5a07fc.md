---
title: 【NewStarCTF】逆向—week3
date: 2022-10-09 23:50:01
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
    - week3
description: NewStarCTF 逆向部分 第3周的WriteUp
cover: Untitled1.png
---
> 這周考了挺多知識點的…
> 

## Zzzzzz3333

這題明顯是在考**z3求解器**的應用，~~本人對此了解不多就不多BB了~~ )。附上我寫的腳本，z3的基本格式大致都是長這樣

```python
import z3
s = z3.Solver()
pwd = [z3.Int("pwd%d"%x) for x in range(8)]

s.add(pwd[3]
     + 4 * pwd[2]
     + pwd[7]
     + 4 * (pwd[3] + 4 * pwd[2])
     + 3 * (pwd[4] + 4 * pwd[0])
     + 2 * (pwd[5] + 4 * pwd[6])
     + 11 * pwd[1] == 6426)
s.add(11 * (pwd[0] + pwd[7] + pwd[3]) + 4 * (pwd[5] + 2 * pwd[4]) + pwd[2] + 45 * pwd[1] + 7 * pwd[6] == 9801)
s.add(5 * pwd[1] + 2 * (pwd[4] + pwd[6] + pwd[5] + 2 * (pwd[7] + pwd[3]) + pwd[2] + 2 * (pwd[6] + pwd[5] + 2 * (pwd[7] + pwd[3])) + 8 * pwd[0]) == 6021)
s.add(19 * pwd[0] + 9 * pwd[1] + 67 * pwd[7] + 5 * (pwd[2] + pwd[6]) + 7 * (pwd[5] + 4 * pwd[3]) + 4 * pwd[4] == 14444)
s.add(22 * pwd[5] + 5 * (pwd[4] + 2 * (pwd[3] + pwd[1] + 2 * pwd[0])) + 4 * (pwd[7] + pwd[6]) + 6 * pwd[2] == 7251)
s.add(19 * pwd[3]
     + 3 * (pwd[7] + pwd[2] + 4 * pwd[7] + pwd[6] + 2 * (pwd[7] + pwd[2] + 4 * pwd[7]))
     + 4 * (pwd[0] + pwd[5] + pwd[1] + 2 * (pwd[0] + pwd[5])) == 10054)
pwd[1] *= 2
s.add(7 * pwd[0] + 17 * (pwd[3] + pwd[1]) + 11 * (pwd[4] + 2 * pwd[5]) + 2 * (pwd[2] + pwd[6] + 4 * pwd[2] + 6 * pwd[7]) == 10735)
s.add(pwd[6] + pwd[4] + 11 * pwd[2] + 15 * (pwd[3] + 2 * pwd[7]) + pwd[1] + 43 * pwd[0] + 21 * pwd[5] == 11646)

key = [0]*8

# s.model()前必須先調用s.check()，看看有沒有解
if s.check():
    res = s.model()
    for e in res:
     index = ord(e.name()[-1:]) - ord('0')
     key[index] = res[e].as_long()

for e in key:
     print(chr(e),end="") # fallw1nd
```

將求出的key輸入到原程序中，就可直接出flag

## EzTea

程序的運行流程很簡單，就是將用戶輸入放到一個函數進行加密，然後對比。**等等分析後可以看出該加密函數是3種Tea加密中的`xxtea`**

![Untitled](Untitled.png)

進入加密函數，**將紅框中的代碼與`xxtea`的加密代碼( 附在了下方 )進行對比**，可以發現基本上是差不多的，只修改了部分地方

![Untitled](Untitled1.png)

附：`xxtea`的加解密通用腳本，`n>1`時為**加密**、`n<-1`時為**解密**

```cpp
#include <stdio.h>  
#include <stdint.h>  
#define DELTA 0x9e3779b9  
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))  
  
void btea(uint32_t *v, int n, uint32_t const key[4])  
{  
    uint32_t y, z, sum;  
    unsigned p, rounds, e;  
    if (n > 1)            /* Coding Part */  
    {  
        rounds = 6 + 52/n;  
        sum = 0;  
        z = v[n-1];  
        do  
        {  
            sum += DELTA;  
            e = (sum >> 2) & 3;  
            for (p=0; p<n-1; p++)  
            {  
                y = v[p+1];  
                z = v[p] += MX;  
            }  
            y = v[0];  
            z = v[n-1] += MX;  
        }  
        while (--rounds);  
    }  
    else if (n < -1)      /* Decoding Part */  
    {  
        n = -n;  
        rounds = 6 + 52/n;  
        sum = rounds*DELTA;  
        y = v[0];  
        do  
        {  
            e = (sum >> 2) & 3;  
            for (p=n-1; p>0; p--)  
            {  
                z = v[p-1];  
                y = v[p] -= MX;  
            }  
            z = v[n-1];  
            y = v[0] -= MX;  
            sum -= DELTA;  
        }  
        while (--rounds);  
    }  
}
```

對比後發現修改的地方為：`DELTA`、`z>>5`與成`z>>4`、`z<<4`變成`z<<5`

```cpp
// 以下是修改後：
#define DELTA 0x11451400
#define MX (((z>>4^y<<2) + (y>>3^z<<5)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
```

最終的解密腳本如下：

```cpp
#include <stdio.h>  
#include <stdint.h>  
#include <iostream>
using namespace std;

#define DELTA 0x11451400
#define MX (((z>>4^y<<2) + (y>>3^z<<5)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))  

void xxtea(uint32_t* v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)            /* Coding Part */
    {
        rounds = 6 + 52 / n;
        sum = 0;
        z = v[n - 1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++)
            {
                y = v[p + 1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n - 1] += MX;
        } while (--rounds);
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--)
            {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}

int main() {
    unsigned char enc[] =
    {
      0x82, 0x8A, 0xFA, 0x38, 0x80, 0x13, 0x50, 0xD7, 0x9D, 0x96,
      0x40, 0x0E, 0x20, 0x91, 0x16, 0x4E, 0xAB, 0x29, 0x3A, 0x71,
      0x3D, 0x39, 0xE5, 0x6C, 0x2E, 0x75, 0x9D, 0xB6, 0xE6, 0x88,
      0x1A, 0x84, 0x59, 0xB4, 0x31, 0x6F, 0x00, 0x00, 0x00, 0x00
    };

    uint32_t key[] = { 0x19,0x19,0x8,0x10 };
		// 傳入-9代表解密
    xxtea((uint32_t*)enc, -9, (uint32_t*)key);

    cout << enc << endl;
    return 0;
}
```

## Annnnnggrr

這題考點是`Angr`，**入門`Angr`的話建議可以看下這個視頻**→[click_me](https://www.bilibili.com/video/BV167411o7WK/?vd_source=999a37555f77c5995df6185262c99be3)，講得還是相當不錯的。以下附上我寫的腳本，每行代碼都有大致的注釋

```python
import angr
import sys
import claripy

def is_good(state):
    return b'Success' in state.posix.dumps(1)

def is_bad(state):
    return b'Failed' in state.posix.dumps(1)  

def main(argv):
    bin_path = argv[1] # argv[1]是調用.py文件時傳入的參數，即【python3 mySolve.py xxx】中的xxx
    p = angr.Project(bin_path)

    # Angr符號執行的起始地址，這裡選定0x140001103是為了跳過scanf函數，因為這題我們需要自己構建一個符號向量來執行
    start_addr = 0x140001103
		# 設置初始狀態，狀態的起始地址為start_addr 
    init_state = p.factory.blank_state(addr = start_addr)

    # 符號向量的構建，32*8是位數，代表32字節( 因為由題目可知最終的flag共有32字節 )
    password = claripy.BVS("password",32*8)

    ''' 
    下面兩段代碼的大致意思：
    程序在正常執行時，若沒有跳過scanf函數，那麼 0x140005640 就是用戶輸入的首地址 (由IDA中看出)
    而現在雖然跳過了scanf函數，但程序依是以 0x140005640 作為用戶輸入的首地址
    所以要將上面創建的符號向量賦給該地址，以及其後31字節的地址也會被我們創建的符號向量所覆蓋
    '''
    password_addr = 0x140005640
    init_state.memory.store(password_addr,password) # 以C++來簡單理解的話，相當於 *password_addr = password

    # 固定寫法
    sm = p.factory.simulation_manager(init_state)
    # 0x14000248A是結束位置，到這時 sm.found = true
    sm.explore(find = 0x14000248A) 
    
    # 在IDA中取得的密文
    enc = [0x4F, 0x17, 0x0C, 0x56, 0xDB, 0x67, 0x5D, 0x67, 0x32, 0x2B, 0x36, 0x03, 0x02, 0xF3, 0xA1, 0xE4, 0xC7, 0x27, 0xC1, 0xB6, 0x4C, 0xD7, 0x59, 0xA1, 0x71, 0x52, 0x9A, 0xE2, 0x21, 0x96, 0x0C, 0xCA]
    
    if sm.found: 
        # 在 0x14000248A 時的狀態
        check_state = sm.found[0]     
        for i in range(32):
            # 遍歷該狀態下password的每個字符
            ch = check_state.memory.load(password_addr+i,1)
            # 添加約束，若不滿足會重新再找( 大致是這樣 )
            check_state.solver.add(ch == enc[i])
        
        # 走到這裡代表滿足了所有的約束，也即是我們的flag
        sol = check_state.solver.eval(password,cast_to=bytes)
        # 打印flag
        print("Solution：{}".format(sol))
        
    else:
        print("Not Solution")

if __name__ == "__main__":
    main(sys.argv)
```

注：腳本運行→`python solve.py Annnnnggrr.exe`

## The Slider's Labyrinth

`main`函數因為存在花指令，導致IDA無法正常分析，找到下圖這個地方，使用IDA插件`Keypatch`將0x04010E5地址處`nop`掉

![Untitled](Untitled2.png)

`nop`掉後，若看到下方有形如這樣IDA未分析出來的地方，可在對著第1行按`c`，手動將其分析成代碼

![Untitled](Untitled3.png)

接著向下看，發現第2處花指令，用同樣方法處理

![Untitled](Untitled4.png)

處理完後，選中`main`函數的所有部分( 0x00401080~0x04011DC )，然後按`P`將選中部分生成一個函數，然後再按`F5`查看偽代碼

![Untitled](Untitled5.png)

- 雖然還有一部分未能正常分析出來，但並不影響解題
- 可以看出這是一道迷宮題，`w`、`a`、`s`、`d`對應上下左右四個方向，且每次會走好幾步，直到遇到`#`才會停下，然後繼續輸入，直到到達`O`才結束
- 最後將走出來的路徑進行`md5(path)`就得到flag

![Untitled](Untitled6.png)

在`shift+F12`中找到地圖，將其dump出來

![Untitled](Untitled7.png)

dump出來後發現地圖大小為`160`，而由下圖可以看出每行占`16`，所以這是一個`16*10`的地圖

![Untitled](Untitled8.png)

- 整理後地圖長這樣，`s`是起始位置( 由`v8 = 17`這句判斷出來的 )
- 然後就是**走迷宮**，我的方法是**手動走**，第一次走的路徑為：`sdsdwdsasdwds`，提交後發現不對
- 由此可知**路徑不唯一**，應該是**要最短的路徑。**第二次走的路徑為：`dsasdwds`，結果就對了，看來我走迷宮還是有點東西的，也挺幸運^^

![Untitled](Untitled9.png)

## funnyOTL

- 整體加密邏輯如下圖所示( 有大致注釋 )，若知道`posLogMe`的值就能很輕易地求出flag，但`posLogMe`是隨機數，所以其中一種做法或許可以爆破( 但我沒爆出來 )，所以只能動調獲取
- IDA動調ELF文件需用到Linux虛擬機，我用的是**Ubuntu22.04版本**，**建議使用這個版本來動調**( 之前用20.04版本連文件都打不開。~~真係哭撚左…~~ )
- >>[IDA動調ELF文件的教程](https://blog.csdn.net/m0_51713041/article/details/112135426)( 以**Ubuntu22.04**為例，需要先開放23946端口，指令：`sudo ufw allow 23946/tcp` )

![Untitled](Untitled10.png)

動調→獲取每次循環的`posLogMe`並記錄下來

![Untitled](Untitled11.png)

腳本：

```cpp
#include <iostream>
#include <string>
#include <algorithm>
using namespace std;

void change(string& str, int pos1, int pos2) {
    char tmp1 = str[pos1];
    char tmp2 = str[pos1 + 1];
    str[pos1] = str[pos2];
    str[pos1 + 1] = str[pos2 + 1];
    str[pos2] = tmp1;
    str[pos2 + 1] = tmp2;
}

void decrypt(string& enc) {

    int sNum[] = { 0x12, 6, 8, 0xA, 6, 0x14, 0xA, 0x14, 0, 0xC, 2, 4 };

    for (int i = 23; i >= 0; i -= 2) {
        change(enc, i - 1, sNum[i / 2]);
        enc[i - 1] ^= sNum[i / 2];
        enc[i] = ~(enc[i] ^ sNum[i / 2]);

    }
    std::reverse(enc.begin(), enc.end());

}

int main() {

    string str = "L\xABxIh\x9DQyu_}\xC5\x63RL\xB4O{gaonk_";
    decrypt(str);
    cout << str << endl;

    return 0;
}
```