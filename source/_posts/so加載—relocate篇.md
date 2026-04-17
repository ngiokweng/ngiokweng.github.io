---
title: so加載—relocate篇
date: 2024-11-20 20:07:14
tags:
- Android逆向
categories: Android逆向
keywords:
- relocate
description: relocate
cover: image1.png
---

> [https://xrefandroid.com/android-10.0.0_r47/xref/bionic/linker/linker.cpp](https://xrefandroid.com/android-10.0.0_r47/xref/bionic/linker/linker.cpp)
> 

## relocate分析

只保留`relocate`中與arm64有關的部份，刪除了其他架構&tls相關的東西。

`relocate`做了以下事情：

1. 調用`soinfo_do_lookup`獲取類型為`ElfW(Sym)`的`s`。
2. 將`s`傳入`resolve_symbol_address`函數，它會返回對應符號的地址`sym_addr`。
3. 最後會根據不同的重定向類型來進行重定向，主要分為3類`R_GENERIC_JUMP_SLOT`、`R_GENERIC_GLOB_DAT`、`R_GENERIC_RELATIVE`。

`reloc`指向待重定向的地址，根據不同的重定向類型，修改為不同的值。

```cpp
template<typename ElfRelIteratorT>
bool soinfo::relocate(const VersionTracker& version_tracker, ElfRelIteratorT&& rel_iterator,
                      const soinfo_list_t& global_group, const soinfo_list_t& local_group) {
  const size_t tls_tp_base = __libc_shared_globals()->static_tls_layout.offset_thread_pointer();
  std::vector<std::pair<TlsDescriptor*, size_t>> deferred_tlsdesc_relocs;

  for (size_t idx = 0; rel_iterator.has_next(); ++idx) {
    const auto rel = rel_iterator.next();
    if (rel == nullptr) {
      return false;
    }

    ElfW(Word) type = ELFW(R_TYPE)(rel->r_info);
    ElfW(Word) sym = ELFW(R_SYM)(rel->r_info);

    ElfW(Addr) reloc = static_cast<ElfW(Addr)>(rel->r_offset + load_bias);
    ElfW(Addr) sym_addr = 0;
    const char* sym_name = nullptr;
    ElfW(Addr) addend = get_addend(rel, reloc);

    DEBUG("Processing \"%s\" relocation at index %zd", get_realpath(), idx);
    if (type == R_GENERIC_NONE) {
      continue;
    }

    const ElfW(Sym)* s = nullptr;
    soinfo* lsi = nullptr;

    if (sym == 0) {
        // ...
    } else if (ELF_ST_BIND(symtab_[sym].st_info) == STB_LOCAL && is_tls_reloc(type)) {
        // tls?
    } else {
      sym_name = get_string(symtab_[sym].st_name);
      const version_info* vi = nullptr;

      if (!lookup_version_info(version_tracker, sym, sym_name, &vi)) {
        return false;
      }
			// 1. 調用soinfo_do_lookup獲取類型為ElfW(Sym)的s。
      if (!soinfo_do_lookup(this, sym_name, vi, &lsi, global_group, local_group, &s)) {
        return false;
      }

      if (s == nullptr) {
        // We only allow an undefined symbol if this is a weak reference...
        s = &symtab_[sym];
        if (ELF_ST_BIND(s->st_info) != STB_WEAK) {
          DL_ERR("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name, get_realpath());
          return false;
        }

        switch (type) {
          case R_GENERIC_JUMP_SLOT:
          case R_GENERIC_GLOB_DAT:
          case R_GENERIC_RELATIVE:
          case R_GENERIC_IRELATIVE:
          case R_GENERIC_TLS_DTPMOD:
          case R_GENERIC_TLS_DTPREL:
          case R_GENERIC_TLS_TPREL:
          case R_GENERIC_TLSDESC:
          case R_AARCH64_ABS64:
          case R_AARCH64_ABS32:
          case R_AARCH64_ABS16:
            break;
          default:
            DL_ERR("unknown weak reloc type %d @ %p (%zu)", type, rel, idx);
            return false;
        }
      } else { // We got a definition.
        if (is_tls_reloc(type)) {
          // ...
        } else {
          // ...tls
					
					// 2. 將s傳入resolve_symbol_address函數，它會返回對應符號的地址sym_addr
          sym_addr = lsi->resolve_symbol_address(s);
        }
      }
      count_relocation(kRelocSymbol);
    }
		
		// 3. 根據不同的重定向類型來進行重定向
    switch (type) {
      case R_GENERIC_JUMP_SLOT:
        *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
        break;
      case R_GENERIC_GLOB_DAT:
        *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
        break;
      case R_GENERIC_RELATIVE:
        *reinterpret_cast<ElfW(Addr)*>(reloc) = (load_bias + addend);
        break;
      case R_GENERIC_IRELATIVE:
        {

          ElfW(Addr) ifunc_addr = call_ifunc_resolver(load_bias + addend);
          *reinterpret_cast<ElfW(Addr)*>(reloc) = ifunc_addr;
        }
        break;

      case R_AARCH64_ABS64:
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend;
        break;
      case R_AARCH64_ABS32:
        {
          const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT32_MIN);
          const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT32_MAX);
          if ((min_value <= (sym_addr + addend)) &&
              ((sym_addr + addend) <= max_value)) {
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend;
          } else {
            DL_ERR("0x%016llx out of range 0x%016llx to 0x%016llx",
                   sym_addr + addend, min_value, max_value);
            return false;
          }
        }
        break;
      case R_AARCH64_ABS16:
        {
          const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT16_MIN);
          const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT16_MAX);
          if ((min_value <= (sym_addr + addend)) &&
              ((sym_addr + addend) <= max_value)) {
            *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
          } else {
            DL_ERR("0x%016llx out of range 0x%016llx to 0x%016llx",
                   sym_addr + addend, min_value, max_value);
            return false;
          }
        }
        break;
      case R_AARCH64_PREL64:
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend - rel->r_offset;
        break;
      case R_AARCH64_PREL32:
        {
          const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT32_MIN);
          const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT32_MAX);
          if ((min_value <= (sym_addr + addend - rel->r_offset)) &&
              ((sym_addr + addend - rel->r_offset) <= max_value)) {
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend - rel->r_offset;
          } else {
            DL_ERR("0x%016llx out of range 0x%016llx to 0x%016llx",
                   sym_addr + addend - rel->r_offset, min_value, max_value);
            return false;
          }
        }
        break;
      case R_AARCH64_PREL16:
        {
          const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT16_MIN);
          const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT16_MAX);
          if ((min_value <= (sym_addr + addend - rel->r_offset)) &&
              ((sym_addr + addend - rel->r_offset) <= max_value)) {
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend - rel->r_offset;
          } else {
            DL_ERR("0x%016llx out of range 0x%016llx to 0x%016llx",
                   sym_addr + addend - rel->r_offset, min_value, max_value);
            return false;
          }
        }
        break;

      case R_AARCH64_COPY:
        DL_ERR("%s R_AARCH64_COPY relocations are not supported", get_realpath());
        return false;
      default:
        DL_ERR("unknown reloc type %d @ %p (%zu)", type, rel, idx);
        return false;
    }
  }

  return true;
}
```

## 實例分析

- 源代碼如下：
    
    ```cpp
    #include <string.h>
    #include <jni.h>
    #include <stdio.h>
    
    typedef void(*PPP)();
    __attribute__((visibility("default"))) void myFunc()
    {
    	int i = 0;
    	i = 1;
    	i = 2;
    	return;
    }
    
    PPP g1 = myFunc;
    PPP g2;
    
    __attribute__((constructor)) int mian_()
    {	
    
    	__asm("nop");
    	__asm("nop");
    	__asm("nop");
    	PPP s1 = myFunc;
    
    	__asm("nop");
    	__asm("nop");
    	__asm("nop");			
    	s1();
    
    	__asm("nop");
    	__asm("nop");
    	__asm("nop");
    	g1();
    
    	__asm("nop");
    	__asm("nop");
    	__asm("nop");
    	g2 = myFunc;
    	g2();
    
    	__asm("nop");
    	__asm("nop");
    	__asm("nop");
    	myFunc();
    	
    	
    	__asm("nop");
    	__asm("nop");
    	__asm("nop");
    	return 0;
    	
    }
    ```
    

從010可以看到`.dynamic`就在`.got`上面

![image.png](image.png)

將生成的so拉入IDA，`ctrl+s`定位到`.got`節，它上面確實就是`.dynamic`節。

`.dynamic`節中保存了很多so的信息，其中就包含所有的重定位信息，下圖紅框中的就是重定位信息對應的`Elf64_Dyn`元素，`DT_RELA`對應`.rela.dyn` ( FileOffset為`0x4B0` )，`DT_JMPREL`對應`.rela.plt` ( FileOffset為`0x570` )。

雙擊`0x4B0`跳到對應的重定向表。

![image.png](image1.png)

這裡就是重定向表，每個`Elf64_Rela`占8*3=24個字節，`<r_offset, r_info, r_addend>`。

- `r_offset`：待重定向符號的FileOffset。
- `r_info`：包括`type`和`sym`，前者是重定向類型，後者是`symtab_`符號表的索引，通過`ELF64_R_SYM`和`ELF64_R_TYPE`宏來解析`r_info`。
- `r_addend`：額外的信息，下圖中只有`0x403`類型的重定向的這個值才不為`0`

![image.png](image2.png)

解析`r_info`的宏定義&用法：

```cpp
#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i) & 0xffffffff)

ElfW(Word) type = ELFW(R_TYPE)(rel->r_info);
ElfW(Word) sym = ELFW(R_SYM)(rel->r_info);
```

上述的`symtab_`符號表可以從010裡看出，`.rela.dyn`的`s_link`是`3`，代表與之鏈接的符號表是索引為`3`的那個section，即`.dynsym`。

![image.png](image3.png)

### 403重定向

403重定向即`R_GENERIC_RELATIVE`類型的重定向，以一組實際的數據`<0x1898, 0x403, 0x71C>`來分析其重定向流程。

首先計算`type`和`sym`：

```cpp
ElfW(Word) type = ELFW(R_TYPE)(rel->r_info); // 0x403
ElfW(Word) sym = ELFW(R_SYM)(rel->r_info);   // 0x0
```

403重定向的`sym`固定為`0`，而符號表中的第`0`項也全都是`0`。

![image.png](image4.png)

403重定向的目標是當前so中的一些函數，本例的`0x1898`指向的是`.fini_array`中的函數。這也是為什麼叫做`R_GENERIC_RELATIVE`( 相對 )。

![image.png](image5.png)

最終會將`0x1898`地址指向的內容設置為`0x71C`。

```cpp
case R_GENERIC_RELATIVE:
  *reinterpret_cast<ElfW(Addr)*>(reloc) = (load_bias + addend);
  break;
```

### 402重定向

402重定向即`R_GENERIC_JUMP_SLOT`類型的重定向，以一組實際的數據`<0x1AB0, 0x100000402, 0>`來分析其重定向流程。

首先計算`type`和`sym`：

```cpp
ElfW(Word) type = ELFW(R_TYPE)(rel->r_info); // 0x402
ElfW(Word) sym = ELFW(R_SYM)(rel->r_info);   // 0x1
```

`0x1`對應的符號信息如下，符號名為`__cxa_finalize`，與IDA看到的一致。

![image.png](image6.png)

402重定向的目標是一些外部的導入函數和內部函數( `.init_array`中用到的函數，如`myFunc` )。

最終會將`0x1AB0`地址指向的內容設置為`sym_addr`( 具體`sym_addr`是什麼沒有深究，maybe是真實的函數地址？ )。

```cpp
case R_GENERIC_JUMP_SLOT:
  *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
  break;
```

### 401重定向

401重定向即`R_GENERIC_GLOB_DAT`類型的重定向，以一組實際的數據`<0x1A88, 0x600000401, 0>`來分析其重定向流程。

首先計算`type`和`sym`：

```cpp
ElfW(Word) type = ELFW(R_TYPE)(rel->r_info); // 0x401
ElfW(Word) sym = ELFW(R_SYM)(rel->r_info);   // 0x6
```

`0x6`對應的符號信息如下，符號名為`g1`，是一個全局變量。

![image.png](image7.png)

最終同樣會將`0x1A88`地址指向的內容設置為`sym_addr`

```cpp
case R_GENERIC_GLOB_DAT:
  *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
  break;
```

### 101重定向

101重定向即`R_AARCH64_ABS64`，屬於`Static Data relocations`。

本例中有2個這種類型的重定向塊，一個是屬於`myFunc`、另一個是屬於`.init_array`裡的函數。

![image.png](image8.png)

最終的重定位實現與上面一樣：

```cpp
case R_AARCH64_ABS64:
  *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend;
  break;
```

## ext：readelf工具使用

使用`readelf`可以很方便查看一個elf文件的各種信息，直接在cmd輸入指令即可使用：

```bash
# 1. 查看重定向信息
readelf -r <so_path>

# 2. 查看.dynsym table
readelf --dyn-syms <so_path>

# 3. 查看.dynamic
readelf - <so_path>
```