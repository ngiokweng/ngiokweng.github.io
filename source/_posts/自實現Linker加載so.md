---
title: 自實現Linker加載so
date: 2024-06-28 17:21:58
tags:
- Linker
- Android逆向
categories: Android逆向
keywords:
- Linker
- Android逆向
description: 自實現Linker加載so
cover: Untitled.png
---

# 前言

前一陣子在研究so加固，發現其中涉及自實現的Linker加載so的技術，而我對此知之什少，因此只好先來學習下Linker的加載流程。

本文參考AOSP源碼和[r0ysue大佬的文章](https://bbs.kanxue.com/thread-269484.htm)( 不知為何文中給出的那個demo我一直跑不起來 )來實現一個簡單的自實現Linker Demo。

環境：`Pixel1XL`、`AOSP - Oreo - 8.1.0_r81`

# Demo實現

Linker在加載so時大致可以分成五步：

1. 讀取so文件：讀取ehdr( Elf header )、phdr( Program header )等信息。
2. 載入so：預留一片內存空間，隨後將相關信息加載進去，最後修正so。
3. 預鏈接：主要處理`.dynamic`節的內容。
4. 正式鏈接：處理重定位的信息。
5. 調用`.init`、`.init_array`

## `Read`

利用`open`+`mmap`來將待加載的so文件映射到內存空間，存放在`start_addr_`中。然後調用`Read`函數來獲取ehdr、phdr等信息。

```cpp
int fd;
struct stat sb;
fd = open(path, O_RDONLY);
fstat(fd, &sb);
start_addr_ = static_cast<void **>(mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));

// 1. 讀取so文件
if(!Read(path, fd, 0, sb.st_size)){
    LOGD("Read so failed");
    munmap(start_addr_, sb.st_size);
    close(fd);
}
```

`Read`函數實現如下，調用`ReadElfHeader`和`ReadProgramHeaders`來讀取ehdr和phdr。

AOSP源碼的`Read`中還會讀取Section Headers和Dynamic節，一開始我也有實現這部份的邏輯，但後來發現讀取後的信息根本沒有被用到，因此就把這部份給刪了。

```cpp
bool MyLoader::Read(const char* name, int fd, off64_t file_offset, off64_t file_size) {
    bool res = false;

    name_ = name;
    fd_ = fd;
    file_offset_ = file_offset;
    file_size_ = file_size;

    if (ReadElfHeader() &&
        ReadProgramHeaders()) {
        res = true;
    }

    return res;
}
```

`ReadElfHeader`的實現如下，直接通過`memcpy`來賦值。

```cpp
bool MyLoader::ReadElfHeader() {
    return memcpy(&(header_),start_addr_,sizeof(header_));
}
```

`ReadProgramHeaders`的實現直接copy源碼就可以，本質上還是內存映射的過程。

```cpp
bool MyLoader::ReadProgramHeaders() {

    phdr_num_ = header_.e_phnum;

    size_t size = phdr_num_ * sizeof(ElfW(Phdr));

    void* data = Utils::getMapData(fd_, file_offset_, header_.e_phoff, size);
    if(data == nullptr) {
        LOGE("ProgramHeader mmap failed");
        return false;
    }
    phdr_table_ = static_cast<ElfW(Phdr)*>(data);

    return true;
}

void* Utils::getMapData(int fd, off64_t base_offset, size_t elf_offset, size_t size) {
    off64_t offset;
    safe_add(&offset, base_offset, elf_offset);

    off64_t page_min = page_start(offset);
    off64_t end_offset;

    safe_add(&end_offset, offset, size);
    safe_add(&end_offset, end_offset, page_offset(offset));

    size_t map_size = static_cast<size_t>(end_offset - page_min);

    uint8_t* map_start = static_cast<uint8_t*>(
            mmap64(nullptr, map_size, PROT_READ, MAP_PRIVATE, fd, page_min));

    if (map_start == MAP_FAILED) {
        return nullptr;
    }

    return map_start + page_offset(offset);

}
```

## `Load`

### 載入so基本信息

調用`Load`來載入so。

```cpp
// 2. 載入so
if(!Load()) {
    LOGD("Load so failed");
    munmap(start_addr_, sb.st_size);
    close(fd);
}
```

`Load`的實現如下：

`ReserveAddressSpace`用於生成一片新的內存空間，之後的操作基本上都是在這片內存空間進行。`LoadSegments`、`FindPhdr`用於將待加載so的對應信息填充到此內存空間。

最後要修正so，將當前so修正為待加載的so，這部份放到後面來解析。

```cpp
bool MyLoader::Load() {
    bool res = false;
    if (ReserveAddressSpace() &&
        LoadSegments() &&
        FindPhdr()) {

        LOGD("Load Done.........");
        res = true;
    }

    // 獲取當前so (加載器的so)
    si_ = Utils::get_soinfo("libnglinker.so");

    if(!si_) {
        LOGE("si_ return nullptr");
        return false;
    }
    LOGD("si_ -> base: %lx", si_->base);

    // 使si_可以被修改
    mprotect((void*) PAGE_START(reinterpret_cast<ElfW(Addr)>(si_)), 0x1000, PROT_READ | PROT_WRITE);

    // 修正so
    si_->base = load_start();
    si_->size = load_size();
//        si_->set_mapped_by_caller(elf_reader.is_mapped_by_caller());
    si_->load_bias = load_bias();
    si_->phnum = phdr_count();
    si_->phdr = loaded_phdr();

    return res;
}

```

`ReserveAddressSpace`的具體實現如下，先計算出`load_size_`後`mmap`一片內存，在我這個demo中`min_vaddr`是`0`，因此`load_start_  == load_bias_`，`load_bias_`代表的就是這片內存，而這片內存是用來存放待加載的so。

```cpp
bool MyLoader::ReserveAddressSpace() {
    ElfW(Addr) min_vaddr;
    load_size_ = phdr_table_get_load_size(phdr_table_, phdr_num_, &min_vaddr);
    LOGD("load_size_: %x", load_size_);
    if (load_size_ == 0) {
        LOGE("\"%s\" has no loadable segments", name_.c_str());
        return false;
    }

    uint8_t* addr = reinterpret_cast<uint8_t*>(min_vaddr);

    void* start;

    // Assume position independent executable by default.
    void* mmap_hint = nullptr;

    start = mmap(mmap_hint, load_size_, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    load_start_ = start;
    load_bias_ = reinterpret_cast<uint8_t*>(start) - addr;

    return true;
}
```

`LoadSegments`的具體實現如下，遍歷Program Header Table將所有type為`PT_LOAD`的段加載進內存，源碼中是采用`mmap`來映射，但我嘗試後發現會有權限問題，因而采用`memcpy`的方案。

```cpp
bool MyLoader::LoadSegments() {
    // 在這個函數中會往 ReserveAddressSpace
    // 裡mmap的那片內存填充數據

    for (size_t i = 0; i < phdr_num_; ++i) {
        const ElfW(Phdr)* phdr = &phdr_table_[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        // Segment addresses in memory.
        ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
        ElfW(Addr) seg_end   = seg_start + phdr->p_memsz;

        ElfW(Addr) seg_page_start = PAGE_START(seg_start);
        ElfW(Addr) seg_page_end   = PAGE_END(seg_end);

        ElfW(Addr) seg_file_end   = seg_start + phdr->p_filesz;

        // File offsets.
        ElfW(Addr) file_start = phdr->p_offset;
        ElfW(Addr) file_end   = file_start + phdr->p_filesz;

        ElfW(Addr) file_page_start = PAGE_START(file_start);
        ElfW(Addr) file_length = file_end - file_page_start;

        if (file_size_ <= 0) {
            LOGE("\"%s\" invalid file size: %", name_.c_str(), file_size_);
            return false;
        }

        if (file_end > static_cast<size_t>(file_size_)) {
            LOGE("invalid ELF file");
            return false;
        }

        if (file_length != 0) {
            // 按AOSP裡那樣用mmap會有問題, 因此改為直接 memcpy
            mprotect(reinterpret_cast<void *>(seg_page_start), seg_page_end - seg_page_start, PROT_WRITE);
            void* c = (char*)start_addr_ + file_page_start;
            void* res = memcpy(reinterpret_cast<void *>(seg_page_start), c, file_length);

            LOGD("[LoadSeg] %s  seg_page_start: %lx   c : %lx", strerror(errno), seg_page_start, c);

        }

        // if the segment is writable, and does not end on a page boundary,
        // zero-fill it until the page limit.
        if ((phdr->p_flags & PF_W) != 0 && PAGE_OFFSET(seg_file_end) > 0) {
            memset(reinterpret_cast<void*>(seg_file_end), 0, PAGE_SIZE - PAGE_OFFSET(seg_file_end));
        }

        seg_file_end = PAGE_END(seg_file_end);

        // seg_file_end is now the first page address after the file
        // content. If seg_end is larger, we need to zero anything
        // between them. This is done by using a private anonymous
        // map for all extra pages.

        if (seg_page_end > seg_file_end) {
            size_t zeromap_size = seg_page_end - seg_file_end;
            void* zeromap = mmap(reinterpret_cast<void*>(seg_file_end),
                                 zeromap_size,
                                 PFLAGS_TO_PROT(phdr->p_flags),
                                 MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,
                                 -1,
                                 0);
            if (zeromap == MAP_FAILED) {
                LOGE("couldn't zero fill \"%s\" gap: %s", name_.c_str(), strerror(errno));
                return false;
            }

            // 分配.bss節
            prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, zeromap, zeromap_size, ".bss");
        }
    }

    return true;
}

```

`FindPhdr`的具體實現如下，簡單來說就是將Phdr信息填充進`load_bias_`那片內存。

```cpp
bool MyLoader::FindPhdr() {

    const ElfW(Phdr)* phdr_limit = phdr_table_ + phdr_num_;

    // If there is a PT_PHDR, use it directly.
    for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_PHDR) {
            return CheckPhdr(load_bias_ + phdr->p_vaddr);
        }
    }

    // Otherwise, check the first loadable segment. If its file offset
    // is 0, it starts with the ELF header, and we can trivially find the
    // loaded program header from it.
    for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_LOAD) {
            if (phdr->p_offset == 0) {
                ElfW(Addr)  elf_addr = load_bias_ + phdr->p_vaddr;
                const ElfW(Ehdr)* ehdr = reinterpret_cast<const ElfW(Ehdr)*>(elf_addr);
                ElfW(Addr)  offset = ehdr->e_phoff;
                return CheckPhdr(reinterpret_cast<ElfW(Addr)>(ehdr) + offset);
            }
            break;
        }
    }

    LOGE("can't find loaded phdr for \"%s\"", name_.c_str());
    return false;
}

bool MyLoader::CheckPhdr(ElfW(Addr) loaded) {
    const ElfW(Phdr)* phdr_limit = phdr_table_ + phdr_num_;
    ElfW(Addr) loaded_end = loaded + (phdr_num_ * sizeof(ElfW(Phdr)));
    for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
        ElfW(Addr) seg_end = phdr->p_filesz + seg_start;
        if (seg_start <= loaded && loaded_end <= seg_end) {
            loaded_phdr_ = reinterpret_cast<const ElfW(Phdr)*>(loaded);
            return true;
        }
    }
    LOGE("\"%s\" loaded phdr %p not in loadable segment",
           name_.c_str(), reinterpret_cast<void*>(loaded));
    return false;
}
```

### 修正so

`Load`函數最後是在對soinfo的修正，將當前so( 加載器 )修正為待加載的so。AOSP源碼中的`si_`是通過特定方法new出來的全新soinfo，而我看大多數文章都是獲取當前so作為`si_`，然後修正其中的信息。

本來是想嘗試按AOSP源碼那樣new一個soinfo看看結果有什麼不同，但最終被soinfo結構的複雜性勸退了。

修正so的第一步是要獲取當前so的soinfo對象，從[這篇文章](https://nszdhd1.github.io/2020/07/03/%E7%BD%91%E6%98%93%E4%BF%9D%E6%8A%A4%E5%88%86%E6%9E%90/#/%E7%BD%91%E6%98%93%E4%BF%9D%E6%8A%A4%E7%A0%94%E7%A9%B6)發現`find_containing_library`這個函數，似乎可以一步到位直接獲取soinfo對象。該函數位於`linker64`中，將它拉入IDA，能直接搜尋到該函數，這意味著能夠「借用」這個函數。

![Untitled](Untitled.png)

想要「借用」`linker64`裡的`find_containing_library`，需要知道`linker64`在內存的基址和`find_containing_library`的函數偏移( 相對基址的偏移 )，前者可以通過遍歷`/proc/self/maps`來取得，而後者的獲取有以下兩種思路：

1. 直接從IDA查看其偏移( `0x9AB0` )
2. 解析`linker64`的文件，自動獲取，具體實現在`Utils::get_export_func`中。

成功獲取`find_containing_library`地址後，強轉成`FunctionPtr`函數指針後即可調用，參數為當前so的地址( 同樣是遍歷maps取得的 )，最終會返回當前so的soinfo對象。

```cpp
soinfo* Utils::get_soinfo(const char* so_name) {
    typedef soinfo* (*FunctionPtr)(ElfW(Addr));

    char line[1024];
    ElfW(Addr) linker_base = 0;
    ElfW(Addr) so_addr = 0;
    FILE *fp=fopen("/proc/self/maps","r");
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "linker64") && !linker_base) {
            char* addr = strtok(line, "-");
            linker_base = strtoull(addr, NULL, 16);

        }else if(strstr(line, so_name) && !so_addr) {
            char* addr = strtok(line, "-");
            so_addr = strtoull(addr, NULL, 16);

        }

        if(linker_base && so_addr)break;

    }

    ElfW(Addr) func_offset = Utils::get_export_func("/system/bin/linker64", "find_containing_library");
    if(!func_offset) {
        LOGE("func_offset == 0? check it ---> get_soinfo");
        return nullptr;
    }
//    ElfW(Addr) find_containing_library_addr =  static_cast<ElfW(Addr)>(linker_base + 0x9AB0);
    ElfW(Addr) find_containing_library_addr =  static_cast<ElfW(Addr)>(linker_base + func_offset);
    FunctionPtr find_containing_library = reinterpret_cast<FunctionPtr>(find_containing_library_addr);

    return find_containing_library(so_addr);
}
```

`get_export_func`的實現如下，主要依賴於elf的文件結構，可以參考下[我之前寫的文章](https://ngiokweng.github.io/2024/05/30/elf%E6%96%87%E4%BB%B6%E7%B5%90%E6%A7%8B/)，大致原理如下：

1. elf header的`e_shstrndx`是一個索引，指向了`.shstrtab`節區，而`.shstrtab`節區存儲著所有節區的名字。
2. 遍歷所有節區，找到名為`.symtab`和`.strtab`的節區( `.symtab`節每項都有一個`st_name`屬性，是`.strtab`節區的一個索引值，指向某符號名 )
3. 遍歷`.symtab`節區，對比`func_name`，匹配則返回對應的函數偏移。

```cpp
ElfW(Addr) Utils::get_export_func(char* path, char* func_name) {

    struct stat sb;
    int fd = open(path, O_RDONLY);
    fstat(fd, &sb);
    void* base = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    // 讀取elf header
    ElfW(Ehdr) header;
    memcpy(&(header), base, sizeof(header));

    // 讀取Section header table
    size_t size = header.e_shnum * sizeof(ElfW(Shdr));
    void* tmp = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); // 注: 必須要 MAP_ANONYMOUS
    LOGD("error: %s", strerror(errno));
    ElfW(Shdr)* shdr_table;
    memcpy(tmp, (void*)((ElfW(Off))base + header.e_shoff), size);
    shdr_table = static_cast<ElfW(Shdr)*>(tmp);

    char* shstrtab = reinterpret_cast<char*>(shdr_table[header.e_shstrndx].sh_offset + (ElfW(Off))base);

    void* symtab = nullptr;
    char* strtab = nullptr;
    uint32_t symtab_size = 0;

    // 遍歷獲取.symtab和.strtab節
    for (size_t i = 0; i < header.e_shnum; ++i) {
        const ElfW(Shdr) *shdr = &shdr_table[i];
        char* section_name = shstrtab + shdr->sh_name;
        if(!strcmp(section_name, ".symtab")) {
//            LOGD("[test] %d: shdr->sh_name = %s", i, (shstrtab + shdr->sh_name));
            symtab = reinterpret_cast<void*>(shdr->sh_offset + (ElfW(Off))base);
            symtab_size = shdr->sh_size;
        }
        if(!strcmp(section_name, ".strtab")) {
//            LOGD("[test] %d: shdr->sh_name = %s", i, (shstrtab + shdr->sh_name));
            strtab = reinterpret_cast<char*>(shdr->sh_offset + (ElfW(Off))base);
        }

        if(strtab && symtab)break;
    }

    // 讀取 Symbol table
    ElfW(Sym)* sym_table;
    tmp = mmap(nullptr, symtab_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(tmp, symtab, symtab_size);
    sym_table = static_cast<ElfW(Sym)*>(tmp);

    int sym_num = symtab_size / sizeof(ElfW(Sym));

    // 遍歷 Symbol table
    for(int i = 0; i < sym_num; i++) {
        const ElfW(Sym) *sym = &sym_table[i];
        char* sym_name = strtab + sym->st_name;
        if(strstr(sym_name, func_name)) {
            return sym->st_value;
        }

    }

    return 0;
}
```

成功獲取`si_`後要修改其對應屬性。在這裡我遇到一個很玄學的問題，就是一開始不知為什麼死活修改不了`si_`的屬性，一改就會報內存讀寫的錯，即使`mprotect`賦予可讀可寫權限也無用，嘗試了各種方法都無用，在這卡了我好幾天，直到某次重啟手機後就突然好了？？？

```cpp
// 使si_可以被修改
mprotect((void*) PAGE_START(reinterpret_cast<ElfW(Addr)>(si_)), 0x1000, PROT_READ | PROT_WRITE);

// 修正so
si_->base = load_start();
si_->size = load_size();
//        si_->set_mapped_by_caller(elf_reader.is_mapped_by_caller());
si_->load_bias = load_bias();
si_->phnum = phdr_count();
si_->phdr = loaded_phdr();
```

### 補充：soinfo結構( 巨TM坑 )

soinfo結構體定義在`bionic/linker/linker_soinfo.h`中。

將它copy到本地後會有很多報錯，一開始我是將那些沒有用到又報紅的直接刪掉，但後來發現這樣做會間接導致最後發生「`android linker java.lang.unsatisfiedlinkerror: no implementation found for XXX`」的錯誤( 這個錯誤我排查了很久很久，最終才發現是soinfo結構的問題，果然細節決定成敗…… )。

正確的做法是必須要保留所有的成員變量( 即使該變量用不到也要留下來占位 )，函數由於不占空間可以隨便刪掉。

## `prelink_image`

預鏈接，主要是在遍歷`.dynamic`節獲取各種動態信息並保存在修正後的soinfo中。

```cpp
// 3. 預鏈接, 主要處理 .dynamic節
si_->prelink_image()
```

`prelink_image`的具體實現太長( 基本上是copy源碼的 )就不展示了，比較大的改動是在`DT_NEEDED`時手動保存對應的依賴庫，之後重定向時會用到。

```cpp
bool soinfo::prelink_image() {
    /* Extract dynamic section */
    ElfW(Word) dynamic_flags = 0;
    Utils::phdr_table_get_dynamic_section(phdr, phnum, load_bias, &dynamic, &dynamic_flags);

    if (dynamic == nullptr) {
        return false;
    } else {
    }

    for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
        LOGD("d = %p, d[0](tag) = %p d[1](val) = %p",
              d, reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
        switch (d->d_tag) {
			        // ...
				      case DT_NEEDED:
                // 手動保留所有依賴庫, 用於之後的重定位
                myneed[needed_count] = d->d_un.d_val;
                ++needed_count;
                break;
               // ...
        }
    }

    return true;
}

```

## `link_image`

`link_image`裡處理重定向信息。

```cpp
// 4. 正式鏈接, 在這裡處理重定位的信息
si_->link_image();
```

`link_image`的實現如下，`android_relocs_`的重定向我沒有處理( 嘗試處理過，但有點問題就刪了 )，好像問題不大？

之後調用`relocate`對`rela_`和`plt_rela_`的內容進行重定向。

```cpp
bool soinfo::link_image() {
    local_group_root_ = this;

    if (android_relocs_ != nullptr) {
        LOGD("android_relocs_ 不用處理?");

    } else {
        LOGE("bad android relocation header.");
//        return false;
    }

///*
#if defined(USE_RELA)
    if (rela_ != nullptr) {
LOGD("[ relocating %s ]", get_realpath());
if (!relocate(plain_reloc_iterator(rela_, rela_count_))) {
  return false;
}
}
if (plt_rela_ != nullptr) {
LOGD("[ relocating %s plt ]", get_realpath());
if (!relocate(plain_reloc_iterator(plt_rela_, plt_rela_count_))) {
  return false;
}
}
#else
    LOGE("TODO: !defined(USE_RELA) ");
#endif

    LOGD("[ finished linking %s ]", get_realpath());

    // We can also turn on GNU RELRO protection if we're not linking the dynamic linker
    // itself --- it can't make system calls yet, and will have to call protect_relro later.
    if (!((flags_ & FLAG_LINKER) != 0) && !protect_relro()) {
        return false;
    }

    return true;
}

```

`relocate`函數的實現如下，在重定位時最需要確定的就是目標函數的真實地址。

這裡采用一種偷懶的方式，直接遍歷所有依賴庫( 之前保存在`myneed`中 )，調用`dlopen`+`dlsym`查找對應函數地址，找到的結果會保存在`sym_addr`中，後續再根據`type`來決定重定位的方式；而如果遍歷完所有依賴庫都沒有找到，則嘗試從`symtab_[sym].st_value`裡獲取。

```cpp
template<typename ElfRelIteratorT>
bool soinfo::relocate(ElfRelIteratorT&& rel_iterator) {
    for (size_t idx = 0; rel_iterator.has_next(); ++idx) {
        const auto rel = rel_iterator.next();
        if (rel == nullptr) {
            return false;
        }

        ElfW(Word) type = ELFW(R_TYPE)(rel->r_info);
        ElfW(Word) sym = ELFW(R_SYM)(rel->r_info);

        // reloc 指向需要重定向的內容, 根據type來決定重定向成什麼
        ElfW(Addr) reloc = static_cast<ElfW(Addr)>(rel->r_offset + load_bias);
        ElfW(Addr) sym_addr = 0;
        const char* sym_name = nullptr;
        ElfW(Addr) addend = Utils::get_addend(rel, reloc);

//        LOGD("Processing \"%s\" relocation at index %zd", get_realpath(), idx);
        if (type == R_GENERIC_NONE) {
            continue;
        }

        const ElfW(Sym)* s = nullptr;
        soinfo* lsi = nullptr;

        if (sym != 0) {

            sym_name = get_string(symtab_[sym].st_name);
            LOGD("sym = %lx   sym_name: %s   st_value: %lx", sym, sym_name, symtab_[sym].st_value);

            for(int s = 0; s < needed_count; s++) {
                void* handle = dlopen(get_string(myneed[s]),RTLD_NOW);
                sym_addr = reinterpret_cast<Elf64_Addr>(dlsym(handle, sym_name));
                if(sym_addr) break;

            }

            if(!sym_addr) {
                if(symtab_[sym].st_value != 0) {
                    sym_addr = load_bias + symtab_[sym].st_value;
                }else {
                    LOGE("%s find addr fail", sym_name);
                }

            }else {
                LOGD("%s find addr success : %lx", sym_name, sym_addr);
            }
        }

        LOGD("reloc addr: %x", (reloc - base));
        LOGD("type: %x", type);
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

                    ElfW(Addr) ifunc_addr = Utils::call_ifunc_resolver(load_bias + addend);
                    *reinterpret_cast<ElfW(Addr)*>(reloc) = ifunc_addr;
                }
                break;

#if defined(__aarch64__)
                case R_AARCH64_ABS64:
                    LOGD("R_AARCH64_ABS64  %lx    addend: %lx", sym_addr + addend, addend);
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
        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
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
        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
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
        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
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
        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
               sym_addr + addend - rel->r_offset, min_value, max_value);
        return false;
      }
    }
    break;

  case R_AARCH64_COPY:
    LOGE("%s R_AARCH64_COPY relocations are not supported", get_realpath());
    return false;
  case R_AARCH64_TLS_TPREL64:
    LOGD("RELO TLS_TPREL64 *** %16llx <- %16llx - %16llx\n",
               reloc, (sym_addr + addend), rel->r_offset);
    break;
  case R_AARCH64_TLS_DTPREL32:
      LOGD("RELO TLS_DTPREL32 *** %16llx <- %16llx - %16llx\n",
               reloc, (sym_addr + addend), rel->r_offset);
    break;
#endif
            default:
                LOGE("unknown reloc type %d @ %p (%zu)  sym_name: %s", type, rel, idx, sym_name);
                return false;
        }
//    */
    }
    return true;
}
```

## `call_constructors`

調用soinfo的構建函數：`.init`和`.init_array`內所有函數

```cpp
// 使被加載的so有執行權限, 否則在調用.init_array時會報錯
mprotect(reinterpret_cast<void *>(load_bias_), sb.st_size, PROT_READ | PROT_WRITE | PROT_EXEC);
//...

// 5. 調用.init和.init_array
si_->call_constructors();
```

原版Linker在調用`.init`和`.init_array`時傳入的是`0, nullptr, nullptr`，我這裡與其保持一致。

```cpp
void soinfo::call_constructors() {
    // 對於so文件來說, 由於沒有_start函數
    // 因此init_func_和init_array_都無法傳參, 只能是默認值

    if(init_func_) {
        LOGD("init func: %p", init_func_);
        init_func_(0, nullptr, nullptr);
    }
    if(init_array_) {
        for(int i = 0; i < init_array_count_; i++) {
            if(!init_array_[i])continue;
            init_array_[i](0, nullptr, nullptr);
        }
    }

}
```

## 完整代碼

項目地址：https://github.com/ngiokweng/ng1ok-linker

# 測試

隨便寫一個so作為待加載的so( 名為`libdemo1.so` )，內容如下，將它push到`/data/local/tmp`。

```cpp
#include <jni.h>
#include <string>
#include <android/log.h>

#define  TAG    "nglog"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__)

extern "C" JNIEXPORT jstring JNICALL
Java_ng1ok_demo1_NativeLib_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_ng1ok_linker_MainActivity_demo1Func(JNIEnv *env, jobject thiz) {
    LOGD("Java_ng1ok_linker_MainActivity_demo1Func calleeeeeeeddddddddd");
    std::string str = "Java_ng1ok_linker_MainActivity_demo1Func";

    return env->NewStringUTF(str.c_str());
}

__attribute__((constructor()))
void sayHello(){
    LOGD("[from libdemo1.so .init_array] Hello~~~");
}

extern "C" {
    void _init(void){
        LOGD("[from libdemo1.so .init] _init~~~~");
    }
}
```

Demo的用例如下，實例化`MyLoader`，調用`run`函數加載指定路徑的so。

![Untitled](Untitled1.png)

Java層的`onCreate`如下，在`test`之後調用待加載so裡的`demo1Func`函數。

![Untitled](Untitled2.png)

輸出如下，大功告成~

![Untitled](Untitled3.png)

# 結語

前前後後弄了兩、三周的時間，最終總算是弄好了這一個小Demo。自知該Demo仍有很多不足之處( 如無法捕獲try…catch )，而且只經過簡單的測試，定然存在諸多的BUG，歡迎各位大佬的指正！！有任何也問題歡迎評論，或者私聊我/找我聊聊天都可以！！！