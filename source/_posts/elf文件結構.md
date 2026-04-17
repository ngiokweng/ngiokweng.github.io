---
title: elf文件結構
date: 2024-05-30 16:46:47
tags:
- elf
categories: elf
keywords:
- elf
description: elf 文件結構
cover: Untitled.png
---

## 前言

在研究360加固時，發現自己對elf文件完全不理解，於是決定先好好學下elf文件結構。

本文以AOSP版本`Oreo8.1.0_r33`作為研究對象，由上到下逐漸解析一個so文件。

## Elf Header

32位elf文件的Elf Header的結構體是`Elf32_Ehdr`，64位基本一致，除了`e_ident[4]`。

同時也列出一些會用到的常量( 宏定義/枚舉值 )如下：

```cpp
/*=================== art/runtime/elf.h ===================*/

struct Elf32_Ehdr {
  unsigned char e_ident[EI_NIDENT]; // ELF Identification bytes
  Elf32_Half    e_type;      // Type of file (see ET_* below)
  Elf32_Half    e_machine;   // Required architecture for this file (see EM_*)
  Elf32_Word    e_version;   // Must be equal to 1
  Elf32_Addr    e_entry;     // Address to jump to in order to start program
  Elf32_Off     e_phoff;     // Program header table's file offset, in bytes
  Elf32_Off     e_shoff;     // Section header table's file offset, in bytes
  Elf32_Word    e_flags;     // Processor-specific flags
  Elf32_Half    e_ehsize;    // Size of ELF header, in bytes
  Elf32_Half    e_phentsize; // Size of an entry in the program header table
  Elf32_Half    e_phnum;     // Number of entries in the program header table
  Elf32_Half    e_shentsize; // Size of an entry in the section header table
  Elf32_Half    e_shnum;     // Number of entries in the section header table
  Elf32_Half    e_shstrndx;  // Sect hdr table index of sect name string table
};

// e_ident size and indices.
enum {
  EI_MAG0       = 0,          // File identification index.
  EI_MAG1       = 1,          // File identification index.
  EI_MAG2       = 2,          // File identification index.
  EI_MAG3       = 3,          // File identification index.
  EI_CLASS      = 4,          // File class.
  EI_DATA       = 5,          // Data encoding.
  EI_VERSION    = 6,          // File version.
  EI_OSABI      = 7,          // OS/ABI identification.
  EI_ABIVERSION = 8,          // ABI version.
  EI_PAD        = 9,          // Start of padding bytes.
  EI_NIDENT     = 16          // Number of bytes in e_ident.
};

// File types
enum {
  ET_NONE   = 0,      // No file type
  ET_REL    = 1,      // Relocatable file
  ET_EXEC   = 2,      // Executable file
  ET_DYN    = 3,      // Shared object file
  ET_CORE   = 4,      // Core file
  ET_LOPROC = 0xff00, // Beginning of processor-specific codes
  ET_HIPROC = 0xffff  // Processor-specific
};

// Machine architectures
enum {
	// ...
  EM_AARCH64       = 183, // ARM AArch64
  // ...
};

/*=================== toolchain/binutils/binutils-2.25/libiberty/simple-object-elf.c ===================*/
#define ELFCLASSNONE	      0	/* Invalid class */
#define ELFCLASS32	      1	/* 32-bit objects */
#define ELFCLASS64	      2	/* 64-bit objects */
```

一些個人認為比較重要的字段：

- `e_ident`：長度為`EI_NIDENT`( 定義為`16` )，`e_ident[0~3]`是elf文件的標誌，固定為`7F 45 4C 46`，第`e_ident[4]`用來表示該ELF是32位/64位，`1`是前者`2`是後者。
- `e_type`：文件類型，取值範圍是`ET_`開頭的枚舉值，如so文件就是`3`。
- `e_machine`：該文件所需的架構，取值範圍是EM_開頭的枚舉值，如arm64是`183`。
- `e_entry`：是一個相對偏移，指向程序的起始地址，對於一個可執行的elf文件來說，它指向`start`函數的起始地址，而對於so文件來說，它為`0`。
- `e_phoff`：Program Header Table的偏移。
- `e_shoff`：Section Header Table的偏移。
- `e_ehsize`：Elf Header的大小。
- `e_phentsize`：Program Header Table每個元素的大小。
- `e_phnum`：Program Header Table中元素的數量。
- `e_shentsize`：Section Header Table每個元素的大小。
- `e_shnum`：Section Header Table中元素的數量。
- `e_shstrndx`：是Section Header Table的一個索引值，指向了`.shstrtab`節區( 這個節區存儲著所有節區的名字，例如`.text` )在Section Header Table裡的索引值。

## Program Header

```cpp
/*=================== art/runtime/elf.h ===================*/

// Program header for ELF32.
struct Elf32_Phdr {
  Elf32_Word p_type;   // Type of segment
  Elf32_Off  p_offset; // File offset where segment is located, in bytes
  Elf32_Addr p_vaddr;  // Virtual address of beginning of segment
  Elf32_Addr p_paddr;  // Physical address of beginning of segment (OS-specific)
  Elf32_Word p_filesz; // Num. of bytes in file image of segment (may be zero)
  Elf32_Word p_memsz;  // Num. of bytes in mem image of segment (may be zero)
  Elf32_Word p_flags;  // Segment flags
  Elf32_Word p_align;  // Segment alignment constraint
};

// Segment types.
enum {
  PT_NULL    = 0, // Unused segment.
  PT_LOAD    = 1, // Loadable segment. (該字後表示可以被加載到內存執行的)
  PT_DYNAMIC = 2, // Dynamic linking information.
  PT_INTERP  = 3, // Interpreter pathname.
  PT_NOTE    = 4, // Auxiliary information.
  PT_SHLIB   = 5, // Reserved.
  PT_PHDR    = 6, // The program header table itself.
  PT_TLS     = 7, // The thread-local storage template.
	// ...
};

// Segment flag bits.
enum : unsigned {
  PF_X        = 1,         // Execute
  PF_W        = 2,         // Write
  PF_R        = 4,         // Read
  PF_MASKOS   = 0x0ff00000,// Bits for operating system-specific semantics.
  PF_MASKPROC = 0xf0000000 // Bits for processor-specific semantics.
};
```

一些個人認為比較重要的字段：

- `p_type`：當前segment的類型，如`PT_LOAD`、`PT_DYNAMIC`。
- `p_offset`：當前segment的文件偏移。
- `p_vaddr`：加載進內存後的虛擬地址。
- `p_paddr`：加載進內存後的實際物理地址。
- `p_filesz`：當前segment在文件中的大小( 單位：byte )。
- `p_memsz`：當前segment在內存中的大小( 單位：byte )。
- `p_flags`：當前段的屬性，如可讀`PF_R`、可寫`PF_X` 等等。
- `p_align`：內存對齊的字節數。

### Segment的類型

記錄一些常見`p_type`

`PT_LOAD`：一個可執行文件最少要有一個該類型的segment，該類型描述表示當前segment是可裝載的，即當前segment會被裝載或映射到內存中。一段來說elf文件通常會有2個`PT_LOAD`的segment，分別是存放代碼的`text`段和存放全局變量和動態鏈接信息的`data`段。

`PT_PHDR`：表示program header table本身。

`PT_DYNAMIC`：該類型的segment header指定動態鏈接的一些信息。

## Section Header

```cpp
/*=================== art/runtime/elf.h ===================*/

// Section header.
struct Elf32_Shdr {
  Elf32_Word sh_name;      // Section name (index into string table)
  Elf32_Word sh_type;      // Section type (SHT_*)
  Elf32_Word sh_flags;     // Section flags (SHF_*)
  Elf32_Addr sh_addr;      // Address where section is to be loaded
  Elf32_Off  sh_offset;    // File offset of section data, in bytes
  Elf32_Word sh_size;      // Size of section, in bytes
  Elf32_Word sh_link;      // Section type-specific header table index link
  Elf32_Word sh_info;      // Section type-specific extra information
  Elf32_Word sh_addralign; // Section address alignment
  Elf32_Word sh_entsize;   // Size of records contained within the section
};

// Section types.
enum : unsigned {
  SHT_NULL          = 0,  // No associated section (inactive entry).
  SHT_PROGBITS      = 1,  // Program-defined contents.
  SHT_SYMTAB        = 2,  // Symbol table.
  SHT_STRTAB        = 3,  // String table.
  SHT_RELA          = 4,  // Relocation entries; explicit addends.
  SHT_HASH          = 5,  // Symbol hash table.
  SHT_DYNAMIC       = 6,  // Information for dynamic linking.
  // ...
}

// Section flags.
enum : unsigned {
  // Section data should be writable during execution.
  SHF_WRITE = 0x1,

  // Section occupies memory during program execution.
  SHF_ALLOC = 0x2,

  // Section contains executable machine instructions.
  SHF_EXECINSTR = 0x4,
  
  //...
}
```

一些個人認為比較重要的字段：

- `sh_name`：是`shstrtab`表( 見Elf Header的`e_shstrndx`字段 )的一個索引，該索引指向了當前section的名字。
- `sh_type`：當前section的類型，取值範圍是`SHT_`開頭的枚舉值，如`SHT_DYNAMIC`代表section與動態鏈接有關。
- `sh_flags`：當前section的屬性，取值範圍是`SHF_`開頭的枚舉值，如`SHF_WRITE`代表section在執行過程中應是可寫的。
- `sh_addr`：當前section的加載進內存的地址( 內存偏移 )。
- `sh_offset`：當前section的文件偏移。
- `sh_size`：當前section大小( 單位：byte )。
- `sh_addralign`：內存對齊的字節大小( 某些Section帶有地址對齊約束，例如某個節區保存了一個DWROD，那麼系統必須保證整個節區能夠按雙字對齊。`sh_addr%sh_addralign`必須為`0`，目前僅允許取值為0和2的冪次數。數值為`0`、`1`表示節區沒有對齊約束 )。
- `sh_entsize`：當前節區中每個項占用的字節數。

## 補充：Segment與Section

參考：[https://www.cnblogs.com/jiqingwu/p/elf_format_research_01.html](https://www.cnblogs.com/jiqingwu/p/elf_format_research_01.html)

ELF全稱是Executable and Linking Format，即可執行和可鏈接的格式，下圖分別是ELF文件的鏈接視圖和執行視圖。

可以看到，鏈接視圖由Section組成，而執行視圖由Segment組成。對前者來說Program header table( Segment )不是必要的，對後者來說Section header table不是必要的。

[鏈接過程](https://blog.csdn.net/weixin_44256803/article/details/108359900)：**鏈接器將目標文件中屬性相同的Section合並成一個集合，此集合便稱為Segment**

![Untitled](Untitled.png)

## Sections

記錄幾個比較重要的section，以後有需要再補充😎

### Symbol Table ( `.symtab` )

Symbol Table是一個特殊的Section( 是名為`.symtab`的Section Header指向的那個節區 )，它包含了所有的符號信息，**包括已定義的符號和未定義的符號**。

```cpp
/*=================== art/runtime/elf.h ===================*/

// Symbol table entries for ELF32.
struct Elf32_Sym {
  Elf32_Word    st_name;  // Symbol name (index into string table)
  Elf32_Addr    st_value; // Value or address associated with the symbol
  Elf32_Word    st_size;  // Size of the symbol
  unsigned char st_info;  // Symbol's type and binding attributes
  unsigned char st_other; // Must be zero; reserved
  Elf32_Half    st_shndx; // Which section (header table index) it's defined in
};

// Special section indices.
enum {
  SHN_UNDEF     = 0,      // Undefined, missing, irrelevant, or meaningless
  SHN_LORESERVE = 0xff00, // Lowest reserved index
  SHN_LOPROC    = 0xff00, // Lowest processor-specific index
  SHN_HIPROC    = 0xff1f, // Highest processor-specific index
  SHN_LOOS      = 0xff20, // Lowest operating system-specific index
  SHN_HIOS      = 0xff3f, // Highest operating system-specific index
  SHN_ABS       = 0xfff1, // Symbol has absolute value; does not need relocation
  SHN_COMMON    = 0xfff2, // FORTRAN COMMON or C external global variables
  SHN_XINDEX    = 0xffff, // Mark that the index is >= SHN_LORESERVE
  SHN_HIRESERVE = 0xffff  // Highest reserved index
};

// Symbol bindings.
enum {
  STB_LOCAL = 0,   // Local symbol, not visible outside obj file containing def
  STB_GLOBAL = 1,  // Global symbol, visible to all object files being combined
  STB_WEAK = 2,    // Weak symbol, like global but lower-precedence
  STB_LOOS   = 10, // Lowest operating system-specific binding type
  STB_HIOS   = 12, // Highest operating system-specific binding type
  STB_LOPROC = 13, // Lowest processor-specific binding type
  STB_HIPROC = 15  // Highest processor-specific binding type
};
```

一些個人認為比較重要的字段：

- `st_name`：`.strtab`節區( 由Section Header定位到對應節區 )的一個索引值，指向某符號名。
- `st_value`：這個值在不同的上下文中有不同的意義：
    1. 在可重定位文件中，若符號的`st_shndx`等於`SHN_COMMON`，剛`st_value`表示該符號的對齊字節數。
    2. 在可重定位文件中，若一個符號是已定義時( 何為已定義？後面會給出 )，`st_value`表示section內的偏移( section由`st_shndx`指定 )。
    3. 在可執行文件和so文件中，`st_value`是一個虛擬地址，這時不需要關心`st_shndx`的值。
- `st_info`：符號的綁定屬性，取值範圍是`STB_`開頭的枚舉值，如`STB_LOCAL`是局部符號，局部符號就是一種未定義的符號。
- `st_shndx`：當符號已定義時，它代表Section Header Table的某個下標索引，配合`st_value`定位到對應該符號。

何為已定義的符號？GPT給出的回答如下，僅供參考：

![Untitled](Untitled1.png)

### **.dynamic**

Section Header Table中名為`.dynamic`的那項指向的節表，其實是一個`Elf32_Dyn`數組，32位每個元素占8字節，64位則占16字節，以下列出了32位的。

```cpp
/*=================== art/runtime/elf.h ===================*/

// Dynamic table entry for ELF32.
struct Elf32_Dyn
{
  Elf32_Sword d_tag;            // Type of dynamic table entry.
  union
  {
      Elf32_Word d_val;         // Integer value of entry.
      Elf32_Addr d_ptr;         // Pointer value of entry.
  } d_un;
};

// Dynamic table entry tags.
enum {
  DT_NULL         = 0,        // Marks end of dynamic array.
  DT_NEEDED       = 1,        // String table offset of needed library.
  DT_PLTRELSZ     = 2,        // Size of relocation entries in PLT.
  DT_PLTGOT       = 3,        // Address associated with linkage table.
  DT_HASH         = 4,        // Address of symbolic hash table.
  DT_STRTAB       = 5,        // Address of dynamic string table.
	// ....
}

```

字段解析：

- `d_tag`：該字段決定了這個是什麼類別，以及如何解析`d_un`，取值範圍是`DT_`開頭的枚舉值。
- `d_un`：根據`d_tag`決定是使用`d_val`或`d_ptr`。

例子：

當`d_tag`為`DT_NEEDED`時，使用`d_un`的`d_val`，而這時`d_val`代表字符表的下標索引( 這個字符表是由`DT_STRTAB`確定 )

其他更多可以參考：

- [https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html](https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html)
- [https://ctf-wiki.org/executable/elf/structure/dynamic-sections/](https://ctf-wiki.org/executable/elf/structure/dynamic-sections/)
- [https://cloud.tencent.com/developer/article/2216942](https://cloud.tencent.com/developer/article/2216942)

## 參考

- https://bbs.kanxue.com/thread-272077.htm#msg_header_h1_5
- https://www.cnblogs.com/AndroidBinary/p/15364043.html#213-pt_load段
- https://blog.csdn.net/astrotycoon/article/details/42042991
- https://www.bluepuni.com/archives/elf-symbols/#符号的值