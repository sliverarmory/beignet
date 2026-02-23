/*
 * Based on Metasploit's OSX Stager Code
 * Copyright: 2006-2026, Rapid7, Inc.
 * License: BSD-3-clause
 * https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/osx/stager/main.c
 *
 * NOTE: This file is intentionally "freestanding-ish" and avoids calling libc.
 * It is built into a Mach-O, then relevant segments are extracted into a flat
 * in-memory image and executed as shellcode.
 *
 * Diskless requirement:
 * - The primary load path must never write to disk (no open/write/unlink temp files).
 * - arm64 uses dyld4's JustInTimeLoader to load a Mach-O image from memory.
 * - x86_64 uses a local in-memory mapper + chained-fixups engine and resolves
 *   imports with dlsym from already-loaded images.
 *
 * Platform:
 * - darwin/arm64 and darwin/amd64
 */

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>

// Optional debug output is intentionally disabled in the embedded loader.
#define print(...) do { } while (0)
#define printf(...) do { } while (0)

#ifndef LC_DYLD_CHAINED_FIXUPS
#define LC_DYLD_CHAINED_FIXUPS 0x80000034u
#endif

struct dyld_chained_fixups_header
{
  uint32_t fixups_version;
  uint32_t starts_offset;
  uint32_t imports_offset;
  uint32_t symbols_offset;
  uint32_t imports_count;
  uint32_t imports_format;
  uint32_t symbols_format;
};

struct dyld_chained_starts_in_image
{
  uint32_t seg_count;
  uint32_t seg_info_offset[1];
};

struct dyld_chained_starts_in_segment
{
  uint32_t size;
  uint16_t page_size;
  uint16_t pointer_format;
  uint64_t segment_offset;
  uint32_t max_valid_pointer;
  uint16_t page_count;
  uint16_t page_start[1];
};

enum {
  DYLD_CHAINED_PTR_START_NONE = 0xFFFF,
  DYLD_CHAINED_PTR_START_MULTI = 0x8000,
  DYLD_CHAINED_PTR_START_LAST = 0x8000,
  DYLD_CHAINED_PTR_64_OFFSET = 6,
  DYLD_CHAINED_IMPORT = 1,
  DYLD_CHAINED_IMPORT_ADDEND = 2,
  DYLD_CHAINED_IMPORT_ADDEND64 = 3,
};

struct dyld_chained_import
{
  uint32_t lib_ordinal : 8, weak_import : 1, name_offset : 23;
};

struct dyld_chained_import_addend
{
  uint32_t lib_ordinal : 8, weak_import : 1, name_offset : 23;
  int32_t addend;
};

struct dyld_chained_import_addend64
{
  uint64_t lib_ordinal : 16, weak_import : 1, reserved : 15, name_offset : 32;
  uint64_t addend;
};

struct dyld_cache_header {
  char magic[16];
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
  uint8_t uuid[16];
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
  uint32_t formatVersion : 8, dylibsExpectedOnDisk : 1, simulator : 1, locallyBuiltCache : 1,
      builtFromChainedFixups : 1, padding : 20;
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
  uint8_t symbolFileUUID[16];
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

// Diagnostics is a C++ type in dyld. We treat it opaquely and call its
// constructor/methods via resolved function pointers.

// Stored in PrebuiltLoaders and generated on the fly by JustInTimeLoaders.
struct Region
{
  uint64_t vmOffset : 59,
           perms : 3,
           isZeroFill : 1,
           readOnlyData : 1;
  uint32_t fileOffset;
  uint32_t fileSize;
};

struct ArrayOfRegions
{
  struct Region* _elements;
  uintptr_t _allocCount;
  uintptr_t _usedCount;
};

struct ArrayOfLoaderPointers
{
  void** _elements;
  uintptr_t _allocCount;
  uintptr_t _usedCount;
};

struct FileID
{
  uint64_t iNode;
  uint64_t modTime;
  bool isValid;
};

struct LoadChain
{
  const void* previous;
  const void* image;
};

struct LoadOptions;
typedef const void* (^Finder)(void* diag, uint64_t, const char* loadPath, const struct LoadOptions* options);
typedef void (^Missing)(const char* pathNotFound);
struct LoadOptions
{
  bool launching;
  bool staticLinkage;
  bool canBeMissing;
  bool rtldLocal;
  bool rtldNoDelete;
  bool rtldNoLoad;
  bool insertedDylib;
  bool canBeDylib;
  bool canBeBundle;
  bool canBeExecutable;
  bool forceUnloadable;
  bool useFallBackPaths;
  struct LoadChain* rpathStack;
  Finder finder;
  Missing pathNotFoundHandler;
};

struct Loaded {
  void* _allocator;
  void** elements;
  size_t size;
  size_t capacity;
};

struct PartialLoader {
  const uint32_t magic;
  const uint16_t isPrebuilt : 1,
      dylibInDyldCache : 1,
      hasObjC : 1,
      mayHavePlusLoad : 1,
      hasReadOnlyData : 1,
      neverUnload : 1,
      leaveMapped : 1,
      padding2 : 8;
  const void* mappedAddress;
  uint64_t pathOffset : 16,
      dependentsSet : 1,
      fixUpsApplied : 1,
      inited : 1,
      hidden : 1,
      altInstallName : 1,
      lateLeaveMapped : 1,
      overridesCache : 1,
      allDepsAreNormal : 1,
      overrideIndex : 15,
      depCount : 16,
      padding : 9;
  uint64_t sliceOffset;
  struct FileID fileIdent;
  const void* overridePatches;
  const void* overridePatchesCatalystMacTwin;
  uint32_t exportsTrieRuntimeOffset;
  uint32_t exportsTrieSize;
  void* dependents[1];
};

struct DyldCacheDataConstLazyScopedWriter {
  void** _state;
  bool _wasMadeWritable;
};

// lsl::MemoryManager::lockGuard() returns an RAII guard by value. We only need
// the first word (a pointer to the underlying Lock) to call Lock::unlock().
// The actual type is a C++ class with a non-trivial destructor, so it is
// returned indirectly (sret in x8). Make this struct large enough to ensure
// the same ABI in C.
struct LockGuardRet
{
  void* lock;
  uint64_t _pad[3];
};

typedef void (*WithVMLayout_ptr)(void* ma, void* diag, void (^callback)(const void* layout));
typedef void* (*JustInTimeLoaderMake2_ptr)(void* apis, void* ma, const char* path, const struct FileID* fileId,
                                          uint64_t sliceOffset, bool willNeverUnload, bool leaveMapped, bool overridesCache,
                                          uint16_t overridesDylibIndex, const void* layout);
typedef void* (*AnalyzeSegmentsLayout_ptr)(void* ma, uintptr_t* vmSpace, bool* hasZeroFill);
typedef void* (*WithRegions_ptr)(void* ma, void* callback);
typedef void (*LoadDependents_ptr)(void* topLoader, void* diag, void* apis, const struct LoadOptions* lo);
typedef void (*RunInitializers_ptr)(void* topLoader, void* apis);
typedef void (*IncDlRefCount_ptr)(void* apis, void* topLoader);
typedef void (*ApplyFixups_ptr)(void* ldr, void* diag, void* apis,
                               struct DyldCacheDataConstLazyScopedWriter* dcd, bool b, void* outPairs);
typedef void* (*MemoryManager_ptr)(void);
typedef struct LockGuardRet (*LockGuard_ptr)(void* mm);
typedef void (*WriteProtect_ptr)(void* mm, bool protect);
typedef void (*LockLock_ptr)(void* lock);
typedef void (*LockUnlock_ptr)(void* lock);
typedef void (*WithProtectedStack_ptr)(void* protectedStack, void (^callback)(void));

typedef void (*DiagnosticsCtor_ptr)(void* diag);
typedef void (*DiagnosticsClearError_ptr)(void* diag);
typedef bool (*DiagnosticsHasError_ptr)(const void* diag);

typedef void* (*Dlsym_ptr)(void* handle, const char* symbol);

static void* syscall_mmap(void* addr, uint64_t length, int prot, int flags, int fd, uint64_t offset);
static int syscall_mprotect(void* addr, uint64_t length, int prot);
static void* find_symbol(uint64_t base, const char* symbol, uint64_t offset);
static uint64_t find_cache_image(uint64_t shared_region_start, const struct dyld_cache_header* header, const char* wantPath, uint64_t slide);

static int string_compare(const char* s1, const char* s2)
{
  while (*s1 != '\0' && *s1 == *s2) {
    s1++;
    s2++;
  }
  return (*(unsigned char*)s1) - (*(unsigned char*)s2);
}

static void* memcpy2(void* dest, const void* src, size_t len)
{
  char* d = dest;
  const char* s = src;
  while (len--) {
    *d++ = *s++;
  }
  return dest;
}

static void memzero2(void* dest, size_t len)
{
  unsigned char* d = (unsigned char*)dest;
  while (len--) {
    *d++ = 0;
  }
}

static uint64_t align_up_u64(uint64_t v, uint64_t align)
{
  if (align == 0) {
    return v;
  }
  uint64_t mask = align - 1;
  return (v + mask) & ~mask;
}

static size_t bounded_cstrlen(const char* s, size_t maxLen)
{
  size_t n = 0;
  while (n < maxLen && s[n] != '\0') {
    n++;
  }
  return n;
}

#define MAX_MACHO_SEGMENTS 32u

struct MappedSegment {
  uint64_t vmaddr;
  uint64_t vmsize;
  uint64_t fileoff;
  uint64_t filesize;
  int initprot;
};

struct MappedImageX86 {
  uintptr_t imageBase; // runtime address corresponding to minVmAddr
  uint64_t minVmAddr;
  uint64_t maxVmAddr;
  uint64_t slide;
  uintptr_t machHeaderAddr;
  struct MappedSegment segs[MAX_MACHO_SEGMENTS];
  uint32_t segCount;
};

static bool map_macho_image_x86(const void* image, uint64_t imageLen, struct MappedImageX86* outImage)
{
  if (!image || !outImage || imageLen < sizeof(struct mach_header_64)) {
    return false;
  }

  const struct mach_header_64* mh = (const struct mach_header_64*)image;
  if (mh->magic != MH_MAGIC_64) {
    return false;
  }
  if ((uint64_t)sizeof(*mh) + (uint64_t)mh->sizeofcmds > imageLen) {
    return false;
  }

  struct MappedImageX86 mapped;
  mapped.segCount = 0;
  mapped.minVmAddr = (uint64_t)-1;
  mapped.maxVmAddr = 0;
  mapped.imageBase = 0;
  mapped.slide = 0;
  mapped.machHeaderAddr = 0;

  uint64_t headerVmAddr = (uint64_t)-1;

  const struct load_command* lc = (const struct load_command*)((const char*)image + sizeof(*mh));
  uint64_t cmdBytes = mh->sizeofcmds;
  while (cmdBytes >= sizeof(struct load_command)) {
    if (lc->cmdsize < sizeof(struct load_command) || lc->cmdsize > cmdBytes) {
      return false;
    }

    if (lc->cmd == LC_SEGMENT_64) {
      const struct segment_command_64* seg = (const struct segment_command_64*)lc;
      if (seg->vmsize != 0) {
        if (mapped.segCount >= MAX_MACHO_SEGMENTS) {
          return false;
        }
        if (seg->filesize > 0 && (seg->fileoff > imageLen || seg->filesize > (imageLen - seg->fileoff))) {
          return false;
        }

        mapped.segs[mapped.segCount].vmaddr = seg->vmaddr;
        mapped.segs[mapped.segCount].vmsize = seg->vmsize;
        mapped.segs[mapped.segCount].fileoff = seg->fileoff;
        mapped.segs[mapped.segCount].filesize = seg->filesize;
        mapped.segs[mapped.segCount].initprot = (int)seg->initprot;
        mapped.segCount++;

        if (seg->vmaddr < mapped.minVmAddr) {
          mapped.minVmAddr = seg->vmaddr;
        }
        uint64_t segEnd = seg->vmaddr + seg->vmsize;
        if (segEnd < seg->vmaddr) {
          return false;
        }
        if (segEnd > mapped.maxVmAddr) {
          mapped.maxVmAddr = segEnd;
        }

        if (seg->fileoff == 0 && seg->filesize >= sizeof(struct mach_header_64)) {
          headerVmAddr = seg->vmaddr;
        }
      }
    }

    cmdBytes -= lc->cmdsize;
    lc = (const struct load_command*)((const char*)lc + lc->cmdsize);
  }
  if (cmdBytes != 0 || mapped.segCount == 0 || mapped.maxVmAddr <= mapped.minVmAddr || headerVmAddr == (uint64_t)-1) {
    return false;
  }

  uint64_t vmSpan = align_up_u64(mapped.maxVmAddr - mapped.minVmAddr, 0x1000);
  if (vmSpan == 0) {
    return false;
  }

  void* mapBaseP = syscall_mmap(0, vmSpan, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (mapBaseP == (void*)-1 || mapBaseP == 0) {
    return false;
  }

  uintptr_t mapBase = (uintptr_t)mapBaseP;
  for (uint32_t i = 0; i < mapped.segCount; i++) {
    const struct MappedSegment* seg = &mapped.segs[i];
    if (seg->vmaddr < mapped.minVmAddr) {
      return false;
    }
    uintptr_t dst = mapBase + (uintptr_t)(seg->vmaddr - mapped.minVmAddr);
    if (seg->filesize > 0) {
      memcpy2((void*)dst, (const void*)((const char*)image + seg->fileoff), (size_t)seg->filesize);
    }
    if (seg->vmsize > seg->filesize) {
      memzero2((void*)(dst + (uintptr_t)seg->filesize), (size_t)(seg->vmsize - seg->filesize));
    }
  }

  mapped.imageBase = mapBase;
  mapped.slide = mapBase - mapped.minVmAddr;
  mapped.machHeaderAddr = mapBase + (uintptr_t)(headerVmAddr - mapped.minVmAddr);

  outImage->imageBase = mapped.imageBase;
  outImage->minVmAddr = mapped.minVmAddr;
  outImage->maxVmAddr = mapped.maxVmAddr;
  outImage->slide = mapped.slide;
  outImage->machHeaderAddr = mapped.machHeaderAddr;
  outImage->segCount = mapped.segCount;
  for (uint32_t i = 0; i < mapped.segCount; i++) {
    outImage->segs[i].vmaddr = mapped.segs[i].vmaddr;
    outImage->segs[i].vmsize = mapped.segs[i].vmsize;
    outImage->segs[i].fileoff = mapped.segs[i].fileoff;
    outImage->segs[i].filesize = mapped.segs[i].filesize;
    outImage->segs[i].initprot = mapped.segs[i].initprot;
  }
  return true;
}

static void apply_segment_protections_x86(const struct MappedImageX86* mapped)
{
  if (!mapped) {
    return;
  }
  for (uint32_t i = 0; i < mapped->segCount; i++) {
    const struct MappedSegment* seg = &mapped->segs[i];
    if (seg->vmsize == 0 || seg->vmaddr < mapped->minVmAddr) {
      continue;
    }
    uintptr_t segAddr = mapped->imageBase + (uintptr_t)(seg->vmaddr - mapped->minVmAddr);
    uint64_t segSize = align_up_u64(seg->vmsize, 0x1000);
    (void)syscall_mprotect((void*)segAddr, segSize, seg->initprot);
  }
}

static const struct linkedit_data_command* find_chained_fixups_command(const void* image, uint64_t imageLen)
{
  if (!image || imageLen < sizeof(struct mach_header_64)) {
    return 0;
  }
  const struct mach_header_64* mh = (const struct mach_header_64*)image;
  if (mh->magic != MH_MAGIC_64 || (uint64_t)sizeof(*mh) + (uint64_t)mh->sizeofcmds > imageLen) {
    return 0;
  }
  const struct load_command* lc = (const struct load_command*)((const char*)image + sizeof(*mh));
  uint64_t cmdBytes = mh->sizeofcmds;
  while (cmdBytes >= sizeof(struct load_command)) {
    if (lc->cmdsize < sizeof(struct load_command) || lc->cmdsize > cmdBytes) {
      return 0;
    }
    if (lc->cmd == LC_DYLD_CHAINED_FIXUPS) {
      return (const struct linkedit_data_command*)lc;
    }
    cmdBytes -= lc->cmdsize;
    lc = (const struct load_command*)((const char*)lc + lc->cmdsize);
  }
  return 0;
}

static bool decode_import_entry(const uint8_t* imports, uint64_t importsLen, uint32_t importsFormat, uint32_t importIndex,
                                uint32_t importsCount, int* outLibOrdinal, bool* outWeakImport, uint32_t* outNameOffset,
                                int64_t* outImportAddend)
{
  if (!imports || !outLibOrdinal || !outWeakImport || !outNameOffset || !outImportAddend || importIndex >= importsCount) {
    return false;
  }

  if (importsFormat == DYLD_CHAINED_IMPORT) {
    uint64_t need = (uint64_t)(importIndex + 1) * sizeof(struct dyld_chained_import);
    if (need > importsLen) {
      return false;
    }
    const struct dyld_chained_import* imp = (const struct dyld_chained_import*)imports + importIndex;
    *outLibOrdinal = (int)(int8_t)imp->lib_ordinal;
    *outWeakImport = (imp->weak_import != 0);
    *outNameOffset = imp->name_offset;
    *outImportAddend = 0;
    return true;
  }
  if (importsFormat == DYLD_CHAINED_IMPORT_ADDEND) {
    uint64_t need = (uint64_t)(importIndex + 1) * sizeof(struct dyld_chained_import_addend);
    if (need > importsLen) {
      return false;
    }
    const struct dyld_chained_import_addend* imp = (const struct dyld_chained_import_addend*)imports + importIndex;
    *outLibOrdinal = (int)(int8_t)imp->lib_ordinal;
    *outWeakImport = (imp->weak_import != 0);
    *outNameOffset = imp->name_offset;
    *outImportAddend = imp->addend;
    return true;
  }
  if (importsFormat == DYLD_CHAINED_IMPORT_ADDEND64) {
    uint64_t need = (uint64_t)(importIndex + 1) * sizeof(struct dyld_chained_import_addend64);
    if (need > importsLen) {
      return false;
    }
    const struct dyld_chained_import_addend64* imp = (const struct dyld_chained_import_addend64*)imports + importIndex;
    *outLibOrdinal = (int)(int16_t)imp->lib_ordinal;
    *outWeakImport = (imp->weak_import != 0);
    *outNameOffset = (uint32_t)imp->name_offset;
    *outImportAddend = (int64_t)imp->addend;
    return true;
  }

  return false;
}

#define MAX_IMPORT_DEP_IMAGES 32u

struct ImportDepImage {
  const char* path;
  uint64_t imageBase;
};

static bool gather_import_dep_images(const void* image, uint64_t imageLen, uint64_t shared_region_start,
                                     const struct dyld_cache_header* cacheHeader, uint64_t cacheSlide,
                                     struct ImportDepImage* outDeps, uint32_t* outDepCount)
{
  if (!image || !cacheHeader || !outDeps || !outDepCount || imageLen < sizeof(struct mach_header_64)) {
    return false;
  }
  const struct mach_header_64* mh = (const struct mach_header_64*)image;
  if (mh->magic != MH_MAGIC_64 || (uint64_t)sizeof(*mh) + (uint64_t)mh->sizeofcmds > imageLen) {
    return false;
  }

  uint32_t depCount = 0;
  const struct load_command* lc = (const struct load_command*)((const char*)image + sizeof(*mh));
  uint64_t cmdBytes = mh->sizeofcmds;
  while (cmdBytes >= sizeof(struct load_command)) {
    if (lc->cmdsize < sizeof(struct load_command) || lc->cmdsize > cmdBytes) {
      return false;
    }

    if (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB || lc->cmd == LC_REEXPORT_DYLIB || lc->cmd == LC_LAZY_LOAD_DYLIB ||
        lc->cmd == LC_LOAD_UPWARD_DYLIB) {
      if (depCount >= MAX_IMPORT_DEP_IMAGES || lc->cmdsize < sizeof(struct dylib_command)) {
        return false;
      }
      const struct dylib_command* dc = (const struct dylib_command*)lc;
      uint32_t nameOffset = dc->dylib.name.offset;
      if (nameOffset >= lc->cmdsize) {
        return false;
      }
      const char* path = (const char*)dc + nameOffset;
      size_t maxNameLen = (size_t)(lc->cmdsize - nameOffset);
      if (bounded_cstrlen(path, maxNameLen) == maxNameLen) {
        return false;
      }
      outDeps[depCount].path = path;
      outDeps[depCount].imageBase = find_cache_image(shared_region_start, cacheHeader, path, cacheSlide);
      depCount++;
    }

    cmdBytes -= lc->cmdsize;
    lc = (const struct load_command*)((const char*)lc + lc->cmdsize);
  }

  *outDepCount = depCount;
  return (cmdBytes == 0);
}

static void* resolve_import_symbol_x86(const struct MappedImageX86* mapped, Dlsym_ptr dlsymFunc, const struct ImportDepImage* deps,
                                       uint32_t depCount, uint64_t cacheSlide, const char* symbolName, int libOrdinal,
                                       bool weakImport)
{
  if (!mapped || !symbolName) {
    return 0;
  }

  void* addr = 0;
  if (dlsymFunc) {
    const char* lookup = symbolName;
    if (lookup[0] == '_') {
      lookup++;
    }
    if (lookup[0] != '\0') {
      addr = dlsymFunc((void*)(intptr_t)-2, lookup);
    }
    if (!addr) {
      addr = dlsymFunc((void*)(intptr_t)-2, symbolName);
    }
  }

  if (libOrdinal == BIND_SPECIAL_DYLIB_SELF) {
    if (!addr) {
      addr = find_symbol((uint64_t)mapped->machHeaderAddr, symbolName, mapped->slide);
    }
  } else if (libOrdinal > 0) {
    uint32_t depIndex = (uint32_t)(libOrdinal - 1);
    if (!addr && deps && depIndex < depCount && deps[depIndex].imageBase != 0) {
      addr = find_symbol(deps[depIndex].imageBase, symbolName, cacheSlide);
    }
  } else if (libOrdinal == BIND_SPECIAL_DYLIB_FLAT_LOOKUP || libOrdinal == BIND_SPECIAL_DYLIB_WEAK_LOOKUP ||
             libOrdinal == BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE) {
    if (!addr) {
      addr = find_symbol((uint64_t)mapped->machHeaderAddr, symbolName, mapped->slide);
    }
    if (!addr && deps) {
      for (uint32_t i = 0; i < depCount; i++) {
        if (deps[i].imageBase == 0) {
          continue;
        }
        addr = find_symbol(deps[i].imageBase, symbolName, cacheSlide);
        if (addr) {
          break;
        }
      }
    }
  }

  if (!addr && weakImport) {
    return 0;
  }
  return addr;
}

static bool apply_chain_start_x86(const struct MappedImageX86* mapped, uintptr_t chainAddr, uintptr_t imageStart, uintptr_t imageEnd,
                                  const uint8_t* imports, uint64_t importsLen, uint32_t importsFormat, uint32_t importsCount,
                                  const char* symbols, uint64_t symbolsLen, Dlsym_ptr dlsymFunc,
                                  const struct ImportDepImage* deps, uint32_t depCount, uint64_t cacheSlide)
{
  uintptr_t cursor = chainAddr;
  uint32_t guard = 0;
  while (1) {
    if (cursor < imageStart || (cursor + sizeof(uint64_t)) > imageEnd) {
      return false;
    }
    uint64_t raw = *(uint64_t*)(uintptr_t)cursor;
    uint64_t next = (raw >> 51) & 0xFFF;
    bool bind = ((raw >> 63) & 1) != 0;
    uint64_t value = 0;

    if (bind) {
      uint32_t importIndex = (uint32_t)(raw & 0xFFFFFFu);
      uint32_t chainAddend = (uint32_t)((raw >> 24) & 0xFFu);

      int libOrdinal = 0;
      bool weakImport = false;
      uint32_t nameOffset = 0;
      int64_t importAddend = 0;
      if (!decode_import_entry(imports, importsLen, importsFormat, importIndex, importsCount, &libOrdinal, &weakImport, &nameOffset,
                               &importAddend)) {
        return false;
      }
      if (nameOffset >= symbolsLen) {
        return false;
      }
      const char* symName = symbols + nameOffset;
      size_t maxName = (size_t)(symbolsLen - nameOffset);
      if (bounded_cstrlen(symName, maxName) == maxName) {
        return false;
      }

      void* resolved = resolve_import_symbol_x86(mapped, dlsymFunc, deps, depCount, cacheSlide, symName, libOrdinal, weakImport);
      if (!resolved && !weakImport) {
        return false;
      }
      if (resolved) {
        value = (uint64_t)(uintptr_t)resolved + (uint64_t)importAddend + (uint64_t)chainAddend;
      } else {
        value = 0;
      }
    } else {
      uint64_t target = raw & ((1ULL << 36) - 1);
      uint64_t high8 = (raw >> 36) & 0xFF;
      value = ((high8 << 56) | target) + mapped->slide;
    }

    *(uint64_t*)(uintptr_t)cursor = value;
    if (next == 0) {
      break;
    }
    cursor += (uintptr_t)(next * 4);
    if (++guard > 0x20000u) {
      return false;
    }
  }
  return true;
}

static bool apply_chained_fixups_x86(const struct MappedImageX86* mapped, const void* image, uint64_t imageLen, uint64_t shared_region_start,
                                     const struct dyld_cache_header* cacheHeader, uint64_t cacheSlide, Dlsym_ptr dlsymFunc)
{
  if (!mapped || !image || !cacheHeader) {
    return false;
  }

  const struct linkedit_data_command* fixupsCmd = find_chained_fixups_command(image, imageLen);
  if (!fixupsCmd) {
    return true; // image has no chained fixups
  }
  if ((uint64_t)fixupsCmd->dataoff + (uint64_t)fixupsCmd->datasize > imageLen) {
    return false;
  }
  const uint8_t* chainData = (const uint8_t*)image + fixupsCmd->dataoff;
  uint64_t chainLen = fixupsCmd->datasize;
  if (chainLen < sizeof(struct dyld_chained_fixups_header)) {
    return false;
  }

  const struct dyld_chained_fixups_header* fixHdr = (const struct dyld_chained_fixups_header*)chainData;
  if (fixHdr->starts_offset >= chainLen || fixHdr->imports_offset >= chainLen || fixHdr->symbols_offset >= chainLen) {
    return false;
  }

  const uint8_t* imports = chainData + fixHdr->imports_offset;
  uint64_t importsLen = chainLen - fixHdr->imports_offset;
  const char* symbols = (const char*)(chainData + fixHdr->symbols_offset);
  uint64_t symbolsLen = chainLen - fixHdr->symbols_offset;

  struct ImportDepImage deps[MAX_IMPORT_DEP_IMAGES];
  uint32_t depCount = 0;
  if (!gather_import_dep_images(image, imageLen, shared_region_start, cacheHeader, cacheSlide, deps, &depCount)) {
    return false;
  }

  const uint8_t* startsRaw = chainData + fixHdr->starts_offset;
  if ((uint64_t)(chainLen - fixHdr->starts_offset) < sizeof(uint32_t)) {
    return false;
  }
  const struct dyld_chained_starts_in_image* startsImage = (const struct dyld_chained_starts_in_image*)startsRaw;
  uint32_t segCount = startsImage->seg_count;
  if ((uint64_t)(chainLen - fixHdr->starts_offset) < (sizeof(uint32_t) + (uint64_t)segCount * sizeof(uint32_t))) {
    return false;
  }

  uintptr_t imageStart = mapped->imageBase;
  uintptr_t imageEnd = mapped->imageBase + (uintptr_t)(mapped->maxVmAddr - mapped->minVmAddr);

  for (uint32_t segIndex = 0; segIndex < segCount; segIndex++) {
    uint32_t segInfoOffset = startsImage->seg_info_offset[segIndex];
    if (segInfoOffset == 0) {
      continue;
    }

    if ((uint64_t)segInfoOffset > (chainLen - fixHdr->starts_offset)) {
      return false;
    }
    const uint8_t* segInfoRaw = startsRaw + segInfoOffset;
    if ((uint64_t)(chainData + chainLen - segInfoRaw) < sizeof(struct dyld_chained_starts_in_segment)) {
      return false;
    }

    const struct dyld_chained_starts_in_segment* startsSeg = (const struct dyld_chained_starts_in_segment*)segInfoRaw;
    if (startsSeg->size < sizeof(struct dyld_chained_starts_in_segment)) {
      return false;
    }
    if ((uint64_t)startsSeg->size > (uint64_t)(chainData + chainLen - segInfoRaw)) {
      return false;
    }
    if (startsSeg->pointer_format != DYLD_CHAINED_PTR_64_OFFSET) {
      return false;
    }
    if (startsSeg->page_size == 0) {
      return false;
    }

    uint64_t pageArrayNeed = (uint64_t)startsSeg->page_count * sizeof(uint16_t);
    uint64_t fixedPrefix = sizeof(struct dyld_chained_starts_in_segment) - sizeof(uint16_t);
    if (startsSeg->size < (fixedPrefix + pageArrayNeed)) {
      return false;
    }

    if (startsSeg->segment_offset < mapped->minVmAddr) {
      return false;
    }
    uintptr_t segRuntimeBase = mapped->imageBase + (uintptr_t)(startsSeg->segment_offset - mapped->minVmAddr);
    const uint16_t* pageStarts = startsSeg->page_start;
    const uint16_t* extras = pageStarts + startsSeg->page_count;

    for (uint32_t pageIndex = 0; pageIndex < startsSeg->page_count; pageIndex++) {
      uint16_t pageStart = pageStarts[pageIndex];
      if (pageStart == DYLD_CHAINED_PTR_START_NONE) {
        continue;
      }

      if (pageStart & DYLD_CHAINED_PTR_START_MULTI) {
        uint32_t listIndex = (uint32_t)(pageStart & ~DYLD_CHAINED_PTR_START_MULTI);
        uint32_t guard = 0;
        while (1) {
          uintptr_t extraAddr = (uintptr_t)&extras[listIndex];
          if ((extraAddr + sizeof(uint16_t)) > ((uintptr_t)startsSeg + startsSeg->size)) {
            return false;
          }
          uint16_t entry = extras[listIndex++];
          bool isLast = ((entry & DYLD_CHAINED_PTR_START_LAST) != 0);
          uint16_t startOff = (uint16_t)(entry & ~DYLD_CHAINED_PTR_START_LAST);
          uintptr_t chainAddr = segRuntimeBase + (uintptr_t)pageIndex * startsSeg->page_size + startOff;
          if (!apply_chain_start_x86(mapped, chainAddr, imageStart, imageEnd, imports, importsLen, fixHdr->imports_format,
                                     fixHdr->imports_count, symbols, symbolsLen, dlsymFunc, deps, depCount, cacheSlide)) {
            return false;
          }
          if (isLast) {
            break;
          }
          if (++guard > 0x20000u) {
            return false;
          }
        }
      } else {
        uintptr_t chainAddr = segRuntimeBase + (uintptr_t)pageIndex * startsSeg->page_size + pageStart;
        if (!apply_chain_start_x86(mapped, chainAddr, imageStart, imageEnd, imports, importsLen, fixHdr->imports_format,
                                   fixHdr->imports_count, symbols, symbolsLen, dlsymFunc, deps, depCount, cacheSlide)) {
          return false;
        }
      }
    }
  }

  return true;
}

typedef void (*init_func_x86_t)(int, const char**, const char**, const char**, void*);

static void run_initializers_x86(const struct MappedImageX86* mapped)
{
  if (!mapped || !mapped->machHeaderAddr) {
    return;
  }
  uintptr_t imageStart = mapped->imageBase;
  uintptr_t imageEnd = mapped->imageBase + (uintptr_t)(mapped->maxVmAddr - mapped->minVmAddr);

  const struct mach_header_64* mh = (const struct mach_header_64*)(uintptr_t)mapped->machHeaderAddr;
  const struct load_command* lc = (const struct load_command*)((const char*)mh + sizeof(*mh));
  uint64_t cmdBytes = mh->sizeofcmds;
  while (cmdBytes >= sizeof(struct load_command)) {
    if (lc->cmdsize < sizeof(struct load_command) || lc->cmdsize > cmdBytes) {
      return;
    }
    if (lc->cmd == LC_SEGMENT_64) {
      const struct segment_command_64* seg = (const struct segment_command_64*)lc;
      const struct section_64* sect = (const struct section_64*)((const char*)seg + sizeof(*seg));
      for (uint32_t i = 0; i < seg->nsects; i++) {
        uint32_t sectionType = (sect[i].flags & SECTION_TYPE);
        if (sectionType == S_INIT_FUNC_OFFSETS) {
          if (sect[i].addr < mapped->minVmAddr) {
            continue;
          }
          uintptr_t secRuntime = mapped->imageBase + (uintptr_t)(sect[i].addr - mapped->minVmAddr);
          uint64_t count = sect[i].size / sizeof(uint32_t);
          uint32_t* offsets = (uint32_t*)(uintptr_t)secRuntime;
          for (uint64_t n = 0; n < count; n++) {
            uint32_t off = offsets[n];
            if (off == 0) {
              continue;
            }
            uintptr_t initAddr = (uintptr_t)(mapped->slide + off);
            if (initAddr < imageStart || initAddr >= imageEnd) {
              continue;
            }
            init_func_x86_t init_func = (init_func_x86_t)initAddr;
            init_func(0, 0, 0, 0, 0);
          }
        } else if (sectionType == S_MOD_INIT_FUNC_POINTERS) {
          if (sect[i].addr < mapped->minVmAddr) {
            continue;
          }
          uintptr_t secRuntime = mapped->imageBase + (uintptr_t)(sect[i].addr - mapped->minVmAddr);
          uint64_t count = sect[i].size / sizeof(uint64_t);
          uint64_t* initPtrs = (uint64_t*)(uintptr_t)secRuntime;
          for (uint64_t n = 0; n < count; n++) {
            uint64_t ptr = initPtrs[n];
            if (ptr != 0) {
              uintptr_t initAddr = (uintptr_t)ptr;
              if (initAddr < imageStart || initAddr >= imageEnd) {
                continue;
              }
              init_func_x86_t init_func = (init_func_x86_t)initAddr;
              init_func(0, 0, 0, 0, 0);
            }
          }
        }
      }
    }
    cmdBytes -= lc->cmdsize;
    lc = (const struct load_command*)((const char*)lc + lc->cmdsize);
  }
}

/*
 * aPLib compression library  -  the smaller the better :)
 *
 * C safe depacker (based on internal/stager/aplib/src/depacks.c)
 *
 * Copyright (c) 1998-2014 Joergen Ibsen
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 */

#ifndef APLIB_ERROR
#define APLIB_ERROR ((unsigned int) (-1))
#endif

struct APDSSTATE {
  const unsigned char* source;
  unsigned int srclen;
  unsigned char* destination;
  unsigned int dstlen;
  unsigned int tag;
  unsigned int bitcount;
};

static int aP_getbit_safe(struct APDSSTATE* ud, unsigned int* result)
{
  unsigned int bit;

  /* check if tag is empty */
  if (!ud->bitcount--) {
    if (!ud->srclen--) {
      return 0;
    }

    /* load next tag */
    ud->tag = *ud->source++;
    ud->bitcount = 7;
  }

  /* shift bit out of tag */
  bit = (ud->tag >> 7) & 0x01;
  ud->tag <<= 1;

  *result = bit;

  return 1;
}

static int aP_getgamma_safe(struct APDSSTATE* ud, unsigned int* result)
{
  unsigned int bit;
  unsigned int v = 1;

  /* input gamma2-encoded bits */
  do {
    if (!aP_getbit_safe(ud, &bit)) {
      return 0;
    }

    if (v & 0x80000000) {
      return 0;
    }

    v = (v << 1) + bit;

    if (!aP_getbit_safe(ud, &bit)) {
      return 0;
    }
  } while (bit);

  *result = v;

  return 1;
}

static unsigned int aP_depack_safe(const void* source, unsigned int srclen, void* destination, unsigned int dstlen)
{
  struct APDSSTATE ud;
  unsigned int offs, len, R0, LWM, bit;
  int done;
  int i;

  if (!source || !destination) {
    return APLIB_ERROR;
  }

  ud.source = (const unsigned char*)source;
  ud.srclen = srclen;
  ud.destination = (unsigned char*)destination;
  ud.dstlen = dstlen;
  ud.bitcount = 0;

  R0 = (unsigned int)-1;
  LWM = 0;
  done = 0;

  /* first byte verbatim */
  if (!ud.srclen-- || !ud.dstlen--) {
    return APLIB_ERROR;
  }
  *ud.destination++ = *ud.source++;

  /* main decompression loop */
  while (!done) {
    if (!aP_getbit_safe(&ud, &bit)) {
      return APLIB_ERROR;
    }

    if (bit) {
      if (!aP_getbit_safe(&ud, &bit)) {
        return APLIB_ERROR;
      }

      if (bit) {
        if (!aP_getbit_safe(&ud, &bit)) {
          return APLIB_ERROR;
        }

        if (bit) {
          offs = 0;

          for (i = 4; i; i--) {
            if (!aP_getbit_safe(&ud, &bit)) {
              return APLIB_ERROR;
            }
            offs = (offs << 1) + bit;
          }

          if (offs) {
            if (offs > (dstlen - ud.dstlen)) {
              return APLIB_ERROR;
            }

            if (!ud.dstlen--) {
              return APLIB_ERROR;
            }

            *ud.destination = *(ud.destination - offs);
            ud.destination++;
          } else {
            if (!ud.dstlen--) {
              return APLIB_ERROR;
            }

            *ud.destination++ = 0x00;
          }

          LWM = 0;
        } else {
          if (!ud.srclen--) {
            return APLIB_ERROR;
          }

          offs = *ud.source++;

          len = 2 + (offs & 0x0001);

          offs >>= 1;

          if (offs) {
            if (offs > (dstlen - ud.dstlen)) {
              return APLIB_ERROR;
            }

            if (len > ud.dstlen) {
              return APLIB_ERROR;
            }

            ud.dstlen -= len;

            for (; len; len--) {
              *ud.destination = *(ud.destination - offs);
              ud.destination++;
            }
          } else {
            done = 1;
          }

          R0 = offs;
          LWM = 1;
        }
      } else {
        if (!aP_getgamma_safe(&ud, &offs)) {
          return APLIB_ERROR;
        }

        if ((LWM == 0) && (offs == 2)) {
          offs = R0;

          if (!aP_getgamma_safe(&ud, &len)) {
            return APLIB_ERROR;
          }

          if (offs > (dstlen - ud.dstlen)) {
            return APLIB_ERROR;
          }

          if (len > ud.dstlen) {
            return APLIB_ERROR;
          }

          ud.dstlen -= len;

          for (; len; len--) {
            *ud.destination = *(ud.destination - offs);
            ud.destination++;
          }
        } else {
          if (LWM == 0) {
            offs -= 3;
          } else {
            offs -= 2;
          }

          if (offs > 0x00fffffe) {
            return APLIB_ERROR;
          }

          if (!ud.srclen--) {
            return APLIB_ERROR;
          }

          offs <<= 8;
          offs += *ud.source++;

          if (!aP_getgamma_safe(&ud, &len)) {
            return APLIB_ERROR;
          }

          if (offs >= 32000) {
            len++;
          }
          if (offs >= 1280) {
            len++;
          }
          if (offs < 128) {
            len += 2;
          }

          if (offs > (dstlen - ud.dstlen)) {
            return APLIB_ERROR;
          }

          if (len > ud.dstlen) {
            return APLIB_ERROR;
          }

          ud.dstlen -= len;

          for (; len; len--) {
            *ud.destination = *(ud.destination - offs);
            ud.destination++;
          }

          R0 = offs;
        }

        LWM = 1;
      }
    } else {
      if (!ud.srclen-- || !ud.dstlen--) {
        return APLIB_ERROR;
      }
      *ud.destination++ = *ud.source++;
      LWM = 0;
    }
  }

  return (unsigned int)(ud.destination - (unsigned char*)destination);
}

#define APLIB_SAFE_TAG 0x32335041u /* 'AP32' */
#define APLIB_SAFE_HEADER_MIN 24u

struct aplib_safe_header
{
  uint32_t tag;
  uint32_t header_size;
  uint32_t packed_size;
  uint32_t packed_crc;
  uint32_t orig_size;
  uint32_t orig_crc;
};

static uint64_t syscall_shared_region_check_np()
{
  long shared_region_check_np = 0x2000126; // #294
  uint64_t address = 0;
  uint64_t ret = 0;
  unsigned int carry = 0;
#ifdef __aarch64__
  __asm__ volatile(
      "mov x16, %2;\n"
      "mov x0, %3;\n"
      "svc #0;\n"
      "mov %0, x0;\n"
      "cset %w1, cs;\n"
      : "=r"(ret), "=r"(carry)
      : "r"(shared_region_check_np), "r"(&address)
      : "x16", "x0", "memory");
#elif defined(__x86_64__)
  unsigned char cflag = 0;
  ret = (uint64_t)shared_region_check_np;
  __asm__ volatile(
      "syscall;\n"
      "setc %b0;\n"
      : "=q"(cflag), "+a"(ret)
      : "D"(&address)
      : "rcx", "r11", "memory");
  carry = cflag;
#else
  (void)shared_region_check_np;
#endif
  if (carry != 0 || ret != 0) {
    return 0;
  }
  return address;
}

static void* syscall_mmap(void* addr, uint64_t length, int prot, int flags, int fd, uint64_t offset)
{
  uint64_t mmap_num = 0x20000c5; // #197
  uint64_t ret = (uint64_t)-1;
  unsigned int carry = 0;
#ifdef __aarch64__
  __asm__ volatile(
      "mov x16, %2;\n"
      "mov x0, %3;\n"
      "mov x1, %4;\n"
      "mov x2, %5;\n"
      "mov x3, %6;\n"
      "mov x4, %7;\n"
      "mov x5, %8;\n"
      "svc #0;\n"
      "mov %0, x0;\n"
      "cset %w1, cs;\n"
      : "=r"(ret), "=r"(carry)
      : "r"(mmap_num), "r"(addr), "r"(length), "r"((uint64_t)prot), "r"((uint64_t)flags), "r"((uint64_t)fd), "r"(offset)
      : "x16", "x0", "x1", "x2", "x3", "x4", "x5", "memory");
#elif defined(__x86_64__)
  unsigned char cflag = 0;
  register uint64_t r10 __asm__("r10") = (uint64_t)flags;
  register uint64_t r8 __asm__("r8") = (uint64_t)fd;
  register uint64_t r9 __asm__("r9") = offset;
  ret = mmap_num;
  __asm__ volatile(
      "syscall;\n"
      "setc %b0;\n"
      : "=q"(cflag), "+a"(ret)
      : "D"(addr), "S"(length), "d"((uint64_t)prot), "r"(r10), "r"(r8), "r"(r9)
      : "rcx", "r11", "memory");
  carry = cflag;
#else
  (void)addr;
  (void)length;
  (void)prot;
  (void)flags;
  (void)fd;
  (void)offset;
  return (void*)-1;
#endif
  if (carry != 0) {
    return (void*)-1;
  }
  return (void*)(uintptr_t)ret;
}

static int syscall_mprotect(void* addr, uint64_t length, int prot)
{
  uint64_t mprotect_num = 0x200004a; // #74
  uint64_t ret = (uint64_t)-1;
  unsigned int carry = 0;
#ifdef __aarch64__
  __asm__ volatile(
      "mov x16, %2;\n"
      "mov x0, %3;\n"
      "mov x1, %4;\n"
      "mov x2, %5;\n"
      "svc #0;\n"
      "mov %0, x0;\n"
      "cset %w1, cs;\n"
      : "=r"(ret), "=r"(carry)
      : "r"(mprotect_num), "r"(addr), "r"(length), "r"((uint64_t)prot)
      : "x16", "x0", "x1", "x2", "memory");
#elif defined(__x86_64__)
  unsigned char cflag = 0;
  ret = mprotect_num;
  __asm__ volatile(
      "syscall;\n"
      "setc %b0;\n"
      : "=q"(cflag), "+a"(ret)
      : "D"(addr), "S"(length), "d"((uint64_t)prot)
      : "rcx", "r11", "memory");
  carry = cflag;
#else
  (void)addr;
  (void)length;
  (void)prot;
  return -1;
#endif
  if (carry != 0) {
    return -1;
  }
  return (int)ret;
}

static void* find_symbol(uint64_t base, const char* symbol, uint64_t offset)
{
  struct segment_command_64 *sc, *linkedit, *text;
  struct load_command* lc;
  struct symtab_command* symtab;
  struct nlist_64* nl;

  char* strtab;
  symtab = 0;
  linkedit = 0;
  text = 0;

  lc = (struct load_command*)(base + sizeof(struct mach_header_64));
  for (int i = 0; i < ((struct mach_header_64*)base)->ncmds; i++) {
    if (lc->cmd == LC_SYMTAB) {
      symtab = (struct symtab_command*)lc;
    } else if (lc->cmd == LC_SEGMENT_64) {
      sc = (struct segment_command_64*)lc;
      char* segname = ((struct segment_command_64*)lc)->segname;
      if (string_compare(segname, "__LINKEDIT") == 0) {
        linkedit = sc;
      } else if (string_compare(segname, "__TEXT") == 0) {
        text = sc;
      }
    }
    lc = (struct load_command*)((unsigned long)lc + lc->cmdsize);
  }

  if (!linkedit || !symtab || !text) {
    return 0;
  }

  unsigned long file_slide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
  strtab = (char*)(base + file_slide + symtab->stroff);

  nl = (struct nlist_64*)(base + file_slide + symtab->symoff);
  for (int i = 0; i < symtab->nsyms; i++) {
    char* name = strtab + nl[i].n_un.n_strx;
    if (string_compare(name, symbol) == 0) {
      if (nl[i].n_value == 0) {
        continue;
      }
      return (void*)(nl[i].n_value + offset);
    }
  }

  return 0;
}

static void* find_section(uint64_t base, const char* segName, const char* sectName, uint64_t slide)
{
  struct mach_header_64* mh = (struct mach_header_64*)base;
  struct load_command* lc = (struct load_command*)(base + sizeof(*mh));
  for (uint32_t i = 0; i < mh->ncmds; i++) {
    if (lc->cmd == LC_SEGMENT_64) {
      struct segment_command_64* seg = (struct segment_command_64*)lc;
      if (string_compare(seg->segname, segName) == 0) {
        struct section_64* sect = (struct section_64*)((char*)seg + sizeof(*seg));
        for (uint32_t j = 0; j < seg->nsects; j++) {
          if (string_compare(sect->sectname, sectName) == 0) {
            return (void*)(sect->addr + slide);
          }
          sect++;
        }
      }
    }
    lc = (struct load_command*)((char*)lc + lc->cmdsize);
  }
  return 0;
}

static uint64_t find_cache_image(uint64_t shared_region_start, const struct dyld_cache_header* header, const char* wantPath, uint64_t slide)
{
  uint32_t imagesCount = header->imagesCountOld;
  if (imagesCount == 0) {
    imagesCount = header->imagesCount;
  }
  uint32_t imagesOffset = header->imagesOffsetOld;
  if (imagesOffset == 0) {
    imagesOffset = header->imagesOffset;
  }
  struct dyld_cache_image_info* img = (struct dyld_cache_image_info*)((char*)header + imagesOffset);
  for (uint32_t i = 0; i < imagesCount; i++) {
    const char* path = (const char*)shared_region_start + img[i].pathFileOffset;
    if (string_compare(path, wantPath) == 0) {
      return img[i].address + slide;
    }
  }
  return 0;
}

static bool enter_writable_dyld_state(void* mm, LockGuard_ptr lockGuard, WriteProtect_ptr writeProtect, LockUnlock_ptr unlockFunc)
{
  if (!mm || !lockGuard || !writeProtect || !unlockFunc) {
    return false;
  }
  struct LockGuardRet guard = lockGuard(mm);
  uint64_t* counter = (uint64_t*)((char*)mm + 0x18);
  uint64_t c = *counter;
  if (c == 0) {
    writeProtect(mm, false);
    c = *counter;
  }
  *counter = c + 1;
  unlockFunc(guard.lock);
  return true;
}

static void exit_writable_dyld_state(void* mm, LockGuard_ptr lockGuard, WriteProtect_ptr writeProtect, LockUnlock_ptr unlockFunc)
{
  if (!mm || !lockGuard || !writeProtect || !unlockFunc) {
    return;
  }
  struct LockGuardRet guard = lockGuard(mm);
  uint64_t* counter = (uint64_t*)((char*)mm + 0x18);
  uint64_t c = *counter;
  if (c != 0) {
    c = c - 1;
    *counter = c;
    if (c == 0) {
      writeProtect(mm, true);
    }
  }
  unlockFunc(guard.lock);
}

static bool enter_writable_dyld_state_lock(void* mm, LockLock_ptr lockFunc, WriteProtect_ptr writeProtect, LockUnlock_ptr unlockFunc)
{
  if (!mm || !lockFunc || !writeProtect || !unlockFunc) {
    return false;
  }
  lockFunc(mm);
  uint64_t* counter = (uint64_t*)((char*)mm + 0x18);
  uint64_t c = *counter;
  if (c == 0) {
    writeProtect(mm, false);
    c = *counter;
  }
  *counter = c + 1;
  unlockFunc(mm);
  return true;
}

static void exit_writable_dyld_state_lock(void* mm, LockLock_ptr lockFunc, WriteProtect_ptr writeProtect, LockUnlock_ptr unlockFunc)
{
  if (!mm || !lockFunc || !writeProtect || !unlockFunc) {
    return;
  }
  lockFunc(mm);
  uint64_t* counter = (uint64_t*)((char*)mm + 0x18);
  uint64_t c = *counter;
  if (c != 0) {
    c = c - 1;
    *counter = c;
    if (c == 0) {
      writeProtect(mm, true);
    }
  }
  unlockFunc(mm);
}

__attribute__((used, noinline)) int beignet_loader(void* buffer_ro, uint64_t buffer_size, const char* entry_symbol)
{
  if (buffer_ro == 0 || buffer_size == 0 || entry_symbol == 0) {
    return 1;
  }

  uint64_t shared_region_start = syscall_shared_region_check_np();
  if (shared_region_start == 0) {
    return 2;
  }

  struct dyld_cache_header* header = (void*)shared_region_start;
  struct shared_file_mapping* sfm = (struct shared_file_mapping*)((char*)header + header->mappingOffset);

  uint32_t imagesCount = header->imagesCountOld;
  if (imagesCount == 0) {
    imagesCount = header->imagesCount;
  }
  uint32_t imagesOffset = header->imagesOffsetOld;
  if (imagesOffset == 0) {
    imagesOffset = header->imagesOffset;
  }
  if (imagesCount == 0 || imagesOffset == 0) {
    return 2;
  }

  // Slide between the on-disk/shared-cache VM addresses and this process' mapping.
  uint64_t slide = (uint64_t)header - sfm->address;

  uint64_t libdyld = find_cache_image(shared_region_start, header, "/usr/lib/system/libdyld.dylib", slide);
  if (libdyld == 0) {
    return 2;
  }
  uint64_t dyld = find_cache_image(shared_region_start, header, "/usr/lib/dyld", slide);
  if (dyld == 0) {
    return 2;
  }

  // libdyld provides a pointer to RuntimeState/APIs in a tiny section.
  void* apis_sec = find_section(libdyld, "__TPRO_CONST", "__dyld_apis", slide);
  if (!apis_sec) {
    return 3;
  }
  void* apis = *(void**)apis_sec;
  if (!apis) {
    return 3;
  }

  uint64_t buffer = (uint64_t)buffer_ro;
  uint64_t bufferLen = buffer_size;

  // If the staged buffer is aPLib safe-packed ("AP32"), depack it before
  // handing it to dyld.
  if (bufferLen >= APLIB_SAFE_HEADER_MIN) {
    const struct aplib_safe_header* hdr = (const struct aplib_safe_header*)(uintptr_t)buffer;
    if (hdr->tag == APLIB_SAFE_TAG) {
      uint64_t headerSize = (uint64_t)hdr->header_size;
      uint64_t packedSize = (uint64_t)hdr->packed_size;
      uint64_t origSize = (uint64_t)hdr->orig_size;

      if (headerSize < APLIB_SAFE_HEADER_MIN || headerSize > bufferLen) {
        return 14;
      }
      if (packedSize == 0 || packedSize > (bufferLen - headerSize)) {
        return 14;
      }
      if (origSize == 0) {
        return 14;
      }

      void* depacked = syscall_mmap(0, origSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
      if (depacked == (void*)-1 || depacked == 0) {
        return 15;
      }
      const void* packedData = (const void*)(uintptr_t)(buffer + headerSize);
      unsigned int outlen = aP_depack_safe(packedData, (unsigned int)packedSize, depacked, (unsigned int)origSize);
      if (outlen != (unsigned int)origSize) {
        return 15;
      }

      buffer = (uint64_t)(uintptr_t)depacked;
      bufferLen = origSize;
    }
  }

#if defined(__x86_64__)
  Dlsym_ptr dlsym_func = (Dlsym_ptr)find_symbol(libdyld, "_dlsym", slide);
  if (!dlsym_func) {
    return 4;
  }

  struct MappedImageX86 mappedImage;
  if (!map_macho_image_x86((const void*)(uintptr_t)buffer, bufferLen, &mappedImage)) {
    return 5;
  }

  if (!apply_chained_fixups_x86(&mappedImage, (const void*)(uintptr_t)buffer, bufferLen, shared_region_start, header, slide,
                                dlsym_func)) {
    return 9;
  }

  apply_segment_protections_x86(&mappedImage);
  // run_initializers_x86(&mappedImage);

  void* x86_addr_entry = find_symbol((uint64_t)mappedImage.machHeaderAddr, entry_symbol, mappedImage.slide);
  if (!x86_addr_entry) {
    return 12;
  }
  uintptr_t imageStart = mappedImage.imageBase;
  uintptr_t imageEnd = mappedImage.imageBase + (uintptr_t)(mappedImage.maxVmAddr - mappedImage.minVmAddr);
  if ((uintptr_t)x86_addr_entry < imageStart || (uintptr_t)x86_addr_entry >= imageEnd) {
    return 46;
  }
  void (*x86_entry_func)(void) = (void (*)(void))x86_addr_entry;
  x86_entry_func();
  return 0;
#endif

  // Resolve the dyld4 internals we need from /usr/lib/dyld.
  JustInTimeLoaderMake2_ptr JustInTimeLoaderMake2_func = (JustInTimeLoaderMake2_ptr)find_symbol(
      dyld, "__ZN5dyld416JustInTimeLoader4makeERNS_12RuntimeStateEPKN5dyld39MachOFileEPKcRKNS_6FileIDEybbbtPKN6mach_o6LayoutE", slide);
  WithVMLayout_ptr WithVMLayout_func =
      (WithVMLayout_ptr)find_symbol(dyld, "__ZNK5dyld313MachOAnalyzer12withVMLayoutER11DiagnosticsU13block_pointerFvRKN6mach_o6LayoutEE", slide);
  AnalyzeSegmentsLayout_ptr AnalyzeSegmentsLayout_func =
      (AnalyzeSegmentsLayout_ptr)find_symbol(dyld, "__ZNK5dyld39MachOFile21analyzeSegmentsLayoutERyRb", slide);
  WithRegions_ptr WithRegions_func = (WithRegions_ptr)find_symbol(
      dyld, "__ZN5dyld416JustInTimeLoader11withRegionsEPKN5dyld39MachOFileEU13block_pointerFvRKNS1_5ArrayINS_6Loader6RegionEEEE", slide);
  LoadDependents_ptr LoadDependents_func =
      (LoadDependents_ptr)find_symbol(dyld, "__ZN5dyld46Loader14loadDependentsER11DiagnosticsRNS_12RuntimeStateERKNS0_11LoadOptionsE", slide);
  ApplyFixups_ptr ApplyFixups_func = (ApplyFixups_ptr)find_symbol(
      dyld, "__ZNK5dyld46Loader11applyFixupsER11DiagnosticsRNS_12RuntimeStateERNS_34DyldCacheDataConstLazyScopedWriterEbPN3lsl6VectorINSt3__14pairIPKS0_PKcEEEE", slide);
  IncDlRefCount_ptr IncDlRefCount_func =
      (IncDlRefCount_ptr)find_symbol(dyld, "__ZN5dyld412RuntimeState13incDlRefCountEPKNS_6LoaderE", slide);
  RunInitializers_ptr RunInitializers_func =
      (RunInitializers_ptr)find_symbol(dyld, "__ZNK5dyld46Loader38runInitializersBottomUpPlusUpwardLinksERNS_12RuntimeStateE", slide);

  DiagnosticsCtor_ptr DiagnosticsCtor_func = (DiagnosticsCtor_ptr)find_symbol(dyld, "__ZN11DiagnosticsC1Ev", slide);
  DiagnosticsClearError_ptr DiagnosticsClearError_func = (DiagnosticsClearError_ptr)find_symbol(dyld, "__ZN11Diagnostics10clearErrorEv", slide);
  DiagnosticsHasError_ptr DiagnosticsHasError_func = (DiagnosticsHasError_ptr)find_symbol(dyld, "__ZNK11Diagnostics8hasErrorEv", slide);

  if (!JustInTimeLoaderMake2_func || !WithVMLayout_func || !AnalyzeSegmentsLayout_func || !WithRegions_func || !LoadDependents_func ||
      !ApplyFixups_func || !IncDlRefCount_func || !RunInitializers_func || !DiagnosticsCtor_func || !DiagnosticsClearError_func ||
      !DiagnosticsHasError_func) {
    return 4;
  }

#if defined(__aarch64__)
  // Optional helpers for working with dyld's internal write-protected allocator/state.
  MemoryManager_ptr MemoryManager_func = (MemoryManager_ptr)find_symbol(dyld, "__ZN3lsl13MemoryManager13memoryManagerEv", slide);
  LockGuard_ptr LockGuard_func = (LockGuard_ptr)find_symbol(dyld, "__ZN3lsl13MemoryManager9lockGuardEv", slide);
  WriteProtect_ptr WriteProtect_func = (WriteProtect_ptr)find_symbol(dyld, "__ZN3lsl13MemoryManager12writeProtectEb", slide);
  LockUnlock_ptr LockUnlock_func = (LockUnlock_ptr)find_symbol(dyld, "__ZN3lsl4Lock6unlockEv", slide);
  WithProtectedStack_ptr WithProtectedStack_func =
      (WithProtectedStack_ptr)find_symbol(dyld, "__ZN3lsl14ProtectedStack18withProtectedStackEU13block_pointerFvvE", slide);

  void* mm = 0;
  void* protectedStack = 0;
  if (MemoryManager_func) {
    mm = MemoryManager_func();
    if (mm) {
      protectedStack = *(void**)((char*)mm + 0x30);
    }
  }
#elif defined(__x86_64__)
  // Under Rosetta/x86_64, direct lsl::MemoryManager manipulation is unstable
  // across dyld builds. Keep the amd64 path on dyld RuntimeState APIs only.
#endif

  // Allocate a region large enough for the mapped Mach-O.
  uintptr_t vmSpace = 0;
  bool hasZeroFill;
  AnalyzeSegmentsLayout_func((void*)buffer, &vmSpace, &hasZeroFill);
  (void)hasZeroFill;
  if (vmSpace == 0) {
    return 5;
  }

  void* loadAddressP = syscall_mmap(0, vmSpace, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
  if (loadAddressP == (void*)-1 || loadAddressP == 0) {
    return 6;
  }
  uintptr_t loadAddress = (uintptr_t)loadAddressP;

  // Map segments into the reserved space.
  WithRegions_func((void*)buffer, ^(struct ArrayOfRegions* rptr) {
    uint32_t segIndex = 0;
    uint64_t sliceOffset = 0;
    for (int i = 0; i < (int)rptr->_usedCount; i++) {
      const struct Region region = rptr->_elements[i];
      if (region.isZeroFill || (region.fileSize == 0)) {
        continue;
      }
      if ((region.vmOffset == 0) && (segIndex > 0)) {
        continue;
      }
      int perms = (int)region.perms;
      if ((region.vmOffset >= vmSpace) || (region.fileSize > (vmSpace - region.vmOffset))) {
        continue;
      }
      void* segAddress = (void*)(loadAddress + region.vmOffset);
      memcpy2(segAddress, (const void*)(buffer + sliceOffset + region.fileOffset), (size_t)region.fileSize);
      syscall_mprotect(segAddress, region.fileSize, perms);
      ++segIndex;
    }
  });

  // Scratch space for dyld4 structs (avoid __block). Keep this large enough to
  // host a real dyld Diagnostics object.
  void* structspaceP = syscall_mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (structspaceP == (void*)-1 || structspaceP == 0) {
    return 7;
  }
  uintptr_t structspace = (uintptr_t)structspaceP;

  uint64_t* rtopLoader = (uint64_t*)structspace;
  uintptr_t cursor = structspace + sizeof(void*);

  struct FileID* fileid = (struct FileID*)cursor;
  cursor += sizeof(struct FileID);
  fileid->iNode = 0;
  fileid->modTime = 0;
  fileid->isValid = false;

  void* diag = (void*)cursor;
  cursor += 0x1000;
  DiagnosticsCtor_func(diag);

  struct LoadChain* loadChainMain = (struct LoadChain*)cursor;
  cursor += sizeof(struct LoadChain);

  struct LoadChain* loadChainCaller = (struct LoadChain*)cursor;
  cursor += sizeof(struct LoadChain);

  struct LoadChain* loadChain = (struct LoadChain*)cursor;
  cursor += sizeof(struct LoadChain);

  struct LoadOptions* depOptions = (struct LoadOptions*)cursor;
  cursor += sizeof(struct LoadOptions);
  int* rcSlot = (int*)cursor;
  cursor += 8;
  *rcSlot = 0;

	  void (^doLoad)(void) = ^(){
	    struct Loaded* loaded = (struct Loaded*)((char*)apis + 32);
	    uintptr_t startLoaderCount = loaded->size;

	    DiagnosticsClearError_func(diag);
	    *rtopLoader = 0;
	    WithVMLayout_func((void*)loadAddress, diag, ^(const void* layout) {
	      *rtopLoader = (uint64_t)JustInTimeLoaderMake2_func(apis, (void*)loadAddress, "A", fileid, 0, false, true, false, 0, layout);
	    });
	    if (DiagnosticsHasError_func(diag)) {
	      *rcSlot = 8;
	      return;
	    }
	    void* topLoader = (void*)(uintptr_t)(*rtopLoader);
	    if (!topLoader) {
	      *rcSlot = 8;
	      return;
	    }
	    ((struct PartialLoader*)topLoader)->lateLeaveMapped = 1;

    loadChainMain->previous = 0;
    loadChainMain->image = *(void**)((char*)apis + 24);

    loadChainCaller->previous = loadChainMain;
    loadChainCaller->image = loaded->elements[0];

    loadChain->previous = loadChainCaller;
    loadChain->image = topLoader;

    depOptions->staticLinkage = false;
    depOptions->rtldLocal = false;
    depOptions->rtldNoDelete = true;
    depOptions->canBeDylib = true;
	    depOptions->rpathStack = loadChain;
	    depOptions->useFallBackPaths = true;

	    DiagnosticsClearError_func(diag);
	    LoadDependents_func(topLoader, diag, apis, depOptions);
	    if (DiagnosticsHasError_func(diag)) {
	      *rcSlot = 9;
	      return;
	    }

    uintptr_t newLoadersCount = loaded->size - startLoaderCount;
	    void** newLoaders = &loaded->elements[startLoaderCount];
	    if (newLoadersCount != 0) {
	      ApplyFixups_ptr ApplyFixups = ApplyFixups_func;
	      struct DyldCacheDataConstLazyScopedWriter dcdclsw = { apis, false };
	      for (uintptr_t i = 0; i != newLoadersCount; ++i) {
	        void* ldr = newLoaders[i];
	        ApplyFixups(ldr, diag, apis, &dcdclsw, true, 0);
	      }
	      if (DiagnosticsHasError_func(diag)) {
	        *rcSlot = 9;
	        return;
	      }
	    }

	    IncDlRefCount_func(apis, topLoader);
	    RunInitializers_func(topLoader, apis);
	    *rtopLoader = (uint64_t)topLoader;
	  };

#if defined(__aarch64__)
  void (^doLoadWithWritableDyldState)(void) = ^(){
    bool entered = enter_writable_dyld_state(mm, LockGuard_func, WriteProtect_func, LockUnlock_func);
    doLoad();
    if (entered) {
      exit_writable_dyld_state(mm, LockGuard_func, WriteProtect_func, LockUnlock_func);
    }
  };

  if (protectedStack && WithProtectedStack_func) {
    WithProtectedStack_func(protectedStack, ^{
      doLoadWithWritableDyldState();
    });
  } else {
    doLoadWithWritableDyldState();
  }
#elif defined(__x86_64__)
  doLoad();
#else
  doLoad();
#endif

  if (*rcSlot != 0) {
    return *rcSlot;
  }

  void* topLoader = (void*)(uintptr_t)(*rtopLoader);
  if (!topLoader) {
    return 8;
  }

  // Resolve the entry symbol directly from the loaded image. This avoids
  // dyld-private handle conversion APIs that vary across versions/architectures.
  struct mach_header_64* loadedMh = (struct mach_header_64*)(uintptr_t)loadAddress;
  struct segment_command_64* loadedText = 0;
  struct load_command* llc = (struct load_command*)((char*)loadedMh + sizeof(*loadedMh));
  for (uint32_t i = 0; i < loadedMh->ncmds; i++) {
    if (llc->cmd == LC_SEGMENT_64) {
      struct segment_command_64* seg = (struct segment_command_64*)llc;
      if (string_compare(seg->segname, "__TEXT") == 0) {
        loadedText = seg;
        break;
      }
    }
    llc = (struct load_command*)((char*)llc + llc->cmdsize);
  }
  if (!loadedText) {
    return 10;
  }
  if (loadAddress < loadedText->vmaddr) {
    return 11;
  }

  uint64_t imageSlide = loadAddress - loadedText->vmaddr;
  void* addr_entry = find_symbol((uint64_t)loadAddress, entry_symbol, imageSlide);
  if (!addr_entry) {
    return 12;
  }

  void (*entry_func)(void) = (void (*)(void))addr_entry;
  entry_func();

  return 0;
}

int main(int argc, char** argv)
{
  (void)argc;
  (void)argv;
  (void)beignet_loader(0, 0, 0);
  return 0;
}
  typedef void (*init_func_x86_t)(int, const char**, const char**, const char**, void*);
