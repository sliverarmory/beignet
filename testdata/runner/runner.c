#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ucontext.h>
#include <unistd.h>

static void* g_shellcode_base = 0;

static void segv_handler(int sig, siginfo_t* info, void* uap) {
  (void)sig;
  ucontext_t* uc = (ucontext_t*)uap;
#if defined(__aarch64__)
  uintptr_t pc = (uintptr_t)uc->uc_mcontext->__ss.__pc;
  uintptr_t lr = (uintptr_t)uc->uc_mcontext->__ss.__lr;
  uintptr_t x8 = (uintptr_t)uc->uc_mcontext->__ss.__x[8];
  uintptr_t x9 = (uintptr_t)uc->uc_mcontext->__ss.__x[9];
  uintptr_t x10 = (uintptr_t)uc->uc_mcontext->__ss.__x[10];
  uintptr_t x11 = (uintptr_t)uc->uc_mcontext->__ss.__x[11];
  uintptr_t x12 = (uintptr_t)uc->uc_mcontext->__ss.__x[12];
  fprintf(stderr, "SIGSEGV pc=%p lr=%p fault=%p\n", (void*)pc, (void*)lr,
          info ? info->si_addr : 0);
  fprintf(stderr, "regs x8=%p x9=%p x10=%p x11=%p x12=%p\n", (void*)x8,
          (void*)x9, (void*)x10, (void*)x11, (void*)x12);
  if (g_shellcode_base) {
    fprintf(stderr, "pc_offset=0x%lx\n",
            (unsigned long)(pc - (uintptr_t)g_shellcode_base));
  }
#elif defined(__x86_64__)
  uintptr_t rip = (uintptr_t)uc->uc_mcontext->__ss.__rip;
  uintptr_t rsp = (uintptr_t)uc->uc_mcontext->__ss.__rsp;
  uintptr_t rax = (uintptr_t)uc->uc_mcontext->__ss.__rax;
  uintptr_t rbx = (uintptr_t)uc->uc_mcontext->__ss.__rbx;
  uintptr_t rcx = (uintptr_t)uc->uc_mcontext->__ss.__rcx;
  uintptr_t rdx = (uintptr_t)uc->uc_mcontext->__ss.__rdx;
  uintptr_t rdi = (uintptr_t)uc->uc_mcontext->__ss.__rdi;
  uintptr_t rsi = (uintptr_t)uc->uc_mcontext->__ss.__rsi;
  fprintf(stderr, "SIGSEGV rip=%p rsp=%p fault=%p\n", (void*)rip, (void*)rsp,
          info ? info->si_addr : 0);
  fprintf(stderr, "regs rax=%p rbx=%p rcx=%p rdx=%p rdi=%p rsi=%p\n",
          (void*)rax, (void*)rbx, (void*)rcx, (void*)rdx, (void*)rdi,
          (void*)rsi);
  Dl_info dli;
  if (dladdr((void*)rip, &dli) != 0) {
    const char* fname = dli.dli_fname ? dli.dli_fname : "?";
    const char* sname = dli.dli_sname ? dli.dli_sname : "?";
    uintptr_t fbase = (uintptr_t)dli.dli_fbase;
    uintptr_t saddr = (uintptr_t)dli.dli_saddr;
    fprintf(stderr, "dladdr image=%s base=%p\n", fname, (void*)fbase);
    fprintf(stderr, "dladdr sym=%s addr=%p+0x%lx\n", sname, (void*)saddr,
            (unsigned long)(rip - saddr));
  }
  void* bt[64];
  int bt_n = backtrace(bt, 64);
  fprintf(stderr, "backtrace n=%d\n", bt_n);
  backtrace_symbols_fd(bt, bt_n, STDERR_FILENO);
  if (g_shellcode_base) {
    fprintf(stderr, "rip_offset=0x%lx\n",
            (unsigned long)(rip - (uintptr_t)g_shellcode_base));
  }
#else
  fprintf(stderr, "SIGSEGV fault=%p\n", info ? info->si_addr : 0);
#endif
  _exit(139);
}

static int read_all(int fd, unsigned char* buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t r = read(fd, buf + off, n - off);
    if (r < 0) {
      return -1;
    }
    if (r == 0) {
      return -1;
    }
    off += (size_t)r;
  }
  return 0;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
    return 2;
  }

  struct sigaction sa;
  sa.sa_sigaction = segv_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  if (sigaction(SIGSEGV, &sa, 0) != 0) {
    perror("sigaction");
    return 1;
  }
  if (sigaction(SIGBUS, &sa, 0) != 0) {
    perror("sigaction");
    return 1;
  }
  if (sigaction(SIGILL, &sa, 0) != 0) {
    perror("sigaction");
    return 1;
  }

  const char* path = argv[1];
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  struct stat st;
  if (fstat(fd, &st) != 0) {
    perror("fstat");
    close(fd);
    return 1;
  }
  if (st.st_size <= 0) {
    fprintf(stderr, "invalid size\n");
    close(fd);
    return 1;
  }

  size_t size = (size_t)st.st_size;
  void* mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  if (mem == MAP_FAILED) {
    perror("mmap");
    close(fd);
    return 1;
  }

  if (read_all(fd, (unsigned char*)mem, size) != 0) {
    perror("read");
    munmap(mem, size);
    close(fd);
    return 1;
  }
  close(fd);

  __builtin___clear_cache((char*)mem, (char*)mem + size);

  if (mprotect(mem, size, PROT_READ | PROT_EXEC) != 0) {
    perror("mprotect");
    munmap(mem, size);
    return 1;
  }

  g_shellcode_base = mem;
  int (*sc)(void) = (int (*)(void))mem;
  int rc = sc();
  if (rc != 0) {
    fprintf(stderr, "shellcode rc=%d\n", rc);
    return 1;
  }

  return 0;
}
