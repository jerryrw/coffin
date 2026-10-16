/*
 * One small C source produces all nine root-level Hello World fixtures.
 * The preprocessor chooses exactly one OS/CPU branch at compile time. Direct
 * Windows imports and Linux syscalls avoid requiring cross-compiled C libraries;
 * the macOS branch uses its normal C runtime. These deliberate platform-specific
 * examples are not the portability model used by the inspector itself.
 */

/* Known-source inspector fixtures. No third-party source or runtime is bundled. */
/*
 * A string literal includes a final zero byte. sizeof(message) - 1 writes
 * the message and newline while excluding that C string terminator.
 */
static const char message[] = "Hello from coffin!\n";

#if defined(_WIN32)
/*
 * dllimport tells the Windows linker these functions come from another DLL.
 * __stdcall is the 32-bit Windows calling convention; the import library records
 * these names. The fixture's entry point replaces normal C runtime startup.
 */
__declspec(dllimport) void *__stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int __stdcall WriteFile(void *, const void *, unsigned long, unsigned long *, void *);
__declspec(dllimport) __attribute__((noreturn)) void __stdcall ExitProcess(unsigned int);

/*
 * GetStdHandle(-11) requests standard output; WriteFile reports its byte count
 * through &written. ExitProcess terminates with zero only on a complete write.
 * Casting -11 to unsigned long preserves the Windows API's required bit pattern.
 */
void mainCRTStartup(void)
{
    unsigned long written = 0;
    int ok = WriteFile(GetStdHandle((unsigned long)-11), message, sizeof(message) - 1, &written, 0);
    ExitProcess(ok && written == sizeof(message) - 1 ? 0 : 1);
}
#elif defined(__linux__)
/* Freestanding Linux syscalls avoid a cross-compiled libc dependency. */
/*
 * Linux enters here without a C main/startup wrapper. Write to descriptor 1,
 * then invoke the architecture's exit syscall. Return values smaller than the
 * message length (including negative errors) produce a nonzero exit status.
 */
__attribute__((noreturn)) void _start(void)
{
    long result;
/*
 * Inline assembly below is compiler-specific C. The text before the first
 * colon is the instruction; output operands follow it, then inputs, then
 * clobbers (registers/memory the instruction may change). volatile prevents
 * discarding the syscall merely because C cannot see its external effects.
 * Each CPU ABI assigns different registers and syscall numbers.
 */
#if defined(__i386__)
    __asm__ volatile("int $0x80" : "=a"(result) : "a"(4), "b"(1), "c"(message), "d"(sizeof(message) - 1) : "memory");
    __asm__ volatile("int $0x80" : : "a"(1), "b"(result == (long)(sizeof(message) - 1) ? 0 : 1) : "memory");
#elif defined(__x86_64__)
    __asm__ volatile("syscall" : "=a"(result) : "a"(1), "D"(1), "S"(message), "d"(sizeof(message) - 1) : "rcx", "r11", "memory");
    __asm__ volatile("syscall" : : "a"(60), "D"(result == (long)(sizeof(message) - 1) ? 0 : 1) : "rcx", "r11", "memory");
#elif defined(__arm__)
    /*
     * ARM32 pins variables to syscall ABI registers: r0=fd/result, r1=buffer,
     * r2=byte count, r7=syscall number. "+r" marks a register as both input
     * and output, so C sees the result returned by svc.
     */
    register long r0 __asm__("r0") = 1;
    register const char *r1 __asm__("r1") = message;
    register unsigned long r2 __asm__("r2") = sizeof(message) - 1;
    register long r7 __asm__("r7") = 4; /* ARM EABI write */
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory", "cc");
    result = r0;
    r0 = result == (long)(sizeof(message) - 1) ? 0 : 1;
    r7 = 1; /* ARM EABI exit */
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7) : "memory", "cc");
#elif defined(__aarch64__)
    /*
     * AArch64 uses x0-x2 for these arguments and x8 for the syscall number.
     * The write result comes back in x0; exit then reuses x0 for its status.
     */
    register long x0 __asm__("x0") = 1;
    register const char *x1 __asm__("x1") = message;
    register unsigned long x2 __asm__("x2") = sizeof(message) - 1;
    register long x8 __asm__("x8") = 64; /* AArch64 write */
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory", "cc");
    result = x0;
    x0 = result == (long)(sizeof(message) - 1) ? 0 : 1;
    x8 = 93; /* AArch64 exit */
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory", "cc");
#else
#error Linux sample supports i386, x86_64, ARM EABI, and AArch64
#endif
    /*
     * The exit syscall does not return. Tell the compiler that no C execution
     * path continues here; this matches the function's noreturn declaration.
     */
    __builtin_unreachable();
}
#else
extern int puts(const char *);
/*
 * On macOS the normal runtime calls main. puts adds the newline and returns
 * a negative value on error; the comparison becomes exit status zero or one.
 */
int main(void)
{
    return puts("Hello from coffin!") < 0;
}
#endif
