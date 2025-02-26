// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
// https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/
// https://tech-zealots.com/malware-analysis/journey-towards-import-address-table-of-an-executable-file/
// https://0xrick.github.io/win-internals/pe8/

#include <stdint.h>

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned long long QWORD;
typedef unsigned long LONG;
typedef __int64 LONGLONG;
typedef unsigned __int64 ULONGLONG;

/* u.x.wProcessorArchitecture (NT) */
#define PROCESSOR_ARCHITECTURE_INTEL 0
#define PROCESSOR_ARCHITECTURE_MIPS 1
#define PROCESSOR_ARCHITECTURE_ALPHA 2
#define PROCESSOR_ARCHITECTURE_PPC 3
#define PROCESSOR_ARCHITECTURE_SHX 4
#define PROCESSOR_ARCHITECTURE_ARM 5
#define PROCESSOR_ARCHITECTURE_IA64 6
#define PROCESSOR_ARCHITECTURE_ALPHA64 7
#define PROCESSOR_ARCHITECTURE_MSIL 8
#define PROCESSOR_ARCHITECTURE_AMD64 9
#define PROCESSOR_ARCHITECTURE_IA32_ON_WIN64 10
#define PROCESSOR_ARCHITECTURE_UNKNOWN 0xFFFF

/* dwProcessorType */
#define PROCESSOR_INTEL_386 386
#define PROCESSOR_INTEL_486 486
#define PROCESSOR_INTEL_PENTIUM 586
#define PROCESSOR_INTEL_860 860
#define PROCESSOR_INTEL_IA64 2200
#define PROCESSOR_AMD_X8664 8664
#define PROCESSOR_MIPS_R2000 2000
#define PROCESSOR_MIPS_R3000 3000
#define PROCESSOR_MIPS_R4000 4000
#define PROCESSOR_ALPHA_21064 21064
#define PROCESSOR_PPC_601 601
#define PROCESSOR_PPC_603 603
#define PROCESSOR_PPC_604 604
#define PROCESSOR_PPC_620 620
#define PROCESSOR_HITACHI_SH3 10003
#define PROCESSOR_HITACHI_SH3E 10004
#define PROCESSOR_HITACHI_SH4 10005
#define PROCESSOR_MOTOROLA_821 821
#define PROCESSOR_SHx_SH3 103
#define PROCESSOR_SHx_SH4 104
#define PROCESSOR_STRONGARM 2577
#define PROCESSOR_ARM720 1824 /* 0x720 */
#define PROCESSOR_ARM820 2080 /* 0x820 */
#define PROCESSOR_ARM920 2336 /* 0x920 */
#define PROCESSOR_ARM_7TDMI 70001
#define PROCESSOR_OPTIL 18767

typedef struct _IMAGE_DOS_HEADER
{
    WORD e_magic;    /* 00: MZ Header signature */
    WORD e_cblp;     /* 02: Bytes on last page of file */
    WORD e_cp;       /* 04: Pages in file */
    WORD e_crlc;     /* 06: Relocations */
    WORD e_cparhdr;  /* 08: Size of header in paragraphs */
    WORD e_minalloc; /* 0a: Minimum extra paragraphs needed */
    WORD e_maxalloc; /* 0c: Maximum extra paragraphs needed */
    WORD e_ss;       /* 0e: Initial (relative) SS value */
    WORD e_sp;       /* 10: Initial SP value */
    WORD e_csum;     /* 12: Checksum */
    WORD e_ip;       /* 14: Initial IP value */
    WORD e_cs;       /* 16: Initial (relative) CS value */
    WORD e_lfarlc;   /* 18: File address of relocation table */
    WORD e_ovno;     /* 1a: Overlay number */
    WORD e_res[4];   /* 1c: Reserved words */
    WORD e_oemid;    /* 24: OEM identifier (for e_oeminfo) */
    WORD e_oeminfo;  /* 26: OEM information; e_oemid specific */
    WORD e_res2[10]; /* 28: Reserved words */
    DWORD e_lfanew;  /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

#define IMAGE_DOS_SIGNATURE 0x5A4D    /* MZ   */
#define IMAGE_OS2_SIGNATURE 0x454E    /* NE   */
#define IMAGE_OS2_SIGNATURE_LE 0x454C /* LE   */
#define IMAGE_OS2_SIGNATURE_LX 0x584C /* LX */
#define IMAGE_VXD_SIGNATURE 0x454C    /* LE   */
#define IMAGE_NT_SIGNATURE 0x00004550 /* PE00 */
