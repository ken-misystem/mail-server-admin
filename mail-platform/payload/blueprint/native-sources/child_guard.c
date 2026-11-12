/* INERT Linux/x86_64 preload constructor candidate. No keys/certificates here.
 * Build in a future approved PRIVATE Linux validation, NOT on production now:
 * cc -shared -fPIC -O2 -Wall -Wextra -Werror -Wl,-z,relro,-z,now -o guard.so child_guard.c
 * Secret FDs are absent at exec. Constructor hardens and acknowledges first;
 * only then SCM_RIGHTS installs inputs/output for the existing pinned OpenSSL.
 */
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/auxv.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#if !defined(__x86_64__) || defined(__ILP32__)
#error Native guard requires reviewed x86_64 ABI; other architectures fail closed.
#endif

#define CONTROL 256
#define MAX_FDS 16
#define DENY (SECCOMP_RET_ERRNO | EPERM)
#define BLOCK(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(n),0,1), BPF_STMT(BPF_RET|BPF_K,DENY)

static void fail(unsigned stage) {
    unsigned char packet[3] = {'E', (unsigned char)stage, (unsigned char)(errno & 255)};
    (void)send(CONTROL, packet, sizeof(packet), MSG_NOSIGNAL);
    _exit(120 + (int)stage);
}

static int no_caps(void) {
    char line[512]; unsigned found = 0;
    FILE *f = fopen("/proc/self/status", "re");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        const char *names[] = {"CapInh:", "CapPrm:", "CapEff:", "CapAmb:"};
        for (unsigned i=0; i<4; i++) {
            if (strncmp(line,names[i],strlen(names[i]))==0) {
                char *end; unsigned long long value=strtoull(line+strlen(names[i]),&end,16);
                if (value != 0 || end == line+strlen(names[i])) { fclose(f); return 0; }
                found |= 1u<<i;
            }
        }
    }
    fclose(f); return found == 15;
}

static int seal_execution(void) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        /* Reject x32 syscall namespace, not just native exec numbers. */
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,0x40000000,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BLOCK(__NR_execve), BLOCK(__NR_execveat),
        BLOCK(__NR_fork), BLOCK(__NR_vfork), BLOCK(__NR_clone), BLOCK(__NR_clone3),
        BLOCK(__NR_setuid), BLOCK(__NR_setgid), BLOCK(__NR_setreuid), BLOCK(__NR_setregid),
        BLOCK(__NR_setresuid), BLOCK(__NR_setresgid), BLOCK(__NR_setfsuid), BLOCK(__NR_setfsgid),
        BLOCK(__NR_setgroups), BLOCK(__NR_capset),
        BLOCK(__NR_ptrace), BLOCK(__NR_process_vm_readv), BLOCK(__NR_process_vm_writev),
        BLOCK(__NR_munlock), BLOCK(__NR_munlockall), BLOCK(__NR_mlockall),
        BLOCK(__NR_socket), BLOCK(__NR_socketpair), BLOCK(__NR_connect),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_prctl,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_SET_DUMPABLE,0,1),
        BPF_STMT(BPF_RET|BPF_K,DENY),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={(unsigned short)(sizeof(f)/sizeof(f[0])),f};
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)==0;
}

__attribute__((constructor)) static void protect_before_openssl_main(void) {
    int kind; socklen_t size=sizeof(kind); struct rlimit core={0,0};
    pid_t parent=getppid();
    if (getauxval(AT_SECURE)!=0 || getuid()==0 || geteuid()!=getuid() || getegid()!=getgid()
        || getsockopt(CONTROL,SOL_SOCKET,SO_TYPE,&kind,&size)!=0 || kind!=SOCK_SEQPACKET) fail(1);
    if (prctl(PR_SET_PDEATHSIG,SIGKILL)!=0 || getppid()!=parent
        || setrlimit(RLIMIT_CORE,&core)!=0 || prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0
        || prctl(PR_SET_DUMPABLE,0,0,0,0)!=0 || !no_caps()) fail(2);
    /* Future allocations, including OpenSSL heap, must remain locked or fail. */
    if (mlockall(MCL_CURRENT|MCL_FUTURE)!=0 || !seal_execution()
        || prctl(PR_GET_DUMPABLE,0,0,0,0)!=0 || prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1
        || prctl(PR_GET_SECCOMP,0,0,0,0)!=2) fail(3);
    if (send(CONTROL,"READY1",6,MSG_NOSIGNAL)!=6) fail(4);

    /* Parent waits for kernel credentials + READY1 before sending any FD. */
    unsigned char body[1+MAX_FDS*2];
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(MAX_FDS*sizeof(int))]; } ancillary;
    memset(&ancillary,0,sizeof(ancillary));
    struct iovec io={body,sizeof(body)};
    struct msghdr msg={0}; msg.msg_iov=&io; msg.msg_iovlen=1;
    msg.msg_control=ancillary.bytes; msg.msg_controllen=sizeof(ancillary.bytes);
    ssize_t n=recvmsg(CONTROL,&msg,MSG_CMSG_CLOEXEC);
    if (n<1 || msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)) fail(5);
    unsigned count=body[0];
    struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
    if (count==0 || count>MAX_FDS || n!=(ssize_t)(1+2*count) || !c
        || c->cmsg_level!=SOL_SOCKET || c->cmsg_type!=SCM_RIGHTS
        || c->cmsg_len!=CMSG_LEN(count*sizeof(int)) || CMSG_NXTHDR(&msg,c)!=NULL) fail(5);
    int received[MAX_FDS], held[MAX_FDS], target[MAX_FDS];
    memcpy(received,CMSG_DATA(c),count*sizeof(int));
    for (unsigned i=0;i<count;i++) {
        target[i]=(int)body[1+2*i]*256+(int)body[2+2*i];
        if ((target[i]!=1 && (target[i]<3 || target[i]>=200))) fail(6);
        for (unsigned j=0;j<i;j++) if (target[j]==target[i]) fail(6);
        held[i]=fcntl(received[i],F_DUPFD_CLOEXEC,512);
        if (held[i]<0) fail(6);
    }
    for (unsigned i=0;i<count;i++) close(received[i]);
    for (unsigned i=0;i<count;i++) {
        if (dup2(held[i],target[i])!=target[i]) fail(6);
        close(held[i]);
    }
    /* Only now can application main access secret descriptors. No more exec. */
    if (prctl(PR_GET_DUMPABLE,0,0,0,0)!=0 || send(CONTROL,"BOUND1",6,MSG_NOSIGNAL)!=6) fail(7);
    close(CONTROL);
    unsetenv("LD_PRELOAD");
}
