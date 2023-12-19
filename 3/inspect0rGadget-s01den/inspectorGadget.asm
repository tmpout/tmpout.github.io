%include "gadget_list.asm"

; inspect0rGadget by s01den
; Build command: 
; nasm -f elf64 inspectorGadget.asm ; ld inspectorGadget.o -o inspectorGadget
; run: ./inspect0rGadget test.bin

section .text
global _start

_start:
	
	; mmap the place where we're gonna put the gadgets addresses
	mov r8, -1   
	mov rsi, 0x8000

	xor rdi, rdi
	mov rdx, 3				; protect RW = PROT_READ (0x04) | PROT_WRITE (0x2)
	xor r9, r9				; r9 = 0 <=> offset_start = 0
	mov r10, 0x22				; flag = MAP_PRIVATE
	mov rax, 9				; mmap syscall number
	syscall

	mov r15, rax ; r15 is now the addr of the gadget-fridge (serves as pointer)
	mov r10, rax ; r10 is the addr of the beginning of the gadget-fridge

	pop r8
	pop rsi
	pop rdi 				; get argv[1]

	; open the file
	mov rax, 2
	mov rsi, 0x402 				; RW mode
	syscall

	cmp rax, 0
	jng quit_prog

	mov rbx, rax

	; stat the file to know its length
	mov rsi, rsp
	sub rsi, r13
	mov rax, 4
	syscall

	; mmap the file
	mov r8, rbx				; the fd
	mov rsi, [rsi+STAT.st_size]		; the len

	mov rdi, rsp				; we write this shit on the stack
	mov rdx, 3				; protect RW 
	xor r9, r9				; r9 = 0 <=> offset_start = 0
	push r10
	mov r10, 0x1				; flag = MAP_SHARED
	xor rax, rax
	mov rax, 9				; mmap syscall number
	syscall

	pop r10

	cmp dword [rax+e_hdr.magic], 0x464c457f	; check if the file is an ELF
	jne quit_prog

	cmp byte [rax+e_hdr.class], 2		; check if the binary is 64 bits
	jne quit_prog
	
parse_shdr:
  xor rcx, rcx
  xor rdx, rdx
  mov cx, word [rax+e_hdr.shnum]	; rcx contains the num of entries in PHT
  mov rbx, qword [rax+e_hdr.shoff]	; rbx contains the offset of the PHT
  mov dx, word [rax+e_hdr.shentsize]	; rdx contains the size of an entry in PHT

  loop_shdr:
	push rax
	mov eax, dword [rax+rbx+e_shdr.flags]
	and al, 0x4			; check if the segment is executable
	test al, al
	pop rax
	push rax
	push rdx
	push rcx
	push rbx
	jz continue_loop_shdr
	call exec_seg_found 
continue_loop_shdr:
	pop rbx
	pop rcx
	pop rdx
	pop rax
	add rbx, rdx
	dec rcx
	cmp rcx, 0
	jne loop_shdr
	je quit_prog

exec_seg_found:
	mov r11, qword [rax+rbx+e_shdr.size]
	mov r12, qword [rax+rbx+e_shdr.addr]
	add r12, rax
	xor rcx, rcx
	test r11, r11
	je return_search
	pop r14

search_ret:
	; rcx is the counter 
	; r12 is the address
	; rbx is the opcode

	xor rbx, rbx
	inc r12
	mov ebx, dword [r12]

	cmp bl, 0xc3
	je find_ret
	cmp bx, 0xcd80
	je find_system_call
	cmp bx, 0x0f05
	je find_system_call
	cmp bx, 0x0f34
	je find_system_call
end_search:
	inc rcx
	cmp rcx, r11
	jne search_ret
return_search:
	push r14
	ret

find_ret: 
	;mov r14, [rsp] ; save the return addr
	jmp gadget_list

search_gadget:
	pop r13
	push rax
	push rcx
	xor rax, rax
	xor rbx, rbx
	xor rcx, rcx

	; compare each gadget, byte per byte, with the bytes before ret
	loop_compare_gadget:
		mov bl, byte [r13]
		inc r13
		mov rdi, r12
		sub rdi, rbx
		xor rsi, rsi
		
		copy_inst: 
			mov cl, byte [r13+rsi]
			mov al, byte [rdi+rsi]
			inc rsi
			cmp cl, al
			jne test_other_gadget
			cmp rsi, rbx
			jne copy_inst

save_gadget:
	pop rcx
	pop rax
	sub rdi, rax			; calculate the true address of the gadget
	mov qword [r15], rdi		; save the gadget
	add r15, 0x10			; update the gadget_fridge pointer (add 0x10 = a qword)	
	add r12, rbx			; update r12
	inc r12
	jmp end_search

test_other_gadget:
	add r13, rbx
	cmp byte [r13], 0xff
	je quit_save_gadget
	jmp loop_compare_gadget

quit_save_gadget:
	pop rcx
	pop rax
	jmp end_search

find_system_call:
	mov qword [r15], r12	; save the sys_call gadget
	add r15, 0x10		; update the gadget_fridge pointer (add 0x10 = a qword)
	jmp end_search

quit_prog:
	; from here, r10 contains all the addresses of the gadgets!
	mov rax, 60
	mov rdi, r10
	syscall


;--------------------------------------------------------------------------------------------------------------------------

;___________               _______          __
;\__    ___/____ ______    \   _  \  __ ___/  |_
;  |    | /     \\____ \   /  /_\  \|  |  \   __\
;  |    ||  Y Y  \  |_> >  \  \_/   \  |  /|  |
;  |____||__|_|  /   __/ /\ \_____  /____/ |__|
;              \/|__|    \/       \/              in your stack...
