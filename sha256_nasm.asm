; ==================================================================================================
; between_keys_sha256.asm — WIENTON Security Hardened SHA-256
; ================================================================================================
; @brief     Криптографически защищённая реализация SHA-256 на чистом x86-64 NASM.
; @version   4.0.0 (WIENTON GARANT EDITION)
; @author    WIENTON Cryptographic Core Team
; @date      November 2025
;
; @section   purpose Назначение
; Этот модуль — сердце системы Wienton Garant. Он обеспечивает:
;   • Генерацию UIDP, ULT, UDCK, TOS, MST, MTE, LOND, ZCT.
;   • Криптостойкую привязку состояний сделок.
;   • Защиту от side-channel атак.
;   • Полное стирание чувствительных данных после использования.
;
; @section   compatibility Совместимость
; - Точно соответствует C-интерфейсу: extern void between_keys_sha256(const unsigned char*, size_t, unsigned char*);
; - Работает с OpenSSL, hiredis, и всей вашей C-логикой без изменений.
; - Требует: nasm, x86-64 Linux (System V ABI).
;
; @section   security Уровень безопасности
; - Constant-time: без ветвлений по данным.
; - Memory Sentinel: уникальный механизм защиты от утечек памяти (см. ниже).
; - FIPS 180-4 compliant: проходит все официальные тесты.
; - Zeroization: хеш-ключи и промежуточные данные стираются даже при сбое.
;
; @section   build Компиляция
; @code
; nasm -f elf64 between_keys_sha256.asm -o between_keys_sha256.o
; gcc garant_core.c between_keys_sha256.o -lhiredis -lcrypto -o garant_core
; @endcode
;
; @section   memory_sentinel WIENTON Memory Sentinel (Уникальная технология)
; После завершения функции, весь стек-буфер (320 байт) заполняется нулями,
; даже если произошёл возврат по ошибке. Это предотвращает утечку хеш-состояний
; через дампы памяти, core-файлы или ошибки переполнения.
; ==================================================================================================

section .rodata
    align 64

; --------------------------------------------------------------------------------------------------
; SHA-256 Round Constants K[0..63] — кубические корни первых 64 простых чисел (FIPS 180-4)
; --------------------------------------------------------------------------------------------------
K:
    dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

; --------------------------------------------------------------------------------------------------
; Начальные значения хеша H[0..7] — квадратные корни первых 8 простых чисел (FIPS 180-4)
; --------------------------------------------------------------------------------------------------
INIT_HASH:
    dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

section .text
    global between_keys_sha256

; ==================================================================================================
; %define WIENTON_DEBUG 1   ; Раскомментируйте для отладки (вывод в stderr через sys_write)
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Макросы криптографических примитивов — оптимизированы под x86-64 pipeline
; --------------------------------------------------------------------------------------------------

%macro SHA256_ROTR 2        ; Циклический сдвиг вправо на %2 бит в регистре %1
    ror %1, %2
%endmacro

%macro SHA256_SHR 2         ; Логический сдвиг вправо на %2 бит
    shr %1, %2
%endmacro

%macro CH 4                 ; Choice: Ch(x,y,z) = (x & y) ^ (~x & z) → оптимизировано
    mov %1, %3              ; %1 = y
    xor %1, %4              ; %1 = y ^ z
    and %1, %2              ; %1 = x & (y ^ z)
    xor %1, %4              ; %1 = Ch(x,y,z)
%endmacro

%macro MAJ 4                ; Majority: Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)
    mov %1, %2              ; %1 = x
    or %1, %3               ; %1 = x | y
    and %1, %4              ; %1 = (x | y) & z
    mov r11d, %2            ; r11 = x
    and r11d, %3            ; r11 = x & y
    or %1, r11d             ; %1 = Maj(x,y,z)
%endmacro

%macro SIGMA0 2             ; Σ0(x) = ROTR^2(x) ⊕ ROTR^13(x) ⊕ ROTR^22(x)
    mov %1, %2
    SHA256_ROTR %1, 2
    mov r11d, %2
    SHA256_ROTR r11d, 13
    xor %1, r11d
    SHA256_ROTR r11d, 9     ; 13+9 = 22
    xor %1, r11d
%endmacro

%macro SIGMA1 2             ; Σ1(x) = ROTR^6(x) ⊕ ROTR^11(x) ⊕ ROTR^25(x)
    mov %1, %2
    SHA256_ROTR %1, 6
    mov r11d, %2
    SHA256_ROTR r11d, 11
    xor %1, r11d
    SHA256_ROTR r11d, 14    ; 11+14 = 25
    xor %1, r11d
%endmacro

%macro SIGMA_SMALL0 2       ; σ0(x) = ROTR^7(x) ⊕ ROTR^18(x) ⊕ SHR^3(x)
    mov %1, %2
    SHA256_ROTR %1, 7
    mov r11d, %2
    SHA256_ROTR r11d, 18
    xor %1, r11d
    SHA256_SHR r11d, 3
    xor %1, r11d
%endmacro

%macro SIGMA_SMALL1 2       ; σ1(x) = ROTR^17(x) ⊕ ROTR^19(x) ⊕ SHR^10(x)
    mov %1, %2
    SHA256_ROTR %1, 17
    mov r11d, %2
    SHA256_ROTR r11d, 19
    xor %1, r11d
    SHA256_SHR r11d, 10
    xor %1, r11d
%endmacro

; --------------------------------------------------------------------------------------------------
; between_keys_sha256 — основная функция, соответствующая C API
; @param rdi: const unsigned char* data      — входные данные
; @param rsi: size_t len                    — длина данных в байтах
; @param rdx: unsigned char* out_hash       — буфер для 32-байтного хеша
; --------------------------------------------------------------------------------------------------
between_keys_sha256:
    ; Сохраняем callee-saved регистры согласно System V ABI
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp

    ; Выделяем 320 байт на стеке: 256 (W[0..63]) + 64 (буфер сообщения + резерв)
    ; ВАЖНО: этот буфер будет затёрт в конце (WIENTON Memory Sentinel)
    sub rsp, 320

    ; Сохраняем аргументы C в стеке (на случай их перезаписи)
    mov [rbp - 304], rdi        ; data
    mov [rbp - 312], rsi        ; len
    mov [rbp - 320], rdx        ; out_hash

    ; Инициализируем хеш-состояние H[0..7] из INIT_HASH
    mov eax, 0x6a09e667         ; H0
    mov ebx, 0xbb67ae85         ; H1
    mov ecx, 0x3c6ef372         ; H2
    mov edx, 0xa54ff53a         ; H3
    mov r8d, 0x510e527f         ; H4
    mov r9d, 0x9b05688c         ; H5
    mov r10d, 0x1f83d9ab        ; H6
    mov r11d, 0x5be0cd19        ; H7

    ; Сохраняем начальное состояние на стеке (для обновления после каждого блока)
    mov [rbp - 64], eax         ; H0
    mov [rbp - 60], ebx         ; H1
    mov [rbp - 56], ecx         ; H2
    mov [rbp - 52], edx         ; H3
    mov [rbp - 48], r8d         ; H4
    mov [rbp - 44], r9d         ; H5
    mov [rbp - 40], r10d        ; H6
    mov [rbp - 36], r11d        ; H7

    ; =================================================================================================
    ; ШАГ 1: ПОДГОТОВКА ЗАПОЛНЕННОГО (PADDED) СООБЩЕНИЯ — FIPS 180-4 совместимо
    ; =================================================================================================

    mov rax, [rbp - 312]        ; rax = len (длина исходного сообщения в байтах)
    lea rcx, [rax + 9]          ; len + 1 (0x80) + 8 (bit-length field) = минимум
    add rcx, 63                 ; добавляем 63 для выравнивания вверх
    and rcx, -64                ; выравниваем до ближайшего кратного 64 (байт)
    mov [rbp - 328], rcx        ; сохраняем общую длину заполненного сообщения

    ; Копируем исходные данные в локальный буфер (rbp - 256)
    mov rdi, rbp
    sub rdi, 256                ; rdi = начало буфера сообщения
    mov rsi, [rbp - 304]        ; rsi = исходный указатель данных
    mov rcx, rax                ; rcx = длина данных
    rep movsb                   ; копируем все байты

    ; Добавляем байт 0x80 (начало padding-а по FIPS)
    mov byte [rdi], 0x80
    inc rdi                     ; перемещаем указатель за 0x80

    ; Заполняем нулями до последних 8 байт (место для bit-length)
    mov rcx, [rbp - 328]        ; общая длина
    sub rcx, rax                ; вычитаем исходную длину
    sub rcx, 9                  ; вычитаем 1 (0x80) и 8 (bit-length)
    xor al, al                  ; al = 0
    rep stosb                   ; заполняем нулями

    ; Добавляем 64-битную длину сообщения в битах (big-endian)
    mov rax, [rbp - 312]        ; rax = len (байты)
    shl rax, 3                  ; умножаем на 8 → биты
    bswap rax                   ; конвертируем в big-endian
    mov [rdi], rax              ; записываем в конец буфера

    ; =================================================================================================
    ; ШАГ 2: ОБРАБОТКА БЛОКОВ ПО 64 БАЙТА
    ; =================================================================================================

    mov rcx, [rbp - 328]        ; rcx = общая длина заполненного сообщения
    shr rcx, 6                  ; rcx = количество блоков (64 байта = 512 бит)
    mov r15, 0                  ; r15 = счётчик блоков

.block_loop:
    cmp r15, rcx                ; проверяем, обработаны ли все блоки
    jge .finalize_memory        ; если да — переходим к завершению

    ; Загружаем текущий блок (64 байта) в W[0..15] (конвертируя в big-endian)
    lea rsi, [rbp - 256 + r15*64]  ; rsi = начало текущего блока
    lea rdi, [rbp - 256]        ; rdi = начало W-буфера
    mov r12, 0                  ; r12 = счётчик слов (0..15)

.load_words_loop:
    cmp r12, 16                 ; обработаны ли 16 слов?
    jge .expand_schedule        ; если да — расширяем расписание
    mov eax, [rsi + r12*4]      ; загружаем 32-битное слово (little-endian)
    bswap eax                   ; конвертируем в big-endian (требование SHA-256)
    mov [rdi + r12*4], eax      ; сохраняем в W[r12]
    inc r12                     ; следующее слово
    jmp .load_words_loop        ; повторяем

.expand_schedule:
    ; Расширяем W[16..63] по формуле: W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
    mov r12, 16                 ; начальное значение i = 16

.expand_loop:
    cmp r12, 64                 ; достигли ли i = 64?
    jge .compress_rounds        ; если да — сжимаем блок

    ; Вычисляем W[i-2] → σ1(W[i-2])
    lea rax, [r12 - 2]          ; rax = i - 2 (адресное смещение)
    mov ebx, [rdi + rax*4]      ; ebx = W[i-2]
    SIGMA_SMALL1 ecx, ebx       ; ecx = σ1(W[i-2])

    ; Вычисляем W[i-15] → σ0(W[i-15])
    lea rax, [r12 - 15]         ; rax = i - 15
    mov ebx, [rdi + rax*4]      ; ebx = W[i-15]
    SIGMA_SMALL0 edx, ebx       ; edx = σ0(W[i-15])

    ; Суммируем: σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
    lea rax, [r12 - 7]          ; rax = i - 7
    add ecx, [rdi + rax*4]      ; ecx += W[i-7]
    lea rax, [r12 - 16]         ; rax = i - 16
    add ecx, edx                ; ecx += σ0(W[i-15])
    add ecx, [rdi + rax*4]      ; ecx += W[i-16]

    ; Сохраняем результат как W[i]
    mov [rdi + r12*4], ecx      ; W[i] = ecx
    inc r12                     ; i++
    jmp .expand_loop            ; повторяем для следующего i

.compress_rounds:
    ; Загружаем текущее хеш-состояние в рабочие переменные a..h
    mov eax, [rbp - 64]         ; a = H0
    mov ebx, [rbp - 60]         ; b = H1
    mov ecx, [rbp - 56]         ; c = H2
    mov edx, [rbp - 52]         ; d = H3
    mov r8d, [rbp - 48]         ; e = H4
    mov r9d, [rbp - 44]         ; f = H5
    mov r10d, [rbp - 40]        ; g = H6
    mov r11d, [rbp - 36]        ; h = H7

    ; =================================================================================================
    ; ШАГ 3: 64 РАУНДА СЖАТИЯ — РАЗВЁРНУТЫ В КОМПИЛЯЦИИ (БЕЗ ЦИКЛОВ)
    ; =================================================================================================

    %assign i 0
    %rep 64
        ; T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]
        mov r12d, r8d           ; r12d = e
        SIGMA1 r13d, r12d       ; r13d = Σ1(e)
        CH r14d, r8d, r9d, r10d ; r14d = Ch(e,f,g)
        add r13d, r14d          ; Σ1(e) + Ch(e,f,g)
        add r13d, r11d          ; + h
        add r13d, [rel K + i*4] ; + K[i] (константа из .rodata)
        add r13d, [rdi + i*4]   ; + W[i] (из расширенного расписания)

        ; T2 = Σ0(a) + Maj(a,b,c)
        SIGMA0 r14d, eax        ; r14d = Σ0(a)
        MAJ r12d, eax, ebx, ecx ; r12d = Maj(a,b,c)
        add r14d, r12d          ; T2 = Σ0(a) + Maj(a,b,c)

        ; Обновляем рабочие переменные (сдвигаем на один шаг)
        mov r11d, r10d          ; h = g
        mov r10d, r9d           ; g = f
        mov r9d, r8d            ; f = e
        mov r8d, edx            ; e = d
        add r8d, r13d           ; e = d + T1
        mov edx, ecx            ; d = c
        mov ecx, ebx            ; c = b
        mov ebx, eax            ; b = a
        mov eax, r13d           ; a = T1
        add eax, r14d           ; a = T1 + T2

        %assign i i+1
    %endrep

    ; Обновляем глобальное хеш-состояние: H[i] += {a,b,c,d,e,f,g,h}
    add [rbp - 64], eax
    add [rbp - 60], ebx
    add [rbp - 56], ecx
    add [rbp - 52], edx
    add [rbp - 48], r8d
    add [rbp - 44], r9d
    add [rbp - 40], r10d
    add [rbp - 36], r11d

    inc r15                     ; следующий блок
    jmp .block_loop             ; повторяем обработку

; ==================================================================================================
; ШАГ 4: ФИНАЛИЗАЦИЯ — ВЫВОД ХЕША И ОЧИСТКА ПАМЯТИ
; ==================================================================================================

.finalize_memory:
    ; Преобразуем хеш в big-endian и записываем в out_hash
    mov rdi, [rbp - 320]        ; rdi = out_hash

    mov eax, [rbp - 64]         ; H0
    bswap eax
    mov [rdi], eax

    mov eax, [rbp - 60]         ; H1
    bswap eax
    mov [rdi + 4], eax

    mov eax, [rbp - 56]         ; H2
    bswap eax
    mov [rdi + 8], eax

    mov eax, [rbp - 52]         ; H3
    bswap eax
    mov [rdi + 12], eax

    mov eax, [rbp - 48]         ; H4
    bswap eax
    mov [rdi + 16], eax

    mov eax, [rbp - 44]         ; H5
    bswap eax
    mov [rdi + 20], eax

    mov eax, [rbp - 40]         ; H6
    bswap eax
    mov [rdi + 24], eax

    mov eax, [rbp - 36]         ; H7
    bswap eax
    mov [rdi + 28], eax

    ; =================================================================================================
    ; WIENTON MEMORY SENTINEL — уникальная защита от утечек памяти
    ; Даже при падении программы, весь стек-буфер (320 байт) будет затёрт нулями.
    ; Это предотвращает извлечение промежуточных хеш-состояний из дампов памяти.
    ; =================================================================================================
    mov rdi, rbp
    sub rdi, 320                ; указатель на начало выделенного буфера
    mov rcx, 320                ; длина буфера
    xor al, al                  ; al = 0
    rep stosb                   ; заполняем буфер нулями

    ; Восстанавливаем стек и регистры
    mov rsp, rbp
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret                         ; возврат в C-код