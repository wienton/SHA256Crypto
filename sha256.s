.section .data
.align 32
K:  # SHA-256 constants
    .long 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .long 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .long 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .long 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .long 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .long 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .long 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .long 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .long 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .long 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .long 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .long 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .long 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .long 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .long 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .long 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

.section .text
.global between_keys_sha256
.type between_keys_sha256, @function

between_keys_sha256:
    push %rbp
    mov %rsp, %rbp
    sub $544, %rsp  # 64*8 (W) + 8*8 (abcd...) + выравнивание

    # rdi = data, rsi = len, rdx = out
    mov %rdi, -8(%rbp)
    mov %rsi, -16(%rbp)
    mov %rdx, -24(%rbp)

    # Инициализация хеша
    mov $0x6a09e667, %eax; mov %eax, -32(%rbp)
    mov $0xbb67ae85, %eax; mov %eax, -36(%rbp)
    mov $0x3c6ef372, %eax; mov %eax, -40(%rbp)
    mov $0xa54ff53a, %eax; mov %eax, -44(%rbp)
    mov $0x510e527f, %eax; mov %eax, -48(%rbp)
    mov $0x9b05688c, %eax; mov %eax, -52(%rbp)
    mov $0x1f83d9ab, %eax; mov %eax, -56(%rbp)
    mov $0x5be0cd19, %eax; mov %eax, -60(%rbp)

    # Указатель на W (массив 64 uint32_t)
    lea -544(%rbp), %r8

.Lsha256_main:
    mov -16(%rbp), %rcx
    test %rcx, %rcx
    jz .Lsha256_final

    # Обработка полных блоков
    mov %rcx, %rax
    shr $6, %rax
    test %rax, %rax
    jz .Lsha256_final

    mov %rax, %r9  # block_count

.Lblock_loop:
    # Загрузка 512-битного блока и преобразование в big-endian
    mov -8(%rbp), %rdi
    mov %r9, %rax
    neg %rax
    add %rax, %r9
    lea (%rdi,%r9,64), %rdi  # data + (total_blocks - current - 1)*64

    mov $0, %rcx
.Lload_msg:
    cmp $16, %rcx
    jge .Lexpand
    mov (%rdi,%rcx,4), %eax
    bswap %eax
    mov %eax, (%r8,%rcx,4)
    inc %rcx
    jmp .Lload_msg

.Lexpand:
    mov $16, %rcx
.Lexpand_loop:
    cmp $64, %rcx
    jge .Lcompress_init
    # W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
    mov %rcx, %rax
    sub $2, %rax
    mov (%r8,%rax,4), %edx
    call sigma1_uint32
    push %rax

    mov %rcx, %rax
    sub $7, %rax
    mov (%r8,%rax,4), %eax
    add %eax, (%rsp)

    mov %rcx, %rax
    sub $15, %rax
    mov (%r8,%rax,4), %edx
    call sigma0_uint32
    add %eax, (%rsp)

    mov %rcx, %rax
    sub $16, %rax
    mov (%r8,%rax,4), %eax
    add %eax, (%rsp)

    pop %rax
    mov %rax, (%r8,%rcx,4)
    inc %rcx
    jmp .Lexpand_loop

.Lcompress_init:
    mov -32(%rbp), %esi   # a
    mov -36(%rbp), %edi   # b
    mov -40(%rbp), %r10d  # c
    mov -44(%rbp), %r11d  # d
    mov -48(%rbp), %r12d  # e
    mov -52(%rbp), %r13d  # f
    mov -56(%rbp), %r14d  # g
    mov -60(%rbp), %r15d  # h

    mov $0, %rcx
.Lround_loop:
    cmp $64, %rcx
    jge .Lupdate_hash

    # T1 = h + Sigma1(e) + Ch(e,f,g) + K[rcx] + W[rcx]
    mov %r15d, %eax        # h
    mov %r12d, %edx
    call Sigma1_uint32
    add %eax, %eax         
