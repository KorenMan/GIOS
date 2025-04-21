bits 16
org 0x8000

start:
    ; Save boot drive number
    mov [boot_drive], dl
    
    ; Set up segments
    xor ax, ax
    mov ds, ax
    mov es, ax
    
    ; Set up stack
    mov bp, 0x9000
    mov sp, bp
    
    ; Clear screen
    mov ax, 0x0003
    int 0x10
    
    ; Print welcome message
    mov si, welcome_msg
    call print_string
    
    ; Load kernel using LBA addressing
    call load_kernel
    
    ; Switch to protected mode and jump to kernel
    call switch_to_protected_mode
    
    ; Should never get here
    jmp $
    
; Load kernel function
load_kernel:
    mov si, loading_msg
    call print_string
    
    ; Use LBA disk read (int 13h, ah=42h)
    mov si, kernel_address_packet
    mov ah, 0x42
    mov dl, [boot_drive]
    int 0x13
    jc disk_error
    
    mov si, loaded_msg
    call print_string
    ret
    
disk_error:
    mov si, disk_error_msg
    call print_string
    mov ah, 0x01    ; Get status
    mov dl, [boot_drive]
    int 0x13
    mov al, ah      ; Move error code to AL
    call print_hex
    jmp $

; Print string function (SI = string address)
print_string:
    pusha
    mov ah, 0x0e    ; BIOS teletype function
.loop:
    lodsb           ; Load byte from SI into AL and increment SI
    test al, al     ; Check if character is 0 (end of string)
    jz .done        ; If zero, we're done
    int 0x10        ; Print character
    jmp .loop       ; Continue loop
.done:
    popa
    ret

; Print hex value in AL
print_hex:
    pusha
    mov cx, 2       ; 2 digits (1 byte)
    mov ah, 0x0e    ; BIOS teletype
.hex_loop:
    rol al, 4       ; Rotate 4 bits left (get high nibble)
    mov bl, al      ; Copy to BL
    and bl, 0x0f    ; Mask off high nibble
    add bl, '0'     ; Convert to ASCII
    cmp bl, '9'     ; Is it > 9?
    jle .print_digit
    add bl, 7       ; Adjust for A-F
.print_digit:
    mov al, bl      ; Move to AL for printing
    int 0x10        ; Print character
    loop .hex_loop  ; Decrement CX and loop
    popa
    ret

; Switch to protected mode
switch_to_protected_mode:
    cli                     ; Disable interrupts
    lgdt [gdt_descriptor]   ; Load GDT
    
    ; Enable protected mode
    mov eax, cr0
    or al, 1
    mov cr0, eax
    
    ; Far jump to 32-bit code
    jmp 0x08:protected_mode_start

bits 32
protected_mode_start:
    ; Set up segment registers
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    ; Set up stack
    mov esp, 0x90000
    
    ; Jump to kernel
    jmp 0x10000

boot_drive: db 0
welcome_msg: db "Second Stage Bootloader Loaded at 0x8000", 13, 10, 0
loading_msg: db "Loading kernel...", 13, 10, 0
loaded_msg: db "Kernel loaded successfully!", 13, 10, 0
disk_error_msg: db "Disk read error! Code: ", 0

; Disk Address Packet for loading kernel
kernel_address_packet:
    db 0x10         ; Size of packet (16 bytes)
    db 0            ; Reserved
    dw 0x0080      ; Number of sectors to transfer (64 = 32KB)
    dw 0x0000       ; Transfer buffer (offset)
    dw 0x1000       ; Transfer buffer (segment) - 0x10000 physical address
    dq 0x00000003   ; Starting LBA (sector 3, after stage1+stage2)

; GDT
gdt_start:
    ; Null descriptor
    dd 0
    dd 0
    
    ; Code segment descriptor
    dw 0xFFFF    ; Limit (bits 0-15)
    dw 0         ; Base (bits 0-15)
    db 0         ; Base (bits 16-23)
    db 10011010b ; Access byte
    db 11001111b ; Flags + Limit (bits 16-19)
    db 0         ; Base (bits 24-31)
    
    ; Data segment descriptor
    dw 0xFFFF    ; Limit (bits 0-15)
    dw 0         ; Base (bits 0-15)
    db 0         ; Base (bits 16-23)
    db 10010010b ; Access byte
    db 11001111b ; Flags + Limit (bits 16-19)
    db 0         ; Base (bits 24-31)
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1 ; Size
    dd gdt_start               ; Address

; Padding to fill sectors
times 1024-($-$$) db 0
