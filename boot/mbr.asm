; First stage bootloader - Hard Drive version
bits 16
org 0x7C00

start:
    ; Save boot drive number from DL
    mov [boot_drive], dl
    
    ; Setup segments
    cli             ; Disable interrupts while changing segments
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00  ; Setup stack
    sti             ; Re-enable interrupts
    
    ; Print boot message
    mov si, boot_msg
    call print_string
    
    ; Reset disk system
    mov ah, 0x00
    mov dl, [boot_drive]
    int 0x13
    jc disk_error
    
    ; Load second stage bootloader using LBA addressing (int 13h, ah=42h)
    ; This is more reliable for hard drives
    mov si, disk_address_packet
    mov ah, 0x42
    mov dl, [boot_drive]
    int 0x13
    jc disk_error
    
    ; Jump to second stage
    jmp 0x0000:0x8000
    
; Error handlers
disk_error:
    mov si, error_msg
    call print_string
    mov ah, 0x01    ; Get status
    mov dl, [boot_drive]
    int 0x13        ; Call BIOS for error code
    mov al, ah      ; Move error code to AL for printing
    call print_hex  ; Print error code
    jmp $           ; Infinite loop

; Print string function (SI = string address)
print_string:
    pusha
    mov ah, 0x0E    ; BIOS teletype function
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
    mov ah, 0x0E    ; BIOS teletype
.hex_loop:
    rol al, 4       ; Rotate 4 bits left (get high nibble)
    mov bl, al      ; Copy to BL
    and bl, 0x0F    ; Mask off high nibble
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

; Data
boot_drive: db 0
boot_msg:   db "Loading stage 2...", 13, 10, 0
error_msg:  db 13, 10, "Disk error! Code: ", 0

; Disk Address Packet for int 13h extended read
disk_address_packet:
    db 0x10         ; Size of packet (16 bytes)
    db 0            ; Reserved, always 0
    dw 0x0002       ; Number of sectors to transfer (2)
    dw 0x8000       ; Transfer buffer (offset)
    dw 0x0000       ; Transfer buffer (segment)
    dq 0x00000001   ; Starting LBA (sector 1, 0-based, right after MBR)

times 510-($-$$) db 0   ; Pad to 510 bytes
dw 0xAA55              ; Boot signature