disk_load:
    pusha
    
    push dx

    mov ah, 0x02 ; int 0x13 "read"
    mov al, dh   ; number of sectors to read
    mov cl, 0x02 ; available sector
    mov ch, 0x00 ; cylinder 0
    mov dh, 0x00 ; drive number is stored in dl

    int 0x13      ; bios interupt
    jc disk_error ; in the case of an error the carry flag will be set to 1

    pop dx
    cmp al, dh   ; al has the amount of sectors read
    jne sectors_error
    
    popa
    ret

disk_error:
    mov ah, 0x0e
    mov al, "E"
    int 0x10
    mov al, ":"
    int 0x10
    mov al, " "
    int 0x10
    mov al, "d"
    int 0x10

    jmp disk_error_loop

sectors_error:
    mov ah, 0x0e
    mov al, "E"
    int 0x10
    mov al, ":"
    int 0x10
    mov al, " "
    int 0x10
    mov al, "s"

    jmp disk_error_loop

disk_error_loop:
    jmp $
