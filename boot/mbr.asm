bits 16
org 0x7c00

KERNEL_OFFSET equ 0x1000 ; where to load the kernel to

start:
    ; setup the stack
    mov bp, 0x9000 
    mov sp, bp
    
    call load_kernel
    call switch_to_32bit

%include "boot/disk.asm"
%include "boot/gdt.asm"
%include "boot/32bit.asm"

bits 16
load_kernel:
    mov bx, KERNEL_OFFSET ; where to store the data read from the disk 
    mov dh, 0x16 ; number of sectors to read
    call disk_load
    ret

bits 32
begin_32bit:
    call KERNEL_OFFSET
    jmp $ ; kernel isn`t suppose to return

times 510-($-$$) db 0
; magic number
dw 0xaa55 
