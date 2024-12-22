gdt_start:
    dq 0x0 ; GDT starts with 8 null bytes

gdt_code:
    dw 0xffff    ; segment length
    dw 0x0       ; segment bits 0-15
    db 0x0       ; 16-23
    db 10011010b ; flags
    db 11001111b ; 4 flags + segment length
    db 0x0       ; segment base bits 24-31

gdt_data:
    dw 0xffff
    dw 0x0
    db 0x0
    db 10010010b
    db 11001111b
    db 0x0

gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1 ; gdt size in 16 bits
    dd gdt_start               ; address 32 bits

CODE_SEG equ gdt_code - gdt_start
DATA_SEG equ gdt_data - gdt_start