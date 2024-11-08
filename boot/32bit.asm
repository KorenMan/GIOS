bits 16
switch_to_32bit:
    cli                   ; disable interrupts
    lgdt [gdt_descriptor] ; load the GDT descriptor
    mov eax, cr0 
    or eax, 0x1           ; enable 32 bit mode
    mov cr0, eax
    jmp CODE_SEG:init_32bit

bits 32
init_32bit:
    mov ax, DATA_SEG ; update the segment registers
    mov ds, ax
    mov ss, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    mov ebp, 0x90000 ; update the stack
    mov esp, ebp

    call begin_32bit ; go back to mbr.asm 