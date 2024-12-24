extern isr_handler
extern irq_handler

%macro ISR 1
    global isr%1
    
    isr%1:
        cli
        
        push 0
        push %1
        
        jmp isr_common_stub
%endmacro

%macro ISR_EXC 1
    global isr%1
    
    isr%1:
        cli
        
        push %1
        
        jmp isr_common_stub
%endmacro

%macro IRQ 2 
    global irq%1
    
    irq%1:
        cli
        
        push 0
        push %2
        
        jmp irq_common_stub
%endmacro

isr_common_stub:
    pusha 
    mov eax, ds
    push eax
    mov eax, cr2
    push eax

    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    push esp
    call isr_handler

    add esp, 8
    pop ebx
    mov ds, bx
    mov es, bx
    mov fs, bx
    mov gs, bx

    popa
    add esp, 8
    sti
    iret

irq_common_stub:
    pusha 
    mov eax, ds
    push eax
    mov eax, cr2
    push eax

    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    push esp
    call irq_handler

    add esp, 8
    pop ebx
    mov ds, bx
    mov es, bx
    mov fs, bx
    mov gs, bx

    popa
    add esp, 8
    sti
    iret

ISR 0
ISR 1
ISR 2
ISR 3
ISR 4
ISR 5
ISR 6
ISR 7
ISR_EXC 8
ISR 9
ISR_EXC 10
ISR_EXC 11
ISR_EXC 12
ISR_EXC 13
ISR_EXC 14
ISR 15
ISR 16
ISR 17
ISR 18
ISR 19
ISR 20
ISR 21
ISR 22
ISR 23
ISR 24
ISR 25
ISR 26
ISR 27
ISR 28
ISR 29
ISR 30
ISR 31

IRQ 0, 32
IRQ 1, 33
IRQ 2, 34
IRQ 3, 35
IRQ 4, 36
IRQ 5, 37
IRQ 6, 38
IRQ 7, 39
IRQ 8, 40
IRQ 9, 41
IRQ 10, 42
IRQ 11, 43
IRQ 12, 44
IRQ 13, 45
IRQ 14, 46
IRQ 15, 47
