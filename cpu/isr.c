#include "isr.h"
#include "idt.h"
#include "../lib/ports.h"
#include "../drivers/vga-driver.h"

char *exception_messages[] = {
    "Division by zero",
    "Single-step interrupt",
    "NMI",
    "Breakpoint",
    "Overflow",
    "Bound Range Exceeded ",
    "Invalid Opcode",
    "Coprocessor not available ",
    "Double Fault",
    "Coprocessor Segment Overrun",
    "Invalid Task State Segment",
    "Segment not present",
    "Stack Segment Fault ",
    "General Protection Fault",
    "Page Fault",
    "reserved",
    "x87 Floating Point Exception ",
    "Alignment Check",
    "Machine Check",
    "SIMD Floating-Point Exception",
    "Virtualization Exception ",
    "Control Protection Exception",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
};

isr_t irq_map[256];

/* =============================== Public Functions =============================== */

void isr_install() {
    idt_set_gate(0, (u32_t)isr0);
    idt_set_gate(1, (u32_t)isr1);
    idt_set_gate(2, (u32_t)isr2);
    idt_set_gate(3, (u32_t)isr3);
    idt_set_gate(4, (u32_t)isr4);
    idt_set_gate(5, (u32_t)isr5);
    idt_set_gate(6, (u32_t)isr6);
    idt_set_gate(7, (u32_t)isr7);
    idt_set_gate(8, (u32_t)isr8);
    idt_set_gate(9, (u32_t)isr9);
    idt_set_gate(10, (u32_t)isr10);
    idt_set_gate(11, (u32_t)isr11);
    idt_set_gate(12, (u32_t)isr12);
    idt_set_gate(13, (u32_t)isr13);
    idt_set_gate(14, (u32_t)isr14);
    idt_set_gate(15, (u32_t)isr15);
    idt_set_gate(16, (u32_t)isr16);
    idt_set_gate(17, (u32_t)isr17);
    idt_set_gate(18, (u32_t)isr18);
    idt_set_gate(19, (u32_t)isr19);
    idt_set_gate(20, (u32_t)isr20);
    idt_set_gate(21, (u32_t)isr21);
    idt_set_gate(22, (u32_t)isr22);
    idt_set_gate(23, (u32_t)isr23);
    idt_set_gate(24, (u32_t)isr24);
    idt_set_gate(25, (u32_t)isr25);
    idt_set_gate(26, (u32_t)isr26);
    idt_set_gate(27, (u32_t)isr27);
    idt_set_gate(28, (u32_t)isr28);
    idt_set_gate(29, (u32_t)isr29);
    idt_set_gate(30, (u32_t)isr30);
    idt_set_gate(31, (u32_t)isr31);

    // Remap the PIC 
    port_byte_out(0x20, 0x11);
    port_byte_out(0xA0, 0x11);

    port_byte_out(0x21, 0x20);
    port_byte_out(0xA1, 0x28);

    port_byte_out(0x21, 0x04);
    port_byte_out(0xA1, 0x02);

    port_byte_out(0x21, 0x01);
    port_byte_out(0xA1, 0x01);

    port_byte_out(0x21, 0x0);
    port_byte_out(0xA1, 0x0); 

    // Install the IRQs
    idt_set_gate(32, (u32_t)irq0);
    idt_set_gate(33, (u32_t)irq1);
    idt_set_gate(34, (u32_t)irq2);
    idt_set_gate(35, (u32_t)irq3);
    idt_set_gate(36, (u32_t)irq4);
    idt_set_gate(37, (u32_t)irq5);
    idt_set_gate(38, (u32_t)irq6);
    idt_set_gate(39, (u32_t)irq7);
    idt_set_gate(40, (u32_t)irq8);
    idt_set_gate(41, (u32_t)irq9);
    idt_set_gate(42, (u32_t)irq10);
    idt_set_gate(43, (u32_t)irq11);
    idt_set_gate(44, (u32_t)irq12);
    idt_set_gate(45, (u32_t)irq13);
    idt_set_gate(46, (u32_t)irq14);
    idt_set_gate(47, (u32_t)irq15);

    idt_init();

    asm volatile ("sti");
}

void isr_handler(registers_t *registers) {
    if (registers->int_number < 32) {
        vga_print("Exception\n");
        vga_print(exception_messages[registers->int_number]);
        while(1); // Halt
    }
}

void irq_set_handler(u8_t n, isr_t handler) {
    irq_map[n] = handler;
}

void irq_handler(registers_t *registers) {
    if (registers->int_number >= 40) 
        port_byte_out(0xA0, 0x20);
    port_byte_out(0x20, 0x20);

    if (irq_map[registers->int_number] != 0)
        irq_map[registers->int_number](registers);
}
