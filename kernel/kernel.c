#include "../drivers/vga-driver.h"

void main() {
    vga_clear_screen();
    vga_printk("GIOS");
}
