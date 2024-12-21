# First rule is the one executed when no parameters are fed to the Makefile
all: run

# Directories
SRC_DIR = kernel
DRIVER_DIR = drivers
LIB_DIR = libraries/types
CPU_DIR = cpu

# Find all C source files in the kernel, driver, library, and CPU directories
KERNEL_SOURCES = $(wildcard $(SRC_DIR)/*.c)
DRIVER_SOURCES = $(wildcard $(DRIVER_DIR)/*.c)
LIB_SOURCES = $(wildcard $(LIB_DIR)/*.c)
CPU_SOURCES = $(wildcard $(CPU_DIR)/*.c)

# Combine all source files
SOURCES = $(KERNEL_SOURCES) $(DRIVER_SOURCES) $(LIB_SOURCES) $(CPU_SOURCES)

# Define object files corresponding to the source files
OBJECTS = $(SOURCES:.c=.o)

# Link the kernel binary from the entry and kernel object files
kernel.bin: kernel-entry.o $(OBJECTS)
	ld -m elf_i386 -o $@ -Ttext 0x1000 $^ --oformat binary

# Assemble the entry point from assembly
kernel-entry.o: boot/kernel-entry.asm
	nasm $< -f elf32 -o $@

# Compile each source file into its corresponding object file
%.o: %.c
	gcc -m32 -ffreestanding -c $< -o $@ -fno-pic -fno-stack-protector

# Assemble the boot sector
mbr.bin: boot/mbr.asm
	nasm $< -f bin -o $@

# Create the OS image from the boot sector and kernel
os-image.bin: mbr.bin kernel.bin
	cat $^ > $@

# Run the OS image using QEMU
run: os-image.bin
	qemu-system-i386 -fda $<

# Clean up generated files
clean:
	rm -f kernel/*.o drivers/*.o libraries/types/*.o cpu/*.o *.o kernel-entry.o mbr.bin kernel.bin os-image.bin
