# First rule is the one executed when no parameters are fed to the Makefile
all: run

# Directories
SRC_DIR = kernel
DRIVER_DIR = drivers
LIB_DIR = lib
CPU_DIR = cpu
TEST_DIR = tests

# Find all C source files in the kernel, driver, library, CPU directories
KERNEL_SOURCES = $(wildcard $(SRC_DIR)/*.c)
DRIVER_SOURCES = $(wildcard $(DRIVER_DIR)/*.c)
LIB_SOURCES = $(wildcard $(LIB_DIR)/*.c)
CPU_SOURCES = $(wildcard $(CPU_DIR)/*.c)
TEST_SOURCES = $(wildcard $(TEST_DIR)/*.c)

# Find all assembly files in the kernel, driver, library, CPU directories
KERNEL_ASM = $(wildcard $(SRC_DIR)/*.asm)
DRIVER_ASM = $(wildcard $(DRIVER_DIR)/*.asm)
LIB_ASM = $(wildcard $(LIB_DIR)/*.asm)
CPU_ASM = $(wildcard $(CPU_DIR)/*.asm)

# Combine all source files
SOURCES = $(KERNEL_SOURCES) $(DRIVER_SOURCES) $(LIB_SOURCES) $(CPU_SOURCES) $(TEST_SOURCES)
ASM_SOURCES = $(KERNEL_ASM) $(DRIVER_ASM) $(LIB_ASM) $(CPU_ASM)

# Define object files corresponding to the source files
OBJECTS = $(SOURCES:.c=.o) $(ASM_SOURCES:.asm=.o)

# Link the kernel binary from the entry and kernel object files
kernel.bin: kernel-entry.o $(OBJECTS)
	ld -m elf_i386 -o $@ -Ttext 0x1000 $^ --oformat binary

# Assemble the entry point from assembly
kernel-entry.o: boot/kernel-entry.asm
	nasm $< -f elf32 -o $@

# Compile each source file into its corresponding object file
%.o: %.c
	gcc -m32 -ffreestanding -c $< -o $@ -fno-pic -fno-stack-protector

# Assemble each assembly file into object files
%.o: %.asm
	nasm $< -f elf32 -o $@

# Assemble the boot sector
mbr.bin: boot/mbr.asm
	nasm $< -f bin -o $@

# Create the OS image from the boot sector and kernel
os-image.bin: mbr.bin kernel.bin
	cat $^ > $@

# Run the OS image using QEMU
run: os-image.bin
	qemu-system-i386 $<

# Clean up generated files
clean:
	rm -f kernel/*.o drivers/*.o lib/*.o cpu/*.o *.o kernel-entry.o mbr.bin kernel.bin os-image.bin
