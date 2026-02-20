CC ?= gcc
YASM ?= yasm
LD ?= ld
OBJCOPY ?= objcopy

all: payload.bin payload-elfldr.elf prosper0gdb.o

clean:
	rm -f payload.elf payload-elfldr.elf payload-elfldr-dbg.elf payload.bin r0run.o prosper0gdb.o

../lib/lib-elf-ps5.a:
	cd ../lib; make

r0run.o: r0run.asm
	$(YASM) -f elf64 -g dwarf2 r0run.asm -o r0run.o

prosper0gdb.o: r0gdb.c r0run.o offsets.c offsets.h offset_list.txt
	$(CC) -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -r -Wl,--unique='*' -ffunction-sections -fdata-sections $(EXTRA_CFLAGS) -DPS5KEK r0gdb.c r0run.o offsets.c -o prosper0gdb.o -fPIE -ffreestanding -fno-unwind-tables -fno-asynchronous-unwind-tables

payload.elf: ../lib/lib-elf-ps5.a main.c prosper0gdb.o dbg.c
	$(CC) -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib-elf-ps5.a $(EXTRA_CFLAGS) main.c prosper0gdb.o -DPS5KEK dbg.c -o payload.elf -fPIE -ffreestanding -Wl,-no-pie -Wl,-gc-sections -Wl,-zmax-page-size=16384 -Wl,-zcommon-page-size=16384

payload-elfldr-dbg.elf: ../lib/lib-elf-ps5.a main.c prosper0gdb.o dbg.c
	$(CC) -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib-elf-ps5.a $(EXTRA_CFLAGS) main.c prosper0gdb.o -DPS5KEK -DPIE_BUILD dbg.c -o payload-elfldr-dbg.elf -fPIE -ffreestanding -Wl,-pie -Wl,-gc-sections -Wl,-zmax-page-size=16384 -Wl,-zcommon-page-size=16384

payload-elfldr.elf: payload-elfldr-dbg.elf
	$(OBJCOPY) --strip-all payload-elfldr-dbg.elf payload-elfldr.elf

payload.bin: payload.elf
	$(OBJCOPY) payload.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload.bin
	python3 ../lib/frankenelf.py payload.bin
