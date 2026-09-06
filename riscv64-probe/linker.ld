/* A standalone riscv64 confined program (same layout constraints as
 * lantern-abi/demo/linker.ld). The bump arena in platform.rs lands in .bss;
 * the loader that eventually runs this needs to zero-map that whole region,
 * which is why the arena is only 64 MiB here. */
OUTPUT_ARCH(riscv)
ENTRY(_start)

BASE_ADDRESS = 0x84000000;
MEGAPAGE_SIZE = 0x200000;

SECTIONS
{
    . = BASE_ADDRESS;

    .text : {
        *(.text._start)
        *(.text .text.*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    . = ALIGN(MEGAPAGE_SIZE);

    .data : {
        *(.data .data.*)
    }

    .bss : ALIGN(4K) {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
