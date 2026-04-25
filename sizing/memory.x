/* Minimal memory layout for binary-size measurement only. Not meant to run
   on any specific device. cortex-m-rt requires FLASH+RAM regions to produce
   a linkable ELF; the exact addresses and sizes only affect the section
   placement, not the .text/.rodata byte counts we measure. */

MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 1M
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
