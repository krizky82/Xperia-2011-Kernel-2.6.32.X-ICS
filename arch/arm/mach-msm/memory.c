/* arch/arm/mach-msm/memory.c
 *
 * Copyright (C) 2007 Google, Inc.
 * Copyright (c) 2009-2010, Code Aurora Forum. All rights reserved.
 * Copyright (C) 2001 Sony Ericsson Mobile Communications AB.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/bootmem.h>
#include <linux/memory_alloc.h>
#include <linux/module.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/mach/map.h>
#include <asm/cacheflush.h>
#include <linux/hardirq.h>
#if defined(CONFIG_MSM_NPA_REMOTE)
#include "npa_remote.h"
#include <linux/completion.h>
#include <linux/err.h>
#endif
#include <mach/msm_memtypes.h>

int arch_io_remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
			    unsigned long pfn, unsigned long size, pgprot_t prot)
{
	unsigned long pfn_addr = pfn << PAGE_SHIFT;
	if ((pfn_addr >= 0x88000000) && (pfn_addr < 0xD0000000)) {
		prot = pgprot_device(prot);
		printk("remapping device %lx\n", prot);
	}
	return remap_pfn_range(vma, addr, pfn, size, prot);
}

void *zero_page_strongly_ordered;

void map_zero_page_strongly_ordered(void)
{
#if defined(CONFIG_ARCH_MSM7X27)
	if (zero_page_strongly_ordered)
		return;

	zero_page_strongly_ordered =
		ioremap_strongly_ordered(page_to_pfn(empty_zero_page)
		<< PAGE_SHIFT, PAGE_SIZE);
	printk(KERN_ALERT "Initialized Zero page successfully\n");
#endif
}
EXPORT_SYMBOL(map_zero_page_strongly_ordered);

void write_to_strongly_ordered_memory(void)
{
#if defined(CONFIG_ARCH_MSM7X27)
	if (!zero_page_strongly_ordered) {
		if (!in_interrupt())
			map_zero_page_strongly_ordered();
		else {
			printk(KERN_ALERT "Cannot map zero page in "
				"Interrupt Context\n");
			/* capture it here before the allocation fails later */
			BUG();
		}
	}
	*(int *)zero_page_strongly_ordered = 0;
#endif
}
EXPORT_SYMBOL(write_to_strongly_ordered_memory);

/* These cache related routines make the assumption (if outer cache is
 * available) that the associated physical memory is contiguous.
 * They will operate on all (L1 and L2 if present) caches.
 */
void clean_and_invalidate_caches(unsigned long vstart,
	unsigned long length, unsigned long pstart)
{
	dmac_flush_range((void *)vstart, (void *) (vstart + length));
	outer_flush_range(pstart, pstart + length);
}

void clean_caches(unsigned long vstart,
	unsigned long length, unsigned long pstart)
{
	dmac_clean_range((void *)vstart, (void *) (vstart + length));
	outer_clean_range(pstart, pstart + length);
}

void invalidate_caches(unsigned long vstart,
	unsigned long length, unsigned long pstart)
{
	dmac_inv_range((void *)vstart, (void *) (vstart + length));
	outer_inv_range(pstart, pstart + length);
}

void *alloc_bootmem_aligned(unsigned long size, unsigned long alignment)
{
	void *unused_addr = NULL;
	unsigned long addr, tmp_size, unused_size;

	/* Allocate maximum size needed, see where it ends up.
	 * Then free it -- in this path there are no other allocators
	 * so we can depend on getting the same address back
	 * when we allocate a smaller piece that is aligned
	 * at the end (if necessary) and the piece we really want,
	 * then free the unused first piece.
	 */

	tmp_size = size + alignment - PAGE_SIZE;
	addr = (unsigned long)alloc_bootmem(tmp_size);
	free_bootmem(__pa(addr), tmp_size);

	unused_size = alignment - (addr % alignment);
	if (unused_size)
		unused_addr = alloc_bootmem(unused_size);

	addr = (unsigned long)alloc_bootmem(size);
	if (unused_size)
		free_bootmem(__pa(unused_addr), unused_size);

	return (void *)addr;
}

int platform_physical_remove_pages(unsigned long start_pfn,
	unsigned long nr_pages)
{
	return 1;
}

int platform_physical_active_pages(unsigned long start_pfn,
	unsigned long nr_pages)
{
	return 1;
}

int platform_physical_low_power_pages(unsigned long start_pfn,
	unsigned long nr_pages)
{
	return 1;
}

unsigned long allocate_contiguous_ebi_nomap(unsigned long size,
	unsigned long align)
{
	return _allocate_contiguous_memory_nomap(size, MEMTYPE_EBI0,
		align, __builtin_return_address(0));
}
EXPORT_SYMBOL(allocate_contiguous_ebi_nomap);
