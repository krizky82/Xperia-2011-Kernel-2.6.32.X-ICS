#define _LINUX_STRING_H_

#include <linux/compiler.h>	/* for inline */
#include <linux/types.h>	/* for size_t */
#include <linux/stddef.h>	/* for NULL */
#include <linux/linkage.h>
#include <asm/string.h>

#include <asm/unaligned.h>

#ifdef STANDALONE_DEBUG
# define putstr printf
#endif

unsigned long free_mem_ptr;
unsigned long free_mem_end_ptr;
extern void error(char *);

#define STATIC static
#define STATIC_RW_DATA	/* non-static please */

#define ARCH_HAS_DECOMP_WDOG

/* Diagnostic functions */
#ifdef DEBUG
#  define Assert(cond,msg) {if(!(cond)) error(msg);}
#  define Trace(x) fprintf x
#  define Tracev(x) {if (verbose) fprintf x ;}
#  define Tracevv(x) {if (verbose>1) fprintf x ;}
#  define Tracec(c,x) {if (verbose && (c)) fprintf x ;}
#  define Tracecv(c,x) {if (verbose>1 && (c)) fprintf x ;}
#else
#  define Assert(cond,msg)
#  define Trace(x)
#  define Tracev(x)
#  define Tracevv(x)
#  define Tracec(c,x)
#  define Tracecv(c,x)
#endif

#if defined(CONFIG_KERNEL_XZ)
#include "../../../../lib/decompress_unxz.c"
#elif defined(CONFIG_KERNEL_GZIP)
#include "../../../../lib/decompress_inflate.c"
#elif defined(CONFIG_KERNEL_BZIP2)
#include "../../../../lib/decompress_bunzip2.c"
#elif defined(CONFIG_KERNEL_LZMA)
#include "../../../../lib/decompress_unlzma.c"
#elif defined(CONFIG_KERNEL_LZO)
#include "../../../../lib/decompress_unlzo.c"
#endif

void do_decompress(u8 *input, int len, u8 *output, void (*error)(char *x))
{
    decompress(input, len, NULL, NULL, output, NULL, error);
}
