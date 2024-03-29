/*
 *  linux/lib/vsprintf.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/* vsprintf.c -- Lars Wirzenius & Linus Torvalds. */
/*
 * Wirzenius wrote this portably, Torvalds fucked it up :-)
 */

/*
 * Fri Jul 13 2001 Crutcher Dunnavant <crutcher+kernel@datastacks.com>
 * - changed to provide snprintf and vsnprintf functions
 * So Feb  1 16:51:32 CET 2004 Juergen Quade <quade@hsnr.de>
 * - scnprintf and vscnprintf
 */

#include <stdarg.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>
#include <net/addrconf.h>

#include <asm/page.h>		/* for PAGE_SIZE */
#include <asm/div64.h>
#include <asm/sections.h>	/* for dereference_function_descriptor() */

/* Works only for digits and letters, but small and fast */
#define TOLOWER(x) ((x) | 0x20)

static unsigned int simple_guess_base(const char *cp)
{
	if (cp[0] == '0') {
		if (TOLOWER(cp[1]) == 'x' && isxdigit(cp[2]))
			return 16;
		else
			return 8;
	} else {
		return 10;
	}
}

/**
 * simple_strtoull - convert a string to an unsigned long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base)
{
	unsigned long long result = 0;

	if (!base)
		base = simple_guess_base(cp);

	if (base == 16 && cp[0] == '0' && TOLOWER(cp[1]) == 'x')
		cp += 2;

	while (isxdigit(*cp)) {
		unsigned int value;

		value = isdigit(*cp) ? *cp - '0' : TOLOWER(*cp) - 'a' + 10;
		if (value >= base)
			break;
		result = result * base + value;
		cp++;
	}
	if (endp)
		*endp = (char *)cp;

	return result;
}
EXPORT_SYMBOL(simple_strtoull);

/**
 * simple_strtoul - convert a string to an unsigned long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
unsigned long simple_strtoul(const char *cp, char **endp, unsigned int base)
{
	return simple_strtoull(cp, endp, base);
}
EXPORT_SYMBOL(simple_strtoul);

/**
 * simple_strtol - convert a string to a signed long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
long simple_strtol(const char *cp, char **endp, unsigned int base)
{
	if (*cp == '-')
		return -simple_strtoul(cp + 1, endp, base);

	return simple_strtoul(cp, endp, base);
}
EXPORT_SYMBOL(simple_strtol);

/**
 * simple_strtoll - convert a string to a signed long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
long long simple_strtoll(const char *cp, char **endp, unsigned int base)
{
	if (*cp == '-')
		return -simple_strtoull(cp + 1, endp, base);

	return simple_strtoull(cp, endp, base);
}
EXPORT_SYMBOL(simple_strtoll);

/**
 * strict_strtoul - convert a string to an unsigned long strictly
 * @cp: The string to be converted
 * @base: The number base to use
 * @res: The converted result value
 *
 * strict_strtoul converts a string to an unsigned long only if the
 * string is really an unsigned long string, any string containing
 * any invalid char at the tail will be rejected and -EINVAL is returned,
 * only a newline char at the tail is acceptible because people generally
 * change a module parameter in the following way:
 *
 * 	echo 1024 > /sys/module/e1000/parameters/copybreak
 *
 * echo will append a newline to the tail.
 *
 * It returns 0 if conversion is successful and *res is set to the converted
 * value, otherwise it returns -EINVAL and *res is set to 0.
 *
 * simple_strtoul just ignores the successive invalid characters and
 * return the converted value of prefix part of the string.
 */
int strict_strtoul(const char *cp, unsigned int base, unsigned long *res)
{
	char *tail;
	unsigned long val;

	*res = 0;
	if (!*cp)
		return -EINVAL;

	val = simple_strtoul(cp, &tail, base);
	if (tail == cp)
		return -EINVAL;

	if ((tail[0] == '\0') || (tail[0] == '\n' && tail[1] == '\0')) {
		*res = val;
		return 0;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(strict_strtoul);

/**
 * strict_strtol - convert a string to a long strictly
 * @cp: The string to be converted
 * @base: The number base to use
 * @res: The converted result value
 *
 * strict_strtol is similiar to strict_strtoul, but it allows the first
 * character of a string is '-'.
 *
 * It returns 0 if conversion is successful and *res is set to the converted
 * value, otherwise it returns -EINVAL and *res is set to 0.
 */
int strict_strtol(const char *cp, unsigned int base, long *res)
{
	int ret;
	if (*cp == '-') {
		ret = strict_strtoul(cp + 1, base, (unsigned long *)res);
		if (!ret)
			*res = -(*res);
	} else {
		ret = strict_strtoul(cp, base, (unsigned long *)res);
	}

	return ret;
}
EXPORT_SYMBOL(strict_strtol);

/**
 * strict_strtoull - convert a string to an unsigned long long strictly
 * @cp: The string to be converted
 * @base: The number base to use
 * @res: The converted result value
 *
 * strict_strtoull converts a string to an unsigned long long only if the
 * string is really an unsigned long long string, any string containing
 * any invalid char at the tail will be rejected and -EINVAL is returned,
 * only a newline char at the tail is acceptible because people generally
 * change a module parameter in the following way:
 *
 * 	echo 1024 > /sys/module/e1000/parameters/copybreak
 *
 * echo will append a newline to the tail of the string.
 *
 * It returns 0 if conversion is successful and *res is set to the converted
 * value, otherwise it returns -EINVAL and *res is set to 0.
 *
 * simple_strtoull just ignores the successive invalid characters and
 * return the converted value of prefix part of the string.
 */
int strict_strtoull(const char *cp, unsigned int base, unsigned long long *res)
{
	char *tail;
	unsigned long long val;

	*res = 0;
	if (!*cp)
		return -EINVAL;

	val = simple_strtoull(cp, &tail, base);
	if (tail == cp)
		return -EINVAL;
	if ((tail[0] == '\0') || (tail[0] == '\n' && tail[1] == '\0')) {
		*res = val;
		return 0;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(strict_strtoull);

/**
 * strict_strtoll - convert a string to a long long strictly
 * @cp: The string to be converted
 * @base: The number base to use
 * @res: The converted result value
 *
 * strict_strtoll is similiar to strict_strtoull, but it allows the first
 * character of a string is '-'.
 *
 * It returns 0 if conversion is successful and *res is set to the converted
 * value, otherwise it returns -EINVAL and *res is set to 0.
 */
int strict_strtoll(const char *cp, unsigned int base, long long *res)
{
	int ret;
	if (*cp == '-') {
		ret = strict_strtoull(cp + 1, base, (unsigned long long *)res);
		if (!ret)
			*res = -(*res);
	} else {
		ret = strict_strtoull(cp, base, (unsigned long long *)res);
	}

	return ret;
}
EXPORT_SYMBOL(strict_strtoll);

static noinline_for_stack
int skip_atoi(const char **s)
{
	int i = 0;

	while (isdigit(**s))
		i = i*10 + *((*s)++) - '0';

	return i;
}

/* Decimal conversion is by far the most typical, and is used
 * for /proc and /sys data. This directly impacts e.g. top performance
 * with many processes running. We optimize it for speed
 * using ideas described at <http://www.cs.uiowa.edu/~jones/bcd/divide.html>
 * (with permission from the author, Douglas W. Jones).
 */

#if BITS_PER_LONG != 32 || BITS_PER_LONG_LONG != 64
/* Formats correctly any integer in [0, 999999999] */
static noinline_for_stack
char *put_dec_full9(char *buf, unsigned q)
{
	unsigned r;

	/*
	 * Possible ways to approx. divide by 10
	 * (x * 0x1999999a) >> 32 x < 1073741829 (multiply must be 64-bit)
	 * (x * 0xcccd) >> 19     x <      81920 (x < 262149 when 64-bit mul)
	 * (x * 0x6667) >> 18     x <      43699
	 * (x * 0x3334) >> 17     x <      16389
	 * (x * 0x199a) >> 16     x <      16389
	 * (x * 0x0ccd) >> 15     x <      16389
	 * (x * 0x0667) >> 14     x <       2739
	 * (x * 0x0334) >> 13     x <       1029
	 * (x * 0x019a) >> 12     x <       1029
	 * (x * 0x00cd) >> 11     x <       1029 shorter code than * 0x67 (on i386)
	 * (x * 0x0067) >> 10     x <        179
	 * (x * 0x0034) >>  9     x <         69 same
	 * (x * 0x001a) >>  8     x <         69 same
	 * (x * 0x000d) >>  7     x <         69 same, shortest code (on i386)
	 * (x * 0x0007) >>  6     x <         19
	 * See <http://www.cs.uiowa.edu/~jones/bcd/divide.html>
	 */
	r      = (q * (uint64_t)0x1999999a) >> 32;
	*buf++ = (q - 10 * r) + '0'; /* 1 */
	q      = (r * (uint64_t)0x1999999a) >> 32;
	*buf++ = (r - 10 * q) + '0'; /* 2 */
	r      = (q * (uint64_t)0x1999999a) >> 32;
	*buf++ = (q - 10 * r) + '0'; /* 3 */
	q      = (r * (uint64_t)0x1999999a) >> 32;
	*buf++ = (r - 10 * q) + '0'; /* 4 */
	r      = (q * (uint64_t)0x1999999a) >> 32;
	*buf++ = (q - 10 * r) + '0'; /* 5 */
	/* Now value is under 10000, can avoid 64-bit multiply */
	q      = (r * 0x199a) >> 16;
	*buf++ = (r - 10 * q)  + '0'; /* 6 */
	r      = (q * 0xcd) >> 11;
	*buf++ = (q - 10 * r)  + '0'; /* 7 */
	q      = (r * 0xcd) >> 11;
	*buf++ = (r - 10 * q) + '0'; /* 8 */
	*buf++ = q + '0'; /* 9 */
	return buf;
}
#endif

/* Similar to above but do not pad with zeros.
 * Code can be easily arranged to print 9 digits too, but our callers
 * always call put_dec_full9() instead when the number has 9 decimal digits.
 */
static noinline_for_stack
char *put_dec_trunc8(char *buf, unsigned r)
{
	unsigned q;

	/* Copy of previous function's body with added early returns */
	while (r >= 10000) {
		q = r + '0';
		r  = (r * (uint64_t)0x1999999a) >> 32;
		*buf++ = q - 10*r;
	}

	q      = (r * 0x199a) >> 16;	/* r <= 9999 */
	*buf++ = (r - 10 * q)  + '0';
	if (q == 0)
		return buf;
	r      = (q * 0xcd) >> 11;	/* q <= 999 */
	*buf++ = (q - 10 * r)  + '0';
	if (r == 0)
		return buf;
	q      = (r * 0xcd) >> 11;	/* r <= 99 */
	*buf++ = (r - 10 * q) + '0';
	if (q == 0)
		return buf;
	*buf++ = q + '0';		 /* q <= 9 */
	return buf;
}

/* There are two algorithms to print larger numbers.
 * One is generic: divide by 1000000000 and repeatedly print
 * groups of (up to) 9 digits. It's conceptually simple,
 * but requires a (unsigned long long) / 1000000000 division.
 *
 * Second algorithm splits 64-bit unsigned long long into 16-bit chunks,
 * manipulates them cleverly and generates groups of 4 decimal digits.
 * It so happens that it does NOT require long long division.
 *
 * If long is > 32 bits, division of 64-bit values is relatively easy,
 * and we will use the first algorithm.
 * If long long is > 64 bits (strange architecture with VERY large long long),
 * second algorithm can't be used, and we again use the first one.
 *
 * Else (if long is 32 bits and long long is 64 bits) we use second one.
 */

#if BITS_PER_LONG != 32 || BITS_PER_LONG_LONG != 64

/* First algorithm: generic */

static
char *put_dec(char *buf, unsigned long long n)
{
	if (n >= 100*1000*1000) {
		while (n >= 1000*1000*1000)
			buf = put_dec_full9(buf, do_div(n, 1000*1000*1000));
		if (n >= 100*1000*1000)
			return put_dec_full9(buf, n);
	}
	return put_dec_trunc8(buf, n);
}

#else

/* Second algorithm: valid only for 64-bit long longs */

/* See comment in put_dec_full9 for choice of constants */
static noinline_for_stack
void put_dec_full4(char *buf, unsigned q)
{
	unsigned r;
	r      = (q * 0xccd) >> 15;
	buf[0] = (q - 10 * r) + '0';
	q      = (r * 0xcd) >> 11;
	buf[1] = (r - 10 * q)  + '0';
	r      = (q * 0xcd) >> 11;
	buf[2] = (q - 10 * r)  + '0';
	buf[3] = r + '0';
}

/*
 * Call put_dec_full4 on x % 10000, return x / 10000.
 * The approximation x/10000 == (x * 0x346DC5D7) >> 43
 * holds for all x < 1,128,869,999.  The largest value this
 * helper will ever be asked to convert is 1,125,520,955.
 * (d1 in the put_dec code, assuming n is all-ones).
 */
static
unsigned put_dec_helper4(char *buf, unsigned x)
{
        uint32_t q = (x * (uint64_t)0x346DC5D7) >> 43;

        put_dec_full4(buf, x - q * 10000);
        return q;
}

/* Based on code by Douglas W. Jones found at
 * <http://www.cs.uiowa.edu/~jones/bcd/decimal.html#sixtyfour>
 * (with permission from the author).
 * Performs no 64-bit division and hence should be fast on 32-bit machines.
 */
static
char *put_dec(char *buf, unsigned long long n)
{
	uint32_t d3, d2, d1, q, h;

	if (n < 100*1000*1000)
		return put_dec_trunc8(buf, n);

	d1  = ((uint32_t)n >> 16); /* implicit "& 0xffff" */
	h   = (n >> 32);
	d2  = (h      ) & 0xffff;
	d3  = (h >> 16); /* implicit "& 0xffff" */

	q   = 656 * d3 + 7296 * d2 + 5536 * d1 + ((uint32_t)n & 0xffff);
	q = put_dec_helper4(buf, q);

	q += 7671 * d3 + 9496 * d2 + 6 * d1;
	q = put_dec_helper4(buf+4, q);

	q += 4749 * d3 + 42 * d2;
	q = put_dec_helper4(buf+8, q);

	q += 281 * d3;
	buf += 12;
	if (q)
		buf = put_dec_trunc8(buf, q);
	else while (buf[-1] == '0')
		--buf;

	return buf;
}

#endif

/*
 * Convert passed number to decimal string.
 * Returns the length of string.  On buffer overflow, returns 0.
 *
 * If speed is not important, use snprintf(). It's easy to read the code.
 */
int num_to_str(char *buf, int size, unsigned long long num)
{
	char tmp[sizeof(num) * 3];
	int idx, len;

	/* put_dec() may work incorrectly for num = 0 (generate "", not "0") */
	if (num <= 9) {
		tmp[0] = '0' + num;
		len = 1;
	} else {
		len = put_dec(tmp, num) - tmp;
	}

	if (len > size)
		return 0;
	for (idx = 0; idx < len; ++idx)
		buf[idx] = tmp[len - idx - 1];
	return len;
}

#define ZEROPAD	1		/* pad with zero */
#define SIGN	2		/* unsigned/signed long */
#define PLUS	4		/* show plus */
#define SPACE	8		/* space if plus */
#define LEFT	16		/* left justified */
#define SMALL	32		/* use lowercase in hex (must be 32 == 0x20) */
#define SPECIAL	64		/* prefix hex with "0x", octal with "0" */

enum format_type {
	FORMAT_TYPE_NONE, /* Just a string part */
	FORMAT_TYPE_WIDTH,
	FORMAT_TYPE_PRECISION,
	FORMAT_TYPE_CHAR,
	FORMAT_TYPE_STR,
	FORMAT_TYPE_PTR,
	FORMAT_TYPE_PERCENT_CHAR,
	FORMAT_TYPE_INVALID,
	FORMAT_TYPE_LONG_LONG,
	FORMAT_TYPE_ULONG,
	FORMAT_TYPE_LONG,
	FORMAT_TYPE_UBYTE,
	FORMAT_TYPE_BYTE,
	FORMAT_TYPE_USHORT,
	FORMAT_TYPE_SHORT,
	FORMAT_TYPE_UINT,
	FORMAT_TYPE_INT,
	FORMAT_TYPE_NRCHARS,
	FORMAT_TYPE_SIZE_T,
	FORMAT_TYPE_PTRDIFF
};

struct printf_spec {
	u8	type;		/* format_type enum */
	u8	flags;		/* flags to number() */
	u8	base;		/* number base, 8, 10 or 16 only */
	u8	qualifier;	/* number qualifier, one of 'hHlLtzZ' */
	s16	field_width;	/* width of output field */
	s16	precision;	/* # of digits/chars */
};

static noinline_for_stack
char *number(char *buf, char *end, unsigned long long num,
	     struct printf_spec spec)
{
	/* we are called with base 8, 10 or 16, only, thus don't need "G..."  */
	static const char digits[16] = "0123456789ABCDEF"; /* "GHIJKLMNOPQRSTUVWXYZ"; */

	char tmp[66];
	char sign;
	char locase;
	int need_pfx = ((spec.flags & SPECIAL) && spec.base != 10);
	int i;
	bool is_zero = num == 0LL;

	/* locase = 0 or 0x20. ORing digits or letters with 'locase'
	 * produces same digits or (maybe lowercased) letters */
	locase = (spec.flags & SMALL);
	if (spec.flags & LEFT)
		spec.flags &= ~ZEROPAD;
	sign = 0;
	if (spec.flags & SIGN) {
		if ((signed long long)num < 0) {
			sign = '-';
			num = -(signed long long)num;
			spec.field_width--;
		} else if (spec.flags & PLUS) {
			sign = '+';
			spec.field_width--;
		} else if (spec.flags & SPACE) {
			sign = ' ';
			spec.field_width--;
		}
	}
	if (need_pfx) {
		if (spec.base == 16)
			spec.field_width -= 2;
		else if (!is_zero)
			spec.field_width--;
	}

	/* generate full string in tmp[], in reverse order */
	i = 0;
	if (num < spec.base)
		tmp[i++] = digits[num] | locase;
	/* Generic code, for any base:
	else do {
		tmp[i++] = (digits[do_div(num,base)] | locase);
	} while (num != 0);
	*/
	else if (spec.base != 10) { /* 8 or 16 */
		int mask = spec.base - 1;
		int shift = 3;

		if (spec.base == 16)
			shift = 4;
		do {
			tmp[i++] = (digits[((unsigned char)num) & mask] | locase);
			num >>= shift;
		} while (num);
	} else { /* base 10 */
		i = put_dec(tmp, num) - tmp;
	}

	/* printing 100 using %2d gives "100", not "00" */
	if (i > spec.precision)
		spec.precision = i;
	/* leading space padding */
	spec.field_width -= spec.precision;
	if (!(spec.flags & (ZEROPAD+LEFT))) {
		while (--spec.field_width >= 0) {
			if (buf < end)
				*buf = ' ';
			++buf;
		}
	}
	/* sign */
	if (sign) {
		if (buf < end)
			*buf = sign;
		++buf;
	}
	/* "0x" / "0" prefix */
	if (need_pfx) {
		if (spec.base == 16 || !is_zero) {
			if (buf < end)
				*buf = '0';
			++buf;
		}
		if (spec.base == 16) {
			if (buf < end)
				*buf = ('X' | locase);
			++buf;
		}
	}
	/* zero or space padding */
	if (!(spec.flags & LEFT)) {
		char c = (spec.flags & ZEROPAD) ? '0' : ' ';
		while (--spec.field_width >= 0) {
			if (buf < end)
				*buf = c;
			++buf;
		}
	}
	/* hmm even more zero padding? */
	while (i <= --spec.precision) {
		if (buf < end)
			*buf = '0';
		++buf;
	}
	/* actual digits of result */
	while (--i >= 0) {
		if (buf < end)
			*buf = tmp[i];
		++buf;
	}
	/* trailing space padding */
	while (--spec.field_width >= 0) {
		if (buf < end)
			*buf = ' ';
		++buf;
	}

	return buf;
}

static noinline_for_stack
char *string(char *buf, char *end, const char *s, struct printf_spec spec)
{
	int len, i;

	if ((unsigned long)s < PAGE_SIZE)
		s = "(null)";

	len = strnlen(s, spec.precision);

	if (!(spec.flags & LEFT)) {
		while (len < spec.field_width--) {
			if (buf < end)
				*buf = ' ';
			++buf;
		}
	}
	for (i = 0; i < len; ++i) {
		if (buf < end)
			*buf = *s;
		++buf; ++s;
	}
	while (len < spec.field_width--) {
		if (buf < end)
			*buf = ' ';
		++buf;
	}

	return buf;
}

static noinline_for_stack
char *symbol_string(char *buf, char *end, void *ptr,
		    struct printf_spec spec, char ext)
{
	unsigned long value = (unsigned long) ptr;
#ifdef CONFIG_KALLSYMS
	char sym[KSYM_SYMBOL_LEN];
	if (ext != 'f' && ext != 's')
		sprint_symbol(sym, value);
	else
		kallsyms_lookup(value, NULL, NULL, NULL, sym);

	return string(buf, end, sym, spec);
#else
	spec.field_width = 2 * sizeof(void *);
	spec.flags |= SPECIAL | SMALL | ZEROPAD;
	spec.base = 16;

	return number(buf, end, value, spec);
#endif
}

static noinline_for_stack
char *resource_string(char *buf, char *end, struct resource *res,
		      struct printf_spec spec)
{
#ifndef IO_RSRC_PRINTK_SIZE
#define IO_RSRC_PRINTK_SIZE	6
#endif

#ifndef MEM_RSRC_PRINTK_SIZE
#define MEM_RSRC_PRINTK_SIZE	10
#endif
	struct printf_spec num_spec = {
		.base = 16,
		.precision = -1,
		.flags = SPECIAL | SMALL | ZEROPAD,
	};
	/* room for the actual numbers, the two "0x", -, [, ] and the final zero */
	char sym[4*sizeof(resource_size_t) + 8];
	char *p = sym, *pend = sym + sizeof(sym);
	int size = -1;

	if (res->flags & IORESOURCE_IO)
		size = IO_RSRC_PRINTK_SIZE;
	else if (res->flags & IORESOURCE_MEM)
		size = MEM_RSRC_PRINTK_SIZE;

	*p++ = '[';
	num_spec.field_width = size;
	p = number(p, pend, res->start, num_spec);
	*p++ = '-';
	p = number(p, pend, res->end, num_spec);
	*p++ = ']';
	*p = 0;

	return string(buf, end, sym, spec);
}

static noinline_for_stack
char *mac_address_string(char *buf, char *end, u8 *addr,
			 struct printf_spec spec, const char *fmt)
{
	char mac_addr[sizeof("xx:xx:xx:xx:xx:xx")];
	char *p = mac_addr;
	int i;

	for (i = 0; i < 6; i++) {
		p = pack_hex_byte(p, addr[i]);
		if (fmt[0] == 'M' && i != 5)
			*p++ = ':';
	}
	*p = '\0';

	return string(buf, end, mac_addr, spec);
}

static noinline_for_stack
char *ip4_string(char *p, const u8 *addr, const char *fmt)
{
	int i;
	bool leading_zeros = (fmt[0] == 'i');
	int index;
	int step;

	switch (fmt[2]) {
	case 'h':
#ifdef __BIG_ENDIAN
		index = 0;
		step = 1;
#else
		index = 3;
		step = -1;
#endif
		break;
	case 'l':
		index = 3;
		step = -1;
		break;
	case 'n':
	case 'b':
	default:
		index = 0;
		step = 1;
		break;
	}
	for (i = 0; i < 4; i++) {
		char temp[3];	/* hold each IP quad in reverse order */
		int digits = put_dec_trunc8(temp, addr[index]) - temp;
		if (leading_zeros) {
			if (digits < 3)
				*p++ = '0';
			if (digits < 2)
				*p++ = '0';
		}
		/* reverse the digits in the quad */
		while (digits--)
			*p++ = temp[digits];
		if (i < 3)
			*p++ = '.';
		index += step;
	}
	*p = '\0';

	return p;
}

static noinline_for_stack
char *ip6_compressed_string(char *p, const char *addr)
{
	int i, j, range;
	unsigned char zerolength[8];
	int longest = 1;
	int colonpos = -1;
	u16 word;
	u8 hi, lo;
	bool needcolon = false;
	bool useIPv4;
	struct in6_addr in6;

	memcpy(&in6, addr, sizeof(struct in6_addr));

	useIPv4 = ipv6_addr_v4mapped(&in6) || ipv6_addr_is_isatap(&in6);

	memset(zerolength, 0, sizeof(zerolength));

	if (useIPv4)
		range = 6;
	else
		range = 8;

	/* find position of longest 0 run */
	for (i = 0; i < range; i++) {
		for (j = i; j < range; j++) {
			if (in6.s6_addr16[j] != 0)
				break;
			zerolength[i]++;
		}
	}
	for (i = 0; i < range; i++) {
		if (zerolength[i] > longest) {
			longest = zerolength[i];
			colonpos = i;
		}
	}
	if (longest == 1)		/* don't compress a single 0 */
		colonpos = -1;

	/* emit address */
	for (i = 0; i < range; i++) {
		if (i == colonpos) {
			if (needcolon || i == 0)
				*p++ = ':';
			*p++ = ':';
			needcolon = false;
			i += longest - 1;
			continue;
		}
		if (needcolon) {
			*p++ = ':';
			needcolon = false;
		}
		/* hex u16 without leading 0s */
		word = ntohs(in6.s6_addr16[i]);
		hi = word >> 8;
		lo = word & 0xff;
		if (hi) {
			if (hi > 0x0f)
				p = pack_hex_byte(p, hi);
			else
				*p++ = hex_asc_lo(hi);
			p = pack_hex_byte(p, lo);
		}
		else if (lo > 0x0f)
			p = pack_hex_byte(p, lo);
		else
			*p++ = hex_asc_lo(lo);
		needcolon = true;
	}

	if (useIPv4) {
		if (needcolon)
			*p++ = ':';
		p = ip4_string(p, &in6.s6_addr[12], "I4");
	}
	*p = '\0';

	return p;
}

static noinline_for_stack
char *ip6_string(char *p, const char *addr, const char *fmt)
{
	int i;

	for (i = 0; i < 8; i++) {
		p = pack_hex_byte(p, *addr++);
		p = pack_hex_byte(p, *addr++);
		if (fmt[0] == 'I' && i != 7)
			*p++ = ':';
	}
	*p = '\0';

	return p;
}

static noinline_for_stack
char *ip6_addr_string(char *buf, char *end, const u8 *addr,
		      struct printf_spec spec, const char *fmt)
{
	char ip6_addr[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255")];

	if (fmt[0] == 'I' && fmt[2] == 'c')
		ip6_compressed_string(ip6_addr, addr);
	else
		ip6_string(ip6_addr, addr, fmt);

	return string(buf, end, ip6_addr, spec);
}

static noinline_for_stack
char *ip4_addr_string(char *buf, char *end, const u8 *addr,
		      struct printf_spec spec, const char *fmt)
{
	char ip4_addr[sizeof("255.255.255.255")];

	ip4_string(ip4_addr, addr, fmt);

	return string(buf, end, ip4_addr, spec);
}

/*
 * Show a '%p' thing.  A kernel extension is that the '%p' is followed
 * by an extra set of alphanumeric characters that are extended format
 * specifiers.
 *
 * Right now we handle:
 *
 * - 'F' For symbolic function descriptor pointers with offset
 * - 'f' For simple symbolic function names without offset
 * - 'S' For symbolic direct pointers with offset
 * - 's' For symbolic direct pointers without offset
 * - 'R' For a struct resource pointer, it prints the range of
 *       addresses (not the name nor the flags)
 * - 'M' For a 6-byte MAC address, it prints the address in the
 *       usual colon-separated hex notation
 * - 'm' For a 6-byte MAC address, it prints the hex address without colons
 * - 'I' [46] for IPv4/IPv6 addresses printed in the usual way
 *       IPv4 uses dot-separated decimal without leading 0's (1.2.3.4)
 *       IPv6 uses colon separated network-order 16 bit hex with leading 0's
 * - 'i' [46] for 'raw' IPv4/IPv6 addresses
 *       IPv6 omits the colons (01020304...0f)
 *       IPv4 uses dot-separated decimal with leading 0's (010.123.045.006)
 * - '[Ii]4[hnbl]' IPv4 addresses in host, network, big or little endian order
 * - 'I6c' for IPv6 addresses printed as specified by
 *       http://www.ietf.org/id/draft-kawamura-ipv6-text-representation-03.txt
 * Note: The difference between 'S' and 'F' is that on ia64 and ppc64
 * function pointers are really function descriptors, which contain a
 * pointer to the real address.
 */
static noinline_for_stack
char *pointer(const char *fmt, char *buf, char *end, void *ptr,
	      struct printf_spec spec)
{
	if (!ptr)
		return string(buf, end, "(null)", spec);

	switch (*fmt) {
	case 'F':
	case 'f':
		ptr = dereference_function_descriptor(ptr);
		/* Fallthrough */
	case 's':
	case 'S':
		return symbol_string(buf, end, ptr, spec, *fmt);
	case 'R':
		return resource_string(buf, end, ptr, spec);
	case 'M':			/* Colon separated: 00:01:02:03:04:05 */
	case 'm':			/* Contiguous: 000102030405 */
		return mac_address_string(buf, end, ptr, spec, fmt);
	case 'I':			/* Formatted IP supported
					 * 4:	1.2.3.4
					 * 6:	0001:0203:...:0708
					 * 6c:	1::708 or 1::1.2.3.4
					 */
	case 'i':			/* Contiguous:
					 * 4:	001.002.003.004
					 * 6:   000102...0f
					 */
		switch (fmt[1]) {
		case '6':
			return ip6_addr_string(buf, end, ptr, spec, fmt);
		case '4':
			return ip4_addr_string(buf, end, ptr, spec, fmt);
		}
		break;
	}
	spec.flags |= SMALL;
	if (spec.field_width == -1) {
		spec.field_width = 2*sizeof(void *);
		spec.flags |= ZEROPAD;
	}
	spec.base = 16;

	return number(buf, end, (unsigned long) ptr, spec);
}

/*
 * Helper function to decode printf style format.
 * Each call decode a token from the format and return the
 * number of characters read (or likely the delta where it wants
 * to go on the next call).
 * The decoded token is returned through the parameters
 *
 * 'h', 'l', or 'L' for integer fields
 * 'z' support added 23/7/1999 S.H.
 * 'z' changed to 'Z' --davidm 1/25/99
 * 't' added for ptrdiff_t
 *
 * @fmt: the format string
 * @type of the token returned
 * @flags: various flags such as +, -, # tokens..
 * @field_width: overwritten width
 * @base: base of the number (octal, hex, ...)
 * @precision: precision of a number
 * @qualifier: qualifier of a number (long, size_t, ...)
 */
static noinline_for_stack
int format_decode(const char *fmt, struct printf_spec *spec)
{
	const char *start = fmt;

	/* we finished early by reading the field width */
	if (spec->type == FORMAT_TYPE_WIDTH) {
		if (spec->field_width < 0) {
			spec->field_width = -spec->field_width;
			spec->flags |= LEFT;
		}
		spec->type = FORMAT_TYPE_NONE;
		goto precision;
	}

	/* we finished early by reading the precision */
	if (spec->type == FORMAT_TYPE_PRECISION) {
		if (spec->precision < 0)
			spec->precision = 0;

		spec->type = FORMAT_TYPE_NONE;
		goto qualifier;
	}

	/* By default */
	spec->type = FORMAT_TYPE_NONE;

	for (; *fmt ; ++fmt) {
		if (*fmt == '%')
			break;
	}

	/* Return the current non-format string */
	if (fmt != start || !*fmt)
		return fmt - start;

	/* Process flags */
	spec->flags = 0;

	while (1) { /* this also skips first '%' */
		bool found = true;

		++fmt;

		switch (*fmt) {
		case '-': spec->flags |= LEFT;    break;
		case '+': spec->flags |= PLUS;    break;
		case ' ': spec->flags |= SPACE;   break;
		case '#': spec->flags |= SPECIAL; break;
		case '0': spec->flags |= ZEROPAD; break;
		default:  found = false;
		}

		if (!found)
			break;
	}

	/* get field width */
	spec->field_width = -1;

	if (isdigit(*fmt))
		spec->field_width = skip_atoi(&fmt);
	else if (*fmt == '*') {
		/* it's the next argument */
		spec->type = FORMAT_TYPE_WIDTH;
		return ++fmt - start;
	}

precision:
	/* get the precision */
	spec->precision = -1;
	if (*fmt == '.') {
		++fmt;
		if (isdigit(*fmt)) {
			spec->precision = skip_atoi(&fmt);
			if (spec->precision < 0)
				spec->precision = 0;
		} else if (*fmt == '*') {
			/* it's the next argument */
			spec->type = FORMAT_TYPE_PRECISION;
			return ++fmt - start;
		}
	}

qualifier:
	/* get the conversion qualifier */
	spec->qualifier = -1;
	if (*fmt == 'h' || TOLOWER(*fmt) == 'l' ||
	    TOLOWER(*fmt) == 'z' || *fmt == 't') {
		spec->qualifier = *fmt++;
		if (unlikely(spec->qualifier == *fmt)) {
			if (spec->qualifier == 'l') {
				spec->qualifier = 'L';
				++fmt;
			} else if (spec->qualifier == 'h') {
				spec->qualifier = 'H';
				++fmt;
			}
		}
	}

	/* default base */
	spec->base = 10;
	switch (*fmt) {
	case 'c':
		spec->type = FORMAT_TYPE_CHAR;
		return ++fmt - start;

	case 's':
		spec->type = FORMAT_TYPE_STR;
		return ++fmt - start;

	case 'p':
		spec->type = FORMAT_TYPE_PTR;
		return fmt - start;
		/* skip alnum */

	case 'n':
		spec->type = FORMAT_TYPE_NRCHARS;
		return ++fmt - start;

	case '%':
		spec->type = FORMAT_TYPE_PERCENT_CHAR;
		return ++fmt - start;

	/* integer number formats - set up the flags and "break" */
	case 'o':
		spec->base = 8;
		break;

	case 'x':
		spec->flags |= SMALL;

	case 'X':
		spec->base = 16;
		break;

	case 'd':
	case 'i':
		spec->flags |= SIGN;
	case 'u':
		break;

	default:
		spec->type = FORMAT_TYPE_INVALID;
		return fmt - start;
	}

	if (spec->qualifier == 'L')
		spec->type = FORMAT_TYPE_LONG_LONG;
	else if (spec->qualifier == 'l') {
		if (spec->flags & SIGN)
			spec->type = FORMAT_TYPE_LONG;
		else
			spec->type = FORMAT_TYPE_ULONG;
	} else if (TOLOWER(spec->qualifier) == 'z') {
		spec->type = FORMAT_TYPE_SIZE_T;
	} else if (spec->qualifier == 't') {
		spec->type = FORMAT_TYPE_PTRDIFF;
	} else if (spec->qualifier == 'H') {
		if (spec->flags & SIGN)
			spec->type = FORMAT_TYPE_BYTE;
		else
			spec->type = FORMAT_TYPE_UBYTE;
	} else if (spec->qualifier == 'h') {
		if (spec->flags & SIGN)
			spec->type = FORMAT_TYPE_SHORT;
		else
			spec->type = FORMAT_TYPE_USHORT;
	} else {
		if (spec->flags & SIGN)
			spec->type = FORMAT_TYPE_INT;
		else
			spec->type = FORMAT_TYPE_UINT;
	}

	return ++fmt - start;
}

/**
 * vsnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * This function follows C99 vsnprintf, but has some extensions:
 * %pS output the name of a text symbol with offset
 * %ps output the name of a text symbol without offset
 * %pF output the name of a function pointer with its offset
 * %pf output the name of a function pointer without its offset
 * %pR output the address range in a struct resource
 * %n is ignored
 *
 * The return value is the number of characters which would
 * be generated for the given input, excluding the trailing
 * '\0', as per ISO C99. If you want to have the exact
 * number of characters written into @buf as return value
 * (not including the trailing '\0'), use vscnprintf(). If the
 * return is greater than or equal to @size, the resulting
 * string is truncated.
 *
 * Call this function if you are already dealing with a va_list.
 * You probably want snprintf() instead.
 */
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	unsigned long long num;
	char *str, *end;
	struct printf_spec spec = {0};

	/* Reject out-of-range values early.  Large positive sizes are
	   used for unknown buffer sizes. */
	if (WARN_ON_ONCE((int) size < 0))
		return 0;

	str = buf;
	end = buf + size;

	/* Make sure end is always >= buf */
	if (end < buf) {
		end = ((void *)-1);
		size = end - buf;
	}

	while (*fmt) {
		const char *old_fmt = fmt;
		int read = format_decode(fmt, &spec);

		fmt += read;

		switch (spec.type) {
		case FORMAT_TYPE_NONE: {
			int copy = read;
			if (str < end) {
				if (copy > end - str)
					copy = end - str;
				memcpy(str, old_fmt, copy);
			}
			str += read;
			break;
		}

		case FORMAT_TYPE_WIDTH:
			spec.field_width = va_arg(args, int);
			break;

		case FORMAT_TYPE_PRECISION:
			spec.precision = va_arg(args, int);
			break;

		case FORMAT_TYPE_CHAR: {
			char c;

			if (!(spec.flags & LEFT)) {
				while (--spec.field_width > 0) {
					if (str < end)
						*str = ' ';
					++str;

				}
			}
			c = (unsigned char) va_arg(args, int);
			if (str < end)
				*str = c;
			++str;
			while (--spec.field_width > 0) {
				if (str < end)
					*str = ' ';
				++str;
			}
			break;
		}

		case FORMAT_TYPE_STR:
			str = string(str, end, va_arg(args, char *), spec);
			break;

		case FORMAT_TYPE_PTR:
			str = pointer(fmt+1, str, end, va_arg(args, void *),
				      spec);
			while (isalnum(*fmt))
				fmt++;
			break;

		case FORMAT_TYPE_PERCENT_CHAR:
			if (str < end)
				*str = '%';
			++str;
			break;

		case FORMAT_TYPE_INVALID:
			if (str < end)
				*str = '%';
			++str;
			break;

		case FORMAT_TYPE_NRCHARS: {
			u8 qualifier = spec.qualifier;

			if (qualifier == 'l') {
				long *ip = va_arg(args, long *);
				*ip = (str - buf);
			} else if (TOLOWER(qualifier) == 'z') {
				size_t *ip = va_arg(args, size_t *);
				*ip = (str - buf);
			} else {
				int *ip = va_arg(args, int *);
				*ip = (str - buf);
			}
			break;
		}

		default:
			switch (spec.type) {
			case FORMAT_TYPE_LONG_LONG:
				num = va_arg(args, long long);
				break;
			case FORMAT_TYPE_ULONG:
				num = va_arg(args, unsigned long);
				break;
			case FORMAT_TYPE_LONG:
				num = va_arg(args, long);
				break;
			case FORMAT_TYPE_SIZE_T:
				num = va_arg(args, size_t);
				break;
			case FORMAT_TYPE_PTRDIFF:
				num = va_arg(args, ptrdiff_t);
				break;
			case FORMAT_TYPE_UBYTE:
				num = (unsigned char) va_arg(args, int);
				break;
			case FORMAT_TYPE_BYTE:
				num = (signed char) va_arg(args, int);
				break;
			case FORMAT_TYPE_USHORT:
				num = (unsigned short) va_arg(args, int);
				break;
			case FORMAT_TYPE_SHORT:
				num = (short) va_arg(args, int);
				break;
			case FORMAT_TYPE_INT:
				num = (int) va_arg(args, int);
				break;
			default:
				num = va_arg(args, unsigned int);
			}

			str = number(str, end, num, spec);
		}
	}

	if (size > 0) {
		if (str < end)
			*str = '\0';
		else
			end[-1] = '\0';
	}

	/* the trailing null byte doesn't count towards the total */
	return str-buf;

}
EXPORT_SYMBOL(vsnprintf);

/**
 * vscnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The return value is the number of characters which have been written into
 * the @buf not including the trailing '\0'. If @size is == 0 the function
 * returns 0.
 *
 * Call this function if you are already dealing with a va_list.
 * You probably want scnprintf() instead.
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	int i;

	i = vsnprintf(buf, size, fmt, args);

	if (likely(i < size))
		return i;
	if (size != 0)
		return size - 1;
	return 0;
}
EXPORT_SYMBOL(vscnprintf);

/**
 * snprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The return value is the number of characters which would be
 * generated for the given input, excluding the trailing null,
 * as per ISO C99.  If the return is greater than or equal to
 * @size, the resulting string is truncated.
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int snprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, size, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(snprintf);

/**
 * scnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The return value is the number of characters written into @buf not including
 * the trailing '\0'. If @size is == 0 the function returns 0.
 */

int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vscnprintf(buf, size, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(scnprintf);

/**
 * vsprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The function returns the number of characters written
 * into @buf. Use vsnprintf() or vscnprintf() in order to avoid
 * buffer overflows.
 *
 * Call this function if you are already dealing with a va_list.
 * You probably want sprintf() instead.
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int vsprintf(char *buf, const char *fmt, va_list args)
{
	return vsnprintf(buf, INT_MAX, fmt, args);
}
EXPORT_SYMBOL(vsprintf);

/**
 * sprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The function returns the number of characters written
 * into @buf. Use snprintf() or scnprintf() in order to avoid
 * buffer overflows.
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int sprintf(char *buf, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, INT_MAX, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(sprintf);

#ifdef CONFIG_BINARY_PRINTF
/*
 * bprintf service:
 * vbin_printf() - VA arguments to binary data
 * bstr_printf() - Binary data to text string
 */

/**
 * vbin_printf - Parse a format string and place args' binary value in a buffer
 * @bin_buf: The buffer to place args' binary value
 * @size: The size of the buffer(by words(32bits), not characters)
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The format follows C99 vsnprintf, except %n is ignored, and its argument
 * is skiped.
 *
 * The return value is the number of words(32bits) which would be generated for
 * the given input.
 *
 * NOTE:
 * If the return value is greater than @size, the resulting bin_buf is NOT
 * valid for bstr_printf().
 */
int vbin_printf(u32 *bin_buf, size_t size, const char *fmt, va_list args)
{
	struct printf_spec spec = {0};
	char *str, *end;

	str = (char *)bin_buf;
	end = (char *)(bin_buf + size);

#define save_arg(type)							\
do {									\
	if (sizeof(type) == 8) {					\
		unsigned long long value;				\
		str = PTR_ALIGN(str, sizeof(u32));			\
		value = va_arg(args, unsigned long long);		\
		if (str + sizeof(type) <= end) {			\
			*(u32 *)str = *(u32 *)&value;			\
			*(u32 *)(str + 4) = *((u32 *)&value + 1);	\
		}							\
	} else {							\
		unsigned long value;					\
		str = PTR_ALIGN(str, sizeof(type));			\
		value = va_arg(args, int);				\
		if (str + sizeof(type) <= end)				\
			*(typeof(type) *)str = (type)value;		\
	}								\
	str += sizeof(type);						\
} while (0)

	while (*fmt) {
		int read = format_decode(fmt, &spec);

		fmt += read;

		switch (spec.type) {
		case FORMAT_TYPE_NONE:
		case FORMAT_TYPE_INVALID:
		case FORMAT_TYPE_PERCENT_CHAR:
			break;

		case FORMAT_TYPE_WIDTH:
		case FORMAT_TYPE_PRECISION:
			save_arg(int);
			break;

		case FORMAT_TYPE_CHAR:
			save_arg(char);
			break;

		case FORMAT_TYPE_STR: {
			const char *save_str = va_arg(args, char *);
			size_t len;

			if ((unsigned long)save_str > (unsigned long)-PAGE_SIZE
					|| (unsigned long)save_str < PAGE_SIZE)
				save_str = "(null)";
			len = strlen(save_str) + 1;
			if (str + len < end)
				memcpy(str, save_str, len);
			str += len;
			break;
		}

		case FORMAT_TYPE_PTR:
			save_arg(void *);
			/* skip all alphanumeric pointer suffixes */
			while (isalnum(*fmt))
				fmt++;
			break;

		case FORMAT_TYPE_NRCHARS: {
			/* skip %n 's argument */
			u8 qualifier = spec.qualifier;
			void *skip_arg;
			if (qualifier == 'l')
				skip_arg = va_arg(args, long *);
			else if (TOLOWER(qualifier) == 'z')
				skip_arg = va_arg(args, size_t *);
			else
				skip_arg = va_arg(args, int *);
			break;
		}

		default:
			switch (spec.type) {

			case FORMAT_TYPE_LONG_LONG:
				save_arg(long long);
				break;
			case FORMAT_TYPE_ULONG:
			case FORMAT_TYPE_LONG:
				save_arg(unsigned long);
				break;
			case FORMAT_TYPE_SIZE_T:
				save_arg(size_t);
				break;
			case FORMAT_TYPE_PTRDIFF:
				save_arg(ptrdiff_t);
				break;
			case FORMAT_TYPE_UBYTE:
			case FORMAT_TYPE_BYTE:
				save_arg(char);
				break;
			case FORMAT_TYPE_USHORT:
			case FORMAT_TYPE_SHORT:
				save_arg(short);
				break;
			default:
				save_arg(int);
			}
		}
	}

	return (u32 *)(PTR_ALIGN(str, sizeof(u32))) - bin_buf;
#undef save_arg
}
EXPORT_SYMBOL_GPL(vbin_printf);

/**
 * bstr_printf - Format a string from binary arguments and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @bin_buf: Binary arguments for the format string
 *
 * This function like C99 vsnprintf, but the difference is that vsnprintf gets
 * arguments from stack, and bstr_printf gets arguments from @bin_buf which is
 * a binary buffer that generated by vbin_printf.
 *
 * The format follows C99 vsnprintf, but has some extensions:
 *  see vsnprintf comment for details.
 *
 * The return value is the number of characters which would
 * be generated for the given input, excluding the trailing
 * '\0', as per ISO C99. If you want to have the exact
 * number of characters written into @buf as return value
 * (not including the trailing '\0'), use vscnprintf(). If the
 * return is greater than or equal to @size, the resulting
 * string is truncated.
 */
int bstr_printf(char *buf, size_t size, const char *fmt, const u32 *bin_buf)
{
	struct printf_spec spec = {0};
	char *str, *end;
	const char *args = (const char *)bin_buf;

	if (WARN_ON_ONCE((int) size < 0))
		return 0;

	str = buf;
	end = buf + size;

#define get_arg(type)							\
({									\
	typeof(type) value;						\
	if (sizeof(type) == 8) {					\
		args = PTR_ALIGN(args, sizeof(u32));			\
		*(u32 *)&value = *(u32 *)args;				\
		*((u32 *)&value + 1) = *(u32 *)(args + 4);		\
	} else {							\
		args = PTR_ALIGN(args, sizeof(type));			\
		value = *(typeof(type) *)args;				\
	}								\
	args += sizeof(type);						\
	value;								\
})

	/* Make sure end is always >= buf */
	if (end < buf) {
		end = ((void *)-1);
		size = end - buf;
	}

	while (*fmt) {
		const char *old_fmt = fmt;
		int read = format_decode(fmt, &spec);

		fmt += read;

		switch (spec.type) {
		case FORMAT_TYPE_NONE: {
			int copy = read;
			if (str < end) {
				if (copy > end - str)
					copy = end - str;
				memcpy(str, old_fmt, copy);
			}
			str += read;
			break;
		}

		case FORMAT_TYPE_WIDTH:
			spec.field_width = get_arg(int);
			break;

		case FORMAT_TYPE_PRECISION:
			spec.precision = get_arg(int);
			break;

		case FORMAT_TYPE_CHAR: {
			char c;

			if (!(spec.flags & LEFT)) {
				while (--spec.field_width > 0) {
					if (str < end)
						*str = ' ';
					++str;
				}
			}
			c = (unsigned char) get_arg(char);
			if (str < end)
				*str = c;
			++str;
			while (--spec.field_width > 0) {
				if (str < end)
					*str = ' ';
				++str;
			}
			break;
		}

		case FORMAT_TYPE_STR: {
			const char *str_arg = args;
			args += strlen(str_arg) + 1;
			str = string(str, end, (char *)str_arg, spec);
			break;
		}

		case FORMAT_TYPE_PTR:
			str = pointer(fmt+1, str, end, get_arg(void *), spec);
			while (isalnum(*fmt))
				fmt++;
			break;

		case FORMAT_TYPE_PERCENT_CHAR:
		case FORMAT_TYPE_INVALID:
			if (str < end)
				*str = '%';
			++str;
			break;

		case FORMAT_TYPE_NRCHARS:
			/* skip */
			break;

		default: {
			unsigned long long num;

			switch (spec.type) {

			case FORMAT_TYPE_LONG_LONG:
				num = get_arg(long long);
				break;
			case FORMAT_TYPE_ULONG:
			case FORMAT_TYPE_LONG:
				num = get_arg(unsigned long);
				break;
			case FORMAT_TYPE_SIZE_T:
				num = get_arg(size_t);
				break;
			case FORMAT_TYPE_PTRDIFF:
				num = get_arg(ptrdiff_t);
				break;
			case FORMAT_TYPE_UBYTE:
				num = get_arg(unsigned char);
				break;
			case FORMAT_TYPE_BYTE:
				num = get_arg(signed char);
				break;
			case FORMAT_TYPE_USHORT:
				num = get_arg(unsigned short);
				break;
			case FORMAT_TYPE_SHORT:
				num = get_arg(short);
				break;
			case FORMAT_TYPE_UINT:
				num = get_arg(unsigned int);
				break;
			default:
				num = get_arg(int);
			}

			str = number(str, end, num, spec);
		} /* default: */
		} /* switch(spec.type) */
	} /* while(*fmt) */

	if (size > 0) {
		if (str < end)
			*str = '\0';
		else
			end[-1] = '\0';
	}

#undef get_arg

	/* the trailing null byte doesn't count towards the total */
	return str - buf;
}
EXPORT_SYMBOL_GPL(bstr_printf);

/**
 * bprintf - Parse a format string and place args' binary value in a buffer
 * @bin_buf: The buffer to place args' binary value
 * @size: The size of the buffer(by words(32bits), not characters)
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The function returns the number of words(u32) written
 * into @bin_buf.
 */
int bprintf(u32 *bin_buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vbin_printf(bin_buf, size, fmt, args);
	va_end(args);

	return ret;
}
EXPORT_SYMBOL_GPL(bprintf);

#endif /* CONFIG_BINARY_PRINTF */

/**
 * vsscanf - Unformat a buffer into a list of arguments
 * @buf:	input buffer
 * @fmt:	format of buffer
 * @args:	arguments
 */
int vsscanf(const char *buf, const char *fmt, va_list args)
{
	const char *str = buf;
	char *next;
	char digit;
	int num = 0;
	u8 qualifier;
	u8 base;
	s16 field_width;
	bool is_sign;

	while (*fmt) {
		/* skip any white space in format */
		/* white space in format matchs any amount of
		 * white space, including none, in the input.
		 */
		if (isspace(*fmt)) {
			fmt = skip_spaces(++fmt);
			str = skip_spaces(str);
		}

		/* anything that is not a conversion must match exactly */
		if (*fmt != '%' && *fmt) {
			if (*fmt++ != *str++)
				break;
			continue;
		}

		if (!*fmt)
			break;
		++fmt;

		/* skip this conversion.
		 * advance both strings to next white space
		 */
		if (*fmt == '*') {
			if (!*str)
				break;
			while (!isspace(*fmt) && *fmt != '%' && *fmt)
				fmt++;
			while (!isspace(*str) && *str)
				str++;
			continue;
		}

		/* get field width */
		field_width = -1;
		if (isdigit(*fmt))
			field_width = skip_atoi(&fmt);

		/* get conversion qualifier */
		qualifier = -1;
		if (*fmt == 'h' || TOLOWER(*fmt) == 'l' ||
		    TOLOWER(*fmt) == 'z') {
			qualifier = *fmt++;
			if (unlikely(qualifier == *fmt)) {
				if (qualifier == 'h') {
					qualifier = 'H';
					fmt++;
				} else if (qualifier == 'l') {
					qualifier = 'L';
					fmt++;
				}
			}
		}

		if (!*fmt)
			break;

		if (*fmt == 'n') {
			/* return number of characters read so far */
			*va_arg(args, int *) = str - buf;
			++fmt;
			continue;
		}

		if (!*str)
			break;

		base = 10;
		is_sign = 0;

		switch (*fmt++) {
		case 'c':
		{
			char *s = (char *)va_arg(args, char*);
			if (field_width == -1)
				field_width = 1;
			do {
				*s++ = *str++;
			} while (--field_width > 0 && *str);
			num++;
		}
		continue;
		case 's':
		{
			char *s = (char *)va_arg(args, char *);
			if (field_width == -1)
				field_width = SHORT_MAX;
			/* first, skip leading white space in buffer */
			str = skip_spaces(str);

			/* now copy until next white space */
			while (*str && !isspace(*str) && field_width--)
				*s++ = *str++;
			*s = '\0';
			num++;
		}
		continue;
		case 'o':
			base = 8;
			break;
		case 'x':
		case 'X':
			base = 16;
			break;
		case 'i':
			base = 0;
		case 'd':
			is_sign = 1;
		case 'u':
			break;
		case '%':
			/* looking for '%' in str */
			if (*str++ != '%')
				return num;
			continue;
		default:
			/* invalid format; stop here */
			return num;
		}

		/* have some sort of integer conversion.
		 * first, skip white space in buffer.
		 */
		str = skip_spaces(str);

		digit = *str;
		if (is_sign && digit == '-')
			digit = *(str + 1);

		if (!digit
		    || (base == 16 && !isxdigit(digit))
		    || (base == 10 && !isdigit(digit))
		    || (base == 8 && (!isdigit(digit) || digit > '7'))
		    || (base == 0 && !isdigit(digit)))
			break;

		switch (qualifier) {
		case 'H':	/* that's 'hh' in format */
			if (is_sign) {
				signed char *s = (signed char *)va_arg(args, signed char *);
				*s = (signed char)simple_strtol(str, &next, base);
			} else {
				unsigned char *s = (unsigned char *)va_arg(args, unsigned char *);
				*s = (unsigned char)simple_strtoul(str, &next, base);
			}
			break;
		case 'h':
			if (is_sign) {
				short *s = (short *)va_arg(args, short *);
				*s = (short)simple_strtol(str, &next, base);
			} else {
				unsigned short *s = (unsigned short *)va_arg(args, unsigned short *);
				*s = (unsigned short)simple_strtoul(str, &next, base);
			}
			break;
		case 'l':
			if (is_sign) {
				long *l = (long *)va_arg(args, long *);
				*l = simple_strtol(str, &next, base);
			} else {
				unsigned long *l = (unsigned long *)va_arg(args, unsigned long *);
				*l = simple_strtoul(str, &next, base);
			}
			break;
		case 'L':
			if (is_sign) {
				long long *l = (long long *)va_arg(args, long long *);
				*l = simple_strtoll(str, &next, base);
			} else {
				unsigned long long *l = (unsigned long long *)va_arg(args, unsigned long long *);
				*l = simple_strtoull(str, &next, base);
			}
			break;
		case 'Z':
		case 'z':
		{
			size_t *s = (size_t *)va_arg(args, size_t *);
			*s = (size_t)simple_strtoul(str, &next, base);
		}
		break;
		default:
			if (is_sign) {
				int *i = (int *)va_arg(args, int *);
				*i = (int)simple_strtol(str, &next, base);
			} else {
				unsigned int *i = (unsigned int *)va_arg(args, unsigned int*);
				*i = (unsigned int)simple_strtoul(str, &next, base);
			}
			break;
		}
		num++;

		if (!next)
			break;
		str = next;
	}

	return num;
}
EXPORT_SYMBOL(vsscanf);

/**
 * sscanf - Unformat a buffer into a list of arguments
 * @buf:	input buffer
 * @fmt:	formatting of buffer
 * @...:	resulting arguments
 */
int sscanf(const char *buf, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsscanf(buf, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(sscanf);
