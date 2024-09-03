/*
 *  Intel CPU Microcode data manipulation
 *
 *  Copyright (c) 2000-2006 Tigran Aivazian <tigran@aivazian.fsnet.co.uk>
 *                2006      Shaohua Li <shaohua.li@intel.com>
 *                2010-2018 Henrique de Moraes Holschuh <hmh@hmh.eng.br>
 *
 *  Based on Linux kernel Intel Microcode driver v2.6.36-rc3 (1.14)
 *  Based on Linux microcode.ctl version 1.17
 *
 *  Reference: Section 9.11 of Volume 3a, IA-32 Intel Architecture
 *  Software Developer's Manual
 *  Order Number 253668 or free download from:
 *  http://developer.intel.com/design/pentium4/manuals/253668.htm
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "intel_microcode.h"

#include <stdint.h>
#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
 * For micro-optimization on the hotter paths
 */
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

/* pointer alignment test */
#define IS_PTR_ALIGNED(p, a) (!!(((uintptr_t)p & ((uintptr_t)(a)-1)) == 0))

/*
 * Microcode update file data structures
 */

/*
 * Microcode bundle layout, version 1:
 *
 *   sequence of one or more intel_ucode_v1_get_totalsize() bytes:
 *     struct intel_ucode_v1_hdr                             (48 bytes)
 *     uint32_t data[]            (intel_ucode_v1_get_datasize() bytes)
 *     struct intel_ucode_v1_extsig_table       (optional, size varies)
 *
 *  The total size will always be a multiple of 1024 bytes and is
 *  composed of all three of the above structures.
 */

struct intel_ucode_v1_hdr { /* 48 bytes */
	uint32_t	    hdrver; /* must be 0x1 */
	int32_t		    rev;    /* yes, it IS signed */
	uint32_t	    date;   /* packed BCD, MMDDYYYY */
	uint32_t	    sig;
	uint32_t	    cksum;
	uint32_t	    ldrver;
	uint32_t	    pf_mask;
	uint32_t	    datasize;  /* 0 means 2000 */
	uint32_t	    totalsize; /* 0 means 2048 */
	uint32_t	    reserved[3];
} __attribute__((packed));

/* microcode format is extended from prescott processors */
struct intel_ucode_v1_extsig {
	uint32_t	    sig;
	uint32_t	    pf_mask;
	uint32_t	    cksum;
} __attribute__((packed));

struct intel_ucode_v1_extsig_table {
	uint32_t	    count;  /* number of entries in sigs[] */
	uint32_t	    cksum;
	uint32_t	    reserved[3];
	struct intel_ucode_v1_extsig sigs[];
} __attribute__((packed));

#define INTEL_UC_V1_DEF_DATASIZE    (2000)
#define INTEL_UC_V1_HEADER_SIZE     (sizeof(struct intel_ucode_v1_hdr))
#define INTEL_UC_V1_DEF_TOTALSIZE   (INTEL_UC_V1_DEF_DATASIZE + \
				     INTEL_UC_V1_HEADER_SIZE)
#define INTEL_UC_V1_EXTHDR_SIZE	    (sizeof(struct intel_ucode_v1_extsig_table))
#define INTEL_UC_V1_EXTSIG_SIZE     (sizeof(struct intel_ucode_v1_extsig))

#define intel_uc_v1_exttable_size(et) \
	((et)->count * INTEL_UC_V1_EXTSIG_SIZE + INTEL_UC_V1_EXTHDR_SIZE)

/**
 * is_valid_bcd() - validate 8-digit packed BCD
 * @data:	32-bit integer with the 8-digit packet BCD number
 *
 * Check validity of an 8-digit packed BCD (ensure all digits are
 * between 0 and 9).
 *
 * Returns zero if invalid, and non-zero otherwise.
 */
static inline int is_valid_bcd(const uint32_t data)
{
	/* use arcane bit magic to test lower 7 digits just for fun,
	 * try to figure it out when you're feeling bored. */
	return (data < 0xA0000000U) &&
	       ((((data + 0x06666666U) ^ data) & 0x11111110U) == 0);
}

/**
 * intel_ucode_v1_get_totalsize() - get total size of a microcode entry
 *
 * @hdr:	pointer to the start of the microcode entry (header)
 *
 * Returns the total size of a single microcode entry.  The microcode
 * data file is composed of one or more microcode entries, stored
 * back-to-back.
 *
 * The total size includes the header, microcode data, and the optional
 * extended signature table.
 */
static inline uint32_t intel_ucode_v1_get_totalsize(const struct intel_ucode_v1_hdr * const hdr)
{
	/* totalsize is valid only if datasize != 0, IA SDM 9.11.1, page 9-28 */
	if (hdr->datasize != 0)
		return hdr->totalsize;
	else
		return INTEL_UC_V1_DEF_TOTALSIZE;
}

/**
 * intel_ucode_v1_get_datasize() - get microcode data size of a microcode entry
 *
 * @hdr:	pointer to the start of the microcode entry (header)
 *
 * Returns the size of the opaque data field of a single microcode entry.
 */
static inline uint32_t intel_ucode_v1_get_datasize(const struct intel_ucode_v1_hdr * const hdr)
{
	if (hdr->datasize != 0)
		return hdr->datasize;
	else
		return INTEL_UC_V1_DEF_DATASIZE;
}

/**
 * intel_ucode_getmetadata() - extract metadata from microcode
 * @uc:		microcode
 * @metadata:	pointer to struct intel_ucode_metadata to be filled with
 *
 * Fills @metadata with metadata from microcode @uc.  @uc must already have
 * been validated.
 */
intel_ucode_status_t intel_ucode_getmetadata(const void * const uc,
				struct intel_ucode_metadata * const metadata)
{
	const struct intel_ucode_v1_hdr * const hdr = uc;

	if (unlikely(!hdr || !metadata))
		return INTEL_UCODE_BAD_PARAMETERS;

	if (unlikely(hdr->hdrver != 1))
		return INTEL_UCODE_UNKNOWN_FORMAT;

	metadata->date_year  = hdr->date & 0xffffU;
	metadata->date_day   = hdr->date >> 16 & 0xffU;
	metadata->date_month = hdr->date >> 24 & 0xffU;
	metadata->revision = hdr->rev;

	metadata->extsig_count = 0;
	if (hdr->datasize) {
		metadata->size = hdr->totalsize;

		if (unlikely(hdr->totalsize > INTEL_UC_V1_HEADER_SIZE + hdr->datasize)) {
			const struct intel_ucode_v1_extsig_table * const ext_header =
				    (const void *)((const uint8_t *)uc + INTEL_UC_V1_HEADER_SIZE + hdr->datasize);
			metadata->extsig_count = ext_header->count;
		}
	} else {
		metadata->size = INTEL_UC_V1_DEF_TOTALSIZE;
	}

	return INTEL_UCODE_NOERROR;
}

/**
 * intel_ucode_getdate_bcd() - extract microcode date
 * @uc:	microcode
 *
 * Returns the microcode date, in packed BCD (YYYYMMDD) format.
 * The date is not normalized, but it will be valid packed BCD.
 *
 * Call this function only on microcode entries that have been
 * verified to be well-formed by intel_ucode_check_microcode().
 *
 * Returns zero in case of error.
 */
uint32_t intel_ucode_getdate_bcd(const void * const uc)
{
	const struct intel_ucode_v1_hdr * const hdr = uc;

	if (unlikely(!hdr || hdr->hdrver != 1))
		return 0;

	if (unlikely(!is_valid_bcd(hdr->date)))
		return 0;

	/* v1 ucode date field is in MMDDYYYY format */
	return  ((hdr->date & 0xffffU) << 16) |
		((hdr->date >> 16) & 0xffffU);
}

/**
 * intel_ucode_compare() - compares two microcodes
 *
 * @uc1, @uc2: pointer to start of microcode entries to compare
 *
 * Checks if the two microcode entries are compatible, i.e. they
 * differ at most on their pf masks.  Compatible microcode entries can
 * be merged into a single entry by ORing their pf masks.
 *
 * Extended signature tables are not supported.  If any of the
 * microcode entries has one, the function will return a mismatch.
 *
 * Call this function only on microcode entries that have been
 * verified to be well-formed by intel_ucode_check_microcode().
 *
 * Returns:
 *   -EINVAL: parameter problem
 *   -EBADF:  two copies of the same microcode, with different opaque data
 *   0: the two microcodes are incompatible
 *   1: the two microcodes are compatible
 *   2: the two microcodes are identical
 */
int intel_ucode_compare(const void * const uc1, const void * const uc2)
{
	const struct intel_ucode_v1_hdr * const hdr1 = uc1;
	const struct intel_ucode_v1_hdr * const hdr2 = uc2;
	unsigned long int ts1, ts2, ds1, ds2;

	if (unlikely(!uc1 || !uc2))
		return -EINVAL;

	if (unlikely((hdr1->hdrver != 1) || (hdr2->hdrver != 1)))
		return -EINVAL;

	if (unlikely(uc1 == uc2))
		return 2;

	ts1 = intel_ucode_v1_get_totalsize(hdr1);
	ts2 = intel_ucode_v1_get_totalsize(hdr2);
	if (ts1 != ts2)
		return 0;

	ds1 = intel_ucode_v1_get_datasize(hdr1);
	ds2 = intel_ucode_v1_get_datasize(hdr2);
	if (ds1 != ds2)
		return 0;

	if (ds1 + INTEL_UC_V1_HEADER_SIZE < ts1)
		return 0; /* uc1,2 have extended header */

	if (hdr1->sig != hdr2->sig || hdr1->rev != hdr2->rev)
		return 0;

	if (memcmp((const uint8_t *)uc1 + INTEL_UC_V1_HEADER_SIZE,
		   (const uint8_t *)uc2 + INTEL_UC_V1_HEADER_SIZE, ds1))
		return (hdr1->pf_mask & hdr2->pf_mask)? -EBADF: 0;

	/*
	 * we *really* don't want different microcodes with the same
	 * rev number and signature, but we don't care if they're the
	 * same but have different dates.
	 */

	return (hdr1->date == hdr2->date &&
		hdr1->pf_mask == hdr2->pf_mask)? 2 : 1;
}

/**
 * intel_ucode_errstr - converts intel_ucode_status_t to string
 *
 * @status:	intel_ucode_status_t value to convert
 *
 * Returns a human-readable string explaining a intel_ucode_status_t
 * status code.  The string is static allocated, NULL-terminated,
 * and in English.
 */
const char * intel_ucode_errstr(const intel_ucode_status_t status)
{
	/* warning: this is an __attribute__((const)) function! */
	switch (status) {
	case INTEL_UCODE_INVALID_DATA:
		return "invalid microcode data";
	case INTEL_UCODE_UNKNOWN_FORMAT:
		return "unknown microcode format";
	case INTEL_UCODE_BAD_EXTENDED_TABLE:
		return "bad extended signature table";
	case INTEL_UCODE_BAD_EXTENDED_TABLE_CHECKSUM:
		return "incorrect extended signature table checksum";
	case INTEL_UCODE_BAD_CHECKSUM:
		return "incorrect microcode checksum";
	case INTEL_UCODE_BAD_EXTENDED_SIG_CHECKSUM:
		return "incorrect extended signature checksum";
	case INTEL_UCODE_COUNTEROVERFLOW:
		return "too many microcodes or signatures to handle";
	case INTEL_UCODE_CALLBACK_ERROR:
		return "callback returned failure status";
	case INTEL_UCODE_NOERROR:
		return "success";
	case INTEL_UCODE_BAD_PARAMETERS:
		return "internal error: bad parameters passed to function";
	default:
		return "internal error: invalid intel_ucode_status_t status";
	}
}

static int is_zero_checksum(const uint8_t *data, uint32_t dwords)
{
	uint32_t s = 0;

	/*
	 * Test using -tr loader on a valid microcode data file with one to
	 * three bytes of zeros prepended (to offset the valid microcode
	 * data out of alignment).
	 */

	if (IS_PTR_ALIGNED(data, sizeof(uint32_t))) {
		/*
		 * gcc might generate vectorized code that cannot handle
		 * unaligned pointer dereferences when given this pattern:
		 */
		const uint32_t *p = (const uint32_t *)data;
		while (dwords--)
			s += *(p++);
	} else {
		/*
		 * Avoid unaligned accesses.  gcc seems to always vectorize
		 * this properly into code that can handle unaligned data.
		 * When not vectorized, generates slow code.
		 *
		 * Note:
		 * s += (((uint16_t *)data)[0] | (((uint16_t *)data)[1] << 16));
		 *
		 * also works when vectorized by gcc, and generates faster
		 * and better code than doing it one byte at a time like
		 * below.  However, when working around compiler issues, it
		 * often pays off to go all the way...
		 */
		while (dwords--) {
			s += ((unsigned int)data[0] |
			     ((unsigned int)data[1] << 8)  |
			     ((unsigned int)data[2] << 16) |
			     ((unsigned int)data[3] << 24));
			data += 4;
		}
	}

	return (s == 0);
}

/*
 * xx_intel_ucode_check_uc()
 *
 * refer to intel_ucode_check_microcode() for details.
 *
 * @uc does not have to be aligned.
 *
 * We depend on the fact that x86/x86-64 is fine with misaligned data
 * access, as long as you keep away from aligned vector instructions and
 * other "specials".
 */
static intel_ucode_status_t xx_intel_ucode_check_uc(const void * const uc,
						    const size_t maxlen,
						    const int strict)
{
	unsigned long int total_size, data_size, ext_table_size;
	const struct intel_ucode_v1_hdr * const uc_header = uc;
	unsigned int i;

	if (unlikely(!uc || (strict && !IS_PTR_ALIGNED(uc, sizeof(uint32_t)))))
		return INTEL_UCODE_BAD_PARAMETERS;

	if (unlikely(maxlen < INTEL_UC_MINSIZE))
		return INTEL_UCODE_INVALID_DATA;

	if (unlikely(uc_header->hdrver != 1))
		return INTEL_UCODE_UNKNOWN_FORMAT;

	/* Header version 1 format */

	total_size = intel_ucode_v1_get_totalsize(uc_header);
	data_size = intel_ucode_v1_get_datasize(uc_header);

	if (data_size > total_size || data_size < INTEL_UC_V1_HEADER_SIZE)
		return INTEL_UCODE_INVALID_DATA;
	if (data_size + INTEL_UC_V1_HEADER_SIZE > total_size)
		return INTEL_UCODE_INVALID_DATA;

	if (data_size % sizeof(uint32_t))
		return INTEL_UCODE_INVALID_DATA;
	if (total_size % sizeof(uint32_t))
		return INTEL_UCODE_INVALID_DATA;
	if (strict && total_size % 1024)
		return INTEL_UCODE_INVALID_DATA;
	if (total_size > maxlen)
		return INTEL_UCODE_INVALID_DATA;

	/* Calculate the checksum.  We exclude the extended table as it
	 * also has to have a zero checksum, in order to get better
	 * coverage */
	if (!is_zero_checksum(uc, (INTEL_UC_V1_HEADER_SIZE + data_size) / sizeof(uint32_t)))
		return INTEL_UCODE_BAD_CHECKSUM; /* invalid checksum */

	/* we can now assume that this is very likely to be microcode */

	ext_table_size = total_size - (INTEL_UC_V1_HEADER_SIZE + data_size);
	if (unlikely(ext_table_size)) {
		const struct intel_ucode_v1_extsig_table *ext_header;
		const struct intel_ucode_v1_extsig *ext_sig;
		uint32_t ext_sigcount;

		if (ext_table_size < INTEL_UC_V1_EXTHDR_SIZE)
			return INTEL_UCODE_BAD_EXTENDED_TABLE; /* exttable size too small */
		if ((ext_table_size - INTEL_UC_V1_EXTHDR_SIZE) % INTEL_UC_V1_EXTSIG_SIZE)
			return INTEL_UCODE_BAD_EXTENDED_TABLE; /* bad exttable size */

		ext_header = (const void *)((const uint8_t *)uc + INTEL_UC_V1_HEADER_SIZE + data_size);
		if (ext_table_size != intel_uc_v1_exttable_size(ext_header))
			return INTEL_UCODE_BAD_EXTENDED_TABLE; /* bad exttable size */

		/* extended table checksum */
		if (!is_zero_checksum((const uint8_t *)ext_header, ext_table_size / sizeof(uint32_t)))
			return INTEL_UCODE_BAD_EXTENDED_TABLE_CHECKSUM; /* invalid checksum */

		ext_sigcount = ext_header->count;

		/* check checksum of each extended signature */
		ext_sig = (const void *)((const uint8_t *)ext_header + INTEL_UC_V1_EXTHDR_SIZE);
		i = ext_sigcount;
		while (i--) {
			uint32_t sum = (ext_sig->sig + ext_sig->pf_mask + ext_sig->cksum) -
			               (uc_header->sig + uc_header->pf_mask + uc_header->cksum);
			if (sum)
				return INTEL_UCODE_BAD_EXTENDED_SIG_CHECKSUM; /* invalid checksum */
			ext_sig++;
		}
	}

	/* misc sanity checks */
	if (unlikely(!uc_header->date))  /* missing date, breaks filtering */
		return INTEL_UCODE_INVALID_DATA;

	if (unlikely(strict && !uc_header->rev)) /* illegal revision */
		return INTEL_UCODE_INVALID_DATA;

	if (unlikely(strict && (
	     !is_valid_bcd(uc_header->date) || (uc_header->date & 0xffffU) < 0x1995U ||
	     !(uc_header->date >> 16 & 0xffU) || (uc_header->date >> 16 & 0xffU) > 0x31U ||
	     !(uc_header->date >> 24 & 0xffU) || (uc_header->date >> 24 & 0xffU) > 0x12U )))
		return INTEL_UCODE_INVALID_DATA;

	return INTEL_UCODE_NOERROR;
}

/**
 * intel_ucode_check_microcode() - perform sanity checks on a microcode entry
 *
 * @uc:		pointer to the beginning of a microcode entry
 * @strict:	if non-zero, perform more strict checking
 * @maxlen:	memory buffer size (limit microcode entry to maxlen bytes)
 *
 * This function checks the well-formedness and sanity of a microcode entry.
 * All other functions in the library expect to receive sane and well-formed
 * microcode headers and full microcode entries, so this function MUST be
 * used beforehand.
 *
 * @uc must be correctly aligned to a 4-byte boundary.
 *
 * In strict mode, secondary checks such as size constraints are applied
 * which will help weed off almost-correct data.  This DID flag some weird
 * microcode for signature 0x106c0, present in one of the microcode files
 * distributed by urbanmyth.org in 2008 (apparently it was microcode for
 * an engineering stepping of an Atom processor).
 *
 * Returns INTEL_UCODE_NOERROR if the microcode entry looks sane, or a
 * different status code indicating a problem with the microcode entry.
 */
intel_ucode_status_t intel_ucode_check_microcode(const void * const uc,
						 const size_t maxlen,
						 const int strict)
{
	if (unlikely(!uc || !IS_PTR_ALIGNED(uc, sizeof(uint32_t))))
		return INTEL_UCODE_BAD_PARAMETERS;

	return xx_intel_ucode_check_uc(uc, maxlen, strict);
}

/**
 * intel_ucode_scan_for_microcode() - scan for valid microcode
 *
 * @bs: 	pointer to a pointer to the memory area to scan for valid
 * 		microcode.  Modified on return to point to the start of the
 * 		area with valid microcode
 * @be: 	Modified on return to point to the first byte past the end
 * 		of the area with valid microcode
 * @blen:	Modified on return to be the size of the microcode area
 * @alen:	size of the memory area to search.  Modified on return
 *		to account for the bytes that have been already searched
 *		(i.e. @bs delta plus @blen).
 *
 * This function searches for the first well-formed microcode entry in the
 * memory area starting at @bs, with a length of @alen.  Then, it validates
 * all microcodes in that memory area that are stored back-to-back (up to
 * INT_MAX microcodes), and updates @bs to point to the start of the first
 * microcode.  It sets @be to point to the byte after the last microcode
 * and @blen to the size of the microcode block, and updates @alen to
 * account for all data already read from the memory area.
 *
 * Returns the number of microcodes found (can be zero), or a
 * negative error number:
 *
 * -EINVAL:     Invalid function parameters
 * -EFAULT:     Internal error (counter/pointer under/overflow)
 *
 * It searches for valid microcode using intel_ucode_check_microcode()
 * in non-strict mode.
 *
 * There are no alignment requirements on @bs or on the start position of
 * the first microcode inside the memory area.  @bs and @be are pointers
 * to a byte-aligned memory area (i.e. char* / uint8_t*).
 *
 * The resulting microcode area, if one is found, MIGHT BE UNALIGNED, IN
 * WHICH CASE IT MUST BE COPIED/MOVED TO A 4-BYTE ALIGNED BUFFER BEFORE USE.
 */
int intel_ucode_scan_for_microcode(const void ** const bs, const void ** const be,
				   size_t * const blen, size_t * const alen)
{
	intel_ucode_status_t r = INTEL_UCODE_INVALID_DATA;
	const uint8_t *p, *q;
	size_t bl, al, cnt_max;
	int uc_cnt;

	if (!bs || !be || !blen || !alen)
		return -EINVAL;

	al = *alen;
	cnt_max = al;
	p = *bs;

	/* NOTE: update only at success exit path */
	*blen = 0;
	*be = p;

	/* find first microcode */
	while (al >= INTEL_UC_MINSIZE) {
		q = memchr(p, 0x01, al); /* search for a v1 header, which starts with 0x01 */
		if (!q) {
			/* not found */
			*be = *(const uint8_t **)bs + *alen;
			*alen = 0;
			return 0;
		}

		/* successful memchr() ensures q >= p, and (q-p) < al */
		al -= (size_t)(q - p);
		if (unlikely(!al || al > cnt_max))
			goto paranoia_out;

		p = q;
		r = xx_intel_ucode_check_uc(p, al, 0);
		if (r == INTEL_UCODE_NOERROR)
			break;

		p++;
		al--;
	}

	if (r != INTEL_UCODE_NOERROR)
		return 0;

	*bs = p;

	/* find size of the continuous area */
	bl = 0;
	uc_cnt = 0;
	cnt_max = al;
	do {
		const struct intel_ucode_v1_hdr * const uch = (const void *)p;
		const unsigned long int total_size = intel_ucode_v1_get_totalsize(uch);
		p += total_size;
		bl += total_size;
		al -= total_size;
		uc_cnt++;

		if (unlikely(al > cnt_max || bl > cnt_max))
			goto paranoia_out;

		r = xx_intel_ucode_check_uc(p, al, 0);
	} while (uc_cnt < INT_MAX && r == INTEL_UCODE_NOERROR);

	*be = p;
	*blen = bl;
	*alen = al;
	return uc_cnt;

paranoia_out:
	/* Hardening against programming errors that could cause counter
	 * under/overflow or buffer overflow */
	*bs = *be;
	return -EFAULT;
}

/**
 * intel_ucode_foreach_signature() - run callback for every signature
 *
 * @uc:			pointer to the microcode entry
 * @action:		callback of type intel_ucode_sig_callback
 * @userdata:		opaque pointer passed to callback
 *
 * Call the @action callback for each signature in the microcode entry,
 * including any optional extended signatures.
 *
 * Do NOT run this function on microcode that was not verified to be
 * correct by intel_ucode_check_microcode().
 *
 * @uc must be correctly aligned to a 4-byte boundary.
 */
intel_ucode_status_t intel_ucode_foreach_signature(const void * const uc,
					intel_ucode_sig_callback * const action,
					void * const userdata)
{
	const struct intel_ucode_v1_hdr * const uc_header = uc;
	const void *uc_data;
	unsigned int total_size, data_size, ext_table_size;

	if (!action || !uc || !IS_PTR_ALIGNED(uc, sizeof(uint32_t)))
		return INTEL_UCODE_BAD_PARAMETERS;

	if (uc_header->hdrver != 1)
		return INTEL_UCODE_UNKNOWN_FORMAT;

	/* Header version 1 format */

	uc_data = (const uint8_t *)uc + INTEL_UC_V1_HEADER_SIZE;

	total_size = intel_ucode_v1_get_totalsize(uc_header);
	data_size = intel_ucode_v1_get_datasize(uc_header);

	/* Process first signature (from header) */
	if (action(userdata, 0,
		   uc_header->sig, uc_header->pf_mask,
		   uc_data, data_size, uc, total_size))
		return INTEL_UCODE_CALLBACK_ERROR;

	ext_table_size = total_size - (INTEL_UC_V1_HEADER_SIZE + data_size);
	if (ext_table_size) {
		const struct intel_ucode_v1_extsig_table *ext_header;
		const struct intel_ucode_v1_extsig *ext_sig;
		uint32_t ext_sigcount;

		uint32_t i;

		ext_header = (const void *)((const uint8_t *)uc + INTEL_UC_V1_HEADER_SIZE + data_size);
		ext_sig = (const void *)((const uint8_t *)ext_header + INTEL_UC_V1_EXTHDR_SIZE);
		ext_sigcount = ext_header->count;
		for (i = 1; i <= ext_sigcount; i++) {
			if (action(userdata, i,
				   ext_sig->sig, ext_sig->pf_mask,
				   uc_data, data_size, uc, total_size))
				return INTEL_UCODE_CALLBACK_ERROR;
			ext_sig++;
		}
	}

	return INTEL_UCODE_NOERROR;
}

/**
 * intel_ucode_foreach_microcode() - run callback for every microcode entry
 *
 * @uc_bundle:		bundle of microcodes
 * @uc_bundle_size:	size of the microcode bundle in bytes
 * @action:		callback of type intel_ucode_mc_callback
 * @userdata:		opaque pointer passed to callback
 *
 * Call the @action callback for each microcode in the microcode entry.
 *
 * Note that it is very likely that the callback will HAVE to call
 * intel_ucode_check_microcode() to check each microcode, and return
 * non-zero should it be faulty, otherwise nasty things can happen.
 *
 * A version 1 microcode bundle is a series of microcode entries, one
 * after the other, without any sort of padding.
 *
 * @uc_bundle must be correctly aligned to a 4-byte boundary.
 */
intel_ucode_status_t intel_ucode_foreach_microcode(
			const void * const uc_bundle,
			const size_t uc_bundle_size,
			intel_ucode_uc_callback * const action,
			void * const userdata)
{
	const uint8_t *uc = uc_bundle;
	size_t leftover = uc_bundle_size;
	unsigned int uc_count;

	if (!action || !uc || !IS_PTR_ALIGNED(uc, sizeof(uint32_t)))
		return INTEL_UCODE_BAD_PARAMETERS;

	/* try to guess bundle version */
	if (uc_bundle_size < INTEL_UC_MINSIZE)
		return INTEL_UCODE_INVALID_DATA;

	if (((const struct intel_ucode_v1_hdr *)uc)->hdrver != 1)
		return INTEL_UCODE_UNKNOWN_FORMAT;

	/* bundle of version 0x1 microcodes */

	uc_count = 0;
	while (leftover) {
		unsigned int uc_size;

		if (leftover < INTEL_UC_V1_HEADER_SIZE)
			return INTEL_UCODE_INVALID_DATA;

		uc_count++;
		if (!uc_count)
			return INTEL_UCODE_COUNTEROVERFLOW;

		uc_size = intel_ucode_v1_get_totalsize((const struct intel_ucode_v1_hdr *)uc);
		if (uc_size % sizeof(uint32_t) || uc_size > leftover)
			return INTEL_UCODE_INVALID_DATA;

		if (action(userdata, uc_count, uc, leftover))
			return INTEL_UCODE_CALLBACK_ERROR;

		uc	 += uc_size;
		leftover -= uc_size;
	}

	return INTEL_UCODE_NOERROR;
}
