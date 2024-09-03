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

#ifndef INTEL_MICROCODE_H
#define INTEL_MICROCODE_H

#include "iucode_tool_config.h"

#include <stdint.h>
#include <sys/types.h>

/* Minimum object size that could have a valid production microcode */
#define INTEL_UC_MINSIZE 1024

typedef enum { /* status result codes */
	INTEL_UCODE_NOERROR = 0,
	INTEL_UCODE_BAD_PARAMETERS,
	INTEL_UCODE_INVALID_DATA,
	INTEL_UCODE_UNKNOWN_FORMAT,
	/* only returned by intel_ucode_check_microcode() */
	INTEL_UCODE_BAD_EXTENDED_TABLE,
	INTEL_UCODE_BAD_EXTENDED_TABLE_CHECKSUM,
	INTEL_UCODE_BAD_EXTENDED_SIG_CHECKSUM,
	INTEL_UCODE_BAD_CHECKSUM,
	/* only returned by the foreach functions */
	INTEL_UCODE_CALLBACK_ERROR,
	INTEL_UCODE_COUNTEROVERFLOW,
} intel_ucode_status_t;

struct intel_ucode_metadata {
	uint16_t	date_year;	/* 4-bit packed BCD format */
	uint8_t		date_day;	/* 4-bit packed BCD format */
	uint8_t		date_month;	/* 4-bit packed BCD format */
	int32_t		revision;
	uint32_t	size;
	uint32_t	extsig_count;
};

intel_ucode_status_t intel_ucode_getmetadata(const void * const uc,
				struct intel_ucode_metadata * const metadata);

uint32_t intel_ucode_getdate_bcd(const void * const uc);

/**
 * intel_ucode_sigmatch() - match signature against processor signature
 *
 * @s1:    CPUID 0x01, EAX
 * @s2:    microcode signature/extended signature "sig" field
 * @p1:    1 << (MSR IA32_PLATFORM_ID[52:50])
 * @p2:    microcode signature/extended signature "pf" mask
 *
 * Returns true if the microcode can be used in a given processor.
 *
 * The kernel driver exports through sysfs the processor flags already
 * in the format expected by this macro.
 */
#define intel_ucode_sigmatch(s1, s2, p1, p2) \
	(((s1) == (s2)) && (((p1) & (p2)) || (((p1) == 0) && ((p2) == 0))))

const char * intel_ucode_errstr(const intel_ucode_status_t status) __attribute__((const));

intel_ucode_status_t intel_ucode_check_microcode(const void * const uc,
						 const size_t maxlen,
						 const int strict);

int intel_ucode_compare(const void * const uc1, const void * const uc2);

int intel_ucode_scan_for_microcode(const void ** const bs,
				   const void ** const be,
				   size_t * const blen,
				   size_t * const alen);

/* Iterators */

/**
 * intel_ucode_sig_callback() - callback function for the
 *                             intel_ucode_foreach_microcode() function
 *
 * @userdata:    pointer as passed to intel_ucode_foreach_microcode()
 * @uc_count:    one-based counter of microcode entries
 * @uc:          pointer to start of microcode entry
 * @uc_max_size: maximum bound for microcode entry size
 *
 * @uc is a pointer to somewhere inside the original bundle passed to
 * intel_ucode_foreach_microcode(), where a microcode entry starts.
 * DO NOT MODIFY the memory area pointed by @uc.
 *
 * Note that it is very likely that the callback will HAVE to call
 * intel_ucode_check_microcode(uc) to check the microcode entry, and
 * return non-zero should it is faulty, otherwise nasty things can
 * happen.
 *
 * If the callback returns a non-zero value, the foreach operation
 * is aborted with a INTEL_UCODE_CALLBACK_ERROR error.
 */
typedef int (intel_ucode_uc_callback)(void * const userdata,
					const unsigned int uc_count,
					const void * const uc,
					const size_t uc_max_size);

intel_ucode_status_t intel_ucode_foreach_microcode(
			const void * const uc_bundle,
			const size_t uc_bundle_size,
			intel_ucode_uc_callback * const action,
			void * const userdata);

/**
 * intel_ucode_sig_callback() - callback function for the
 *                             intel_ucode_foreach_signature() function
 *
 * @userdata:		pointer as passed to intel_ucode_foreach_signature()
 * @sig_count:		zero-based counter of signatures on this microcode
 * @cpuid:		cpuid this microcode applies to
 * @pf_mask:		processor flags mask this microcode applies to
 * @uc_data:		microcode data
 * @uc_data_size:	microcode data size
 * @uc:			microcode entry (headers and data)
 * @uc_size:		microcode entry size
 *
 * DO NOT MODIFY THE MEMORY AREAS REFERENCED BY @uc_data and @uc.
 *
 * The callback can obtain data about the microcode through
 * a call to intel_ucode_getmetadata(uc, metadata).
 *
 * If the callback returns a non-zero value, the foreach operation
 * is aborted with a INTEL_UCODE_CALLBACK_ERROR error.
 */
typedef int (intel_ucode_sig_callback)(void * const userdata,
				const unsigned int sig_count,
				const uint32_t cpuid,
				const uint32_t pf_mask,
				const void * const uc_data,
				const unsigned int uc_data_size,
				const void * const uc,
				const unsigned int uc_size);

intel_ucode_status_t intel_ucode_foreach_signature(const void * const uc,
				intel_ucode_sig_callback * const action,
				void * const userdata);

#endif /* INTEL_MICROCODE_H */
