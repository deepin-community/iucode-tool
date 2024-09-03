/*
 * iucode_tool - Manipulates Intel(R) IA32/x86_64 processor microcode bundles
 *
 * Copyright (c) 2010-2018 Henrique de Moraes Holschuh <hmh@hmh.eng.br>
 *               2000 Simon Trimmer, Tigran Aivazian
 *
 * Some code copied from microcode.ctl v1.17.
 * Some code based on the Linux kernel microcode_intel driver.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include "iucode_tool_config.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <argp.h>
#include <dirent.h>
#include <time.h>
#include <cpuid.h>

#include "intel_microcode.h"

#define PROGNAME "iucode_tool"

/*
 * For micro-optimization on the hotter paths
 */
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

/* cpio archive constants */
#define LINUX_CPIO_UCODE_NAME    "kernel/x86/microcode/GenuineIntel.bin"
#define LINUX_CPIO_UCODE_PADNAME "kernel/x86/microcode/.enuineIntel.align.0123456789abcdef"
#define LINUX_CPIO_FILE_MODE 0100644U
#define LINUX_CPIO_DIR_MODE  0040755U
#define LINUX_CPIO_BLK_SIZE  1024U

/* file load constants */
#define IUCODE_TYPICAL_MCU_FILE_SIZE (0x200000UL) /* 2MiB */
#define IUCODE_MAX_MCU_FILE_SIZE  (0x40000000ULL) /* 1GiB, arbitrary */

#define IUCODE_DAT_FAST_EXMAX  10    /* Fast-path disable threshold */
#define IUCODE_DAT_LBUF_SIZE 2048    /* Maximum line length for .dat */

/* Command-line processing and UI */

enum {
	EXIT_USAGE = 1,		/* Exit due to command line errors */
	EXIT_SWFAILURE = 2,	/* Exit due to software failure (ENOMEM, etc) */
};

static enum { /* actions */
	IUCODE_DO_UPLOADUC = 0x0001,
	IUCODE_DO_WRITEUC  = 0x0002,
	IUCODE_DO_WRITEFW  = 0x0004,
	IUCODE_DO_SELPROC  = 0x0008,
	IUCODE_DO_LOADFILE = 0x0010,
	IUCODE_DO_WRITEFWN = 0x0020,
	IUCODE_DO_WRITEFWE = 0x0040,
	IUCODE_DO_WRITFWNA = 0x0080,

	IUCODE_F_UCSELECT  = 0x1000,

	IUCODE_DOMASK_NEEDSUC = IUCODE_DO_UPLOADUC
				| IUCODE_DO_WRITEUC
				| IUCODE_DO_WRITEFW
				| IUCODE_DO_WRITEFWN
				| IUCODE_DO_WRITEFWE
				| IUCODE_DO_WRITFWNA,
} command_line_actions;

static char *progname;
static int verbosity = 1; /* 0 = errors, 1 = normal... */
static int strict_checks = 1;
static int ignore_bad_ucode = 0;
static int allow_downgrade = 0;
static int list_all_microcodes = 0;
static int list_sel_microcodes = 0;
static int unlink_files = 0;
static char *upload_microcode = NULL;
static char *write_microcode = NULL;
static char *write_early_firmware = NULL;
static char *write_firmware = NULL;
static char *write_named = NULL;
static char *write_named_all = NULL;

typedef enum { /* File type */
	INTEL_UC_FT_UNKNOWN = 0,
	INTEL_UC_FT_DAT,
	INTEL_UC_FT_BIN,
	INTEL_UC_FT_SCAN,
} intel_ucode_file_type_t;
static intel_ucode_file_type_t ucfiletype = INTEL_UC_FT_UNKNOWN;

/* linked list of filenames */
struct filename_list {
	struct filename_list *next;
	intel_ucode_file_type_t type;
	char path[];
};
static struct filename_list *input_files = NULL;
static int processed_stdin = 0;

/* DAT parser */
static int fast_parser_enabled = 1;
static unsigned int fast_parser_exceptions = 0;

/* cpio generation - defaults must match
 * IUCODE_ARGP_DFLSIZE_EIRFS behavior */
static size_t cpio_blocksize = LINUX_CPIO_BLK_SIZE;
static int cpio_parentdirs = 1;

/* Intel Microcode data structures */

struct microcode_bundle {
	struct microcode_bundle *next;
	const char *filename;	/* source file name */
	unsigned int id;        /* bundle id */
	unsigned long int size; /* bytes */
	const void *data;       /* binary file data */
};
static struct microcode_bundle *microcode_bundles = NULL;
static struct microcode_bundle **microcode_bundles_tail = &microcode_bundles;
static unsigned int next_bundle_id = 1;

/* intel_uclist_entry signature flag constants */
#define INTEL_UCLE_EXTSIG 0x0001U /* Sig came from extended sig table */
#define INTEL_UCLE_HASXST 0x0002U /* ucode has an extended sig table */
#define INTEL_UCLE_SELID  0x0010U /* Sig is candidate for loose datefilter */
#define INTEL_UCLE_SELECT 0x0020U /* Sig selected */
#define INTEL_UCLE_NOWR   0x0100U /* Do not write this sig to output
                                   *  + When INTEL_UCLE_HASXST is set,
                                   *    INTEL_UCLE_NOWR is reserved for
                                   *    uclist_annotate_extsig_dup() */
#define INTEL_UCLE_DUPSIG 0x0200U /* Duplicate signature.  The first one
                                   * in load order won't have this flag */

/* signature single-linked list */
struct intel_uclist_entry {
	struct intel_uclist_entry *next;
	uint32_t cpuid;		/* sorting key */
	uint32_t pfm;		/* microcode platform ID (MSR 0x17) mask */
	int32_t  uc_rev;	/* duplicated from header */
	uint32_t flags;		/* INTEL_UCLE_ flags */
	unsigned int id;	/* microcode id within group */
	unsigned int gid;	/* microcode group id */
	const void *uc;
	uint32_t uc_size;
};
static struct intel_uclist_entry *all_microcodes = NULL;
static struct intel_uclist_entry *microcodes = NULL;

/* UI helpers */
#define UCODE_ID_FMT_UU "%03u/%03u"
#define UCODE_ID_MAX_LEN 22
struct microcode_iterator_data {
	const struct microcode_bundle *current_bundle;
	unsigned long int total_signature_count;
	unsigned long int total_unique_sig_count;
	unsigned long int total_entry_count;
	unsigned int current_uc;
};
static struct microcode_iterator_data microcode_iterator_data;

/* Filter masks */
#define IUCODE_FILTERMASK_SCANCPUS 0xffffffffU

enum iuc_rev_match_mode {
	IUCODE_REVFLT_ANY = 0,	/* Ignore revision on match */
	IUCODE_REVFLT_EQ,	/* Revision must be = filter's rev */
	IUCODE_REVFLT_LT,   	/* Revision must be < filter's rev */
	IUCODE_REVFLT_GT,	/* Revision must be > filter's rev */

	IUCODE_REVFLT_SIZE	/* EOL */
};
static const char * const iuc_rev_match_mode_s[IUCODE_REVFLT_SIZE] = {
	[IUCODE_REVFLT_ANY] = NULL,
	[IUCODE_REVFLT_EQ] = "eq:",
	[IUCODE_REVFLT_LT] = "lt:",
	[IUCODE_REVFLT_GT] = "gt:",
}; /* keep this in sync with enum iuc_rev_match_mode !! */

struct microcode_filter_entry {
	struct microcode_filter_entry *next;
	uint32_t cpuid;		/* exact match */
	uint32_t pfm;		/* common bits set match */
	int32_t  rev;
	enum iuc_rev_match_mode rev_match;
	int      invert;
};
static struct microcode_filter_entry *uc_filter_queue = NULL;
static struct microcode_filter_entry *uc_filter_queue_tail = NULL;
static struct microcode_filter_entry *uc_filter_list = NULL;
static int filter_list_allow = 1;

static uint32_t datefilter_max = 0xffffffffU;  /* select dates before this */
static uint32_t datefilter_min = 0;	       /* select dates after this */
static int datefilter_loose = 0;

static inline int filter_list_active(void)
{
	return !!uc_filter_list ||
		!!(command_line_actions & IUCODE_F_UCSELECT);
}

/* extended sig dedup */
struct microcode_id_entry {
	const void * id;	/* exact match */
	struct microcode_id_entry *next;
};
static unsigned int extsig_tables_in_use = 0;

/* Helpers */

#define print_msg_u(format, arg...) \
	do { fflush(stdout); fprintf(stderr, "%s: " format "\n", progname, ## arg); } while (0)

#define print_msg(level, format, arg...) \
	do { \
	    if (verbosity >= level) { \
		fflush(stdout); \
		fprintf(stderr, "%s: " format "\n", progname, ## arg); \
	    } \
	} while (0)

#define print_err(format, arg...) \
	do { fflush(stdout); fprintf(stderr, "%s: " format "\n", progname, ## arg); } while (0)

#define print_warn(format, arg...) \
	do { fflush(stdout); fprintf(stderr, "%s: warning: " format "\n", progname, ## arg); } while (0)

static inline int is_dash(const char * const fn)
{
	return fn && *fn == '-' && !*(fn+1);
}

static int parse_u32(const char *nptr, char **endptr, int base,
		     uint32_t * const res)
{
	unsigned long int ul;

	assert(nptr);
	assert(endptr);
	assert(res);

	errno = 0;
	ul = strtoul(nptr, endptr, base);
	if (errno || nptr == *endptr)
		return errno ? errno : EINVAL;
	if (ul > UINT32_MAX)
		return ERANGE;

	*res = (uint32_t)ul;
	return 0;
}

/* Do the right thing on ILP32... */
#if ULONG_MAX > UINT32_MAX
typedef long int l_int_t;
#define strtol_l strtol
#else
typedef long long int l_int_t;
#define strtol_l strtoll
#endif

static int parse_s32e(const char *nptr, char **endptr, int base,
		      int32_t * const res)
{
	l_int_t l; /* ILP32 requires long long */

	assert(nptr);
	assert(endptr);
	assert(res);

	errno = 0;
	l = strtol_l(nptr, endptr, base); /* strotl or strotll */
	if (errno || nptr == *endptr)
		return errno ? errno : EINVAL;
	if (l > UINT32_MAX || l < INT32_MIN)
		return ERANGE;

	/*
	 * Accept UINT32_MAX >= x > INT32_MAX, as if it were
	 * the binary representation of int32_t read as uint32_t
	 */
	*res = (int32_t)(l & UINT32_MAX);

	return 0;
}

#undef strtol_l

static int is_valid_fd(const int fd)
{
	return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

static void fix_fds(const int fd, const int fl)
{
	int nfd;

	if (is_valid_fd(fd))
		return;

	nfd = open("/dev/null", fl);
	if (nfd == -1 || dup2(nfd, fd) == -1) {
		print_err("could not attach /dev/null to file descriptor %d: %s",
			  fd, strerror(errno));
		/* if (nfd != -1) close(nfd); - disabled as we're going to exit() now */
		exit(EXIT_SWFAILURE);
	}
	if (nfd != fd)
		close(nfd);
}

/*
 * glibc does not ensure sanity of the standard streams at program start
 * for non suid/sgid applications.  The streams are initialized as open
 * and not in an error state even when their underlying FDs are invalid
 * (closed).  These FDs will later become valid due to an unrelated
 * open(), which will cause undesired behavior (such as data corruption)
 * should the stream be used.
 *
 * freopen() cannot be used to fix this directly, due to a glibc 2.14+ bug
 * when freopen() is called on an open stream that has an invalid FD which
 * also happens to be the first available FD.
 */
static void sanitize_std_fds(void)
{
	/* do it in file descriptor numerical order! */
	fix_fds(STDIN_FILENO,  O_RDONLY);
	fix_fds(STDOUT_FILENO, O_WRONLY);
	fix_fds(STDERR_FILENO, O_RDWR);
}

/* Signature linked list */

/**
 * free_uclist() - frees chain of struct intel_uclist_entry
 * @p:		pointer to the first struct intel_uclist_entry
 *
 * If p != NULL, frees all members of the struct intel_uclist_entry
 * linked list.
 */
static void free_uclist(struct intel_uclist_entry *p)
{
	struct intel_uclist_entry *e;

	while (p) {
		e = p;
		p = e->next;
		free(e);
	}
}

/**
 * uclist_add_signature() - add signature to ucode sig list
 *
 * @id:		microcode id
 * @gid:	microcode group id
 * @flags:	INTEL_UCLE_* flags
 * @cpuid:	signature of the signature entry being added
 * @pf_mask:	pf_mask of the signature entry being added
 * @uc_rev:	revision of the microcode entry being added
 * @uc:		microcode data (including headers)
 * @uc_size:	microcode data size (total, including headers)
 * @strict:	validate microcode opaque data against duplicates
 * @uclist:	pointer to the first entry on the list
 *
 * Adds a microcode signature entry to the list.  Does not filter
 * out duplicates, nor superseed entries.
 *
 * If @strict is true, it will compare the opaque data with one
 * of the previously inserted duplicates (and return EBADF if it
 * doesn't match).
 *
 * returns: ENOMEM: could not allocate memory,
 *          EINVAL: bad @cpuid, @uc pointer or @uclist pointer
 *          EEXIST: entry already in list (will be inserted)
 *          EBADF : entry already in list, with different opaque data
 *          0:      entry not yet in list (will be inserted)
 */
static int uclist_add_signature(const unsigned int id,
			const unsigned int gid,
			uint32_t flags,
			const uint32_t cpuid,
			const uint32_t pf_mask,
			const int32_t uc_rev,
			const void * const uc,
			const uint32_t uc_size,
			const int strict,
			struct intel_uclist_entry ** const uclist)
{
	struct intel_uclist_entry **pnext, *n, *d;
	int res = 0;

	if (unlikely(!cpuid || !uc || !uclist))
		return EINVAL;

	pnext = uclist;
	d = NULL;

	flags &= ~INTEL_UCLE_DUPSIG;

	/* search linked list for first insertion point */
	while (likely(*pnext && (*pnext)->cpuid < cpuid))
		pnext = &((*pnext)->next);

	/* look for duplicates, stop on the first */
	while (likely(*pnext) && (*pnext)->cpuid == cpuid) {
		if ((*pnext)->uc_rev == uc_rev) {
			if ((*pnext)->pfm == pf_mask) {
				res = EEXIST;
				flags |= INTEL_UCLE_DUPSIG;
				d = *pnext;
				break;
			} else if (((*pnext)->pfm & pf_mask)) {
				/* not a DUPSIG, but we need to
				 * compare the payloads */
				d = *pnext;
			}
		}
		pnext = &((*pnext)->next);
	}

	if (strict && d) {
		int rd = intel_ucode_compare(uc, d->uc);
		if (rd == -EINVAL || rd == -EBADF)
			return -rd;
	}

	n = malloc(sizeof(struct intel_uclist_entry));
	if (unlikely(!n))
		return ENOMEM;

	memset(n, 0, sizeof(struct intel_uclist_entry));
	n->id = id;
	n->gid = gid;
	n->cpuid = cpuid;
	n->pfm = pf_mask;
	n->uc_rev = uc_rev;
	n->uc = uc;
	n->uc_size = uc_size;
	n->flags = flags;

	/* prepend */
	n->next = *pnext;
	*pnext = n;

	return res;
}

/**
 * uclist_merge_signature() - merge signature into ucode sig list
 * @id:		microcode id
 * @gid:	microcode group id
 * @flags:	INTEL_UCLE_* flags
 * @cpuid:	signature of the signature entry being added
 * @pf_mask:	pf_mask of the signature entry being added
 * @uc_rev:	revision of the microcode entry being added
 * @uc:		microcode data (including headers)
 * @uc_size:	microcode data size (total, including headers)
 * @downgrade:	version downgrades between groups allowed if NZ
 * @uclist:	pointer to the first entry on the list
 *
 * Adds a microcode signature entry to the list.  When @downgrade
 * is zero, it will replace any suitable entry that has a lesser
 * revision.  When @downgrade is non-zero, it will replace any
 * suitable entry in the same microcode group that has a lesser
 * revision, or any suitable entry from a smaller (earlier)
 * microcode group regardless of revision.
 *
 * "suitable" means microcodes with the same cpuid and with a
 * pf_mask that is either equal or a strict subset of the one from
 * the new microcode.
 *
 * Note that it IS still possible that two signatures in the list
 * could apply to the same processor, if they have different revisions
 * and different pf masks, and the CPU is present in both pf masks.
 *
 * Note that downgrade mode is severely limited by the fact that we
 * do not change @pf_mask, and thus will often result in several
 * microcodes for the same processor being left in @uclist.
 *
 * returns: ENOMEM: could not allocate memory,
 *          EEXIST: entry already in list (but may have been
 *                  inserted if @downgrade is non-zero), or
 *                  contained by an entry already in the list
 *          EINVAL: bad @cpuid, @uc pointer or @uclist pointer
 */
static int uclist_merge_signature(const unsigned int id,
			const unsigned int gid,
			uint32_t flags,
			const uint32_t cpuid,
			const uint32_t pf_mask,
			const int32_t uc_rev,
			const void * const uc,
			const uint32_t uc_size,
			const int downgrade,
			struct intel_uclist_entry ** const uclist)
{
	struct intel_uclist_entry **pnext, **p_ins;
	enum { UCLM_INSERT, UCLM_DISCARD, UCLM_REPLACE } action = UCLM_INSERT;
	int res = 0;

	if (unlikely(!cpuid || !uc || !uclist))
		return EINVAL;

	flags &= ~INTEL_UCLE_DUPSIG;

	pnext = uclist;

	/*
	 * notes: pf_mask *can* be zero on old processors;
	 *        pf_masks rarely change: replace-in-place is typical;
	 */

	/* search linked list for matching CPUID */
	while (*pnext && (*pnext)->cpuid < cpuid)
		pnext = &((*pnext)->next);

	p_ins = NULL;

	/* first stage: look for replace/discard */
	while (*pnext && (*pnext)->cpuid == cpuid) {
		struct intel_uclist_entry * const e = *pnext;

		/* potential insertion point: sort by pf_mask, descending */
		if (!p_ins && pf_mask >= e->pfm)
			p_ins = pnext;

		if (pf_mask && (e->pfm & pf_mask) == 0) {
			/* disjoint sets, continue search */
			pnext = &(e->next);
			continue;
		}

		if (!downgrade || gid == e->gid) { /* do not downgrade */
			if ((e->pfm & pf_mask) == pf_mask) {
				/* new set same or contained in the old set */
				if (e->uc_rev >= uc_rev) {
					/* old set as good, or newer: discard new */
					action = UCLM_DISCARD;
					break;
				} else if (pf_mask == e->pfm) {
					/* the sets are identical, and the new
					 * one is newer microcode: replace old */
					action = UCLM_REPLACE;
					break;
				}
			} else if ((pf_mask & e->pfm) == e->pfm) {
				/* new set a superset of the old */
				if (uc_rev >= e->uc_rev) {
					/* we can replace the old entry */
					action = UCLM_REPLACE;
					break;
				}
			}
		} else if (gid > e->gid) { /* downgrade */
			/* FIXME?: we cannot handle downgrades where we'd have
			 * to remove bits from the pfmask of an entry to make
			 * it "stick".  We don't even attempt to handle
			 * these cases: we just insert.  This can be detected
			 * by a later pass over the entire @uclist for fixup or
			 * warnings. */
			if ((pf_mask & e->pfm) == e->pfm) {
				/* new set same, or superset of old: replace */
				res = (e->uc_rev == uc_rev && e->pfm == pf_mask) ? EEXIST : 0;
				action = UCLM_REPLACE;
				break;
			} else if ((e->pfm & pf_mask) == pf_mask && e->uc_rev == uc_rev) {
				/* new set contained in the old set, and same rev */
				action = UCLM_DISCARD;
				break;
			}
		} else { /* downgrade mode but older group and not disjoint */
			if ((e->pfm & pf_mask) == pf_mask) {
				/* new set same or contained in the old set */
				action = UCLM_DISCARD;
				break;
			}
		}

		pnext = &(e->next);
	}

	/* deleted entry cache to avoid malloc() on discard+insert */
	struct intel_uclist_entry *n = NULL;

	/*
	 * Note: we must skip the current entry if it is to be kept
	 * otherwise it is likely to get removed by the second stage
	 */
	switch (action) {
	case UCLM_REPLACE:
		if (p_ins == pnext) {
			/* replacing will preserve sorting order */
			struct intel_uclist_entry * const e = *pnext;

			e->id = id;
			e->gid = gid;
			e->flags = flags;
			/*e->cpuid = cpuid;*/
			e->pfm = pf_mask;
			e->uc_rev = uc_rev;
			e->uc = uc;
			e->uc_size = uc_size;

			pnext = &(e->next); /* skip good entry */
		} else {
			/* do it the hard way to keep things sorted */
			action = UCLM_INSERT;
			n = *pnext; /* delete and cache */
			*pnext = n->next;
		}
		break;

	case UCLM_DISCARD:
		/* Note: one downgrade mode border condition requires
		 * the second stage, we can't just exit here */
		if (!downgrade)
			return EEXIST;

		res = EEXIST;
		pnext = &((*pnext)->next); /* skip good entry */
		break;

	case UCLM_INSERT:
		break;
	}

	/* second stage: discard superseded, and insert */
	while (*pnext && (*pnext)->cpuid == cpuid) {
		struct intel_uclist_entry * const e = *pnext;

		if (((pf_mask & e->pfm) == e->pfm) &&
		    ((!downgrade && uc_rev >= e->uc_rev) ||
		     (downgrade && gid > e->gid))) {
			/* old entry is a subset of the new */

			/* remove entry from the list */
			*pnext = e->next;
			if (n == NULL) {
				n = e; /* cache to avoid malloc() */
			} else {
				free(e);
			}
		} else {
			/* locate potential insertion point... */
			if (!p_ins && pf_mask >= e->pfm)
				p_ins = pnext;

			pnext = &(e->next);
		}
	}

	if (action == UCLM_INSERT) {
		if (!n) {
			n = malloc(sizeof(struct intel_uclist_entry));
			if (unlikely(!n))
				return ENOMEM;
		}

		memset(n, 0, sizeof(struct intel_uclist_entry));
		n->id = id;
		n->gid = gid;
		n->flags = flags;
		n->cpuid = cpuid;
		n->pfm = pf_mask;
		n->uc_rev = uc_rev;
		n->uc = uc;
		n->uc_size = uc_size;

		/* prepend at insertion point */
		if (!p_ins)
			p_ins = pnext;
		n->next = *p_ins;
		*p_ins = n;

		n = NULL;
	}

	free(n);

	return res;
}

/* Microcode bundle handling */

/**
 * add_intel_microcode_bundle() - add a microcode bundle to set
 * @mcb_filename:	filename (metadata)
 * @mcb_id:		bundle id (metadata)
 * @mcb:		pointer to the microcode bundle data
 * @mcb_size:		size of the microcode bundle data
 *
 * Note: the memory pointed to by @mcb will be freed when
 * the bundles are freed by free_intel_microcode_bundles().
 *
 * Returns 0 if the bundled was added, or ENOMEM
 */
static int add_intel_microcode_bundle(const char * const mcb_filename,
				      unsigned int mcb_id,
				      const void * const mcb,
				      const size_t mcb_size)
{
	assert(mcb && mcb_size >= INTEL_UC_MINSIZE);
	assert(mcb_filename);
	assert(microcode_bundles_tail && !(*microcode_bundles_tail));

	struct microcode_bundle *b = malloc(sizeof(struct microcode_bundle));
	if (!b)
		return ENOMEM;

	memset(b, 0, sizeof(struct microcode_bundle));
	b->id = mcb_id;
	b->filename = strdup(mcb_filename);
	b->size = mcb_size;
	b->data = mcb;

	/* add to end of list */
	*microcode_bundles_tail = b;
	microcode_bundles_tail = &(b->next);

	return 0;
}

static void free_intel_microcode_bundles(void) __attribute__((unused));
static void free_intel_microcode_bundles(void)
{
	struct microcode_bundle *p, *t;

	p = microcode_bundles;
	while (p) {
		t = p;
		p = t->next;
		free((void *)(t->filename));
		free((void *)(t->data));
		free(t);
	}

	microcode_bundles = NULL;
	microcode_bundles_tail = &microcode_bundles;
}

static inline uint32_t xx_asc2digit(const char c)
{
	/* c must be [0-9a-fA-F] */
	return 9*((uint32_t)c >> 6) + ((uint32_t)c & 0xf);
}

static void xx_parser_exception(void)
{
	fast_parser_exceptions++;
	if (fast_parser_exceptions > IUCODE_DAT_FAST_EXMAX)
		fast_parser_enabled = 0;
}

/* For whatever idiotic reason, a static inline doesn't work as well */
#define IS_INVALID_HEX(x) ((x) < '0' || (x) > 'f' || ((x) > '9' && (x) < 'A') || ((x) > 'F' && (x) < 'a'))

/* caller must ensure sanity of all parameters */
static inline int parse_u32_fast(char *s, char **e, uint32_t * const res)
{
	const char * ss = s;

	/* fast path: 0x1234aBcD */
	if (likely((s[0] == '0' && s[1] == 'x') && fast_parser_enabled)) {
		uint32_t r = 0;
		int i;
		s += 2;
		for (i = 0; i < 8; i++) {
			const char c = *s;

			if (unlikely(IS_INVALID_HEX(c))) {
				xx_parser_exception();
				return parse_u32(ss, e, 0, res);
			}

			r = (r << 4) + xx_asc2digit(c);
			s++;
		}

		/* if the next char is not a digit, the fast path was successful */
		if (likely(IS_INVALID_HEX(*s))) {
			*res = r;
			*e = s;
			return 0;
		}

		xx_parser_exception();
	}

	return parse_u32(ss, e, 0, res);
}

#undef IS_INVALID_HEX

#ifndef HAVE_FGETS_UNLOCKED
#define fgets_unlocked fgets
#endif

#ifdef static_assert
	static_assert(IUCODE_MAX_MCU_FILE_SIZE <= SIZE_MAX,
		"IUCODE_MAX_MCU_FILE_SIZE must fit in size_t");
#endif

static int load_intel_microcode_dat(FILE *fp,
				    void ** const mcb, size_t * const mcb_length,
				    unsigned long int * const lineno)
{
	const size_t buffer_size_granularity = IUCODE_TYPICAL_MCU_FILE_SIZE / sizeof(uint32_t);
	const size_t buffer_limit = IUCODE_MAX_MCU_FILE_SIZE / sizeof(uint32_t);
	char *line_buffer = NULL;
	size_t mcb_buflen;
	uint32_t *mcb_buffer = NULL;
	uint32_t *rp;
	size_t length;
	size_t pos = 0;
	unsigned long int lines = 0;
	int nulateol;
	int err;

	assert(mcb);
	assert(mcb_length);

	if (ferror(fp))
		return -EIO;

	/* reset parser fast-path */
	fast_parser_enabled = 1;
	fast_parser_exceptions = 0;

	line_buffer = malloc(IUCODE_DAT_LBUF_SIZE);
	mcb_buflen = buffer_size_granularity;
	mcb_buffer = malloc(mcb_buflen * sizeof(uint32_t));
	if (!mcb_buffer || !line_buffer) {
		err = ENOMEM;
		goto err_out_nolock;
	}

#ifdef HAVE_FLOCKFILE
	flockfile(fp);
#endif

	err = EINVAL;
	nulateol = 0;
	while (likely(fgets_unlocked(line_buffer, IUCODE_DAT_LBUF_SIZE, fp) != NULL)) {
		/*
		 * Data lines are of the form "0x%x, 0x%x, 0x%x, 0x%x,"
		 * Comment lines start with a single "/"
		 *
		 * As long as the initial comment block is stripped, the file
		 * would be valid C source to initialize an array of 32-bit
		 * integers.
		 *
		 * This parser will accept empty lines, and ignore initial
		 * white space.  NULs cannot be considered white space due to
		 * fgets() not being NUL-safe, so they're invalid.
		 *
		 * It will accept a comment after valid data, as long as
		 * there's white space or a comma before the comment start.
		 *
		 * It does not properly handle multi-line C comments
		 * unless they start with / in every line.
		 *
		 * It will accept a file that does not end with an EOL mark.
		 *
		 * This parser is tuned to the exact format Intel has been
		 * using for .dat files since 2008 (which are the ones that
		 * can be distributed by Linux distros).
		 */
		char *lp = line_buffer;

		/* last line "ended" by a NUL, but it was not EOF */
		if (unlikely(nulateol))
			goto err_out;

		lines++;

		if (unlikely(!*lp)) /* "line" of one or more NULs */
			goto err_out;

		while (isspace(*lp))
			lp++;

		while (likely(*lp && *lp != '/')) {
			char *ep;

			if (unlikely(parse_u32_fast(lp, &ep, &(mcb_buffer[pos]))))
				goto err_out;

			pos++;
			if (unlikely(mcb_buflen <= pos)) {
				/* expand buffer */
				if (unlikely(buffer_limit - mcb_buflen < buffer_size_granularity)) {
					err = EFBIG;
					goto err_out;
				}
				mcb_buflen += buffer_size_granularity;
				rp = realloc(mcb_buffer,
					     mcb_buflen * sizeof(uint32_t));
				if (unlikely(!rp)) {
					err = ENOMEM;
					goto err_out;
				}
				mcb_buffer = rp;
			}

			/* seek to start of next value or to EOL */
			lp = ep;
			while (isspace(*lp))
				lp++;
			if (likely(*lp == ',')) {
				/* skip ",[[:space:]]*" */
				do { lp++; } while (isspace(*lp));
				/* we're either at EOL or next value, now */
			} else if (unlikely(*lp && (lp == ep || *lp != '/'))) {
				goto err_out;
			}
		}

		/* if the line ends without EOL, next must be EOF */
		nulateol = (!*lp && *(lp-1) != '\n');
	}
	if (ferror(fp)) {
		err = -errno; /* negative! */
		goto err_out;
	}
	if (!pos && feof(fp)) {
		/* empty data file */
		err = ENOENT;
		goto err_out;
	}

	length = pos * sizeof(uint32_t);
	if (length < INTEL_UC_MINSIZE) {
		err = EINVAL;
		goto err_out;
	}

	/* truncate buffer if too large */
	rp = realloc(mcb_buffer, length);
	if (!rp) {
		err = ENOMEM;
		goto err_out;
	}

	*mcb = rp;
	*mcb_length = length;

	err = 0;

err_out:
#ifdef HAVE_FLOCKFILE
	funlockfile(fp);
#endif

err_out_nolock:
	if (err) {
		free(mcb_buffer);
		*mcb = NULL;
		*mcb_length = 0;
	}

	if (lineno)
		*lineno = lines;

	free(line_buffer);
	return err;
}

static int scan_and_pack_microcodes(uint8_t * const mcb, size_t * const mcb_size)
{
	uint8_t *mcb_e, *bs, *be;
	size_t  mcb_len, b_len;
	unsigned long int bc, ucc;
	int r;

	mcb_len = *mcb_size;
	mcb_e = mcb;
	bs = mcb;
	ucc = 0;
	bc = 0;

	do {
		r = intel_ucode_scan_for_microcode((const void **)&bs,
						   (const void **)&be,
						   &b_len, &mcb_len);
		if (r > 0) {
			/* (in)sanity checks */
			if (unlikely(bs < mcb_e || be < bs || b_len > *mcb_size || mcb_len > *mcb_size)) {
				print_err("Internal error: got insane results from intel_ucode_scan_for_microcode()");
				exit(EXIT_SWFAILURE); /* alternative: return EFAULT */
			}

			print_msg(3, "microcode scan: microcode block at position %td with %d microcode(s), size %zu bytes",
				  bs - mcb, r, b_len);

			if (mcb_e != bs)
				memmove(mcb_e, bs, b_len);
			mcb_e += b_len;
			bs = be;
			bc++;
			ucc += (unsigned int)r;  /* r > 0 enforced in this branch */
		} else if (unlikely(r < 0)) {
			print_err("Internal error: intel_ucode_scan_for_microcode() went out-of-bounds");
			exit(EXIT_SWFAILURE); /* alternatively: return EFAULT */
		}
	} while (r > 0);

	mcb_len = (size_t)(mcb_e - mcb); /* mcb <= mcb_e, delta constrained by mcb_size */
	*mcb_size = mcb_len;

	print_msg(3, "microcode scan: found %lu microcode block(s) with %lu microcode(s), total size: %zu bytes",
		  bc, ucc, mcb_len);

	return (mcb_len) ? 0 : ENOENT;
}

static int load_intel_microcode_bin(int fd,
				    void ** const mcb, size_t * const mcb_length,
				    const int scan)
{
	const size_t buffer_size_granularity = IUCODE_TYPICAL_MCU_FILE_SIZE;
	const size_t buffer_limit = IUCODE_MAX_MCU_FILE_SIZE;

	int file_size_known;
	struct stat stat;

	size_t mcb_size;
	size_t mcb_space_left;
	uint8_t *mcb_buffer = NULL;
	uint8_t *rp;

	size_t pos;
	int err;

	assert(mcb);
	assert(mcb_length);

	/* Try to get file size beforehand */
	if (fstat(fd, &stat))
		return -errno; /* negative! */
	if (S_ISREG(stat.st_mode)) {
		if (stat.st_size < 0 || (uintmax_t)stat.st_size > buffer_limit)
			return EFBIG;
		mcb_size = (size_t)stat.st_size;
		file_size_known = 1;
	} else {
		mcb_size = buffer_size_granularity;
		file_size_known = 0;
	}

	/* sanity check size */
	if (mcb_size < INTEL_UC_MINSIZE) {
		err = (mcb_size && !scan) ? EINVAL : ENOENT;
		goto err_out;
	}

	mcb_buffer = malloc(mcb_size);
	if (!mcb_buffer) {
		err = ENOMEM;
		goto err_out;
	}

	err = 0;
	pos = 0;
	mcb_space_left = mcb_size;
	do {
		ssize_t rc;

		rc = read(fd, mcb_buffer + pos,
			  (mcb_space_left < SSIZE_MAX) ? mcb_space_left : SSIZE_MAX);
		if (rc == -1) {
			if (errno == EINTR)
				continue;
			err = -errno; /* negative! */
			goto err_out;
		}

		/* POSIX ensures 0 <= rc <= SSIZE_MAX here */
		pos += (size_t)rc;
		mcb_space_left -= (size_t)rc;

		if (rc == 0)
			break; /* EOF */
		if (file_size_known && !mcb_space_left)
			break; /* Read entire file */

		if (!mcb_space_left) {
			if (unlikely(buffer_limit - mcb_size < buffer_size_granularity)) {
				err = EFBIG;
				goto err_out;
			}
			mcb_size += buffer_size_granularity;
			mcb_space_left += buffer_size_granularity;
			rp = realloc(mcb_buffer, mcb_size);
			if (!rp) {
				err = ENOMEM;
				goto err_out;
			}
			mcb_buffer = rp;
		}
	} while (1);

	mcb_size = pos;
	if (mcb_size < INTEL_UC_MINSIZE) {
		err = (mcb_size && !scan) ? EINVAL : ENOENT;
		goto err_out;
	}

	if (scan) {
		err = scan_and_pack_microcodes(mcb_buffer, &mcb_size);
		if (err)
			goto err_out;
	}

	rp = realloc(mcb_buffer, mcb_size);
	if (!rp && mcb_size) {
		err = ENOMEM;
		goto err_out;
	}

	/* rp is allowed to be NULL when mcb_size == 0 */

	*mcb = rp;
	*mcb_length = mcb_size;

	return 0;

err_out:
	free(mcb_buffer);
	*mcb = NULL;
	*mcb_length = 0;

	return err;
}

static int load_intel_microcode_file(int fd, FILE *fp,
				     const char * const fn,
				     const intel_ucode_file_type_t ftype)
{
	int err = 0;

	void *mcb = NULL;
	size_t mcb_length = 0;

	unsigned long int tl = 0;

	switch (ftype) {
	case INTEL_UC_FT_SCAN:
	case INTEL_UC_FT_BIN:
		{
			const int scanmode = !!(ftype == INTEL_UC_FT_SCAN);

			print_msg(3, "%s: loading (%sbinary mode)", fn,
				     (scanmode) ? "microcode recovery " : "");
			err = load_intel_microcode_bin(fd, &mcb, &mcb_length, scanmode);
		}
		break;

	case INTEL_UC_FT_DAT:
		if (!fp)
			fp = fdopen(fd, "r");

		if (fp) {
			print_msg(3, "%s: loading (.dat mode)", fn);
			err = load_intel_microcode_dat(fp, &mcb, &mcb_length, &tl);
			if (!fast_parser_enabled)
				print_msg(3, "%s: had to switch over to slow parser mode", fn);
		} else {
			err = -errno;
		}
		break;

	default:
		err = ENOTSUP;
	}

	if (err < 0) { /* error from read() or stdio */
		print_err("%s: could not read: %s", fn, strerror(-err));
		goto err_out;
	}

	/*
	 * If a loader returns a zero-length microcode bundle (mcb_length
	 * was set to 0 by the loader, or mcb is NULL), or an error, the
	 * bundle will NOT be stored for further processing.
	 *
	 * If err == 0, the bundle will be assigned an ID, and listed to
	 * the user when in verbose mode.
	 *
	 * If err == ENOENT, the user is notified that no microcodes were
	 * found in that data file and that the file is being skipped.
	 * It will not be reported as an error to the caller.
	 *
	 * Otherwise, the user will be notified of an error, and the error
	 * will be reported to the caller, which may abort execution of
	 * iucode_tool.
	 */

	if (!err && mcb && mcb_length) {
		err = add_intel_microcode_bundle(fn, next_bundle_id,
						 mcb, mcb_length);
		if (!err)
			mcb = NULL; /* someone else will free it */
	}

	switch (err) {
	case 0:
		print_msg(3, "loaded microcode bundle %u: %s (%zu bytes)",
			  next_bundle_id, fn, mcb_length);
		next_bundle_id++;
		break;
	case ENOENT:
		print_err("%s: no microcodes found in data file, skipping...", fn);
		err = 0;
		break;
	case ENOMEM:
		print_err("%s: could not allocate memory while loading", fn);
		break;
	case EINVAL:
		if (!tl) {
			print_err("%s: invalid file format", fn);
		} else {
			print_err("%s: line %lu: invalid file format", fn, tl);
		}
		break;
	case EFBIG:
		print_err("%s: cowardly refusing to load an insanely large data file", fn);
		break;
	}

err_out:
	if (fp)
		fclose(fp); /* also closes fd */
	else if (fd != -1)
		close(fd);

	free(mcb);

	return err;
}

static int load_intel_microcode(const char * path,
				const intel_ucode_file_type_t baseftype)
{
	int fd = -1;

	DIR *dir;
	int err;

	char fnbuf[PATH_MAX];
	const char *fn;
	intel_ucode_file_type_t ftype;

	assert(path);

	/* Should we read from stdin ? */
	if (is_dash(path)) {
		/* read stdin only once, ignore further requests */
		if (processed_stdin)
			return 0;

		processed_stdin = 1;
		ftype = baseftype;

		/* default to .dat mode for stdin */
		if (ftype == INTEL_UC_FT_UNKNOWN)
			ftype = INTEL_UC_FT_DAT;

		/* paranoia */
		fd = fileno(stdin);
		if (unlikely(fd == -1)) {
			/* shouldn't happen unless iucode_tool starts doing
			 * freopen(stdin).  Refer to sanitize_std_fds(). */
			err = errno;
			print_err("stdin: internal error: %s", strerror(err));
			return -err;
		}

		return load_intel_microcode_file(fd, stdin,
						"(stdin)", ftype);
	}

	dir = NULL;
	fn = path;

	do {
		struct stat st;
		struct dirent *dentry;

		err = 0;

		if (fd != -1) {
			close(fd);
			fd = -1;
		}

		if (dir) {
			errno = 0;
			dentry = readdir(dir);
			if (!dentry) {
				err = errno;
				if (unlikely(err)) {
					print_err("%s: cannot walk directory: %s",
						  path, strerror(err));
					err = -err;
				}
				break; /* finish/abort walk */
			}

			if (dentry->d_name[0] == '.')
				continue;

			int s = snprintf(fnbuf, sizeof(fnbuf), "%s/%s",
					 path, dentry->d_name);
			if (unlikely(s < 1 || (unsigned int)s >= sizeof(fnbuf))) {
				print_err("%s/%s: path too long",
					  path, dentry->d_name);
				err = -ENAMETOOLONG;
				continue;
			}
			fn = fnbuf;
			fd = openat(dirfd(dir), dentry->d_name, O_RDONLY);
		} else {
			fd = open(fn, O_RDONLY);
		}
		if (unlikely(fd == -1)) {
			err = errno;
			print_err("%s: cannot open: %s", fn, strerror(err));
			err = -err;
			continue;
		}
		if (unlikely(fstat(fd, &st) == -1)) {
			err = errno;
			print_err("%s: cannot stat inode: %s", fn,
				  strerror(err));
			err = -err;
			continue;
		}
		if (S_ISDIR(st.st_mode)) {
			if (!dir) {
				dir = fdopendir(fd);
				if (!dir) {
					err = errno;
					print_err("%s: cannot open directory: %s",
						  path, strerror(err));
					err = -err;
					continue;
				}
				print_msg(3, "%s: reading directory", fn);
				/*
				 * fd is now out-of-scope due to successful
				 * fdopendir(fd), and must NOT be closed.
				 */
				fd = -1;
			} else {
				print_msg(1, "%s: skipping nested directory: %s",
					  path, fn);
			}
			continue;
		}

		if (S_ISREG(st.st_mode) && st.st_size == 0) {
			print_msg(3, "skipping empty file: %s", fn);
			continue;
		}

		ftype = baseftype;
		if (ftype == INTEL_UC_FT_UNKNOWN && S_ISREG(st.st_mode)) {
			char *p;

			/* try to guess based on extension */
			p = strrchr(fn, '.');
			if (p) {
				if (!strcasecmp(p + 1, "dat"))
					ftype = INTEL_UC_FT_DAT;
				/*
				 * Unneeded due to default to bin mode
				 *
				else if (!strcasecmp(p + 1, "bin"))
					ftype = INTEL_UC_FT_BIN;
				else if (!strcasecmp(p + 1, "fw"))
					ftype = INTEL_UC_FT_BIN;
				*/
			}
		}

		/* default to bin mode */
		if (ftype == INTEL_UC_FT_UNKNOWN)
			ftype = INTEL_UC_FT_BIN;

		err = load_intel_microcode_file(fd, NULL, fn, ftype);
		fd = -1; /* fd closed by load_intel_microcode_file() */
	} while (dir && (!err || ignore_bad_ucode));

	if (dir)
		closedir(dir);
	if (fd != -1)
		close(fd);
	return err;
}

/* Microcode write (binary format) and kernel upload */

/*
 * The compiler would optimize this for us properly, but
 * it will warn about it, and so will the static checker.
 */
static inline size_t ssizemax_clamp(const uint32_t s)
{
#if UINT32_MAX > SSIZE_MAX
	return (s < SSIZE_MAX) ? (size_t)s : SSIZE_MAX;
#else
	return s;
#endif
}

/* write_data returns -1 on error, with errno set */
static int write_data(int fd,
		      const void * const data,
		      const uint32_t size)
{
	const char *p = data;
	uint32_t len = size;
	ssize_t s;

	while (len > 0) {
		s = write(fd, p, ssizemax_clamp(len));
		if (s >= 0) {
			/* POSIX ensures 0 <= s <= min(SSIZE_MAX,len) */
			p += (size_t)s;
			len -= (size_t)s;
		} else if (errno != EINTR) {
			return -1;
		}
	}

	return 0;
}

static void log_microcode_action(const char * const action,
				const char * const devname,
				const struct intel_uclist_entry * const uce)
{
	print_msg_u("%s: %s microcode " UCODE_ID_FMT_UU
		    " (sig 0x%08x, pf_mask 0x%02x, rev 0x%04x)",
		    devname, action, uce->gid, uce->id,
		    uce->cpuid, uce->pfm, (uint32_t) uce->uc_rev);
}

/**
 * upload_intel_microcodes() - uploads microcodes to kernel device
 * @devname:		device path
 * @uc_write_list:	uclist with the microcodes to write
 *
 * returns 0 if successful, or errno if a problem happens
 */
static int upload_intel_microcodes(const char * const devname,
				  struct intel_uclist_entry *uc_write_list)
{
	int fd;
	struct stat stat;
	int err = 0;
	unsigned long long int total_written = 0;
	unsigned int entries_written = 0;

	assert(uc_write_list);
	assert(devname);

	fd = open(devname, O_WRONLY);
	if (fd == -1) {
		err = errno;
		print_err("%s: cannot open for writing: %s",
			  devname, strerror(err));
		return err;
	}
	/* Is it a char device? */
	if (fstat(fd, &stat) == -1) {
		err = errno;
		print_err("%s: cannot stat: %s", devname, strerror(err));
		close(fd);
		return err;
	}
	if (!S_ISCHR(stat.st_mode)) {
		print_err("%s: not a character device", devname);
		close(fd);
		return EINVAL;
	}

	while (uc_write_list && uc_write_list->uc) {
		if (likely(!(uc_write_list->flags & INTEL_UCLE_NOWR))) {
			if (verbosity >= 3)
				log_microcode_action("uploading",
						     devname, uc_write_list);

			if (write_data(fd, uc_write_list->uc,
				       uc_write_list->uc_size)) {
				err = errno;
				print_err("%s: write error: %s",
					  devname, strerror(err));
				break;
			}
			total_written += uc_write_list->uc_size;
			entries_written++;
		} else {
			if (verbosity >= 3)
				log_microcode_action("skipping",
						     devname, uc_write_list);
		}
		uc_write_list = uc_write_list->next;
	}

	if (close(fd)) {
		err = errno;
		print_err("%s: error while closing device: %s",
			  devname, strerror(err));
	}

	if (!err)
		print_msg(2, "%s: %u microcode entries uploaded, %llu bytes",
			  devname, entries_written, total_written);

	return err;
}

static time_t bcd_date_to_time(const uint32_t d)
{
	unsigned int day, month, year;
	struct tm tm;

	/* packed BCD already validated */
	day   = ( d        & 0xf) +
		((d >>  4) & 0xf) * 10;

	month = ((d >>  8) & 0xf) +
	        ((d >> 12) & 0xf) * 10;

	year  = ((d >> 16) & 0xf) +
	        ((d >> 20) & 0xf) * 10 +
	        ((d >> 24) & 0xf) * 100 +
	        ((d >> 28) & 0xf) * 1000;

	/* clamp to something filesystem-friendly */
	memset(&tm, 0, sizeof(tm));
	tm.tm_hour = 12;
	tm.tm_mday = (int)(day);
	tm.tm_mon  = (likely(month > 0))? (int)month - 1 : 0;
	tm.tm_year = (likely(year >= 1970))? (int)year - 1900 : 1970;

	return timegm(&tm);
}

#define CPIO_STATIC_HDRSIZE (6 + 13*8)
#define CPIO_MAX_HDRSIZE (CPIO_STATIC_HDRSIZE + sizeof(LINUX_CPIO_UCODE_NAME))

/* if size is zero, assume it is a directory */
static int xx_write_cpio_hdrentry(int fd, const char * const name,
				 const size_t size, const uint32_t t,
				 size_t * const pos)
{
	static unsigned int ino = 100;

	char buf[CPIO_MAX_HDRSIZE + 16]; /* worst case padding */
	size_t nsize, bufsize, s;

	assert(name);
	nsize = strlen(name) + 1;

	ino++;

	/* pad to DWORD, assume already DWORD-aligned */
	bufsize = CPIO_STATIC_HDRSIZE + nsize;
	bufsize += (4 - bufsize % 4) % 4;

	/* Gross hack to work around a Linux kernel bug: for file
	 * entries, force file data into a 16-byte alignment by
	 * appending NULs to the file name.  Verified to be compatible
	 * with GNU pax, and GNU cpio.
	 *
	 * See also xx_write_cpio_pad_member() */
	s = (size) ? (16 - (*pos + bufsize) % 16) % 16 : 0;
	bufsize += s;
	nsize += s;

	*pos += bufsize;

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf),
	  "070701" /* signature, new ASCII portable format, no CRC */
	  "%08X%08X%08X%08X%08X%08X%08zX%08X%08X%08X%08X%08zX%08X%s",
	  ino,                                                     /* inode */
	  size ? LINUX_CPIO_FILE_MODE : LINUX_CPIO_DIR_MODE,        /* mode */
	  0U, 0U,                                               /* uid, gid */
	  size ? 1U : 2U, t, size,                    /* nlink, mtime, size */
	  3U, 1U, 0U, 0U, nsize, 0U,              /* devj, devm, nsize, CRC */
	  name);                                               /* name, pad */

	return write_data(fd, buf, bufsize);
}

/*
 * Implement an alternative to the hack in xx_write_cpio_hdrentry() to
 * work around a Linux kernel bug: right before adding the cpio header for
 * the microcode file member, insert an header entry that is sized so that
 * it will force the data section for the next member into a 16-byte
 * alignment.
 *
 * xx_write_cpio_pad_member() is optional.  If it isn't used, or used
 * incorrectly, xx_write_cpio_hdrentry() will extend the microcode data
 * file name with NULs to compensate.
 *
 * We could have it all precalculated and hardcoded as constants instead,
 * but that's annoying.
 */
static int xx_write_cpio_pad_member(int fd, const size_t nl,
				    const uint32_t t, size_t * const pos)
{
	char pad_fn[] = LINUX_CPIO_UCODE_PADNAME;
	size_t s;

	/* Calculate where the microcode data would end up without
	 * the addition of a padding member */
	s = *pos + CPIO_STATIC_HDRSIZE + nl + 1;
	s += (4 - s % 4) % 4; /* pad filename to dword boundary */

	/* Detect when no padding member would be necessary.
	 *
	 * This will never trigger unless the kernel's ABI changes.
	 * But having it here makes me happier, so... */
	if (unlikely(s % 16 == 0))
		return 0;

	/* Calculate the amount of (negative) padding required.  By
	 * varying the size of the padding member's name, we can
	 * offset the next member's (microcode file) *data* section
	 * into a 16-byte alignment */
	s += CPIO_STATIC_HDRSIZE + strlen(LINUX_CPIO_UCODE_PADNAME) + 1;
	pad_fn[strlen(LINUX_CPIO_UCODE_PADNAME) - s % 16] = 0;

	return xx_write_cpio_hdrentry(fd, pad_fn, 0, t, pos);
}

/**
 * write_cpio_header() - writes cpio header for early microcode
 * @fd:			file to write to
 * @size:		size of the file being written, for the header
 * @date:		date for members of the archive, in BCD
 * 			YYYYMMDD format.
 * @parents:		output headers for parent dirs when nonzero
 * @err:		set to errno if an error happens
 *
 * returns the number of bytes written if successful, or -1
 * if a problem happens
 *
 * Write cpio header.  For Intel microcodes, the kernel ABI
 * defines that they should be in a single file, named
 * kernel/x86/microcode/GenuineIntel.bin.  We use the 070701
 * format ("newc" format for GNU cpio).  To work around a kernel
 * bug, we ensure the file data will be 16-byte aligned.
 *
 * The kernel loader cares not for leading parent dirs, but
 * when they are missing, the file won't be available to the
 * regular initramfs.
 *
 * The maximum file size supported by the "newc" format is 4GiB.
 */
static ssize_t write_cpio_header(int fd, const size_t size,
				 const uint32_t date, const int parents,
				 int * const err)
{
	char fn[] = LINUX_CPIO_UCODE_NAME;
	size_t pos = 0;
	time_t uc_time = bcd_date_to_time(date);
	uint32_t t;

	assert(err);

	if (unlikely(size > UINT32_MAX))
	    return -EFBIG;

	/* cpio newc format is not y2038-safe */
	t = (uc_time > INT32_MAX) ? INT32_MAX : (uint32_t) uc_time;

	/*
	 * the early initramfs kernel loader doesn't need the directories
	 * to be created before the file can be accessed, but the regular
	 * initramfs kernel loader does.  Including them makes the file
	 * available inside the regular initramfs.
	 */
	if (parents) {
		char *p1, *p2;

		p1 = fn;
		do {
			p2 = strchr(p1, '/');
			if (p2) {
				*p2 = 0;
				if (xx_write_cpio_hdrentry(fd, fn, 0, t, &pos))
					goto err_exit;
				*p2 = '/';
				p1 = ++p2;
			}
		} while (p2);

		if (xx_write_cpio_pad_member(fd,
					     strlen(LINUX_CPIO_UCODE_NAME),
					     t, &pos))
			goto err_exit;
	}

	if (xx_write_cpio_hdrentry(fd, fn, size, t, &pos))
		goto err_exit;

	assert(pos < SSIZE_MAX);
	return (ssize_t)pos;

err_exit:
	*err = errno;
	return -1;
}

/**
 * write_cpio_trailer() - write a cpio EOF trailer and pad
 * @fd:			file to write to
 * @pos:		file position
 * @blksize:		cpio block size (for padding)
 * @err:		set to errno if an error happens
 *
 * returns the number of bytes written if successful, or -1
 * if a problem happens
 *
 * Write a cpio EOF trailer, padding with NULs to the nearest
 * @blksize boundary.  @pos is used to calculate the amount of
 * padding, instead of requiring a lseek().
 *
 * @blksize should be either 16 (non-standard), 512 or 1024.
 */
static ssize_t write_cpio_trailer(int fd, const size_t pos,
				  const size_t blksize, int * const err)
{
	const char cpio_trailer[] = "070701"
		/* inode, mode,  uid,   gid */
		"00000000" "00000000" "00000000" "00000000" 
		/* nlink, mtime, size,  devj */
		"00000001" "00000000" "00000000" "00000000"
		/* devm,  rdevj, rdevm, name size */
		"00000000" "00000000" "00000000" "0000000B"
		/* checksum, name */
		"00000000" "TRAILER!!!";
	const size_t s = sizeof(cpio_trailer) +
		((blksize - ((pos + sizeof(cpio_trailer)) % blksize)) % blksize);
	char *buf;

	assert(err);
	assert(blksize <= 1024U && (blksize % 16) == 0);

	buf = malloc(s);
	if (!buf) {
		*err = ENOMEM;
		return -1;
	}

	/* we depend on the buffer-fill strncpy() semantics here */
	int rc = write_data(fd, strncpy(buf, cpio_trailer, s), s);
	if (rc)
		*err = errno;

	free(buf);

	/* ssize_t cast valid for any sane blksize */
	return (rc) ? rc : (ssize_t)s;
}


/**
 * write_intel_microcodes() - writes microcodes to bin file
 * @dirfd:		directory where to create file
 * @filename:		file to write to
 * @ft:			file type
 * @uc_write_list:	uclist with the microcodes to write
 *
 * returns 0 if successful, errno if a problem happens,
 * or ENODATA if all microcodes in @uc_write_list have the
 * INTEL_UCLE_NOWR flag set (in which case, nothing is done
 * to the file).
 *
 * @dirfd should be either an open directory for openat(), or
 * the special value AT_FDCWD.
 *
 * @ft should be zero for binary format, 1 for Linux early
 * initramfs cpio format.
 *
 * binary format is the Intel-specified format for binary microcode,
 * used by the Linux firmware loader and a few other operating
 * systems.
 *
 * Linux early initramfs cpio format will write microcodes inside
 * a cpio 070701 (New portable ASCII format without CRC) wrapper,
 * suitable for early microcode loading for Linux kernels v3.9 and
 * newer.  This file should be prepended to the compressed initramfs
 * image.  It *must* be 16-byte aligned to the start of the
 * early initramfs image.
 */
static int write_intel_microcodes(int dirfd,
				  const char * const filename, const int ft,
				  struct intel_uclist_entry *uc_write_list)
{
	int fd;
	int err = 0;
	unsigned long long int total_written;
	unsigned int entries_written = 0;
	struct intel_uclist_entry *e;
	uint32_t latest_date;

	assert(uc_write_list);
	assert(filename);

	/*
	 * precalculate raw file size. It is less annoying than
	 * having to seek back to write it later in cpio mode
	 *
	 * while at it, record the latest microcode date found
	 * in the set of microcodes that will be written
	 */
	e = uc_write_list;
	total_written = 0;
	latest_date = 0;
	while (e && e->uc) {
		if (likely(!(e->flags & INTEL_UCLE_NOWR))) {
			const uint32_t d = intel_ucode_getdate_bcd(e->uc);
			if (d > latest_date)
				latest_date = d;

			total_written += e->uc_size;
		}
		e = e->next;
	}
	if (unlikely(!total_written)) {
		return ENODATA;	/* don't create empty files */
	} else if (unlikely(ft == 1 && total_written > UINT32_MAX)) {
		/* file too large for cpio archive members */
		print_err("%s: too much data", filename);
		return EFBIG;
	}

	/* Unlink first */
	if (unlink_files) {
		if (unlinkat(dirfd, filename, 0) == -1) {
			if (errno != ENOENT) {
				err = errno;
				print_err("%s: cannot unlink: %s", filename,
					  strerror(err));
				return err;
			}
		} else {
			print_msg(3, "unlinked %s", filename);
		}
	}

	fd = openat(dirfd, filename, O_CREAT | O_WRONLY | O_EXCL,
		    S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
	if (fd == -1) {
		err = errno;
		print_err("%s: cannot write to, or create file: %s",
			  filename, strerror(err));
		return err;
	}

	if (ft == 1) {
		ssize_t rc = write_cpio_header(fd, total_written,
					latest_date, cpio_parentdirs,
					&err);
		if (rc < 0)
			goto error;
		total_written += (size_t)rc;
	}

	while (uc_write_list && uc_write_list->uc) {
		if (likely(!(uc_write_list->flags & INTEL_UCLE_NOWR))) {
			if (verbosity >= 3)
				log_microcode_action("writing",
						     filename, uc_write_list);

			if (unlikely(write_data(fd, uc_write_list->uc,
					        uc_write_list->uc_size))) {
				err = -errno;
				goto error;
			}

			entries_written++;
		} else {
			if (verbosity >= 3)
				log_microcode_action("skipping",
						     filename, uc_write_list);
		}
		uc_write_list = uc_write_list->next;
	}

	if (ft == 1) {
		ssize_t rc = write_cpio_trailer(fd, total_written,
						cpio_blocksize, &err);
		if (unlikely(rc < 0))
			goto error;
		total_written += (size_t)rc;
	}

	if (fdatasync(fd)) {
		err = errno;
		print_err("%s: error while flushing file data: %s",
			  filename, strerror(err));
	}
	if (close(fd)) {
		err = errno;
		print_err("%s: error while closing file: %s",
			  filename, strerror(err));
	}

	if (!err)
		print_msg(2, "%s: %u microcode entries written, %llu bytes",
			  filename, entries_written, total_written);

	return err;

error:
	print_err("%s: write error: %s", filename, strerror(err));
	return err;
}

/* Microcode filtering */

#define PFMASK_MATCH_ANY 0xffffffffU

static int is_in_date_range(const struct intel_ucode_metadata * const m)
{
	const uint32_t d = ((unsigned int)m->date_year << 16) |
	                   ((unsigned int)m->date_month << 8) |
			   ((unsigned int)m->date_day);
	return !!((d > datefilter_min) && (d < datefilter_max));
}

static void free_filter_list(struct microcode_filter_entry *f)
{
	static struct microcode_filter_entry *p;

	while (f) {
		p = f;
		f = f->next;
		free(p);
	}
}

static int xx_merge_filter(struct microcode_filter_entry * const f,
			 const uint32_t pf_mask, const int32_t rev,
			 const enum iuc_rev_match_mode rev_match,
			 const int invert)
{
	/* FIXME: we could do better, sometimes it is possible to merge */
	if (f->rev_match != rev_match || f->rev != rev)
		return 0; /* can't merge */

	if (f->invert == invert) {
		f->pfm |= pf_mask;
	} else if (!(f->invert)) {
		f->pfm &= ~pf_mask;
	} else {
		f->invert = 0;
		f->pfm = pf_mask;
	}

	return 1; /* merged */
}

static int add_filter_to_list(uint32_t cpuid, uint32_t pf_mask, int32_t rev,
			      enum iuc_rev_match_mode rev_match, int invert,
			      struct microcode_filter_entry ** const base)
{
	struct microcode_filter_entry **pnext, *n;

	assert(base);

	if (!cpuid || cpuid == IUCODE_FILTERMASK_SCANCPUS)
		return EINVAL;

	if (!pf_mask)
		pf_mask = PFMASK_MATCH_ANY;

	pnext = base;
	/* search for matching cpuid */
	while (*pnext && (*pnext)->cpuid < cpuid)
		pnext = &((*pnext)->next);

	if (*pnext && (*pnext)->cpuid == cpuid) {
		if (((pf_mask & (*pnext)->pfm) == pf_mask) &&
		    (*pnext)->rev_match == rev_match &&
		    (*pnext)->rev == rev &&
		    (*pnext)->invert == invert) {
			/* found equivalent, report it */
			return EEXIST;
		}

		/* merge when possible */
		if (xx_merge_filter(*pnext, pf_mask, rev, rev_match, invert))
			return 0;
	}

	/* insert before */
	n = malloc(sizeof(struct microcode_filter_entry));
	if (!n)
		return ENOMEM;
	n->cpuid = cpuid;
	n->pfm = pf_mask;
	n->rev = rev;
	n->rev_match = rev_match;
	n->invert = invert;
	n->next = *pnext;
	*pnext = n;

	return 0;
}

/* After calling this, "entries" becomes invalid */
static void add_filter_list_to_list(struct microcode_filter_entry ** const base,
				    struct microcode_filter_entry *entries)
{
	struct microcode_filter_entry **pp;

	assert(base);

	/* both lists are sorted, no need to rescan from the
	 * beginning at every iteration */
	pp = base;
	while (entries) {
		struct microcode_filter_entry *e;

		e = entries;
		entries = entries->next;

		while (*pp && (*pp)->cpuid < e->cpuid)
			pp = &((*pp)->next);

		if (!*pp || (*pp)->cpuid != e->cpuid ||
		    !xx_merge_filter(*pp, e->pfm, e->rev, e->rev_match, e->invert)) {
			/* insert before */
			e->next = *pp;
			*pp = e;
			e = NULL;
		}
		free(e);
	}
}

static int xx_compare_rev(const int32_t rev,
			  const struct microcode_filter_entry *f)
{
	const enum iuc_rev_match_mode op = f->rev_match;

	if ((op == IUCODE_REVFLT_ANY) ||
	    (op == IUCODE_REVFLT_EQ && rev == f->rev) ||
	    (op == IUCODE_REVFLT_LT && rev < f->rev)  ||
	    (op == IUCODE_REVFLT_GT && rev > f->rev)) {
		return !(f->invert);
	}

	return -1;
}

/* returns non-zero if selected */
static int is_selected(const uint32_t cpuid,
		       const uint32_t pf_mask,
		       const int32_t rev,
		       const struct microcode_filter_entry *f)
{
	int state = -1;

	while (f && f->cpuid < cpuid)
		f = f->next;
	while (f && f->cpuid == cpuid && state < 0) {
		if ((pf_mask & f->pfm) != 0 ||
		    f->pfm == PFMASK_MATCH_ANY) {
			state = xx_compare_rev(rev, f);
		}
		f = f->next;
	}

	return (state >= 0)? state : filter_list_allow;
}

/* Microcode extended signature deduplication */

static int xx_xtsdeduplist_add(struct intel_uclist_entry * const e,
			       struct microcode_id_entry **list)
{
	struct microcode_id_entry *n;

	n = malloc(sizeof(struct microcode_id_entry));
	if (!n)
		return ENOMEM;

	n->id = e->uc;
	n->next = *list;
	*list = n;

	return 0;
}

/**
 * xtsdeduplist_check_and_add() - track mcu objects for dedup
 *
 * @e:    entry to add signature from to the list
 * @list: pointer to the head of the list used to track duplicates
 *
 * Duplicate tracking is done by storing and comparing struct
 * intel_uclist_entry->uc pointers.  This will work _only_ to dedup
 * several instances of the same microcode due to extended signature
 * processing.
 *
 * It cannot detect multiple copies of the same data stored in
 * multiple objects.
 *
 * To use:
 * Init the list head to NULL.  Call xtsdeduplist_check_and_add() for
 * every struct intel_uclist_entry element you want to track.
 *
 * One should use free_xtsdeduplist() to free the tracking list after
 * use.
 *
 * Returns:
 *   ENOMEM: cannot allocate memory to add entry to list
 *   EEXIST: entry is a duplicate
 *   0:      entry is not a duplicate
 */
static int xtsdeduplist_check_and_add(struct intel_uclist_entry * const e,
                                      struct microcode_id_entry **list)
{
	const void *id = e->uc;

	while (*list) {
		if ((*list)->id == id)
			return EEXIST;
		list = &((*list)->next);
	}
	return xx_xtsdeduplist_add(e, list);
}

/**
 * free_xtsdeduplist() - frees mcu dedup tracking list
 * @list:   head of the list to be freed
 *
 * Frees every element of the list.  @list will be invalid
 * after this function returns.
 */
static void free_xtsdeduplist(struct microcode_id_entry *list)
{
	struct microcode_id_entry *e;

	while (list) {
		e = list;
		list = list->next;
		free(e);
	}
}

static int uclist_annotate_extsig_dup(struct intel_uclist_entry * const uclist)
{
	struct microcode_id_entry *dlist = NULL;
	struct intel_uclist_entry *e;
	int rc = 0;

	if (!extsig_tables_in_use)
		return 0;

	e = uclist;
	while (e) {
		if (unlikely(e->flags & INTEL_UCLE_HASXST)) {
			rc = xtsdeduplist_check_and_add(e, &dlist);
			if (rc == EEXIST) {
				e->flags |= INTEL_UCLE_NOWR;
			} else if (!rc) {
				e->flags &= ~INTEL_UCLE_NOWR;
			} else {
				break;
			}
		}
		e = e->next;
	}

	free_xtsdeduplist(dlist);
	return (rc != EEXIST) ? rc : 0;
}

/* Microcode processing */

static int xx_uclist_add_print_errors(const int status)
{
	switch (status) {
	case EEXIST:
	case 0:
		return 0;
	case ENOMEM:
		print_err("Cannot add index entry: out of memory");
		return 1;
	case EINVAL:
		print_err("Internal error: uclist_merge_signature() returned EINVAL");
		return 1;
	default:
		return 1;
	}
}

static int xx_datefilter_loose_inplaceinsert(struct intel_uclist_entry ** const p,
					     struct intel_uclist_entry ** const uclist)
{
	const uint32_t cpuid = (*p)->cpuid;
	const uint32_t pf_mask = (*p)->pfm;
	struct intel_uclist_entry *e;
	int rc;

	e = *uclist;
	while (e && e->cpuid < cpuid)
		e = e->next;
	*uclist = e; /* speed up next search */

	while (e && e->cpuid == cpuid) {
		if (e->flags & INTEL_UCLE_SELID && e->pfm & pf_mask) {
			e->flags &= ~INTEL_UCLE_SELID;
			e->flags |= INTEL_UCLE_SELECT;
			rc = xx_uclist_add_print_errors(
			        uclist_merge_signature(e->id, e->gid,
				        e->flags, e->cpuid, e->pfm,
					e->uc_rev, e->uc, e->uc_size,
					allow_downgrade, p));
			if (rc)
				return rc;
		}
		e = e->next;
	}

	return 0;
}

static int check_downgrade_shadowing(const struct intel_uclist_entry * uclist)
{
	int res = 0;

	while (uclist) {
		const struct intel_uclist_entry *e = uclist->next;
		const uint32_t sig = uclist->cpuid;
		const uint32_t pfm = uclist->pfm;
		const int32_t  rev = uclist->uc_rev;
		const uint32_t gid = uclist->gid;

		while(e && e->cpuid == sig) {
			if ((pfm & e->pfm) != 0 &&
			    ((gid > e->gid && rev < e->uc_rev) ||
			     (gid < e->gid && rev > e->uc_rev))) {
				print_warn("cannot downgrade microcode sig 0x%x, "
					  "pf_mask 0x%02x (entries: " UCODE_ID_FMT_UU
					  " rev 0x%x, and " UCODE_ID_FMT_UU " rev 0x%x)",
					  sig, (pfm & e->pfm),
					  gid, uclist->id, (uint32_t) rev,
					  e->gid, e->id, (uint32_t) e->uc_rev);
				res = EEXIST;
			}
			e = e->next;
		}

		uclist = uclist->next;
	}

	return res;
}

static int xx_process_ucode_signature_cb(void * const userdata,
				const unsigned int sig_count,
				const uint32_t cpuid,
				const uint32_t pf_mask,
				__attribute__((unused)) const void * const uc_data,
				__attribute__((unused)) const unsigned int uc_data_size,
				const void * const uc,
				const unsigned int uc_size)
{
	struct microcode_iterator_data * const ctx = userdata;
	struct intel_ucode_metadata m;
	intel_ucode_status_t s;
	int add_status;
	uint32_t uce_flags = 0;

	assert(ctx);

	ctx->total_signature_count++;

	s = intel_ucode_getmetadata(uc, &m);
	if (s != INTEL_UCODE_NOERROR) {
		print_err("Microcode entry " UCODE_ID_FMT_UU ": %s",
			  ctx->current_bundle->id, ctx->current_uc,
			  intel_ucode_errstr(s));
		return 1;
	}

	if (m.extsig_count) {
		uce_flags = (sig_count) ?
			(INTEL_UCLE_HASXST | INTEL_UCLE_EXTSIG) :
			INTEL_UCLE_HASXST;
		extsig_tables_in_use = 1;
	}
	if (is_selected(cpuid, pf_mask, m.revision, uc_filter_list))
		uce_flags |= (is_in_date_range(&m)) ?
				INTEL_UCLE_SELECT : INTEL_UCLE_SELID;

	if (list_all_microcodes) {
		if (!sig_count)
			fprintf(stdout,
				"  " UCODE_ID_FMT_UU ": sig 0x%08x, pf_mask 0x%02x, "
				"%04x-%02x-%02x, rev 0x%04x, size %u\n",
				ctx->current_bundle->id, ctx->current_uc,
				cpuid, pf_mask,
				m.date_year, m.date_month, m.date_day,
				(uint32_t) m.revision, uc_size);
		else
			fprintf(stdout,
				"           sig 0x%08x, pf_mask 0x%02x, "
				"%04x-%02x-%02x, rev 0x%04x\n",
				cpuid, pf_mask,
				m.date_year, m.date_month, m.date_day,
				(uint32_t) m.revision);
	}

	add_status = uclist_add_signature(ctx->current_uc,
			ctx->current_bundle->id, uce_flags,
			cpuid, pf_mask, m.revision, uc, uc_size,
			strict_checks, &all_microcodes);

	switch (add_status) {
	case 0:
		ctx->total_unique_sig_count++;
		break;
	case EEXIST:
		break;
	case EBADF:
		print_warn("microcode " UCODE_ID_FMT_UU " has the same revision "
			  "and signature as a previously loaded microcode, but "
			  "different contents", ctx->current_bundle->id, ctx->current_uc);
		return 1;
	case EINVAL:
		print_err("Internal error: uclist_add_signature() returned EINVAL");
		return 1;
	default:
		print_err("Failed to add microcode entry " UCODE_ID_FMT_UU ": %s",
			  ctx->current_bundle->id, ctx->current_uc, strerror(add_status));
		return 1;
	}

	if (uce_flags & INTEL_UCLE_SELECT) {
		add_status = uclist_merge_signature(ctx->current_uc,
					ctx->current_bundle->id, uce_flags,
					cpuid, pf_mask, m.revision,
					uc, uc_size, allow_downgrade,
					&microcodes);
		if (add_status && add_status != EEXIST) {
			print_err("Failed to select microcode entry " UCODE_ID_FMT_UU ": %s",
				  ctx->current_bundle->id, ctx->current_uc,
				  strerror(add_status));
			return 1;
		}
	}

	return xx_uclist_add_print_errors(add_status);
}

static int xx_process_ucode_entry_cb(void * const userdata,
			         const unsigned int uc_count,
			         const void * const uc,
				 const size_t uc_max_size)
{
	struct microcode_iterator_data * const ctx = userdata;
	intel_ucode_status_t s;

	assert(ctx);

	ctx->current_uc = uc_count;

	s = intel_ucode_check_microcode(uc, uc_max_size, strict_checks);
	if (s != INTEL_UCODE_NOERROR) {
		print_err("microcode " UCODE_ID_FMT_UU ": %s",
			  ctx->current_bundle->id, ctx->current_uc,
			  intel_ucode_errstr(s));
		return (ignore_bad_ucode) ? 0 : 1;
	}

	ctx->total_entry_count++;

	s = intel_ucode_foreach_signature(uc, xx_process_ucode_signature_cb,
					  userdata);
	if (s != INTEL_UCODE_NOERROR && !ignore_bad_ucode) {
		print_err("aborting microcode processing...");
		return 1;
	}

	return 0;
}

static int do_process_microcodes(void)
{
	intel_ucode_status_t s;
	struct microcode_bundle *mcb;

	memset(&microcode_iterator_data, 0, sizeof(microcode_iterator_data));
	mcb = microcode_bundles;

	while (mcb) {
		if ((list_all_microcodes || list_sel_microcodes) && verbosity > 0)
			fprintf(stdout, "microcode bundle %u: %s\n", mcb->id,
				mcb->filename ? mcb->filename : "");

		microcode_iterator_data.current_bundle = mcb;
		s = intel_ucode_foreach_microcode(mcb->data, mcb->size,
						xx_process_ucode_entry_cb,
						&microcode_iterator_data);
		if (s != INTEL_UCODE_NOERROR) {
			if (s != INTEL_UCODE_CALLBACK_ERROR)
				print_err("microcode bundle %s: %s",
					mcb->filename ? mcb->filename : "(no filename)",
					intel_ucode_errstr(s));

			if (!ignore_bad_ucode)
				return 1;
		}

		mcb = mcb->next;
	}

	print_msg(2, "processed %lu valid microcode(s), %lu signature(s), %lu unique signature(s)",
		  microcode_iterator_data.total_entry_count,
		  microcode_iterator_data.total_signature_count,
		  microcode_iterator_data.total_unique_sig_count);

	/*
	 * we iterate over all selected microcodes only once, either
	 * to list selected microcodes, or to gather some stats when
	 * the verbosity is high, or to implement the loose date
	 * filtering mode.
	 */
	if (list_sel_microcodes || datefilter_loose || verbosity >= 2) {
		struct intel_uclist_entry *uce = microcodes;
		struct intel_uclist_entry *ucl = all_microcodes;
		struct microcode_id_entry *dl = NULL;
		unsigned long int uccount = 0;
		unsigned long int sigcount = 0;

		if (list_sel_microcodes)
			fprintf(stdout, "selected microcodes:\n");

		while (uce) {
			/*
			 * search any extra microcode for loose mode and
			 * insert it at this point
			 */
			if (unlikely(datefilter_loose &&
			    xx_datefilter_loose_inplaceinsert(&uce, &ucl)))
					return 1;

			/* note: we ignore ENOMEM results for performance */
			if (likely(!(uce->flags & INTEL_UCLE_HASXST) ||
				   !xtsdeduplist_check_and_add(uce, &dl)))
				uccount++;

			sigcount++;

			if (list_sel_microcodes) {
				struct intel_ucode_metadata m;

				if (unlikely(intel_ucode_getmetadata(uce->uc, &m) != INTEL_UCODE_NOERROR))
					exit(EXIT_SWFAILURE); /* memory corruption */
				fprintf(stdout,
					"  " UCODE_ID_FMT_UU ": sig 0x%08x, pf_mask 0x%02x, "
					"%04x-%02x-%02x, rev 0x%04x, size %u\n",
					uce->gid, uce->id, uce->cpuid, uce->pfm,
					m.date_year, m.date_month, m.date_day,
					(uint32_t) m.revision, uce->uc_size);
			}

			uce = uce->next;
		}

		free_xtsdeduplist(dl);
		print_msg(2, "selected %lu microcode(s), %lu signature(s)",
			  uccount, sigcount);
	}

	/* detect annoying downgrade mode shadows, and warn */
	if (allow_downgrade)
		check_downgrade_shadowing(microcodes);

	return 0;
}

static int do_write_microcode(const char * const filename, const int ft)
{
	int rc;

	if (!microcodes)
		return 0;

	print_msg(1, "Writing selected microcodes to: %s", filename);
	rc = write_intel_microcodes(AT_FDCWD, filename, ft, microcodes);
	if (rc == ENODATA) {
		print_warn("All microcodes in %s were skipped, file unchanged", filename);
		return 0;
	}
	return rc;
}

static int do_upload_microcode(const char * const filename)
{
	if (!microcodes)
		return 0;

	print_msg(1, "Uploading selected microcodes to: %s", filename);
	return upload_intel_microcodes(filename, microcodes);
}

static int do_write_named(const char * const dirname,
			  const struct intel_uclist_entry * const ucl)
{
	char fn[35]; /* "s%08X_m%08X_r%08X.fw" */
	int dirfd;
	struct stat st;

	struct intel_uclist_entry e;
	const struct intel_uclist_entry *p;
	unsigned long int count;
	int rc;

	if (!ucl)
		return 0;

	dirfd = open(dirname, O_RDONLY);
	if (dirfd == -1) {
		rc = errno;
		print_err("%s: cannot open: %s", dirname,
			  strerror(rc));
		return rc;
	}

	/* were we given a directory ? */
	if (fstat(dirfd, &st) == -1) {
		rc = errno;
		print_err("%s: cannot stat inode: %s", dirname,
			  strerror(rc));
		goto err_exit;
	}
	if (!S_ISDIR(st.st_mode)) {
		print_err("%s: is not a directory", dirname);
		rc = EINVAL;
		goto err_exit;
	}

	print_msg(1, "Writing microcode file(s) into %s", dirname);

	p = ucl;
	count = 0;
	rc = 0;

	while (p && !rc) {
		if (!(p->flags & INTEL_UCLE_DUPSIG)) {
			snprintf(fn, sizeof(fn), "s%08X_m%08X_r%08X.fw",
				     p->cpuid, p->pfm, (uint32_t) p->uc_rev);

			memcpy(&e, p, sizeof(e));
			e.next = NULL;
			e.flags &= ~INTEL_UCLE_NOWR;
			rc = write_intel_microcodes(dirfd, fn, 0, &e);
			if (!rc)
				count++;
		}

		p = p->next;
	}

	if (fsync(dirfd)) {
		rc = errno;
		print_err("%s: error while flushing directory inodes: %s",
			  dirname, strerror(rc));
	}

	if (count)
		print_msg(2, "%lu file(s) were written into %s", count, dirname);
	else
		print_msg(1, "no files were written into %s", dirname);

err_exit:
	close(dirfd);

	return rc;
}

static int do_write_firmware(const char * const dirname)
{
	char fn[35]; /* "%02x-%02x-%02x" */
	int dirfd;
	struct stat st;

	struct intel_uclist_entry *samecpuid_list, *p;
	unsigned long int count;
	int rc;

	if (!microcodes)
		return 0;

	dirfd = open(dirname, O_RDONLY);
	if (dirfd == -1) {
		rc = errno;
		print_err("%s: cannot open: %s", dirname,
			  strerror(rc));
		return rc;
	}

	/* were we given a directory ? */
	if (fstat(dirfd, &st) == -1) {
		rc = errno;
		print_err("%s: cannot stat inode: %s", dirname,
			  strerror(rc));
		goto err_exit;
	}
	if (!S_ISDIR(st.st_mode)) {
		print_err("%s: is not a directory", dirname);
		rc = EINVAL;
		goto err_exit;
	}

	print_msg(1, "Writing microcode firmware file(s) into %s", dirname);

	p = microcodes;
	samecpuid_list = NULL;
	count = 0;
	rc = 0;

	/* the lists are already ordered by cpuid */
	while (p && !rc) {
		uint32_t cpuid;
		unsigned int x86_family, x86_model, x86_mask;
		int add_status;

		/* select all that share the same cpuid */
		cpuid = p->cpuid;
		while (p && p->cpuid == cpuid) {
			add_status = uclist_merge_signature(p->id, p->gid,
						p->flags, p->cpuid, p->pfm,
						p->uc_rev, p->uc, p->uc_size,
						0, &samecpuid_list);
			if (xx_uclist_add_print_errors(add_status)) {
				rc = add_status;
				goto err_exit;
			}

			p = p->next;
		}

		/* write to file in dirname/ as expected by the kernel */

		x86_family = (cpuid >> 8) & 0x0f;
		x86_model  = (cpuid >> 4) & 0x0f;
		x86_mask   = cpuid & 0x0f;
		if (x86_family == 0x0f)
			x86_family += (cpuid >> 20) & 0xff;
		if (x86_family >= 0x06)
			x86_model += ((cpuid >> 16) & 0x0f) << 4;

		snprintf(fn, sizeof(fn), "%02x-%02x-%02x",
			     x86_family, x86_model, x86_mask);

		rc = uclist_annotate_extsig_dup(samecpuid_list);
		if (rc)
			goto err_exit;

		rc = write_intel_microcodes(dirfd, fn, 0, samecpuid_list);

		free_uclist(samecpuid_list);
		samecpuid_list = NULL;

		if (!rc)
			count++;
		if (rc == ENODATA)
			rc = 0;
	}

	if (fsync(dirfd)) {
		rc = errno;
		print_err("%s: error while flushing directory inodes: %s",
			  dirname, strerror(rc));
	}

	if (count)
		print_msg(2, "%lu file(s) were written into %s", count, dirname);
	else
		print_msg(1, "no files were written into %s", dirname);

err_exit:
	close(dirfd);

	return rc;
}

static int xx_scan_handle_sig(const uint32_t id1, const uint32_t id2,
			      const uint32_t id3, const uint32_t sig,
			      struct microcode_filter_entry ** const ucfp)
{
	/* Is it a supported Intel processor ? */
	if (id1 == 0x756e6547 && /* "Genu" */
	    id3 == 0x49656e69 && /* "ineI" */
	    id2 == 0x6c65746e) { /* "ntel" */
		/*
		 * Get main processor signature from cpuid(1) EAX
		 * and add it as a filter.
		 */
		switch (add_filter_to_list(sig, 0, 0, IUCODE_REVFLT_ANY, 0, ucfp)) {
		case ENOMEM:
			print_err("out of memory");
			return ENOMEM;
		case EEXIST:
			return 0;
		default:
			print_msg(1, "system has processor(s) with signature 0x%08x", sig);
			return 0;
		}
	}

	return ENXIO;
}

#ifdef USE_CPUID_DEVICE
static int is_base10_number(const char *s)
{
	if (!s || !*s)
		return 0;

	while(*s) {
		if (*s < '0' || *s > '9')
			return 0;
		s++;
	}

	return 1;
}

/* requires a kernel driver, and *really* hurts on very large systems */
static int xx_check_cpuid_devs(struct microcode_filter_entry ** const ucfp)
{
	uint32_t cpuid_buf[8];	/* two cpuid levels */
	char cpuid_device[PATH_MAX];
	int cpuid_fd;
	int rc = 0;
	unsigned int i = 0;
	unsigned int ncpu = 0;
	struct dirent *d;

	DIR *cpudir = opendir(CPUID_DEVICE_PARENT);
	if (!cpudir) {
		int en = errno;
		print_err("%s: could not open directory: %s", CPUID_DEVICE_PARENT, strerror(en));
		return -1;
	}

	while (1) {
		errno = 0;
		d = readdir(cpudir);
		if (!d) {
			int err = errno;
			if (unlikely(err)) {
				print_err("%s: cannot walk directory: %s",
					  CPUID_DEVICE_PARENT, strerror(err));
				rc = -1; /* note that we skipped processors due to unexpected errors */
			}
			break; /* finish/abort walk */
		}

		/* Linux procfs supports d_type */
		if (d->d_type != DT_DIR)
			continue; /* next dentry */

		/* must be [0-9]+, no trailling weirdness */
		if (!is_base10_number(d->d_name))
			continue; /* next dentry */

		snprintf(cpuid_device, sizeof(cpuid_device),
			 CPUID_DEVICE_BASE, d->d_name);

		errno = EINTR;
		cpuid_fd = -1;
		while (cpuid_fd == -1 && errno == EINTR)
			cpuid_fd = openat(dirfd(cpudir), cpuid_device, O_RDONLY | O_CLOEXEC);
		if (cpuid_fd == -1) {
			int en = errno;

			print_msg(4, "%s/%s: returned error status on open(): %s",
				  CPUID_DEVICE_PARENT, cpuid_device, strerror(en));

			if (en == ENOENT)
				break;    /* cpuid device inode not found */
			if (en == ENXIO || en == EIO) {
				/* Linux cpuid driver: ENXIO: offline; EIO: no cpuid support */
				print_msg(2, "processor %u is offline or has no cpuid support", i);
			} else {
				print_msg(2, "%s/%s: cannot open cpuid device node: %s",
					CPUID_DEVICE_PARENT, cpuid_device, strerror(en));
				rc = -1; /* note that we skipped processors due to unexpected errors */
			}

			/* skip this processor */
			i++;
			continue;
		}

		print_msg(3, "trying to get CPUID information from %s/%s",
			  CPUID_DEVICE_PARENT, cpuid_device);
		if (read(cpuid_fd, &cpuid_buf, sizeof(cpuid_buf)) == -1) {
			print_err("%s/%s: access to CPUID(0) and CPUID(1) failed: %s",
				  CPUID_DEVICE_PARENT, cpuid_device, strerror(errno));
			/* this is in the should not happen list, so abort */
			close(cpuid_fd);
			closedir(cpudir);
			return 1;
		}

		close(cpuid_fd);
		ncpu++;

		if (xx_scan_handle_sig(cpuid_buf[1], cpuid_buf[2],
				       cpuid_buf[3], cpuid_buf[4], ucfp) == ENOMEM) {
			rc = -1;
			break;
		}

		i++;
	};

	closedir(cpudir);

	if (i == 0 && ncpu == 0) {
		print_err("cpuid kernel driver unavailable");
		return -1;
	} else if (rc) {
		if (ncpu)
			print_err("some processors were not scanned due to unexpected errors");
		else
			print_err("could not open any cpuid devices");
	}

	if (ncpu)
		print_msg(2, "checked the signature of %u processor(s)", ncpu);

	return rc;
}
#else
static int xx_check_cpuid_devs(__attribute__((unused)) struct microcode_filter_entry ** const ucfp)
{
	print_msg(1, "support for exact system scan disabled at compile time");
	return -1;
}
#endif /* USE_CPUID_DEVICE */


/* xx_add_all_steppings(cpuid) hurts a lot less on very big systems... */
static int xx_add_all_steppings(uint32_t sig, struct microcode_filter_entry ** const ucfp)
{
	unsigned int i;

	sig |= 0xf;
	for (i = 0; i < 0x10; i++) {
		if (add_filter_to_list(sig, 0, 0, IUCODE_REVFLT_ANY, 0, ucfp) == ENOMEM) {
			print_err("out of memory");
			return ENOMEM;
		}
		sig--;
	}
	return 0;
}

/* Handle mixed-signature systems, even if Intel still hasn't admited that
 * they will exist in the SDM, the writing is already out in the wall */
static int xx_add_all_steppings_for_every_sig(uint32_t sig, struct microcode_filter_entry ** const ucfp)
{
	struct microcode_filter_entry *fl = NULL;
	struct microcode_filter_entry *p;
	int rc;

	/* failsafe of the failsafe: add running processor sig */
	rc = xx_add_all_steppings(sig, &fl);

	/* creating a new list is just plain safer in the long run */
	p = *ucfp;
	while (p && !rc) {
		/* handle mixed sig systems, unlikely as that might be */
		if (p->cpuid != sig)
			rc = xx_add_all_steppings(p->cpuid, &fl);
		p = p->next;
	}

	if (!rc) {
		free_filter_list(*ucfp);
		*ucfp = fl;
	} else {
		free_filter_list(fl);
	}

	return rc;
}

static int scan_system_processors(unsigned int strategy,
	                          struct microcode_filter_entry ** const filter_list)
{
	uint32_t id0, id1, id2, id3, sig, idx;
	struct microcode_filter_entry *uc_cpu = NULL;
	int rc = 0;

	assert(filter_list);

	print_msg(3, "trying to get CPUID information directly");
	if (!(__get_cpuid(0, &id0, &id1, &id2, &id3) &&
	      __get_cpuid(1, &sig, &idx, &idx, &idx))) {
		print_msg(1, "microcode signature unavailable");
		return 0;
	}

	/*
	 * fail-safe: only change filter_list_allow (switch away from "select
	 * all microcodes by default") if we did scan/cpuid.  This way, all
	 * microcodes will be included if cpuid is not available, and no other
	 * microcode selection option was used.  On non-Intel, this results in
	 * "no microcodes by default", because the scan/cpuid was successful,
	 * but uc_cpu will be empty.
	 */

	switch (xx_scan_handle_sig(id1, id2, id3, sig, &uc_cpu)) {
	case 0:
		if (strategy == 2) {
			if (xx_check_cpuid_devs(&uc_cpu)) {
				print_warn("exact cpuid signature scan failed, switching to failsafe strategy");
				rc = xx_add_all_steppings_for_every_sig(sig, &uc_cpu);
			}
		} else {
			print_msg(2, "assuming all processors have the same type, family and model");
			rc = xx_add_all_steppings(sig, &uc_cpu);
		}
		break;
	case ENXIO:
		print_msg(1, "running on a non-Intel processor");
		break;
	default:
		rc = 1;
	}

	if (!rc) {
		filter_list_allow = 0;
	} else {
		print_warn("cpuid signature scan failed, ignoring incomplete results...");
	}

	if (uc_cpu) {
		/* tie linked lists */
		add_filter_list_to_list(filter_list, uc_cpu);
		uc_cpu = NULL;
	}

	return (rc > 0) ? rc : 0;
}

static int cmdline_queue_ucode_filter(uint32_t cpuid, uint32_t pf_mask,
				      int32_t rev, enum iuc_rev_match_mode rev_match,
				      int invert)
{
	struct microcode_filter_entry *n;

	n = malloc(sizeof(struct microcode_filter_entry));
	if (!n)
		return ENOMEM;
	n->cpuid = cpuid;
	n->pfm = pf_mask;
	n->rev = rev;
	n->rev_match = rev_match;
	n->invert = invert;
	n->next = NULL;

	if (uc_filter_queue_tail) {
		uc_filter_queue_tail->next = n;
	} else {
		uc_filter_queue = n;
	}

	uc_filter_queue_tail = n;

	return 0;
}

static int process_ucode_filter_queue(void)
{
	struct microcode_filter_entry *p = uc_filter_queue;
	int rc = 0;

	while(p && !rc) {
		if (p->cpuid != IUCODE_FILTERMASK_SCANCPUS) {
			rc = add_filter_to_list(p->cpuid, p->pfm, p->rev, p->rev_match, p->invert, &uc_filter_list);
			if (rc == EEXIST)
				rc = 0;
		} else {
			rc = scan_system_processors(p->pfm, &uc_filter_list);
		}

		p = p->next;
	}

	uc_filter_queue_tail = NULL;
	free_filter_list(uc_filter_queue);
	uc_filter_queue = NULL;

	switch(rc) {
	case 0:
		return 0;

	case ENOMEM:
		print_err("Cannot add filter entry: out of memory");
		break;
	case EINVAL:
		print_err("Internal error while processing filter list");
		break;
	}

	return 1;
}

/* Command line processing */

static const char program_version[] =
	PROGNAME " " VERSION "\n"
	"Copyright (c) 2010-2018 by Henrique de Moraes Holschuh\n\n"

	"Based on code from the Linux microcode_intel driver and from\n"
	"the microcode.ctl package, copyright (c) 2000 by Simon Trimmer\n"
	"and Tigran Aivazian.\n\n"

	"This is free software; see the source for copying conditions.\n"
	"There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR\n"
	"A PARTICULAR PURPOSE.";
static const char program_bug_address[] = PACKAGE_BUGREPORT;

static const char cmdline_doc[] =
	PROGNAME " - Tool to manipulate Intel IA32/X86_64 microcode bundles\n"

	"\v"

	"The microcode bundle files should be specified as arguments.  "
	"The bundle type is determined by the file name suffix.  It "
	"defaults to the binary format.\n\n"

	"Should the filename end with \".bin\", binary mode will be "
	"used.  Should the filename end with \".dat\", text mode will be "
	"used.  The -t option can be used to set the type of the "
	"microcode bundle files that come after it, e.g. "
	"-td /tmp/dat-file -tb /tmp/binary /tmp/binary2.\n\n"

	"To load microcode data from stdin, use \"-\" as the filename.  "
	"File type will be assumed to be text (\".dat\"), use option -tb "
	"to load binary data from stdin.\n\n"

	"To load all files from a directory, specify the directory name.  "
	"It will not recurse into subdirectories, they will be skipped.\n\n"

	"Empty files and directories will be ignored, and will be skipped.";

enum {
	IUCODE_ARGP_STRICTCHK = 0x81,
	IUCODE_ARGP_NOSTRICTCHK,
	IUCODE_ARGP_IGNOREBROKEN,
	IUCODE_ARGP_NOIGNOREBROKEN,
	IUCODE_ARGP_UNLINK,
	IUCODE_ARGP_NOUNLINK,
	IUCODE_ARGP_DOWNGRADE,
	IUCODE_ARGP_NODOWNGRADE,
	IUCODE_ARGP_DATEBEFORE,
	IUCODE_ARGP_DATEAFTER,
	IUCODE_ARGP_DATEFSTRICT,
	IUCODE_ARGP_DATEFLOOSE,
	IUCODE_ARGP_SCANSYSTEMOPT,
	IUCODE_ARGP_EIRFS,
	IUCODE_ARGP_MINSIZE_EIRFS,
	IUCODE_ARGP_DFLSIZE_EIRFS,
	IUCODE_ARGP_WRITENAMEDALL,
};

static const struct argp_option cmdline_options[] = {
	{ NULL, 'h', NULL, 0, "Give this help list", -1 },

	{ "quiet",   'q', NULL, 0, "Quiet operation",                1 },
	{ "verbose", 'v', NULL, 0, "Verbose operation (cumulative)", 1 },

	{ NULL, 't', "type", 0,
	   "Sets input file type for the next microcode files. The type is "
	   "a single character: \"b\" (binary), \"d\" (Intel .dat), \"r\" "
	   "(search inside unknown binary data), or \"a\" (type will be "
	   "selected by filename suffix)",
	  10 },

	{ NULL, 's', "! | [!]signature[,[pf_mask][,[lt:|eq:|gt:]revision]]", 0,
	   "Select microcodes by the specified signature, processor "
	   "flags mask (pf_mask), and revision.  Optionally, prefix revision "
	   "with eq: (equal -- implied there is no prefix), lt: (less than) "
	   "or gt: (greater than).  "
	   "Specify more than once to select/unselect more microcodes.  "
	   "Prefix with ! to unselect microcodes.  "
	   "Use -s ! to disable the default behavior of selecting all "
	   "microcodes when no -s or -S filter is specified",
	  20 },
	{ NULL, 'S', NULL, 0,
	   "Same as --scan-system=auto",
	  21 },
	{ "scan-system", IUCODE_ARGP_SCANSYSTEMOPT, "mode", OPTION_ARG_OPTIONAL,
	   "Select microcodes based on the running system processor(s).  "
	   "Can be combined with the -s option, and can be used only once.  "
	   "Microcodes selected by --scan-system can be unselected by a "
	   "later -s !<signature> option.  The optional mode argument "
	   "selects the strategy: 0 or auto (default); 1 or fast (good for "
	   "most systems, including mixed-stepping); and 2 or exact (slow, "
	   "supports multi-signature systems, requires the cpuid kernel "
	   "driver and might require root access)",
	  22 },

	{ "downgrade", IUCODE_ARGP_DOWNGRADE, NULL, 0,
	   "Instead of discarding microcodes based on revision level, "
	   "keep the one from the file loaded last.  Files are loaded "
	   "in the order they were specified in the command line",
	  25 },
	{ "no-downgrade", IUCODE_ARGP_NODOWNGRADE, NULL, 0,
	   "Keep the microcode with the highest revision level, regardless "
	   "of the file load order (default)",
	  25 },

	{ "date-before", IUCODE_ARGP_DATEBEFORE, "YYYY-MM-DD", 0,
	   "Select only microcodes older than the specified date",
	  27 },
	{ "date-after", IUCODE_ARGP_DATEAFTER, "YYYY-MM-DD", 0,
	   "Select only microcodes newer than the specified date",
	  27 },
	{ "loose-date-filtering", IUCODE_ARGP_DATEFLOOSE, NULL, 0,
	   "Consider for selection other revisions (outside of the date range) "
	   "of every microcode that was selected within the date range",
	  28 },
	{ "strict-date-filtering", IUCODE_ARGP_DATEFSTRICT, NULL, 0,
	   "Select only microcodes strictly within the date range (default)",
	  28 },

	{ "list",     'l', NULL, 0, "List selected microcode signatures", 30 },
	{ "list-all", 'L', NULL, 0, "List all microcode signatures",      30 },

	{ "kernel", 'k', "device", OPTION_ARG_OPTIONAL,
	   "Upload selected microcodes to the kernel.  Optionally, the "
	   "device path can be specified (default: " MICROCODE_DEVICE_DEFAULT
	   ")",
	  40 },
	{ "write-firmware", 'K', "directory", OPTION_ARG_OPTIONAL,
	   "Write selected microcodes with the filenames expected by the "
	   "Linux kernel firmware loader.  Optionally, the destination "
	   "directory can be specified (default: " MICROCODE_DIR_DEFAULT ")",
	  40 },
	{ "write-to", 'w', "file", 0,
	   "Write selected microcodes to a file in binary format.  "
	   "The binary format is suitable to be uploaded to the kernel",
	  40 },
	{ "write-earlyfw", IUCODE_ARGP_EIRFS, "file", 0,
	   "Write selected microcodes to an early initramfs file, which "
	   "should be prepended to the regular initramfs",
	  40 },
	{ "write-named-to", 'W', "directory", 0,
	   "Write selected microcodes to files in the specified directory, "
	   "in binary format.  The file name will reflect the microcode "
	   "signature, mask and revision",
	  41 },
	{ "write-all-named-to", IUCODE_ARGP_WRITENAMEDALL, "directory", 0,
	   "Write every microcode to files in the specified directory, "
	   "in binary format.  The file name will reflect the microcode "
	   "signature, mask and revision.  This is the only way to write "
	   "out every revision of a microcode",
	  42 },

	{ "overwrite", IUCODE_ARGP_UNLINK, NULL, 0,
	   "Unlink (remove) destination files before writing",
	  45 },
	{ "no-overwrite", IUCODE_ARGP_NOUNLINK, NULL, 0,
	   "Do not remove existing files (default)",
	  45 },

	{ "mini-earlyfw", IUCODE_ARGP_MINSIZE_EIRFS, NULL, 0,
	  "Optimize the early initramfs cpio container for minimal size.  "
	  "The microcode data file will not be available to the regular "
	  "initramfs, and tools might complain about the non-standard "
	  "cpio block size",
	  48 },
	{ "normal-earlyfw", IUCODE_ARGP_DFLSIZE_EIRFS, NULL, 0,
	  "Write a normal-sized early initramfs (default)",
	  48 },

	{ "strict-checks", IUCODE_ARGP_STRICTCHK, NULL, 0,
	   "Perform strict checks on the microcode data (default)",
	  50 },
	{ "no-strict-checks", IUCODE_ARGP_NOSTRICTCHK, NULL, 0,
	   "Perform less strict checks on the microcode data",
	  51 },

	{ "ignore-broken", IUCODE_ARGP_IGNOREBROKEN, NULL, 0,
	   "Skip broken microcode entries instead of aborting",
	  55 },
	{ "no-ignore-broken", IUCODE_ARGP_NOIGNOREBROKEN, NULL, 0,
	   "Abort on broken microcode entries (default)",
	  56 },

	{ .name = NULL },
};
static const char cmdline_nonarg_doc[] = "[[-t<type>] filename] ...";

static const char * const cmdline_scan_system_tbl[] = { "auto", "fast", "exact", NULL };

static int new_filename(const char * const fn,
			const intel_ucode_file_type_t ftype)
{
	struct filename_list **p, *n;
	size_t s, l;

	l = strlen(fn);
	if (l > 1 && fn[l-1] == '/')
		l--;

	if (!l)
		return EINVAL;

	s = sizeof(struct filename_list) + l + 1;
	n = malloc(s);
	if (!n)
		return ENOMEM;

	memset(n, 0, s);
	memcpy(n->path, fn, l);
	n->type = ftype;

	/* tail-add */
	p = &input_files;
	while (*p)
		p = &((*p)->next);
	*p = n;

	return 0;
}

static void free_filename_list(void) __attribute__((unused));
static void free_filename_list(void)
{
	struct filename_list *p, *q;

	p = input_files;

	while (p) {
		q = p;
		p = p->next;
		free(q);
	}
	input_files = NULL;
}

/* -s ! | [!]cpuid[,[pf_mask][,[<revmatch_operator>]rev]] */
static int cmdline_parse_ucode_filter(const char *arg)
{
	char *p;
	uint32_t acpuid, amask;
	int32_t arev;
	int invert, arev_match;

	amask = 0;
	invert = 0;
	arev = 0;

	while (isspace(*arg))
		arg++;
	if (*arg == '!') {
		invert = 1;
		arg++;

		/* handle -s ! */
		if (isspace(*arg)) {
			while (isspace(*arg))
				arg++;
			if (! *arg)
			    	return EINVAL;
		}
		if (! *arg) {
			filter_list_allow = 0;
			return 0;
		}
	}

	/* cpuid, mandatory */
	if (!*arg || parse_u32(arg, &p, 0, &acpuid))
		return EINVAL;
	while (isspace(*p))
		p++;

	/* pf_mask, optional */
	if (*p == ',') {
		p++;
		if (*p != ',') {
			arg = p;
			if (!*arg || parse_u32(arg, &p, 0, &amask))
				return EINVAL;
		} /* else amask = MATCH_ANY */
		while (isspace(*p))
			p++;
	} else if (*p) {
		return EINVAL;
	}

	/* rev, optional */
	if (*p == ',') {
		p++;
		while (isspace(*p))
			p++;
		if (!*p)
			return EINVAL;

		/* revison match operator, optional */
		int i = 0;
		while (i < IUCODE_REVFLT_SIZE &&
		       (!iuc_rev_match_mode_s[i] ||
		        strncasecmp(p, iuc_rev_match_mode_s[i],
			            strlen(iuc_rev_match_mode_s[i]))))
			i++;
		if (i < IUCODE_REVFLT_SIZE) {
			arev_match = i;
			p += strlen(iuc_rev_match_mode_s[i]);
		} else {
			arev_match = IUCODE_REVFLT_EQ;
		}

		/* revision */
		arg = p;
		if (!*arg || parse_s32e(arg, &p, 0, &arev))
			return EINVAL;
		while (isspace(*p))
			p++;
	} else {
		arev_match = IUCODE_REVFLT_ANY;
	}
	if (*p) {
		return EINVAL;
	}

	if (!invert)
		filter_list_allow = 0;

	return cmdline_queue_ucode_filter(acpuid, amask, arev, arev_match, invert);
}

/* YYYY-MM-DD */
static int cmdline_get_date(const char *arg, uint32_t *d)
{
	unsigned long int year, month, day;
	char *p;

	errno = 0;
	year = strtoul(arg, &p, 10);
	if (errno || p == arg || *p != '-')
		return EINVAL;
	arg = ++p;
	month = strtoul(arg, &p, 10);
	if (errno || p == arg || *p != '-')
		return EINVAL;
	arg = ++p;
	day = strtoul(arg, &p, 10);
	if (errno || p == arg)
		return EINVAL;
	while (isspace(*p))
		p++;
	if (*p)
		return EINVAL;

	if (year > 9999 || month > 99 || day > 99)
		return EINVAL;

	/* Encode in BCD: YYYYMMDD */
	*d = (year / 1000)     << 28 |
	     (year / 100 % 10) << 24 |
	     (year / 10 % 10)  << 20 |
	     (year % 10)       << 16 |
	     (month / 10)      << 12 |
	     (month % 10)      << 8 |
	     (day / 10)        << 4 |
	     (day % 10);

	return 0;
}

static int cmdline_get_int(const char *arg, int pmin, int pmax, int *d)
{
	char *p;
	long int l;

	if (!arg)
		return 0;

	errno = 0;
	l = strtol(arg, &p, 10);
	if (errno || p == arg)
		return errno ? errno : EINVAL;
	if (l > INT32_MAX || l < INT32_MIN)
		return ERANGE;
	if (l < pmin || l > pmax)
		return EINVAL;

	while (isspace(*p))
		p++;
	if (*p)
		return EINVAL;

	if (d)
		*d = (int) l;

	return 0;
}

/* note: does not tolerate trailing blanks */
static int cmdline_get_enumstr(const char *arg, const char * const table[],
			       int *d)
{
	int r = 0;

	if (!arg || !table)
		return 0;

	while (table[r]) {
		if (!strcasecmp(arg, table[r])) {
			if (d)
				*d = r;
			return 0;
		}
		r++;
	}

	return ENOENT;
}

static error_t cmdline_do_parse_arg(int key, char *arg,
				    struct argp_state *state)
{
	int rc;

	switch (key) {
	case 'h':
		argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
		break; /* usually not reached */

	case 'q':
		verbosity = 0;
		break;
	case 'v':
		if (verbosity < 5)
			verbosity++;
		break;

	case 'L':
		list_all_microcodes = 1;
		break;
	case 'l':
		list_sel_microcodes = 1;
		break;

	case 't':
		if (strlen(arg) > 1)
			argp_error(state, "unknown file type: '%s'", arg);
		switch (*arg) {
		case 'd': /* .dat */
			ucfiletype = INTEL_UC_FT_DAT;
			break;
		case 'b': /* .bin */
			ucfiletype = INTEL_UC_FT_BIN;
			break;
		case 'r': /* search inside binary data */
			ucfiletype = INTEL_UC_FT_SCAN;
			break;
		case 'a': /* any (detect) */
			ucfiletype = INTEL_UC_FT_UNKNOWN;
			break;
		default:
			argp_error(state, "unknown file type: '%c'", *arg);
		}
		break;

	case 'k':
		if (command_line_actions & IUCODE_DO_UPLOADUC)
			argp_error(state,
				   "-k option can be specified only once");

		if (arg)
			upload_microcode = strdup(arg);
		else
			upload_microcode = strdup(MICROCODE_DEVICE_DEFAULT);

		command_line_actions |= IUCODE_DO_UPLOADUC;
		break;
	case 'K':
		if (command_line_actions & IUCODE_DO_WRITEFW)
			argp_error(state,
				   "-K option can be specified only once");

		if (arg)
			write_firmware = strdup(arg);
		else
			write_firmware = strdup(MICROCODE_DIR_DEFAULT);

		command_line_actions |= IUCODE_DO_WRITEFW;
		break;
	case 'w':
		if (command_line_actions & IUCODE_DO_WRITEUC)
			argp_error(state,
				   "-w option can be specified only once");

		write_microcode = strdup(arg);
		command_line_actions |= IUCODE_DO_WRITEUC;
		break;
	case IUCODE_ARGP_EIRFS:
		if (command_line_actions & IUCODE_DO_WRITEFWE)
			argp_error(state,
				   "--write-earlyfw option can be specified only once");

		write_early_firmware = strdup(arg);
		command_line_actions |= IUCODE_DO_WRITEFWE;
		break;
	case 'W':
		if (command_line_actions & IUCODE_DO_WRITEFWN)
			argp_error(state,
				   "-W option can be specified only once");

		write_named = strdup(arg);

		command_line_actions |= IUCODE_DO_WRITEFWN;
		break;
	case IUCODE_ARGP_WRITENAMEDALL:
		if (command_line_actions & IUCODE_DO_WRITFWNA)
			argp_error(state,
				   "--write-all-named-to option can be specified only once");

		write_named_all = strdup(arg);

		command_line_actions |= IUCODE_DO_WRITFWNA;
		break;


	case IUCODE_ARGP_UNLINK:
		unlink_files = 1;
		break;
	case IUCODE_ARGP_NOUNLINK:
		unlink_files = 0;
		break;

	case IUCODE_ARGP_MINSIZE_EIRFS:
		cpio_blocksize = 16; /* minimum sane alignment for x86 */
		cpio_parentdirs = 0; /* cut down lots of headers */
		break;
	case IUCODE_ARGP_DFLSIZE_EIRFS:
		cpio_blocksize = LINUX_CPIO_BLK_SIZE;
		cpio_parentdirs = 1;
		break;

	case 's':
		rc = cmdline_parse_ucode_filter(arg);
		switch (rc) {
		case 0:
			break; /* success */
		case EINVAL:
			argp_error(state, "invalid filter: '%s'", arg);
			break; /* not reached */
		default:
			argp_failure(state, EXIT_SWFAILURE, rc,
				     "could not queue filter '%s'", arg);
		}
		command_line_actions |= IUCODE_F_UCSELECT;
		break;

	case 'S':
		/*
		 * -S and --scan-system cannot be handled the same way
		 * because -S cannot be made OPTION_ARG_OPTIONAL: it would
		 * break command-line backwards compatibility when people
		 * specify several short options together and -S is not the
		 * last option in the chain
		 */
		if (command_line_actions & IUCODE_DO_SELPROC)
			argp_error(state,
				   "--scan-system option can be specified only once");
		/*
		 * note: the pfm field of the queue filter item is used to
		 * encode the scan-system strategy.
		 */
		rc = cmdline_queue_ucode_filter(IUCODE_FILTERMASK_SCANCPUS, 0, 0, 0, 0);
		if (rc)
			argp_failure(state, EXIT_SWFAILURE, rc,
				     "could not queue --scan-system action");
		command_line_actions |= IUCODE_DO_SELPROC | IUCODE_F_UCSELECT;
		break;
	case IUCODE_ARGP_SCANSYSTEMOPT:
		if (command_line_actions & IUCODE_DO_SELPROC)
			argp_error(state,
				   "--scan-system option can be specified only once");

		int scan_system_strategy = 0;
		if (cmdline_get_int(arg, 0, 2, &scan_system_strategy) &&
		    cmdline_get_enumstr(arg, cmdline_scan_system_tbl, &scan_system_strategy))
			argp_error(state, "invalid --scan-system mode: '%s'", arg);

		/*
		 * note: the pfm field of the queue filter item is used to
		 * encode the scan-system strategy.
		 */
		rc = cmdline_queue_ucode_filter(IUCODE_FILTERMASK_SCANCPUS,
		                                (uint32_t)scan_system_strategy,
						0, 0, 0);
		if (rc)
			argp_failure(state, EXIT_SWFAILURE, rc,
				     "could not queue --scan-system action");
		command_line_actions |= IUCODE_DO_SELPROC | IUCODE_F_UCSELECT;
		break;

	case IUCODE_ARGP_DATEBEFORE:
	case IUCODE_ARGP_DATEAFTER:
		if (cmdline_get_date(arg, (key == IUCODE_ARGP_DATEBEFORE) ?
					   &datefilter_max : &datefilter_min))
			argp_error(state, "invalid date: '%s'", arg);
		command_line_actions |= IUCODE_F_UCSELECT;
		break;
	case IUCODE_ARGP_DATEFSTRICT:
		datefilter_loose = 0;
		break;
	case IUCODE_ARGP_DATEFLOOSE:
		datefilter_loose = 1;
		break;

	case IUCODE_ARGP_STRICTCHK:
		strict_checks = 1;
		break;
	case IUCODE_ARGP_NOSTRICTCHK:
		strict_checks = 0;
		break;
	case IUCODE_ARGP_IGNOREBROKEN:
		ignore_bad_ucode = 1;
		break;
	case IUCODE_ARGP_NOIGNOREBROKEN:
		ignore_bad_ucode = 0;
		break;
	case IUCODE_ARGP_DOWNGRADE:
		allow_downgrade = 1;
		break;
	case IUCODE_ARGP_NODOWNGRADE:
		allow_downgrade = 0;
		break;

	case ARGP_KEY_ARG: /* NON-OPTION ARGUMENTS */
		rc = new_filename(arg, ucfiletype);
		if (rc)
			argp_failure(state, EXIT_SWFAILURE, rc,
				     "could not add path '%s'", arg);
		command_line_actions |= IUCODE_DO_LOADFILE;
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp cmdline_argp = {
	.options  = cmdline_options,
	.parser   = cmdline_do_parse_arg,
	.args_doc = cmdline_nonarg_doc,
	.doc      = cmdline_doc };

int main(int argc, char *argv[])
{
	int rc;

	progname = argv[0];

	sanitize_std_fds();

	argp_err_exit_status = EXIT_USAGE;
	argp_program_version = program_version;
	argp_program_bug_address = program_bug_address;
	argp_parse(&cmdline_argp, argc, argv, ARGP_IN_ORDER, NULL, NULL);

	if (!command_line_actions) {
		print_msg(1, "nothing to do...");
		goto do_nothing;
	}

	if (process_ucode_filter_queue()) {
		rc = EXIT_SWFAILURE;
		goto err_exit;
	}

	if (command_line_actions & IUCODE_DO_LOADFILE) {
		struct filename_list *fn = input_files;
		while (fn && next_bundle_id) {
			switch (load_intel_microcode(fn->path, fn->type)) {
			case 0:
				break;
			case ENOTSUP:
				rc = EXIT_USAGE;
				goto err_exit;
			default:
				if (!ignore_bad_ucode) {
					rc = EXIT_SWFAILURE;
					goto err_exit;
				}
			}
			fn = fn->next;
		}
		if (!next_bundle_id) {
			/* too many bundles: gid overflow */
			print_err("too many data files");
			rc = EXIT_SWFAILURE;
			goto err_exit;
		}

		if (microcode_bundles && do_process_microcodes()) {
			rc = EXIT_SWFAILURE;
			goto err_exit;
		}
	}

	/* flush --list-* output if it is still pending */
	fflush(stdout);

	if (command_line_actions & IUCODE_DOMASK_NEEDSUC) {
		if (microcodes) {
			rc = uclist_annotate_extsig_dup(microcodes);
			if (!rc && upload_microcode)
				rc = do_upload_microcode(upload_microcode);
			if (!rc && write_microcode)
				rc = do_write_microcode(write_microcode, 0);
			if (!rc && write_early_firmware)
				rc = do_write_microcode(write_early_firmware, 1);
			if (!rc && write_firmware)
				rc = do_write_firmware(write_firmware);
			if (!rc && write_named)
				rc = do_write_named(write_named, microcodes);
			if (!rc && write_named_all)
				rc = do_write_named(write_named_all, all_microcodes);

			if (rc) {
				rc = EXIT_SWFAILURE;
				goto err_exit;
			}
		} else {
			if (filter_list_active()) {
				print_msg(1, "No valid microcodes were selected, nothing to do...");
			} else {
				print_msg(1, "No valid microcodes were loaded, nothing to do...");
			}
		}
	}

do_nothing:
	rc = 0;
err_exit:

	/* Disable all of this cleanup for some speedup... */
#ifdef VALGRIND_BUILD
	free(write_microcode);
	free(upload_microcode);
	free(write_firmware);
	free(write_early_firmware);
	free(write_named);
	free(write_named_all);

	free_filter_list(uc_filter_list);
	uc_filter_list = NULL;
	free_uclist(microcodes);
	microcodes = NULL;
	free_uclist(all_microcodes);
	all_microcodes = NULL;
	free_intel_microcode_bundles();
	free_filename_list();
#endif /* VALGRIND_BUILD */

	return rc;
}
