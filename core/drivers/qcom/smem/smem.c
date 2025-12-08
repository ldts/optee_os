// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015, Sony Mobile Communications AB.
 * Copyright (c) 2012-2013, The Linux Foundation. All rights reserved.
 */

#include <initcall.h>
#include <mm/core_memprot.h>
#include <smem.h>
#include <stdio.h>
#include <string.h>
#include <util.h>

/* Kernel porting add-ons */
#define __ALIGN_MASK(x, mask)					\
	({							\
		typeof(mask) __mask = (mask);			\
		((x) + __mask) & ~__mask;			\
	})
#define ALIGN(x, a)		__ALIGN_MASK((x), (typeof(x))(a) - 1)

#define WARN_ON(condition)					\
	((condition) ? (EMSG("WARNING at %s:%d/%s()!\n",	\
		__FILE__, __LINE__, __func__), 1) : 0)

/* Little endian abstractions */
#define cpu_to_le16(x)		(x)
#define cpu_to_le32(x)		(x)
#define cpu_to_le64(x)		(x)
#define le16_to_cpu(x)		(x)
#define le32_to_cpu(x)		(x)
#define le64_to_cpu(x)		(x)

#define ENOENT			2

typedef uint64_t __le64;
typedef uint64_t u64;
typedef uint32_t __le32;
typedef uint32_t u32;
typedef uint16_t __le16;
typedef uint16_t u16;
typedef uint8_t __le8;
typedef uint8_t u8;

/*
 * The Qualcomm shared memory system is a allocate only heap structure that
 * consists of one of more memory areas that can be accessed by the processors
 * in the SoC.
 *
 * All systems contains a global heap, accessible by all processors in the SoC,
 * with a table of contents data structure (@smem_header) at the beginning of
 * the main shared memory block.
 *
 * The global header contains meta data for allocations as well as a fixed list
 * of 512 entries (@smem_global_entry) that can be initialized to reference
 * parts of the shared memory space.
 *
 *
 * In addition to this global heap a set of "private" heaps can be set up at
 * boot time with access restrictions so that only certain processor pairs can
 * access the data.
 *
 * These partitions are referenced from an optional partition table
 * (@smem_ptable), that is found 4kB from the end of the main smem region. The
 * partition table entries (@smem_ptable_entry) lists the involved processors
 * (or hosts) and their location in the main shared memory region.
 *
 * Each partition starts with a header (@smem_partition_header) that identifies
 * the partition and holds properties for the two internal memory regions. The
 * two regions are cached and non-cached memory respectively. Each region
 * contain a link list of allocation headers (@smem_private_entry) followed by
 * their data.
 *
 * Items in the non-cached region are allocated from the start of the partition
 * while items in the cached region are allocated from the end. The free area
 * is hence the region between the cached and non-cached offsets. The header of
 * cached items comes after the data.
 *
 * Version 12 (SMEM_GLOBAL_PART_VERSION) changes the item alloc/get procedure
 * for the global heap. A new global partition is created from the global heap
 * region with partition type (SMEM_GLOBAL_HOST) and the max smem item count is
 * set by the bootloader.
 *
 * To synchronize allocations in the shared memory heaps a remote spinlock must
 * be held - currently lock number 3 of the sfpb or tcsr is used for this on all
 * platforms.
 *
 */

/*
 * The version member of the smem header contains an array of versions for the
 * various software components in the SoC. We verify that the boot loader
 * version is a valid version as a sanity check.
 */
#define SMEM_MASTER_SBL_VERSION_INDEX	7
#define SMEM_GLOBAL_HEAP_VERSION	11
#define SMEM_GLOBAL_PART_VERSION	12

/*
 * The first 8 items are only to be allocated by the boot loader while
 * initializing the heap.
 */
#define SMEM_ITEM_LAST_FIXED	8

/* Highest accepted item number, for both global and private heaps */
#define SMEM_ITEM_COUNT		512

/* Processor/host identifier for the application processor */
#define SMEM_HOST_APPS		0

/* Processor/host identifier for the global partition */
#define SMEM_GLOBAL_HOST	0xfffe

/* Max number of processors/hosts in a system */
#define SMEM_HOST_COUNT		20

/*
 * struct smem_proc_comm - proc_comm communication struct (legacy)
 * @command:	current command to be executed
 * @status:	status of the currently requested command
 * @params:	parameters to the command
 */
struct smem_proc_comm {
	__le32 command;
	__le32 status;
	__le32 params[2];
};

/*
 * struct smem_global_entry - entry to reference smem items on the heap
 * @allocated:	boolean to indicate if this entry is used
 * @offset:	offset to the allocated space
 * @size:	size of the allocated space, 8 byte aligned
 * @aux_base:	base address for the memory region used by this unit, or 0 for
 *		the default region. bits 0,1 are reserved
 */
struct smem_global_entry {
	__le32 allocated;
	__le32 offset;
	__le32 size;
	__le32 aux_base; /* bits 1:0 reserved */
};

#define AUX_BASE_MASK		0xfffffffc

/*
 * struct smem_header - header found in beginning of primary smem region
 * @proc_comm:		proc_comm communication interface (legacy)
 * @version:		array of versions for the various subsystems
 * @initialized:	boolean to indicate that smem is initialized
 * @free_offset:	index of the first unallocated byte in smem
 * @available:		number of bytes available for allocation
 * @reserved:		reserved field, must be 0
 * @toc:		array of references to items
 */
struct smem_header {
	struct smem_proc_comm proc_comm[4];
	__le32 version[32];
	__le32 initialized;
	__le32 free_offset;
	__le32 available;
	__le32 reserved;
	struct smem_global_entry toc[SMEM_ITEM_COUNT];
};

/*
 * struct smem_ptable_entry - one entry in the @smem_ptable list
 * @offset:	offset, within the main shared memory region, of the partition
 * @size:	size of the partition
 * @flags:	flags for the partition (currently unused)
 * @host0:	first processor/host with access to this partition
 * @host1:	second processor/host with access to this partition
 * @cacheline:	alignment for "cached" entries
 * @reserved:	reserved entries for later use
 */
struct smem_ptable_entry {
	__le32 offset;
	__le32 size;
	__le32 flags;
	__le16 host0;
	__le16 host1;
	__le32 cacheline;
	__le32 reserved[7];
};

/*
 * struct smem_ptable - partition table for the private partitions
 * @magic:	magic number, must be SMEM_PTABLE_MAGIC
 * @version:	version of the partition table
 * @num_entries: number of partitions in the table
 * @reserved:	for now reserved entries
 * @entry:	list of @smem_ptable_entry for the @num_entries partitions
 */
struct smem_ptable {
	u8 magic[4];
	__le32 version;
	__le32 num_entries;
	__le32 reserved[5];
	struct smem_ptable_entry entry[];
};

static const u8 SMEM_PTABLE_MAGIC[] = { 0x24, 0x54, 0x4f, 0x43 }; /* "$TOC" */

/*
 * struct smem_partition_header - header of the partitions
 * @magic:	magic number, must be SMEM_PART_MAGIC
 * @host0:	first processor/host with access to this partition
 * @host1:	second processor/host with access to this partition
 * @size:	size of the partition
 * @offset_free_uncached: offset to the first free byte of uncached memory in
 *		this partition
 * @offset_free_cached: offset to the first free byte of cached memory in this
 *		partition
 * @reserved:	for now reserved entries
 */
struct smem_partition_header {
	u8 magic[4];
	__le16 host0;
	__le16 host1;
	__le32 size;
	__le32 offset_free_uncached;
	__le32 offset_free_cached;
	__le32 reserved[3];
};

/*
 * struct smem_partition - describes smem partition
 * @virt_base:	starting virtual address of partition
 * @phys_base:	starting physical address of partition
 * @cacheline:	alignment for "cached" entries
 * @size:	size of partition
 */
struct smem_partition {
	void *virt_base;
	paddr_t phys_base;
	size_t cacheline;
	size_t size;
};

static const u8 SMEM_PART_MAGIC[] = { 0x24, 0x50, 0x52, 0x54 };

/*
 * struct smem_private_entry - header of each item in the private partition
 * @canary:	magic number, must be SMEM_PRIVATE_CANARY
 * @item:	identifying number of the smem item
 * @size:	size of the data, including padding bytes
 * @padding_data: number of bytes of padding of data
 * @padding_hdr: number of bytes of padding between the header and the data
 * @reserved:	for now reserved entry
 */
struct smem_private_entry {
	u16 canary; /* bytes are the same so no swapping needed */
	__le16 item;
	__le32 size; /* includes padding bytes */
	__le16 padding_data;
	__le16 padding_hdr;
	__le32 reserved;
};

#define SMEM_PRIVATE_CANARY	0xa5a5

/*
 * struct smem_info - smem region info located after the table of contents
 * @magic:	magic number, must be SMEM_INFO_MAGIC
 * @size:	size of the smem region
 * @base_addr:	base address of the smem region
 * @reserved:	for now reserved entry
 * @num_items:	highest accepted item number
 */
struct smem_info {
	u8 magic[4];
	__le32 size;
	__le32 base_addr;
	__le32 reserved;
	__le16 num_items;
};

static const u8 SMEM_INFO_MAGIC[] = { 0x53, 0x49, 0x49, 0x49 }; /* SIII */

/*
 * struct smem_region - representation of a chunk of memory used for smem
 * @aux_base:	identifier of aux_mem base
 * @virt_base:	virtual base address of memory with this aux_mem identifier
 * @size:	size of the memory region
 */
struct smem_region {
	paddr_t aux_base;
	void *virt_base;
	size_t size;
};

/*
 * struct qcom_smem - device data for the smem device
 * @ptable: virtual base of partition table
 * @global_partition: describes for global partition when in use
 * @partitions: list of partitions of current processor/host
 * @item_count: max accepted item number
 * @num_regions: number of @regions
 * @regions:	list of the memory regions defining the shared memory
 */
struct qcom_smem {
	u32 item_count;
	struct smem_ptable *ptable;
	struct smem_partition global_partition;
	struct smem_partition partitions[SMEM_HOST_COUNT];

	unsigned int num_regions;
	struct smem_region regions[];
};

/* Partition header helpers */
static void *phdr_to_last_uncached_entry(struct smem_partition_header *phdr)
{
	unsigned long base = (unsigned long)phdr;
	unsigned long off = le32_to_cpu(phdr->offset_free_uncached);

	return (void *)(base + off);
}

static struct smem_private_entry *
phdr_to_first_cached_entry(struct smem_partition_header *phdr, size_t cacheline)
{
	unsigned long base = (unsigned long)phdr;
	unsigned long off = le32_to_cpu(phdr->size) -
			    ALIGN(sizeof(struct smem_private_entry), cacheline);

	return (struct smem_private_entry *)(base + off);
}

static void *phdr_to_last_cached_entry(struct smem_partition_header *phdr)
{
	unsigned long base = (unsigned long)phdr;
	unsigned long off = le32_to_cpu(phdr->offset_free_cached);

	return (void *)(base + off);
}

static struct smem_private_entry *
phdr_to_first_uncached_entry(struct smem_partition_header *phdr)
{
	unsigned long base = (unsigned long)phdr;
	unsigned long off = sizeof(*phdr);

	return (struct smem_private_entry *)(base + off);
}

static struct smem_private_entry *
uncached_entry_next(struct smem_private_entry *e)
{
	unsigned long base = (unsigned long)e;
	unsigned long off = sizeof(*e) +
			    le16_to_cpu(e->padding_hdr) +
			    le32_to_cpu(e->size);

	return (struct smem_private_entry *)(base + off);
}

static struct smem_private_entry *
cached_entry_next(struct smem_private_entry *e, size_t cacheline)
{
	unsigned long base = (unsigned long)e;
	unsigned long off = le32_to_cpu(e->size) +
			    ALIGN(sizeof(*e), cacheline);

	return (struct smem_private_entry *)(base - off);
}

static void *uncached_entry_to_item(struct smem_private_entry *e)
{
	unsigned long base = (unsigned long)e;
	unsigned long off = sizeof(*e) + le16_to_cpu(e->padding_hdr);

	return (void *)(base + off);
}

static void *cached_entry_to_item(struct smem_private_entry *e)
{
	unsigned long base = (unsigned long)e;
	unsigned long off = le32_to_cpu(e->size);

	return (void *)(base - off);
}

/* Pointer to the one and only smem handle */
static struct qcom_smem *__smem;

/*
 * qcom_smem_is_available() - Check if SMEM is available
 *
 * Return: true if SMEM is available, false otherwise.
 */
bool qcom_smem_is_available(void)
{
	return !!__smem;
}

static inline void le32_add_cpu(__le32 *var, u32 val)
{
	*var = cpu_to_le32(le32_to_cpu(*var) + val);
}

static int qcom_smem_alloc_private(struct smem_partition *part,
				   unsigned int item,
				   size_t size)
{
	struct smem_private_entry *hdr, *end;
	struct smem_partition_header *phdr;
	size_t alloc_size;
	void *cached;
	void *p_end;

	phdr = (struct smem_partition_header *)part->virt_base;
	p_end = (void *)((unsigned long)phdr + part->size);

	hdr = phdr_to_first_uncached_entry(phdr);
	end = phdr_to_last_uncached_entry(phdr);
	cached = phdr_to_last_cached_entry(phdr);

	if (WARN_ON((void *)end > p_end || cached > p_end))
		return -1; /* EINVAL */

	while (hdr < end) {
		if (hdr->canary != SMEM_PRIVATE_CANARY)
			goto bad_canary;
		if (le16_to_cpu(hdr->item) == item)
			return -1; /* EEXIST */

		hdr = uncached_entry_next(hdr);
	}

	if (WARN_ON((void *)hdr > p_end))
		return -1;  /* EINVAL */

	/* Check that we don't grow into the cached region */
	alloc_size = sizeof(*hdr) + ALIGN(size, 8);
	if ((unsigned long)hdr + alloc_size > (unsigned long)cached) {
		EMSG("Out of memory\n");
		return -1; /* ENOSPC */
	}

	hdr->canary = SMEM_PRIVATE_CANARY;
	hdr->item = cpu_to_le16(item);
	hdr->size = cpu_to_le32(ALIGN(size, 8));
	hdr->padding_data = cpu_to_le16(le32_to_cpu(hdr->size) - size);
	hdr->padding_hdr = 0;

	le32_add_cpu(&phdr->offset_free_uncached, alloc_size);

	return 0;
bad_canary:
	EMSG("Found invalid canary in hosts %hu:%hu partition\n",
	     le16_to_cpu(phdr->host0), le16_to_cpu(phdr->host1));

	return -1; /* EINVAL */
}

static int qcom_smem_alloc_global(struct qcom_smem *smem,
				  unsigned int item,
				  size_t size)
{
	struct smem_global_entry *entry;
	struct smem_header *header;

	header = smem->regions[0].virt_base;
	entry = &header->toc[item];
	if (entry->allocated)
		return -1; /* EEXIST */

	size = ALIGN(size, 8);
	if (WARN_ON(size > le32_to_cpu(header->available)))
		return -1; /* ENOMEM */

	entry->offset = header->free_offset;
	entry->size = cpu_to_le32(size);

	entry->allocated = cpu_to_le32(1);

	le32_add_cpu(&header->free_offset, size);
	le32_add_cpu(&header->available, -size);

	return 0;
}

/**
 * qcom_smem_alloc() - allocate space for a smem item
 * @host:	remote processor id, or -1
 * @item:	smem item handle
 * @size:	number of bytes to be allocated
 *
 * Allocate space for a given smem item of size @size, given that the item is
 * not yet allocated.
 */
int qcom_smem_alloc(unsigned int host, unsigned int item, size_t size)
{
	struct smem_partition *part;
	int ret;

	if (!__smem)
		return -1; /* EPROBE_DEFER */

	if (item < SMEM_ITEM_LAST_FIXED) {
		EMSG("Rejecting allocation of static entry %d\n", item);
		return -1; /* EINVAL */
	}

	if (WARN_ON(item >= __smem->item_count))
		return -1; /* EINVAL */

	if (host < SMEM_HOST_COUNT && __smem->partitions[host].virt_base) {
		part = &__smem->partitions[host];
		ret = qcom_smem_alloc_private(part, item, size);
	} else if (__smem->global_partition.virt_base) {
		part = &__smem->global_partition;
		ret = qcom_smem_alloc_private(part, item, size);
	} else {
		ret = qcom_smem_alloc_global(__smem, item, size);
	}

	return ret;
}

static void *qcom_smem_get_global(struct qcom_smem *smem,
				  unsigned int item,
				  size_t *size)
{
	struct smem_header *header;
	struct smem_region *region;
	struct smem_global_entry *entry;
	u64 entry_offset;
	u32 e_size;
	u32 aux_base;
	unsigned int i;

	header = smem->regions[0].virt_base;
	entry = &header->toc[item];
	if (!entry->allocated)
		return NULL;

	aux_base = le32_to_cpu(entry->aux_base) & AUX_BASE_MASK;

	for (i = 0; i < smem->num_regions; i++) {
		region = &smem->regions[i];

		if ((u32)region->aux_base == aux_base || !aux_base) {
			e_size = le32_to_cpu(entry->size);
			entry_offset = le32_to_cpu(entry->offset);

			if (WARN_ON(e_size + entry_offset > region->size))
				return NULL;

			if (size)
				*size = e_size;

			return (void *)((unsigned long)region->virt_base +
					entry_offset);
		}
	}

	return NULL;
}

static void *qcom_smem_get_private(struct smem_partition *part,
				   unsigned int item,
				   size_t *size)
{
	struct smem_private_entry *e, *end;
	struct smem_partition_header *phdr;
	void *item_ptr, *p_end;
	u32 padding_data;
	u32 e_size;

	phdr = (struct smem_partition_header *)part->virt_base;
	p_end = (void *)((unsigned long)phdr + part->size);

	e = phdr_to_first_uncached_entry(phdr);
	end = phdr_to_last_uncached_entry(phdr);

	while (e < end) {
		if (e->canary != SMEM_PRIVATE_CANARY)
			goto invalid_canary;

		if (le16_to_cpu(e->item) == item) {
			if (size) {
				e_size = le32_to_cpu(e->size);
				padding_data = le16_to_cpu(e->padding_data);

				if (WARN_ON(e_size > part->size ||
					    padding_data > e_size))
					return NULL;

				*size = e_size - padding_data;
			}

			item_ptr = uncached_entry_to_item(e);
			if (WARN_ON(item_ptr > p_end))
				return NULL;

			return item_ptr;
		}

		e = uncached_entry_next(e);
	}

	if (WARN_ON((void *)e > p_end))
		return NULL;

	/* Item was not found in the uncached list, search the cached list */

	e = phdr_to_first_cached_entry(phdr, part->cacheline);
	end = phdr_to_last_cached_entry(phdr);

	if (WARN_ON((void *)e < (void *)phdr || (void *)end > p_end))
		return NULL;

	while (e > end) {
		if (e->canary != SMEM_PRIVATE_CANARY)
			goto invalid_canary;

		if (le16_to_cpu(e->item) == item) {
			if (size) {
				e_size = le32_to_cpu(e->size);
				padding_data = le16_to_cpu(e->padding_data);

				if (WARN_ON(e_size > part->size ||
					    padding_data > e_size))
					return NULL;

				*size = e_size - padding_data;
			}

			item_ptr = cached_entry_to_item(e);
			if (WARN_ON(item_ptr < (void *)phdr))
				return NULL;

			return item_ptr;
		}

		e = cached_entry_next(e, part->cacheline);
	}

	if (WARN_ON((void *)e < (void *)phdr))
		return NULL;

	return NULL;

invalid_canary:
	EMSG("Found invalid canary in hosts %hu:%hu partition\n",
	     le16_to_cpu(phdr->host0), le16_to_cpu(phdr->host1));

	return NULL;
}

/**
 * qcom_smem_get() - resolve ptr of size of a smem item
 * @host:	the remote processor, or -1
 * @item:	smem item handle
 * @size:	pointer to be filled out with size of the item
 *
 * Looks up smem item and returns pointer to it. Size of smem
 * item is returned in @size.
 */
void *qcom_smem_get(unsigned int host, unsigned int item, size_t *size)
{
	struct smem_partition *part;
	void *ptr = NULL;

	if (!__smem)
		return ptr;

	if (WARN_ON(item >= __smem->item_count))
		return NULL;

	if (host < SMEM_HOST_COUNT && __smem->partitions[host].virt_base) {
		part = &__smem->partitions[host];
		ptr = qcom_smem_get_private(part, item, size);
	} else if (__smem->global_partition.virt_base) {
		part = &__smem->global_partition;
		ptr = qcom_smem_get_private(part, item, size);
	} else {
		ptr = qcom_smem_get_global(__smem, item, size);
	}

	return ptr;
}

/**
 * qcom_smem_get_free_space() - retrieve amount of free space in a partition
 * @host:	the remote processor identifying a partition, or -1
 *
 * To be used by smem clients as a quick way to determine if any new
 * allocations has been made.
 */
int qcom_smem_get_free_space(unsigned int host)
{
	struct smem_partition *part;
	struct smem_partition_header *phdr;
	struct smem_header *header;
	unsigned int ret;

	if (!__smem)
		return -1; /* EPROBE_DEFER */

	if (host < SMEM_HOST_COUNT && __smem->partitions[host].virt_base) {
		part = &__smem->partitions[host];
		phdr = part->virt_base;
		ret = le32_to_cpu(phdr->offset_free_cached) -
		      le32_to_cpu(phdr->offset_free_uncached);

		if (ret > le32_to_cpu(part->size))
			return -1;  /* EINVAL */
	} else if (__smem->global_partition.virt_base) {
		part = &__smem->global_partition;
		phdr = part->virt_base;
		ret = le32_to_cpu(phdr->offset_free_cached) -
		      le32_to_cpu(phdr->offset_free_uncached);

		if (ret > le32_to_cpu(part->size))
			return -1; /* EINVAL */
	} else {
		header = __smem->regions[0].virt_base;
		ret = le32_to_cpu(header->available);

		if (ret > __smem->regions[0].size)
			return -1; /* EINVAL */
	}

	return ret;
}

static int qcom_smem_get_sbl_version(struct qcom_smem *smem)
{
	struct smem_header *header;
	__le32 *versions;

	header = smem->regions[0].virt_base;
	versions = header->version;

	return le32_to_cpu(versions[SMEM_MASTER_SBL_VERSION_INDEX]);
}

static int qcom_smem_get_ptable(struct qcom_smem *smem,
				struct smem_ptable **ptable)
{
	struct smem_ptable *tmp;
	u32 version;

	tmp = smem->ptable;
	if (!tmp || !ptable)
		return -1;

	if (memcmp(tmp->magic, SMEM_PTABLE_MAGIC, sizeof(tmp->magic)))
		return -ENOENT;

	version = le32_to_cpu(tmp->version);
	if (version != 1) {
		EMSG("Unsupported partition header version %u\n", version);
		return -1; /* EINVAL */
	}

	*ptable = tmp;
	return 0;
}

static uint32_t qcom_smem_get_item_count(struct qcom_smem *smem)
{
	struct smem_ptable *ptable;
	struct smem_info *info;
	unsigned long base;
	unsigned long off;
	int rc;

	rc = qcom_smem_get_ptable(smem, &ptable);
	if (rc)
		return SMEM_ITEM_COUNT;

	base = (unsigned long)ptable->entry;
	off  = ptable->num_entries * sizeof(struct smem_info);
	info = (struct smem_info *)(base + off);

	if (memcmp(info->magic, SMEM_INFO_MAGIC, sizeof(info->magic)))
		return SMEM_ITEM_COUNT;

	return le16_to_cpu(info->num_items);
}

/*
 * Validate the partition header for a partition whose partition
 * table entry is supplied.  Returns a pointer to its header if
 * valid, or a null pointer otherwise.
 */
static struct smem_partition_header *
qcom_smem_partition_header(struct qcom_smem *smem,
			   struct smem_ptable_entry *entry, u16 host0,
			   u16 host1)
{
	struct smem_partition_header *header;
	u64 phys_addr;
	u32 size;

	phys_addr = smem->regions[0].aux_base + le32_to_cpu(entry->offset);
	header = phys_to_virt(phys_addr, MEM_AREA_RAM_NSEC,
			      le32_to_cpu(entry->size));

	if (!header)
		return NULL;

	if (memcmp(header->magic, SMEM_PART_MAGIC, sizeof(header->magic))) {
		EMSG("bad partition magic %4ph\n", header->magic);
		return NULL;
	}

	if (host0 != le16_to_cpu(header->host0)) {
		EMSG("bad host0 (%hu != %hu)\n",
		     host0, le16_to_cpu(header->host0));
		return NULL;
	}
	if (host1 != le16_to_cpu(header->host1)) {
		EMSG("bad host1 (%hu != %hu)\n",
		     host1, le16_to_cpu(header->host1));
		return NULL;
	}

	size = le32_to_cpu(header->size);
	if (size != le32_to_cpu(entry->size)) {
		EMSG("bad partition size (%u != %u)\n",
		     size, le32_to_cpu(entry->size));
		return NULL;
	}

	if (le32_to_cpu(header->offset_free_uncached) > size) {
		EMSG("bad partition free uncached (%u > %u)\n",
		     le32_to_cpu(header->offset_free_uncached), size);
		return NULL;
	}

	return header;
}

static int qcom_smem_set_global_partition(struct qcom_smem *smem)
{
	struct smem_partition_header *header;
	struct smem_ptable_entry *entry;
	struct smem_ptable *ptable;
	bool found = false;
	size_t i;
	int rc;

	if (smem->global_partition.virt_base) {
		EMSG("Already found the global partition\n");
		return -1;
	}

	rc = qcom_smem_get_ptable(smem, &ptable);
	if (rc)
		return rc;

	for (i = 0; i < le32_to_cpu(ptable->num_entries); i++) {
		entry = &ptable->entry[i];
		if (!le32_to_cpu(entry->offset))
			continue;

		if (!le32_to_cpu(entry->size))
			continue;

		if (le16_to_cpu(entry->host0) != SMEM_GLOBAL_HOST)
			continue;

		if (le16_to_cpu(entry->host1) == SMEM_GLOBAL_HOST) {
			found = true;
			break;
		}
	}

	if (!found) {
		EMSG("Missing entry for global partition\n");
		return -1;
	}

	header = qcom_smem_partition_header(smem, entry,
					    SMEM_GLOBAL_HOST, SMEM_GLOBAL_HOST);
	if (!header)
		return -1;

	smem->global_partition.virt_base = (void *)header;
	smem->global_partition.phys_base = smem->regions[0].aux_base +
					   le32_to_cpu(entry->offset);
	smem->global_partition.size = le32_to_cpu(entry->size);
	smem->global_partition.cacheline = le32_to_cpu(entry->cacheline);

	return 0;
}

static int
qcom_smem_enumerate_partitions(struct qcom_smem *smem, u16 local_host)
{
	struct smem_partition_header *header;
	struct smem_ptable_entry *entry;
	struct smem_ptable *ptable;
	u16 remote_host;
	u16 host0, host1;
	size_t i;
	int rc;

	rc = qcom_smem_get_ptable(smem, &ptable);
	if (rc)
		return rc;

	for (i = 0; i < le32_to_cpu(ptable->num_entries); i++) {
		entry = &ptable->entry[i];
		if (!le32_to_cpu(entry->offset))
			continue;

		if (!le32_to_cpu(entry->size))
			continue;

		host0 = le16_to_cpu(entry->host0);
		host1 = le16_to_cpu(entry->host1);
		if (host0 == local_host)
			remote_host = host1;
		else if (host1 == local_host)
			remote_host = host0;
		else
			continue;

		if (remote_host >= SMEM_HOST_COUNT) {
			EMSG("bad host %u\n", remote_host);
			return -1;
		}

		if (smem->partitions[remote_host].virt_base) {
			EMSG("duplicate host %u\n", remote_host);
			return -1;
		}

		header = qcom_smem_partition_header(smem, entry, host0, host1);
		if (!header)
			return -1;

		smem->partitions[remote_host].virt_base = (void *)header;
		smem->partitions[remote_host].phys_base =
			smem->regions[0].aux_base + le32_to_cpu(entry->offset);
		smem->partitions[remote_host].size = le32_to_cpu(entry->size);
		smem->partitions[remote_host].cacheline =
			le32_to_cpu(entry->cacheline);
	}

	return 0;
}

static int qcom_smem_map_toc(struct qcom_smem *smem, struct smem_region *region)
{
	u32 ptable_start;

	/* map starting 4K for smem header */
	region->virt_base = (void *)phys_to_virt(region->aux_base,
						 MEM_AREA_RAM_NSEC, SIZE_4K);
	ptable_start = region->aux_base + region->size - SIZE_4K;

	/* map last 4k for toc */
	smem->ptable = (void *)phys_to_virt(ptable_start,
					    MEM_AREA_RAM_NSEC, SIZE_4K);

	if (!region->virt_base || !smem->ptable)
		return 1;

	return 0;
}

static int qcom_smem_map_global(struct qcom_smem *smem, u32 size)
{
	u64 phys_addr = smem->regions[0].aux_base;

	smem->regions[0].size = size;
	smem->regions[0].virt_base = (void *)phys_to_virt(phys_addr,
							  MEM_AREA_RAM_NSEC,
							  size);
	if (!smem->regions[0].virt_base)
		return -1; /* ENOMEM */

	return 0;
}

static TEE_Result qcom_smem_init(void)
{
	const int num_regions = 1; /* Only one region supported on this port */
	struct smem_header *header = NULL;
	struct qcom_smem *smem = NULL;
	u32 version;
	u32 size;
	int ret;

	if (!core_mmu_add_mapping(MEM_AREA_RAM_NSEC, SMEM_BASE, SMEM_SIZE)) {
		EMSG("Can't add SMEM map");
		return TEE_ERROR_GENERIC;
	}

	smem = calloc(1, sizeof(struct smem_region) * num_regions +
		      sizeof(struct qcom_smem));
	if (!smem) {
		EMSG("Failed to allocate memory for smem\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	smem->regions[0].aux_base = SMEM_BASE;
	smem->regions[0].size = SMEM_SIZE;
	smem->num_regions = num_regions;

	ret = qcom_smem_map_toc(smem, &smem->regions[0]);
	if (ret)
		return TEE_ERROR_GENERIC;

	header = smem->regions[0].virt_base;

	if (le32_to_cpu(header->initialized) != 1 ||
	    le32_to_cpu(header->reserved)) {
		EMSG("SMEM is not initialized by SBL\n");
		return TEE_ERROR_NO_DATA;
	}

	size = header->available + header->free_offset;
	version = qcom_smem_get_sbl_version(smem);

	switch (version >> 16) {
	case SMEM_GLOBAL_PART_VERSION:
		ret = qcom_smem_set_global_partition(smem);
		if (ret < 0)
			return TEE_ERROR_GENERIC;

		smem->item_count = qcom_smem_get_item_count(smem);
		break;
	case SMEM_GLOBAL_HEAP_VERSION:
		ret = qcom_smem_map_global(smem, size);
		if (ret < 0)
			return TEE_ERROR_GENERIC;

		smem->item_count = SMEM_ITEM_COUNT;
		break;
	default:
		EMSG("Unsupported SMEM version 0x%x\n", version);
		return TEE_ERROR_GENERIC; /* EINVAL */
	}

	ret = qcom_smem_enumerate_partitions(smem, SMEM_HOST_APPS);
	if (ret < 0 && ret != -ENOENT) {
		EMSG("Failed to enumerate partitions\n");
		return TEE_ERROR_GENERIC;
	}
	__smem = smem;

	return TEE_SUCCESS;
}
early_init(qcom_smem_init);

