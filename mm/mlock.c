// SPDX-License-Identifier: GPL-2.0
/*
 *	linux/mm/mlock.c
 *
 *  (C) Copyright 1995 Linus Torvalds
 *  (C) Copyright 2002 Christoph Hellwig
 */

#include <linux/capability.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/sched/user.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/pagewalk.h>
#include <linux/mempolicy.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/rmap.h>
#include <linux/mmzone.h>
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/secretmem.h>
#include <linux/syscall_api_spec.h>

#include "internal.h"

struct mlock_fbatch {
	local_lock_t lock;
	struct folio_batch fbatch;
};

static DEFINE_PER_CPU(struct mlock_fbatch, mlock_fbatch) = {
	.lock = INIT_LOCAL_LOCK(lock),
};

bool can_do_mlock(void)
{
	if (rlimit(RLIMIT_MEMLOCK) != 0)
		return true;
	if (capable(CAP_IPC_LOCK))
		return true;
	return false;
}
EXPORT_SYMBOL(can_do_mlock);

/*
 * Mlocked folios are marked with the PG_mlocked flag for efficient testing
 * in vmscan and, possibly, the fault path; and to support semi-accurate
 * statistics.
 *
 * An mlocked folio [folio_test_mlocked(folio)] is unevictable.  As such, it
 * will be ostensibly placed on the LRU "unevictable" list (actually no such
 * list exists), rather than the [in]active lists. PG_unevictable is set to
 * indicate the unevictable state.
 */

static struct lruvec *__mlock_folio(struct folio *folio, struct lruvec *lruvec)
{
	/* There is nothing more we can do while it's off LRU */
	if (!folio_test_clear_lru(folio))
		return lruvec;

	lruvec = folio_lruvec_relock_irq(folio, lruvec);

	if (unlikely(folio_evictable(folio))) {
		/*
		 * This is a little surprising, but quite possible: PG_mlocked
		 * must have got cleared already by another CPU.  Could this
		 * folio be unevictable?  I'm not sure, but move it now if so.
		 */
		if (folio_test_unevictable(folio)) {
			lruvec_del_folio(lruvec, folio);
			folio_clear_unevictable(folio);
			lruvec_add_folio(lruvec, folio);

			__count_vm_events(UNEVICTABLE_PGRESCUED,
					  folio_nr_pages(folio));
		}
		goto out;
	}

	if (folio_test_unevictable(folio)) {
		if (folio_test_mlocked(folio))
			folio->mlock_count++;
		goto out;
	}

	lruvec_del_folio(lruvec, folio);
	folio_clear_active(folio);
	folio_set_unevictable(folio);
	folio->mlock_count = !!folio_test_mlocked(folio);
	lruvec_add_folio(lruvec, folio);
	__count_vm_events(UNEVICTABLE_PGCULLED, folio_nr_pages(folio));
out:
	folio_set_lru(folio);
	return lruvec;
}

static struct lruvec *__mlock_new_folio(struct folio *folio, struct lruvec *lruvec)
{
	VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);

	lruvec = folio_lruvec_relock_irq(folio, lruvec);

	/* As above, this is a little surprising, but possible */
	if (unlikely(folio_evictable(folio)))
		goto out;

	folio_set_unevictable(folio);
	folio->mlock_count = !!folio_test_mlocked(folio);
	__count_vm_events(UNEVICTABLE_PGCULLED, folio_nr_pages(folio));
out:
	lruvec_add_folio(lruvec, folio);
	folio_set_lru(folio);
	return lruvec;
}

static struct lruvec *__munlock_folio(struct folio *folio, struct lruvec *lruvec)
{
	int nr_pages = folio_nr_pages(folio);
	bool isolated = false;

	if (!folio_test_clear_lru(folio))
		goto munlock;

	isolated = true;
	lruvec = folio_lruvec_relock_irq(folio, lruvec);

	if (folio_test_unevictable(folio)) {
		/* Then mlock_count is maintained, but might undercount */
		if (folio->mlock_count)
			folio->mlock_count--;
		if (folio->mlock_count)
			goto out;
	}
	/* else assume that was the last mlock: reclaim will fix it if not */

munlock:
	if (folio_test_clear_mlocked(folio)) {
		__zone_stat_mod_folio(folio, NR_MLOCK, -nr_pages);
		if (isolated || !folio_test_unevictable(folio))
			__count_vm_events(UNEVICTABLE_PGMUNLOCKED, nr_pages);
		else
			__count_vm_events(UNEVICTABLE_PGSTRANDED, nr_pages);
	}

	/* folio_evictable() has to be checked *after* clearing Mlocked */
	if (isolated && folio_test_unevictable(folio) && folio_evictable(folio)) {
		lruvec_del_folio(lruvec, folio);
		folio_clear_unevictable(folio);
		lruvec_add_folio(lruvec, folio);
		__count_vm_events(UNEVICTABLE_PGRESCUED, nr_pages);
	}
out:
	if (isolated)
		folio_set_lru(folio);
	return lruvec;
}

/*
 * Flags held in the low bits of a struct folio pointer on the mlock_fbatch.
 */
#define LRU_FOLIO 0x1
#define NEW_FOLIO 0x2
static inline struct folio *mlock_lru(struct folio *folio)
{
	return (struct folio *)((unsigned long)folio + LRU_FOLIO);
}

static inline struct folio *mlock_new(struct folio *folio)
{
	return (struct folio *)((unsigned long)folio + NEW_FOLIO);
}

/*
 * mlock_folio_batch() is derived from folio_batch_move_lru(): perhaps that can
 * make use of such folio pointer flags in future, but for now just keep it for
 * mlock.  We could use three separate folio batches instead, but one feels
 * better (munlocking a full folio batch does not need to drain mlocking folio
 * batches first).
 */
static void mlock_folio_batch(struct folio_batch *fbatch)
{
	struct lruvec *lruvec = NULL;
	unsigned long mlock;
	struct folio *folio;
	int i;

	for (i = 0; i < folio_batch_count(fbatch); i++) {
		folio = fbatch->folios[i];
		mlock = (unsigned long)folio & (LRU_FOLIO | NEW_FOLIO);
		folio = (struct folio *)((unsigned long)folio - mlock);
		fbatch->folios[i] = folio;

		if (mlock & LRU_FOLIO)
			lruvec = __mlock_folio(folio, lruvec);
		else if (mlock & NEW_FOLIO)
			lruvec = __mlock_new_folio(folio, lruvec);
		else
			lruvec = __munlock_folio(folio, lruvec);
	}

	if (lruvec)
		unlock_page_lruvec_irq(lruvec);
	folios_put(fbatch);
}

void mlock_drain_local(void)
{
	struct folio_batch *fbatch;

	local_lock(&mlock_fbatch.lock);
	fbatch = this_cpu_ptr(&mlock_fbatch.fbatch);
	if (folio_batch_count(fbatch))
		mlock_folio_batch(fbatch);
	local_unlock(&mlock_fbatch.lock);
}

void mlock_drain_remote(int cpu)
{
	struct folio_batch *fbatch;

	WARN_ON_ONCE(cpu_online(cpu));
	fbatch = &per_cpu(mlock_fbatch.fbatch, cpu);
	if (folio_batch_count(fbatch))
		mlock_folio_batch(fbatch);
}

bool need_mlock_drain(int cpu)
{
	return folio_batch_count(&per_cpu(mlock_fbatch.fbatch, cpu));
}

/**
 * mlock_folio - mlock a folio already on (or temporarily off) LRU
 * @folio: folio to be mlocked.
 */
void mlock_folio(struct folio *folio)
{
	struct folio_batch *fbatch;

	local_lock(&mlock_fbatch.lock);
	fbatch = this_cpu_ptr(&mlock_fbatch.fbatch);

	if (!folio_test_set_mlocked(folio)) {
		int nr_pages = folio_nr_pages(folio);

		zone_stat_mod_folio(folio, NR_MLOCK, nr_pages);
		__count_vm_events(UNEVICTABLE_PGMLOCKED, nr_pages);
	}

	folio_get(folio);
	if (!folio_batch_add(fbatch, mlock_lru(folio)) ||
	    folio_test_large(folio) || lru_cache_disabled())
		mlock_folio_batch(fbatch);
	local_unlock(&mlock_fbatch.lock);
}

/**
 * mlock_new_folio - mlock a newly allocated folio not yet on LRU
 * @folio: folio to be mlocked, either normal or a THP head.
 */
void mlock_new_folio(struct folio *folio)
{
	struct folio_batch *fbatch;
	int nr_pages = folio_nr_pages(folio);

	local_lock(&mlock_fbatch.lock);
	fbatch = this_cpu_ptr(&mlock_fbatch.fbatch);
	folio_set_mlocked(folio);

	zone_stat_mod_folio(folio, NR_MLOCK, nr_pages);
	__count_vm_events(UNEVICTABLE_PGMLOCKED, nr_pages);

	folio_get(folio);
	if (!folio_batch_add(fbatch, mlock_new(folio)) ||
	    folio_test_large(folio) || lru_cache_disabled())
		mlock_folio_batch(fbatch);
	local_unlock(&mlock_fbatch.lock);
}

/**
 * munlock_folio - munlock a folio
 * @folio: folio to be munlocked, either normal or a THP head.
 */
void munlock_folio(struct folio *folio)
{
	struct folio_batch *fbatch;

	local_lock(&mlock_fbatch.lock);
	fbatch = this_cpu_ptr(&mlock_fbatch.fbatch);
	/*
	 * folio_test_clear_mlocked(folio) must be left to __munlock_folio(),
	 * which will check whether the folio is multiply mlocked.
	 */
	folio_get(folio);
	if (!folio_batch_add(fbatch, folio) ||
	    folio_test_large(folio) || lru_cache_disabled())
		mlock_folio_batch(fbatch);
	local_unlock(&mlock_fbatch.lock);
}

static inline unsigned int folio_mlock_step(struct folio *folio,
		pte_t *pte, unsigned long addr, unsigned long end)
{
	const fpb_t fpb_flags = FPB_IGNORE_DIRTY | FPB_IGNORE_SOFT_DIRTY;
	unsigned int count = (end - addr) >> PAGE_SHIFT;
	pte_t ptent = ptep_get(pte);

	if (!folio_test_large(folio))
		return 1;

	return folio_pte_batch(folio, addr, pte, ptent, count, fpb_flags, NULL,
			       NULL, NULL);
}

static inline bool allow_mlock_munlock(struct folio *folio,
		struct vm_area_struct *vma, unsigned long start,
		unsigned long end, unsigned int step)
{
	/*
	 * For unlock, allow munlock large folio which is partially
	 * mapped to VMA. As it's possible that large folio is
	 * mlocked and VMA is split later.
	 *
	 * During memory pressure, such kind of large folio can
	 * be split. And the pages are not in VM_LOCKed VMA
	 * can be reclaimed.
	 */
	if (!(vma->vm_flags & VM_LOCKED))
		return true;

	/* folio_within_range() cannot take KSM, but any small folio is OK */
	if (!folio_test_large(folio))
		return true;

	/* folio not in range [start, end), skip mlock */
	if (!folio_within_range(folio, vma, start, end))
		return false;

	/* folio is not fully mapped, skip mlock */
	if (step != folio_nr_pages(folio))
		return false;

	return true;
}

static int mlock_pte_range(pmd_t *pmd, unsigned long addr,
			   unsigned long end, struct mm_walk *walk)

{
	struct vm_area_struct *vma = walk->vma;
	spinlock_t *ptl;
	pte_t *start_pte, *pte;
	pte_t ptent;
	struct folio *folio;
	unsigned int step = 1;
	unsigned long start = addr;

	ptl = pmd_trans_huge_lock(pmd, vma);
	if (ptl) {
		if (!pmd_present(*pmd))
			goto out;
		if (is_huge_zero_pmd(*pmd))
			goto out;
		folio = pmd_folio(*pmd);
		if (folio_is_zone_device(folio))
			goto out;
		if (vma->vm_flags & VM_LOCKED)
			mlock_folio(folio);
		else
			munlock_folio(folio);
		goto out;
	}

	start_pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	if (!start_pte) {
		walk->action = ACTION_AGAIN;
		return 0;
	}

	for (pte = start_pte; addr != end; pte++, addr += PAGE_SIZE) {
		ptent = ptep_get(pte);
		if (!pte_present(ptent))
			continue;
		folio = vm_normal_folio(vma, addr, ptent);
		if (!folio || folio_is_zone_device(folio))
			continue;

		step = folio_mlock_step(folio, pte, addr, end);
		if (!allow_mlock_munlock(folio, vma, start, end, step))
			goto next_entry;

		if (vma->vm_flags & VM_LOCKED)
			mlock_folio(folio);
		else
			munlock_folio(folio);

next_entry:
		pte += step - 1;
		addr += (step - 1) << PAGE_SHIFT;
	}
	pte_unmap(start_pte);
out:
	spin_unlock(ptl);
	cond_resched();
	return 0;
}

/*
 * mlock_vma_pages_range() - mlock any pages already in the range,
 *                           or munlock all pages in the range.
 * @vma - vma containing range to be mlock()ed or munlock()ed
 * @start - start address in @vma of the range
 * @end - end of range in @vma
 * @newflags - the new set of flags for @vma.
 *
 * Called for mlock(), mlock2() and mlockall(), to set @vma VM_LOCKED;
 * called for munlock() and munlockall(), to clear VM_LOCKED from @vma.
 */
static void mlock_vma_pages_range(struct vm_area_struct *vma,
	unsigned long start, unsigned long end, vm_flags_t newflags)
{
	static const struct mm_walk_ops mlock_walk_ops = {
		.pmd_entry = mlock_pte_range,
		.walk_lock = PGWALK_WRLOCK_VERIFY,
	};

	/*
	 * There is a slight chance that concurrent page migration,
	 * or page reclaim finding a page of this now-VM_LOCKED vma,
	 * will call mlock_vma_folio() and raise page's mlock_count:
	 * double counting, leaving the page unevictable indefinitely.
	 * Communicate this danger to mlock_vma_folio() with VM_IO,
	 * which is a VM_SPECIAL flag not allowed on VM_LOCKED vmas.
	 * mmap_lock is held in write mode here, so this weird
	 * combination should not be visible to other mmap_lock users;
	 * but WRITE_ONCE so rmap walkers must see VM_IO if VM_LOCKED.
	 */
	if (newflags & VM_LOCKED)
		newflags |= VM_IO;
	vma_start_write(vma);
	vm_flags_reset_once(vma, newflags);

	lru_add_drain();
	walk_page_range(vma->vm_mm, start, end, &mlock_walk_ops, NULL);
	lru_add_drain();

	if (newflags & VM_IO) {
		newflags &= ~VM_IO;
		vm_flags_reset_once(vma, newflags);
	}
}

/*
 * mlock_fixup  - handle mlock[all]/munlock[all] requests.
 *
 * Filters out "special" vmas -- VM_LOCKED never gets set for these, and
 * munlock is a no-op.  However, for some special vmas, we go ahead and
 * populate the ptes.
 *
 * For vmas that pass the filters, merge/split as appropriate.
 */
static int mlock_fixup(struct vma_iterator *vmi, struct vm_area_struct *vma,
	       struct vm_area_struct **prev, unsigned long start,
	       unsigned long end, vm_flags_t newflags)
{
	struct mm_struct *mm = vma->vm_mm;
	int nr_pages;
	int ret = 0;
	vm_flags_t oldflags = vma->vm_flags;

	if (newflags == oldflags || (oldflags & VM_SPECIAL) ||
	    is_vm_hugetlb_page(vma) || vma == get_gate_vma(current->mm) ||
	    vma_is_dax(vma) || vma_is_secretmem(vma) || (oldflags & VM_DROPPABLE))
		/* don't set VM_LOCKED or VM_LOCKONFAULT and don't count */
		goto out;

	vma = vma_modify_flags(vmi, *prev, vma, start, end, newflags);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto out;
	}

	/*
	 * Keep track of amount of locked VM.
	 */
	nr_pages = (end - start) >> PAGE_SHIFT;
	if (!(newflags & VM_LOCKED))
		nr_pages = -nr_pages;
	else if (oldflags & VM_LOCKED)
		nr_pages = 0;
	mm->locked_vm += nr_pages;

	/*
	 * vm_flags is protected by the mmap_lock held in write mode.
	 * It's okay if try_to_unmap_one unmaps a page just after we
	 * set VM_LOCKED, populate_vma_page_range will bring it back.
	 */
	if ((newflags & VM_LOCKED) && (oldflags & VM_LOCKED)) {
		/* No work to do, and mlocking twice would be wrong */
		vma_start_write(vma);
		vm_flags_reset(vma, newflags);
	} else {
		mlock_vma_pages_range(vma, start, end, newflags);
	}
out:
	*prev = vma;
	return ret;
}

static int apply_vma_lock_flags(unsigned long start, size_t len,
				vm_flags_t flags)
{
	unsigned long nstart, end, tmp;
	struct vm_area_struct *vma, *prev;
	VMA_ITERATOR(vmi, current->mm, start);

	VM_BUG_ON(offset_in_page(start));
	VM_BUG_ON(len != PAGE_ALIGN(len));
	end = start + len;
	if (end < start)
		return -EINVAL;
	if (end == start)
		return 0;
	vma = vma_iter_load(&vmi);
	if (!vma)
		return -ENOMEM;

	prev = vma_prev(&vmi);
	if (start > vma->vm_start)
		prev = vma;

	nstart = start;
	tmp = vma->vm_start;
	for_each_vma_range(vmi, vma, end) {
		int error;
		vm_flags_t newflags;

		if (vma->vm_start != tmp)
			return -ENOMEM;

		newflags = vma->vm_flags & ~VM_LOCKED_MASK;
		newflags |= flags;
		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */
		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;
		error = mlock_fixup(&vmi, vma, &prev, nstart, tmp, newflags);
		if (error)
			return error;
		tmp = vma_iter_end(&vmi);
		nstart = tmp;
	}

	if (tmp < end)
		return -ENOMEM;

	return 0;
}

/*
 * Go through vma areas and sum size of mlocked
 * vma pages, as return value.
 * Note deferred memory locking case(mlock2(,,MLOCK_ONFAULT)
 * is also counted.
 * Return value: previously mlocked page counts
 */
static unsigned long count_mm_mlocked_page_nr(struct mm_struct *mm,
		unsigned long start, size_t len)
{
	struct vm_area_struct *vma;
	unsigned long count = 0;
	unsigned long end;
	VMA_ITERATOR(vmi, mm, start);

	/* Don't overflow past ULONG_MAX */
	if (unlikely(ULONG_MAX - len < start))
		end = ULONG_MAX;
	else
		end = start + len;

	for_each_vma_range(vmi, vma, end) {
		if (vma->vm_flags & VM_LOCKED) {
			if (start > vma->vm_start)
				count -= (start - vma->vm_start);
			if (end < vma->vm_end) {
				count += end - vma->vm_start;
				break;
			}
			count += vma->vm_end - vma->vm_start;
		}
	}

	return count >> PAGE_SHIFT;
}

/*
 * convert get_user_pages() return value to posix mlock() error
 */
static int __mlock_posix_error_return(long retval)
{
	if (retval == -EFAULT)
		retval = -ENOMEM;
	else if (retval == -ENOMEM)
		retval = -EAGAIN;
	return retval;
}

static __must_check int do_mlock(unsigned long start, size_t len, vm_flags_t flags)
{
	unsigned long locked;
	unsigned long lock_limit;
	int error = -ENOMEM;

	start = untagged_addr(start);

	if (!can_do_mlock())
		return -EPERM;

	len = PAGE_ALIGN(len + (offset_in_page(start)));
	start &= PAGE_MASK;

	lock_limit = rlimit(RLIMIT_MEMLOCK);
	lock_limit >>= PAGE_SHIFT;
	locked = len >> PAGE_SHIFT;

	if (mmap_write_lock_killable(current->mm))
		return -EINTR;

	locked += current->mm->locked_vm;
	if ((locked > lock_limit) && (!capable(CAP_IPC_LOCK))) {
		/*
		 * It is possible that the regions requested intersect with
		 * previously mlocked areas, that part area in "mm->locked_vm"
		 * should not be counted to new mlock increment count. So check
		 * and adjust locked count if necessary.
		 */
		locked -= count_mm_mlocked_page_nr(current->mm,
				start, len);
	}

	/* check against resource limits */
	if ((locked <= lock_limit) || capable(CAP_IPC_LOCK))
		error = apply_vma_lock_flags(start, len, flags);

	mmap_write_unlock(current->mm);
	if (error)
		return error;

	error = __mm_populate(start, len, 0);
	if (error)
		return __mlock_posix_error_return(error);
	return 0;
}


DEFINE_KERNEL_API_SPEC(sys_mlock)
	KAPI_DESCRIPTION("Lock pages in memory")
	KAPI_LONG_DESC("Locks pages in the specified address range into RAM, "
		       "preventing them from being paged to swap. Requires "
		       "CAP_IPC_LOCK capability or RLIMIT_MEMLOCK resource limit.")
	KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE)

	KAPI_PARAM(0, "start", "unsigned long", "Starting address of memory range to lock")
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_NONE)
		KAPI_PARAM_CONSTRAINT("Rounded down to page boundary")
	KAPI_PARAM_END
	KAPI_PARAM(1, "len", "size_t", "Length of memory range to lock in bytes")
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_RANGE)
		KAPI_PARAM_RANGE(0, LONG_MAX)
		KAPI_PARAM_CONSTRAINT("Rounded up to page boundary")
	KAPI_PARAM_END

	KAPI_RETURN("long", "0 on success, negative error code on failure")
		KAPI_RETURN_TYPE(KAPI_TYPE_INT)
		KAPI_RETURN_CHECK_TYPE(KAPI_RETURN_ERROR_CHECK)
		KAPI_RETURN_SUCCESS(0)
	KAPI_RETURN_END

	KAPI_ERROR(0, -ENOMEM, "ENOMEM", "Address range issue",
		   "Some of the specified range is not mapped, has unmapped gaps, "
		   "or the lock would cause the number of mapped regions to exceed the limit.")
	KAPI_ERROR(1, -EPERM, "EPERM", "Insufficient privileges",
		   "The caller is not privileged (no CAP_IPC_LOCK) and RLIMIT_MEMLOCK is 0.")
	KAPI_ERROR(2, -EINVAL, "EINVAL", "Address overflow",
		   "The result of the addition start+len was less than start (arithmetic overflow).")
	KAPI_ERROR(3, -EAGAIN, "EAGAIN", "Some or all memory could not be locked",
		   "Some or all of the specified address range could not be locked.")
	KAPI_ERROR(4, -EINTR, "EINTR", "Interrupted by signal",
		   "The operation was interrupted by a fatal signal before completion.")

	KAPI_ERROR_COUNT(5)
	KAPI_PARAM_COUNT(2)
	KAPI_SINCE_VERSION("2.0")

	KAPI_LOCK(0, "mmap_lock", KAPI_LOCK_RWLOCK)
		KAPI_LOCK_ACQUIRED
		KAPI_LOCK_RELEASED
		KAPI_LOCK_DESC("Process memory map write lock")
	KAPI_LOCK_END

	KAPI_LOCK_COUNT(1)

	/* Signal specifications */
	KAPI_SIGNAL_COUNT(1)

	/* Fatal signals can interrupt mmap_write_lock_killable */
	KAPI_SIGNAL(0, 0, "FATAL", KAPI_SIGNAL_RECEIVE, KAPI_SIGNAL_ACTION_RETURN)
		KAPI_SIGNAL_CONDITION("Fatal signal pending")
		KAPI_SIGNAL_DESC("Fatal signals (SIGKILL, etc.) can interrupt the operation "
				 "when acquiring mmap_write_lock_killable(), causing -EINTR return")
		KAPI_SIGNAL_TIMING(KAPI_SIGNAL_TIME_ENTRY)
		KAPI_SIGNAL_PRIORITY(0)
		KAPI_SIGNAL_INTERRUPTIBLE
		KAPI_SIGNAL_ERROR(-EINTR)
		KAPI_SIGNAL_STATE_REQ(KAPI_SIGNAL_STATE_RUNNING | KAPI_SIGNAL_STATE_SLEEPING)
		KAPI_SIGNAL_RESTARTABLE
	KAPI_SIGNAL_END

	KAPI_EXAMPLES("mlock(addr, 4096);  // Lock one page\n"
		      "mlock(addr, len);   // Lock range of pages")
	KAPI_NOTES("Memory locks do not stack - multiple calls on the same range can be "
		   "undone by a single munlock. Locks are not inherited by child processes. "
		   "Pages are locked on whole page boundaries. Commonly used by real-time "
		   "applications to prevent page faults during time-critical operations. "
		   "Also used for security to prevent sensitive data (e.g., cryptographic keys) "
		   "from being written to swap. Note: locked pages may still be saved to "
		   "swap during system suspend/hibernate.")

	/* Side effects */
	KAPI_SIDE_EFFECT(0, KAPI_EFFECT_MODIFY_STATE | KAPI_EFFECT_ALLOC_MEMORY,
			 "process memory",
			 "Locks pages into physical memory, preventing swapping")
		KAPI_EFFECT_REVERSIBLE
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(1, KAPI_EFFECT_MODIFY_STATE,
			 "mm->locked_vm",
			 "Increases process locked memory counter")
		KAPI_EFFECT_REVERSIBLE
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(2, KAPI_EFFECT_ALLOC_MEMORY,
			 "physical pages",
			 "May allocate and populate page table entries")
		KAPI_EFFECT_CONDITION("Pages not already present")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT_COUNT(3)

	/* State transitions */
	KAPI_STATE_TRANS(0, "memory pages", "swappable", "locked in RAM",
			 "Pages become non-swappable and pinned in physical memory")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(1, "VMA flags", "unlocked", "VM_LOCKED set",
			 "Virtual memory area marked as locked")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS_COUNT(2)

	/* Capability specifications */
	KAPI_CAPABILITY(0, CAP_IPC_LOCK, "CAP_IPC_LOCK", KAPI_CAP_BYPASS_CHECK)
		KAPI_CAP_ALLOWS("Lock unlimited amount of memory (no RLIMIT_MEMLOCK enforcement)")
		KAPI_CAP_WITHOUT("Must respect RLIMIT_MEMLOCK resource limit")
		KAPI_CAP_CONDITION("Checked when RLIMIT_MEMLOCK is 0 or locking would exceed limit")
		KAPI_CAP_PRIORITY(0)
	KAPI_CAPABILITY_END

	KAPI_CAPABILITY_COUNT(1)

	/* Additional constraints */
	KAPI_CONSTRAINT(0, "RLIMIT_MEMLOCK Resource Limit",
			"The RLIMIT_MEMLOCK soft resource limit specifies the maximum bytes "
			"of memory that may be locked into RAM. Unprivileged processes are "
			"restricted to this limit. CAP_IPC_LOCK capability allows bypassing "
			"this limit entirely. The limit is enforced per-process, not per-user.")
		KAPI_CONSTRAINT_EXPR("locked_memory + request_size <= RLIMIT_MEMLOCK || CAP_IPC_LOCK")
	KAPI_CONSTRAINT_END

	KAPI_CONSTRAINT(1, "Memory Pressure and OOM",
			"Locking large amounts of memory can cause system-wide memory pressure "
			"and potentially trigger the OOM killer. The kernel does not prevent "
			"locking memory that would destabilize the system.")
	KAPI_CONSTRAINT_END

	KAPI_CONSTRAINT(2, "Special Memory Areas",
			"Some memory types cannot be locked or behave specially: "
			"VM_IO/VM_PFNMAP areas fail with EINVAL; "
			"Hugetlb pages are inherently pinned; "
			"DAX mappings are always present in memory; "
			"VM_LOCKED areas are already locked.")
	KAPI_CONSTRAINT_END

	KAPI_CONSTRAINT_COUNT(3)

KAPI_END_SPEC;

SYSCALL_DEFINE2(mlock, unsigned long, start, size_t, len)
{
	return do_mlock(start, len, VM_LOCKED);
}


DEFINE_KERNEL_API_SPEC(sys_mlock2)
	KAPI_DESCRIPTION("Lock pages in memory with flags")
	KAPI_LONG_DESC("Enhanced version of mlock() that supports flags. "
		       "MLOCK_ONFAULT flag allows locking pages on fault rather than immediately.")
	KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE)

	/* Parameters */
	KAPI_PARAM(0, "start", "unsigned long", "Starting address of memory range to lock")
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN)
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_NONE)
		KAPI_PARAM_CONSTRAINT("Rounded down to page boundary")
	KAPI_PARAM_END

	KAPI_PARAM(1, "len", "size_t", "Length of memory range to lock in bytes")
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN)
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_RANGE)
		KAPI_PARAM_RANGE(0, LONG_MAX)
		KAPI_PARAM_CONSTRAINT("Rounded up to page boundary")
	KAPI_PARAM_END

	KAPI_PARAM(2, "flags", "int", "Flags controlling lock behavior")
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN)
		KAPI_PARAM_TYPE(KAPI_TYPE_INT)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_MASK)
		KAPI_PARAM_VALID_MASK(MLOCK_ONFAULT)
		KAPI_PARAM_CONSTRAINT("Only MLOCK_ONFAULT flag is currently supported")
	KAPI_PARAM_END

	/* Return specification */
	KAPI_RETURN("long", "0 on success, negative error code on failure")
		KAPI_RETURN_TYPE(KAPI_TYPE_INT)
		.check_type = KAPI_RETURN_ERROR_CHECK,
		.success_value = 0,
	KAPI_RETURN_END

	/* Error codes */
	KAPI_ERROR(0, -EINVAL, "EINVAL", "Invalid flags", "Unknown flags were specified (flags & ~MLOCK_ONFAULT).")
	KAPI_ERROR(1, -ENOMEM, "ENOMEM", "Address range issue", "Some of the specified range is not mapped, has unmapped gaps, or the lock would cause the number of mapped regions to exceed the limit.")
	KAPI_ERROR(2, -EPERM, "EPERM", "Insufficient privileges", "The caller is not privileged (no CAP_IPC_LOCK) and RLIMIT_MEMLOCK is 0.")
	KAPI_ERROR(3, -EAGAIN, "EAGAIN", "Some or all memory could not be locked", "Some or all of the specified address range could not be locked.")
	KAPI_ERROR(4, -EINTR, "EINTR", "Interrupted by signal", "The operation was interrupted by a fatal signal before completion.")

	/* Signal specifications */
	KAPI_SIGNAL(0, 0, "FATAL_SIGNALS", KAPI_SIGNAL_RECEIVE, KAPI_SIGNAL_ACTION_RETURN)
		KAPI_SIGNAL_CONDITION("Fatal signal pending during mmap_write_lock_killable")
		KAPI_SIGNAL_DESC("Fatal signals (SIGKILL, SIGTERM, etc.) can interrupt the operation when acquiring mmap_write_lock_killable(), causing -EINTR return")
		KAPI_SIGNAL_TIMING(KAPI_SIGNAL_TIME_ENTRY)
		KAPI_SIGNAL_PRIORITY(0)
		KAPI_SIGNAL_INTERRUPTIBLE
		KAPI_SIGNAL_ERROR(-EINTR)
		KAPI_SIGNAL_STATE_REQ(KAPI_SIGNAL_STATE_RUNNING | KAPI_SIGNAL_STATE_SLEEPING)
		KAPI_SIGNAL_RESTARTABLE
	KAPI_SIGNAL_END

	KAPI_SIGNAL(1, SIGBUS, "SIGBUS", KAPI_SIGNAL_SEND, KAPI_SIGNAL_ACTION_DEFAULT)
		KAPI_SIGNAL_TARGET("Current process")
		KAPI_SIGNAL_CONDITION("Memory access to locked page fails")
		KAPI_SIGNAL_DESC("Can be generated if accessing a locked page that cannot be brought into memory (e.g., truncated file mapping)")
		KAPI_SIGNAL_TIMING(KAPI_SIGNAL_TIME_ANYTIME)
		KAPI_SIGNAL_PRIORITY(1)
		KAPI_SIGNAL_SA_FLAGS_REQ(SA_SIGINFO)
	KAPI_SIGNAL_END

	/* Side effects */
	KAPI_SIDE_EFFECT(0, KAPI_EFFECT_MODIFY_STATE | KAPI_EFFECT_ALLOC_MEMORY,
			 "process memory",
			 "Locks pages into physical memory, preventing swapping")
		KAPI_EFFECT_REVERSIBLE
		KAPI_EFFECT_CONDITION("Pages become resident in RAM")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(1, KAPI_EFFECT_MODIFY_STATE,
			 "mm->locked_vm",
			 "Increases process locked memory counter")
		KAPI_EFFECT_REVERSIBLE
		KAPI_EFFECT_CONDITION("Counted against RLIMIT_MEMLOCK")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(2, KAPI_EFFECT_ALLOC_MEMORY,
			 "page tables",
			 "May allocate and populate page table entries")
		KAPI_EFFECT_CONDITION("Pages not already present")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(3, KAPI_EFFECT_MODIFY_STATE,
			 "VMA flags",
			 "Sets VM_LOCKED and optionally VM_LOCKONFAULT on affected VMAs")
		KAPI_EFFECT_REVERSIBLE
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(4, KAPI_EFFECT_FILESYSTEM,
			 "page fault behavior",
			 "With MLOCK_ONFAULT, changes how future page faults are handled")
		KAPI_EFFECT_CONDITION("MLOCK_ONFAULT flag specified")
	KAPI_SIDE_EFFECT_END

	/* State transitions */
	KAPI_STATE_TRANS(0, "memory pages",
			 "swappable", "locked in RAM",
			 "Pages become non-swappable and pinned in physical memory")
		KAPI_STATE_TRANS_COND("Without MLOCK_ONFAULT")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(1, "VMA flags",
			 "unlocked", "VM_LOCKED set",
			 "Virtual memory area marked as locked")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(2, "VMA flags",
			 "normal fault", "VM_LOCKONFAULT set",
			 "VMA marked to lock pages on future faults")
		KAPI_STATE_TRANS_COND("MLOCK_ONFAULT flag specified")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(3, "page residency",
			 "may be swapped", "resident in memory",
			 "Pages brought into RAM and kept there")
		KAPI_STATE_TRANS_COND("Without MLOCK_ONFAULT")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(4, "process statistics",
			 "normal memory accounting", "locked memory accounting",
			 "Memory counted against RLIMIT_MEMLOCK")
	KAPI_STATE_TRANS_END

	/* Locking information */
	KAPI_LOCK(0, "mmap_lock", KAPI_LOCK_RWLOCK)
		KAPI_LOCK_DESC("Process memory map write lock")
		KAPI_LOCK_ACQUIRED
		KAPI_LOCK_RELEASED
		KAPI_LOCK_DESC("Protects VMA modifications during lock operation")
	KAPI_LOCK_END

	KAPI_LOCK(1, "lru_lock", KAPI_LOCK_SPINLOCK)
		KAPI_LOCK_DESC("Per-memcg LRU list lock")
		KAPI_LOCK_ACQUIRED
		KAPI_LOCK_RELEASED
		KAPI_LOCK_DESC("Taken when moving pages to unevictable list when locking pages")
	KAPI_LOCK_END

	KAPI_ERROR_COUNT(5)
	KAPI_PARAM_COUNT(3)
	KAPI_SINCE_VERSION("4.4")
	KAPI_SIGNAL_COUNT(2)
	KAPI_SIDE_EFFECT_COUNT(5)
	KAPI_STATE_TRANS_COUNT(5)
	KAPI_LOCK_COUNT(2)

	/* Capability specifications */
	KAPI_CAPABILITY(0, CAP_IPC_LOCK, "CAP_IPC_LOCK", KAPI_CAP_BYPASS_CHECK)
		KAPI_CAP_ALLOWS("Lock unlimited amount of memory (no RLIMIT_MEMLOCK enforcement)")
		KAPI_CAP_WITHOUT("Must respect RLIMIT_MEMLOCK resource limit")
		KAPI_CAP_CONDITION("Checked when RLIMIT_MEMLOCK is 0 or locking would exceed limit")
		KAPI_CAP_PRIORITY(0)
	KAPI_CAPABILITY_END

	KAPI_CAPABILITY_COUNT(1)

	KAPI_EXAMPLES("mlock2(addr, len, 0);            // Same as mlock()\n"
		      "mlock2(addr, len, MLOCK_ONFAULT); // Lock on fault")
	KAPI_NOTES("MLOCK_ONFAULT flag defers actual page locking until pages are accessed. "
		   "Memory locks do not stack. Locks are not inherited by child processes. "
		   "Commonly used by real-time applications to prevent page faults. Also used "
		   "for security to prevent sensitive data (e.g., cryptographic keys) from being "
		   "written to swap. Note: locked pages may still be saved to swap during "
		   "system suspend/hibernate.")
KAPI_END_SPEC;

SYSCALL_DEFINE3(mlock2, unsigned long, start, size_t, len, int, flags)
{
	vm_flags_t vm_flags = VM_LOCKED;

	if (flags & ~MLOCK_ONFAULT)
		return -EINVAL;

	if (flags & MLOCK_ONFAULT)
		vm_flags |= VM_LOCKONFAULT;

	return do_mlock(start, len, vm_flags);
}


DEFINE_KERNEL_API_SPEC(sys_munlock)
	KAPI_DESCRIPTION("Unlock pages in memory")
	KAPI_LONG_DESC("Unlocks pages in the specified address range, allowing them "
		       "to be paged out to swap if needed.")
	KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE)

	/* Parameters */
	KAPI_PARAM(0, "start", "unsigned long", "Starting address of memory range to unlock")
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN)
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_NONE)
		KAPI_PARAM_CONSTRAINT("Rounded down to page boundary")
	KAPI_PARAM_END

	KAPI_PARAM(1, "len", "size_t", "Length of memory range to unlock in bytes")
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN)
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_RANGE)
		KAPI_PARAM_RANGE(0, LONG_MAX)
		KAPI_PARAM_CONSTRAINT("Rounded up to page boundary")
	KAPI_PARAM_END

	/* Return specification */
	KAPI_RETURN("long", "0 on success, negative error code on failure")
		.type = KAPI_TYPE_INT,
		.check_type = KAPI_RETURN_ERROR_CHECK,
		.success_value = 0,
	KAPI_RETURN_END

	/* Error codes */
	KAPI_ERROR(0, -ENOMEM, "ENOMEM", "Memory range not mapped", "(Linux 2.6.9 and later) Some of the specified address range does not correspond to mapped pages in the process address space.")
	KAPI_ERROR(1, -EINTR, "EINTR", "Interrupted by signal", "The operation was interrupted by a signal before completion.")
	KAPI_ERROR(2, -EINVAL, "EINVAL", "Address overflow", "The result of the addition start+len was less than start (arithmetic overflow).")

	/* Signal specifications */
	KAPI_SIGNAL(0, 0, "FATAL_SIGNALS", KAPI_SIGNAL_RECEIVE, KAPI_SIGNAL_ACTION_RETURN)
		KAPI_SIGNAL_CONDITION("Fatal signal pending during mmap_write_lock_killable")
		KAPI_SIGNAL_DESC("Fatal signals (SIGKILL, SIGTERM, etc.) can interrupt the operation when acquiring mmap_write_lock_killable(), causing -EINTR return")
		KAPI_SIGNAL_TIMING(KAPI_SIGNAL_TIME_ENTRY)
		KAPI_SIGNAL_PRIORITY(0)
		KAPI_SIGNAL_INTERRUPTIBLE
		KAPI_SIGNAL_ERROR(-EINTR)
		KAPI_SIGNAL_STATE_REQ(KAPI_SIGNAL_STATE_RUNNING | KAPI_SIGNAL_STATE_SLEEPING)
		KAPI_SIGNAL_RESTARTABLE
	KAPI_SIGNAL_END

	/* Side effects */
	KAPI_SIDE_EFFECT(0, KAPI_EFFECT_MODIFY_STATE,
			 "process memory",
			 "Unlocks pages, making them eligible for swapping")
		KAPI_EFFECT_REVERSIBLE
		KAPI_EFFECT_CONDITION("Pages were previously locked")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(1, KAPI_EFFECT_MODIFY_STATE,
			 "mm->locked_vm",
			 "Decreases process locked memory counter")
		KAPI_EFFECT_REVERSIBLE
		KAPI_EFFECT_CONDITION("Pages were counted in locked_vm")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(2, KAPI_EFFECT_MODIFY_STATE,
			 "VMA flags",
			 "Clears VM_LOCKED and VM_LOCKONFAULT from affected VMAs")
		KAPI_EFFECT_REVERSIBLE
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(3, KAPI_EFFECT_MODIFY_STATE,
			 "page flags",
			 "Clears PG_mlocked flag from unlocked pages")
		KAPI_EFFECT_CONDITION("Pages had PG_mlocked set")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(4, KAPI_EFFECT_MODIFY_STATE,
			 "LRU lists",
			 "Moves pages from unevictable to appropriate LRU list")
		KAPI_EFFECT_CONDITION("Pages were on unevictable list")
	KAPI_SIDE_EFFECT_END

	/* State transitions */
	KAPI_STATE_TRANS(0, "memory pages",
			 "locked in RAM", "swappable",
			 "Pages become eligible for swap out")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(1, "VMA flags",
			 "VM_LOCKED set", "VM_LOCKED cleared",
			 "Virtual memory areas no longer marked as locked")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(2, "page residency",
			 "guaranteed resident", "may be swapped",
			 "Pages can now be evicted under memory pressure")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(3, "process statistics",
			 "locked memory accounted", "normal memory accounting",
			 "Memory no longer counted against RLIMIT_MEMLOCK")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(4, "page LRU status",
			 "unevictable list", "active/inactive list",
			 "Pages moved to normal LRU lists for reclaim")
		KAPI_STATE_TRANS_COND("Pages were mlocked")
	KAPI_STATE_TRANS_END

	/* Locking information */
	KAPI_LOCK(0, "mmap_lock", KAPI_LOCK_RWLOCK)
		KAPI_LOCK_DESC("Process memory map write lock")
		KAPI_LOCK_ACQUIRED
		KAPI_LOCK_RELEASED
		KAPI_LOCK_DESC("Protects VMA modifications during unlock operation")
	KAPI_LOCK_END

	KAPI_LOCK(1, "lru_lock", KAPI_LOCK_SPINLOCK)
		KAPI_LOCK_DESC("Per-memcg LRU list lock")
		KAPI_LOCK_ACQUIRED
		KAPI_LOCK_RELEASED
		KAPI_LOCK_DESC("Taken when moving pages from unevictable to normal LRU lists")
	KAPI_LOCK_END

	KAPI_ERROR_COUNT(3)
	KAPI_PARAM_COUNT(2)
	KAPI_SINCE_VERSION("2.0")
	KAPI_SIGNAL_COUNT(1)
	KAPI_SIDE_EFFECT_COUNT(5)
	KAPI_STATE_TRANS_COUNT(5)
	KAPI_LOCK_COUNT(2)
	KAPI_EXAMPLES("munlock(addr, 4096);  // Unlock one page\n"
		      "munlock(addr, len);   // Unlock range of pages")
	KAPI_NOTES("No special permissions required to unlock memory. A single munlock() "
		   "can undo multiple mlock() calls on the same range since locks don't stack.")
KAPI_END_SPEC;

SYSCALL_DEFINE2(munlock, unsigned long, start, size_t, len)
{
	int ret;

	start = untagged_addr(start);

	len = PAGE_ALIGN(len + (offset_in_page(start)));
	start &= PAGE_MASK;

	if (mmap_write_lock_killable(current->mm))
		return -EINTR;
	ret = apply_vma_lock_flags(start, len, 0);
	mmap_write_unlock(current->mm);

	return ret;
}

/*
 * Take the MCL_* flags passed into mlockall (or 0 if called from munlockall)
 * and translate into the appropriate modifications to mm->def_flags and/or the
 * flags for all current VMAs.
 *
 * There are a couple of subtleties with this.  If mlockall() is called multiple
 * times with different flags, the values do not necessarily stack.  If mlockall
 * is called once including the MCL_FUTURE flag and then a second time without
 * it, VM_LOCKED and VM_LOCKONFAULT will be cleared from mm->def_flags.
 */
static int apply_mlockall_flags(int flags)
{
	VMA_ITERATOR(vmi, current->mm, 0);
	struct vm_area_struct *vma, *prev = NULL;
	vm_flags_t to_add = 0;

	current->mm->def_flags &= ~VM_LOCKED_MASK;
	if (flags & MCL_FUTURE) {
		current->mm->def_flags |= VM_LOCKED;

		if (flags & MCL_ONFAULT)
			current->mm->def_flags |= VM_LOCKONFAULT;

		if (!(flags & MCL_CURRENT))
			goto out;
	}

	if (flags & MCL_CURRENT) {
		to_add |= VM_LOCKED;
		if (flags & MCL_ONFAULT)
			to_add |= VM_LOCKONFAULT;
	}

	for_each_vma(vmi, vma) {
		int error;
		vm_flags_t newflags;

		newflags = vma->vm_flags & ~VM_LOCKED_MASK;
		newflags |= to_add;

		error = mlock_fixup(&vmi, vma, &prev, vma->vm_start, vma->vm_end,
				    newflags);
		/* Ignore errors, but prev needs fixing up. */
		if (error)
			prev = vma;
		cond_resched();
	}
out:
	return 0;
}


DEFINE_KERNEL_API_SPEC(sys_mlockall)
	KAPI_DESCRIPTION("Lock all process pages in memory")
	KAPI_LONG_DESC("Locks all pages mapped into the process address space. "
		       "MCL_CURRENT locks current pages, MCL_FUTURE locks future mappings, "
		       "MCL_ONFAULT defers locking until page fault.")
	KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE)

	/* Parameters */
	KAPI_PARAM(0, "flags", "int", "Flags controlling which pages to lock")
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN)
		KAPI_PARAM_TYPE(KAPI_TYPE_INT)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_MASK)
		.valid_mask = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT,
		KAPI_PARAM_CONSTRAINT("Must specify MCL_CURRENT and/or MCL_FUTURE; MCL_ONFAULT can be OR'd")
	KAPI_PARAM_END

	/* Return specification */
	KAPI_RETURN("long", "0 on success, negative error code on failure")
		.type = KAPI_TYPE_INT,
		.check_type = KAPI_RETURN_ERROR_CHECK,
		.success_value = 0,
	KAPI_RETURN_END

	/* Error codes */
	KAPI_ERROR(0, -EINVAL, "EINVAL", "Invalid flags", "Invalid combination of flags specified, or no flags set, or only MCL_ONFAULT without MCL_CURRENT or MCL_FUTURE.")
	KAPI_ERROR(1, -EPERM, "EPERM", "Insufficient privileges", "The caller is not privileged (no CAP_IPC_LOCK) and RLIMIT_MEMLOCK is 0.")
	KAPI_ERROR(2, -ENOMEM, "ENOMEM", "Insufficient resources", "MCL_CURRENT is set and total VM size exceeds RLIMIT_MEMLOCK and caller lacks CAP_IPC_LOCK.")
	KAPI_ERROR(3, -EINTR, "EINTR", "Interrupted by signal", "The operation was interrupted by a signal before completion.")
	KAPI_ERROR(4, -EAGAIN, "EAGAIN", "Some memory could not be locked", "Some pages could not be locked, possibly due to memory pressure.")

	/* Signal specifications */
	KAPI_SIGNAL(0, 0, "FATAL_SIGNALS", KAPI_SIGNAL_RECEIVE, KAPI_SIGNAL_ACTION_RETURN)
		KAPI_SIGNAL_CONDITION("Fatal signal pending during mmap_write_lock_killable")
		KAPI_SIGNAL_DESC("Fatal signals (SIGKILL, SIGTERM, etc.) can interrupt the operation when acquiring mmap_write_lock_killable(), causing -EINTR return")
		KAPI_SIGNAL_TIMING(KAPI_SIGNAL_TIME_ENTRY)
		KAPI_SIGNAL_PRIORITY(0)
		KAPI_SIGNAL_INTERRUPTIBLE
		KAPI_SIGNAL_ERROR(-EINTR)
		KAPI_SIGNAL_STATE_REQ(KAPI_SIGNAL_STATE_RUNNING | KAPI_SIGNAL_STATE_SLEEPING)
		KAPI_SIGNAL_RESTARTABLE
	KAPI_SIGNAL_END

	KAPI_SIGNAL(1, SIGBUS, "SIGBUS", KAPI_SIGNAL_SEND, KAPI_SIGNAL_ACTION_DEFAULT)
		KAPI_SIGNAL_TARGET("Current process")
		KAPI_SIGNAL_CONDITION("Memory access to locked page fails")
		KAPI_SIGNAL_DESC("Can be generated later if accessing a locked page that cannot be brought into memory (e.g., truncated file mapping)")
		KAPI_SIGNAL_TIMING(KAPI_SIGNAL_TIME_ANYTIME)
		KAPI_SIGNAL_PRIORITY(1)
		KAPI_SIGNAL_SA_FLAGS_REQ(SA_SIGINFO)
	KAPI_SIGNAL_END

	/* Side effects */
	KAPI_SIDE_EFFECT(0, KAPI_EFFECT_MODIFY_STATE | KAPI_EFFECT_ALLOC_MEMORY,
			 "all process memory",
			 "Locks all current pages into physical memory, preventing swapping")
		KAPI_EFFECT_REVERSIBLE
		KAPI_EFFECT_CONDITION("MCL_CURRENT flag set")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(1, KAPI_EFFECT_MODIFY_STATE,
			 "mm->def_flags",
			 "Sets VM_LOCKED in default flags for future mappings")
		KAPI_EFFECT_REVERSIBLE
		KAPI_EFFECT_CONDITION("MCL_FUTURE flag set")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(2, KAPI_EFFECT_MODIFY_STATE,
			 "mm->locked_vm",
			 "Increases process locked memory counter for entire address space")
		KAPI_EFFECT_REVERSIBLE
		KAPI_EFFECT_CONDITION("MCL_CURRENT flag set")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(3, KAPI_EFFECT_ALLOC_MEMORY,
			 "page tables",
			 "May allocate and populate page table entries for all mappings")
		KAPI_EFFECT_CONDITION("MCL_CURRENT without MCL_ONFAULT")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(4, KAPI_EFFECT_MODIFY_STATE,
			 "VMA flags",
			 "Sets VM_LOCKED on all existing VMAs")
		KAPI_EFFECT_REVERSIBLE
		KAPI_EFFECT_CONDITION("MCL_CURRENT flag set")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(5, KAPI_EFFECT_SCHEDULE,
			 "mm_populate",
			 "Triggers population of entire address space")
		KAPI_EFFECT_CONDITION("MCL_CURRENT without MCL_ONFAULT")
	KAPI_SIDE_EFFECT_END

	/* State transitions */
	KAPI_STATE_TRANS(0, "all memory pages",
			 "swappable", "locked in RAM",
			 "All pages in process become non-swappable")
		KAPI_STATE_TRANS_COND("MCL_CURRENT flag set")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(1, "future mappings",
			 "normal", "auto-locked",
			 "New mappings will be automatically locked")
		KAPI_STATE_TRANS_COND("MCL_FUTURE flag set")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(2, "VMA flags",
			 "varied", "all VM_LOCKED",
			 "All virtual memory areas marked as locked")
		KAPI_STATE_TRANS_COND("MCL_CURRENT flag set")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(3, "page fault behavior",
			 "normal faulting", "lock on fault",
			 "Pages locked when faulted in rather than immediately")
		KAPI_STATE_TRANS_COND("MCL_ONFAULT flag set")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(4, "process statistics",
			 "partial locked memory", "all memory locked",
			 "Entire VM size counted against RLIMIT_MEMLOCK")
		KAPI_STATE_TRANS_COND("MCL_CURRENT flag set")
	KAPI_STATE_TRANS_END

	/* Locking information */
	KAPI_LOCK(0, "mmap_lock", KAPI_LOCK_RWLOCK)
		KAPI_LOCK_DESC("Process memory map write lock")
		KAPI_LOCK_ACQUIRED
		KAPI_LOCK_RELEASED
		KAPI_LOCK_DESC("Protects VMA modifications during mlockall operation")
	KAPI_LOCK_END

	KAPI_LOCK(1, "lru_lock", KAPI_LOCK_SPINLOCK)
		KAPI_LOCK_DESC("Per-memcg LRU list lock")
		KAPI_LOCK_ACQUIRED
		KAPI_LOCK_RELEASED
		KAPI_LOCK_DESC("Taken when moving pages to unevictable list for all locked pages")
	KAPI_LOCK_END

	KAPI_ERROR_COUNT(5)
	KAPI_PARAM_COUNT(1)
	KAPI_SINCE_VERSION("2.0")
	KAPI_SIGNAL_COUNT(2)
	KAPI_SIDE_EFFECT_COUNT(6)
	KAPI_STATE_TRANS_COUNT(5)
	KAPI_LOCK_COUNT(2)

	/* Capability specifications */
	KAPI_CAPABILITY(0, CAP_IPC_LOCK, "CAP_IPC_LOCK", KAPI_CAP_BYPASS_CHECK)
		KAPI_CAP_ALLOWS("Lock entire process memory exceeding RLIMIT_MEMLOCK")
		KAPI_CAP_WITHOUT("Total VM size must not exceed RLIMIT_MEMLOCK when MCL_CURRENT is set")
		KAPI_CAP_CONDITION("Checked when MCL_CURRENT is set and total VM size exceeds RLIMIT_MEMLOCK")
		KAPI_CAP_PRIORITY(0)
	KAPI_CAPABILITY_END

	KAPI_CAPABILITY_COUNT(1)

	KAPI_EXAMPLES("mlockall(MCL_CURRENT);                    // Lock current mappings\n"
		      "mlockall(MCL_CURRENT | MCL_FUTURE);       // Lock current and future\n"
		      "mlockall(MCL_CURRENT | MCL_ONFAULT);      // Lock current on fault")
	KAPI_NOTES("Affects all current VMAs and optionally future mappings via mm->def_flags. "
		   "Memory locks are not inherited by child processes after fork(). Commonly used "
		   "by real-time applications to prevent page faults. Also used for security to "
		   "prevent sensitive data (e.g., cryptographic keys) from being written to swap. "
		   "Note: locked pages may still be saved to swap during system suspend/hibernate.")

	/* Additional constraints */
	KAPI_CONSTRAINT(0, "MCL_FUTURE Persistence",
			"The MCL_FUTURE flag persists across execve() calls by setting "
			"mm->def_flags. This means all future memory mappings in the new "
			"program will be locked. Care must be taken as this can cause "
			"unexpected memory exhaustion in executed programs.")
		KAPI_CONSTRAINT_EXPR("MCL_FUTURE => mm->def_flags |= VM_LOCKED")
	KAPI_CONSTRAINT_END

	KAPI_CONSTRAINT(1, "Total VM Size Limit",
			"When MCL_CURRENT is set, the total virtual memory size of the "
			"process is checked against RLIMIT_MEMLOCK. This differs from "
			"mlock() which only counts actually locked pages. CAP_IPC_LOCK "
			"bypasses this check entirely.")
		KAPI_CONSTRAINT_EXPR("(flags & MCL_CURRENT) => total_vm <= RLIMIT_MEMLOCK || CAP_IPC_LOCK")
	KAPI_CONSTRAINT_END

	KAPI_CONSTRAINT(2, "Memory Accounting",
			"mlockall() with MCL_CURRENT can lock significantly more memory "
			"than expected, including all shared libraries, heap, stack, and "
			"mapped files. This can easily exhaust memory limits or cause "
			"system-wide memory pressure.")
	KAPI_CONSTRAINT_END

	KAPI_CONSTRAINT_COUNT(3)

KAPI_END_SPEC;

SYSCALL_DEFINE1(mlockall, int, flags)
{
	unsigned long lock_limit;
	int ret;

	if (!flags || (flags & ~(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)) ||
	    flags == MCL_ONFAULT)
		return -EINVAL;

	if (!can_do_mlock())
		return -EPERM;

	lock_limit = rlimit(RLIMIT_MEMLOCK);
	lock_limit >>= PAGE_SHIFT;

	if (mmap_write_lock_killable(current->mm))
		return -EINTR;

	ret = -ENOMEM;
	if (!(flags & MCL_CURRENT) || (current->mm->total_vm <= lock_limit) ||
	    capable(CAP_IPC_LOCK))
		ret = apply_mlockall_flags(flags);
	mmap_write_unlock(current->mm);
	if (!ret && (flags & MCL_CURRENT))
		mm_populate(0, TASK_SIZE);

	return ret;
}


DEFINE_KERNEL_API_SPEC(sys_munlockall)
	KAPI_DESCRIPTION("Unlock all process pages")
	KAPI_LONG_DESC("Unlocks all pages mapped into the process address space and "
		       "clears the MCL_FUTURE flag if set.")
	KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE)

	/* No parameters - this is a SYSCALL_DEFINE0 */
	.param_count = 0,

	/* Return specification */
	KAPI_RETURN("long", "0 on success, negative error code on failure")
		.type = KAPI_TYPE_INT,
		.check_type = KAPI_RETURN_ERROR_CHECK,
		.success_value = 0,
	KAPI_RETURN_END

	/* Error codes */
	KAPI_ERROR(0, -EINTR, "EINTR", "Interrupted by signal", "The operation was interrupted by a signal before completion.")
	KAPI_ERROR(1, -ENOMEM, "ENOMEM", "Memory operation failed", "Failed to modify memory mappings (should not normally occur).")

	/* Signal specifications */
	KAPI_SIGNAL(0, 0, "FATAL_SIGNALS", KAPI_SIGNAL_RECEIVE, KAPI_SIGNAL_ACTION_RETURN)
		KAPI_SIGNAL_CONDITION("Fatal signal pending during mmap_write_lock_killable")
		KAPI_SIGNAL_DESC("Fatal signals (SIGKILL, SIGTERM, etc.) can interrupt the operation when acquiring mmap_write_lock_killable(), causing -EINTR return")
		KAPI_SIGNAL_TIMING(KAPI_SIGNAL_TIME_ENTRY)
		KAPI_SIGNAL_PRIORITY(0)
		KAPI_SIGNAL_INTERRUPTIBLE
		KAPI_SIGNAL_ERROR(-EINTR)
		KAPI_SIGNAL_STATE_REQ(KAPI_SIGNAL_STATE_RUNNING | KAPI_SIGNAL_STATE_SLEEPING)
		KAPI_SIGNAL_RESTARTABLE
	KAPI_SIGNAL_END

	/* Side effects */
	KAPI_SIDE_EFFECT(0, KAPI_EFFECT_MODIFY_STATE,
			 "all process memory",
			 "Unlocks all pages, making entire address space swappable")
		KAPI_EFFECT_REVERSIBLE
		KAPI_EFFECT_CONDITION("Process had locked pages")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(1, KAPI_EFFECT_MODIFY_STATE,
			 "mm->def_flags",
			 "Clears VM_LOCKED from default flags for future mappings")
		KAPI_EFFECT_REVERSIBLE
		KAPI_EFFECT_CONDITION("MCL_FUTURE was previously set")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(2, KAPI_EFFECT_MODIFY_STATE,
			 "mm->locked_vm",
			 "Resets process locked memory counter to zero")
		KAPI_EFFECT_REVERSIBLE
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(3, KAPI_EFFECT_MODIFY_STATE,
			 "all VMA flags",
			 "Clears VM_LOCKED and VM_LOCKONFAULT from all VMAs")
		KAPI_EFFECT_REVERSIBLE
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(4, KAPI_EFFECT_MODIFY_STATE,
			 "page flags",
			 "Clears PG_mlocked flag from all locked pages")
		KAPI_EFFECT_CONDITION("Pages had PG_mlocked set")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(5, KAPI_EFFECT_MODIFY_STATE,
			 "LRU lists",
			 "Moves all pages from unevictable to normal LRU lists")
		KAPI_EFFECT_CONDITION("Pages were on unevictable list")
	KAPI_SIDE_EFFECT_END

	/* State transitions */
	KAPI_STATE_TRANS(0, "all memory pages",
			 "locked in RAM", "swappable",
			 "All pages in process become eligible for swap out")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(1, "future mappings",
			 "auto-locked", "normal",
			 "New mappings will no longer be automatically locked")
		KAPI_STATE_TRANS_COND("MCL_FUTURE was set")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(2, "all VMA flags",
			 "VM_LOCKED set", "VM_LOCKED cleared",
			 "All virtual memory areas no longer marked as locked")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(3, "process statistics",
			 "all memory locked", "no memory locked",
			 "Entire locked memory accounting reset to zero")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(4, "page LRU status",
			 "unevictable list", "active/inactive list",
			 "All pages moved to normal LRU lists for reclaim")
		KAPI_STATE_TRANS_COND("Pages were mlocked")
	KAPI_STATE_TRANS_END

	/* Locking information */
	KAPI_LOCK(0, "mmap_lock", KAPI_LOCK_RWLOCK)
		KAPI_LOCK_DESC("Process memory map write lock")
		KAPI_LOCK_ACQUIRED
		KAPI_LOCK_RELEASED
		KAPI_LOCK_DESC("Protects VMA modifications during munlockall operation")
	KAPI_LOCK_END

	KAPI_LOCK(1, "lru_lock", KAPI_LOCK_SPINLOCK)
		KAPI_LOCK_DESC("Per-memcg LRU list lock")
		KAPI_LOCK_ACQUIRED
		KAPI_LOCK_RELEASED
		KAPI_LOCK_DESC("Taken when moving all pages from unevictable to normal LRU lists")
	KAPI_LOCK_END

	KAPI_ERROR_COUNT(2)
	KAPI_SINCE_VERSION("2.0")
	KAPI_SIGNAL_COUNT(1)
	KAPI_SIDE_EFFECT_COUNT(6)
	KAPI_STATE_TRANS_COUNT(5)
	KAPI_LOCK_COUNT(2)
	KAPI_EXAMPLES("munlockall();  // Unlock all pages")
	KAPI_NOTES("Clears VM_LOCKED and VM_LOCKONFAULT from all VMAs and mm->def_flags. "
		   "A single munlockall() can undo multiple mlockall() calls since locks don't stack.")
KAPI_END_SPEC;

SYSCALL_DEFINE0(munlockall)
{
	int ret;

	if (mmap_write_lock_killable(current->mm))
		return -EINTR;
	ret = apply_mlockall_flags(0);
	mmap_write_unlock(current->mm);
	return ret;
}

/*
 * Objects with different lifetime than processes (SHM_LOCK and SHM_HUGETLB
 * shm segments) get accounted against the user_struct instead.
 */
static DEFINE_SPINLOCK(shmlock_user_lock);

int user_shm_lock(size_t size, struct ucounts *ucounts)
{
	unsigned long lock_limit, locked;
	long memlock;
	int allowed = 0;

	locked = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	lock_limit = rlimit(RLIMIT_MEMLOCK);
	if (lock_limit != RLIM_INFINITY)
		lock_limit >>= PAGE_SHIFT;
	spin_lock(&shmlock_user_lock);
	memlock = inc_rlimit_ucounts(ucounts, UCOUNT_RLIMIT_MEMLOCK, locked);

	if ((memlock == LONG_MAX || memlock > lock_limit) && !capable(CAP_IPC_LOCK)) {
		dec_rlimit_ucounts(ucounts, UCOUNT_RLIMIT_MEMLOCK, locked);
		goto out;
	}
	if (!get_ucounts(ucounts)) {
		dec_rlimit_ucounts(ucounts, UCOUNT_RLIMIT_MEMLOCK, locked);
		allowed = 0;
		goto out;
	}
	allowed = 1;
out:
	spin_unlock(&shmlock_user_lock);
	return allowed;
}

void user_shm_unlock(size_t size, struct ucounts *ucounts)
{
	spin_lock(&shmlock_user_lock);
	dec_rlimit_ucounts(ucounts, UCOUNT_RLIMIT_MEMLOCK, (size + PAGE_SIZE - 1) >> PAGE_SHIFT);
	spin_unlock(&shmlock_user_lock);
	put_ucounts(ucounts);
}
