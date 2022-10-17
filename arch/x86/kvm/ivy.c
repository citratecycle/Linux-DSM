/*
 * Support KVM software distributed memory (Ivy Protocol)
 *
 * This feature allows us to run multiple KVM instances on different machines
 * sharing the same address space.
 *
 * Copyright (C) 2019, Trusted Cloud Group, Shanghai Jiao Tong University.
 * 
 * Authors:
 *   Jin Zhang <jzhang3002@sjtu.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

/************************
 **DEADLOCK DELENDA EST**
 ************************/

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include "dsm-util.h"
#include "ivy.h"
#include "mmu.h"

#include <linux/kthread.h>
#include <linux/mmu_context.h>

// 1                                          prefetch_count (How many pages are prefetched)
// + 2                                        length (Length of target page)
// + PAGE_SIZE                                Data of target page
// + 8 * KVM_PREFETCH_MAX_WINDOW_SIZE         gfns (gfn_t is uint64)
// + 2 * KVM_PREFETCH_MAX_WINDOW_SIZE         copysets (copyset_t is uint16)
// + 4 * KVM_PREFETCH_MAX_WINDOW_SIZE         versions (version_t is uint32)
// + 2 * KVM_PREFETCH_MAX_WINDOW_SIZE         Lengths of prefetched pages
// + PAGE_SIZE * KVM_PREFETCH_MAX_WINDOW_SIZE Data of prefetched pages
#define KVM_PREFETCH_MAX_RESPONSE_SIZE (1 + 2 + PAGE_SIZE + (16 + PAGE_SIZE) * KVM_PREFETCH_MAX_WINDOW_SIZE)

enum kvm_dsm_request_type {
	DSM_REQ_INVALIDATE,
	DSM_REQ_READ,
	DSM_REQ_WRITE,
};
static char* req_desc[3] = {"INV", "READ", "WRITE"};

static inline copyset_t *dsm_get_copyset(
		struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	return slot->vfn_dsm_state[vfn - slot->base_vfn].copyset;
}

static inline void dsm_add_to_copyset(struct kvm_dsm_memory_slot *slot, hfn_t vfn, int id)
{
	set_bit(id, slot->vfn_dsm_state[vfn - slot->base_vfn].copyset);
}

static inline void dsm_clear_copyset(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	bitmap_zero(dsm_get_copyset(slot, vfn), DSM_MAX_INSTANCES);
}

/*
 * @requester:	the requester (real message sender or manager or probOwner) of
 * this invalidate request.
 * @msg_sender: the real message sender.
 */
struct dsm_request {
	unsigned char requester;
	unsigned char msg_sender;
	gfn_t gfn;
	unsigned char req_type;
	bool is_smm;

	/*
	 * If version of two pages in different nodes are the same, the contents
	 * are the same.
	 */
	uint16_t version;

	// For prefetch
	unsigned char prefetch_size;
	gfn_t prefetch_gfns[KVM_PREFETCH_MAX_WINDOW_SIZE];
	version_t prefetch_versions[KVM_PREFETCH_MAX_WINDOW_SIZE];
};

struct dsm_response {
	copyset_t inv_copyset;
	uint16_t version;
};

#ifdef IVY_KVM_DSM_PREFETCH
/*****************************
 * Prefetch Functions Starts *
 *****************************/
// Return 1 if page found, 0 if not found
int invalidate_prefetch_cache(struct kvm *kvm, gfn_t gfn) {
	struct kvm_prefetch_cache_t *temp;
	mutex_lock(&kvm->prefetch_cache_lock);
	temp = kvm->prefetch_cache_head;
	while (temp) {
		if (temp->gfn == gfn && temp->page) {
			kfree(temp->page);
			temp->page = NULL;
			if (temp->prev)
				temp->prev->next = temp->next;
			if (temp->next)
				temp->next->prev = temp->prev;
			if (kvm->prefetch_cache_head == temp)
				kvm->prefetch_cache_head = temp->next;
			kfree(temp);
			mutex_unlock(&kvm->prefetch_cache_lock);
			return 1;
		}
		temp = temp->next;
	}
	mutex_unlock(&kvm->prefetch_cache_lock);
	return 0;
}

// Return 1 if page found, 0 if not found
int read_prefetch_cache(struct kvm *kvm, gfn_t gfn, copyset_t *copyset_ptr, version_t *version_ptr, char *page) {
	struct kvm_prefetch_cache_t *temp;
	mutex_lock(&kvm->prefetch_cache_lock);
	temp = kvm->prefetch_cache_head;
	while (temp) {
		if (temp->gfn == gfn && temp->page) {
			memcpy(page, temp->page, PAGE_SIZE);
			*copyset_ptr = temp->copyset;
			*version_ptr = temp->version;
			kfree(temp->page);
			temp->page = NULL;
			if (temp->prev)
				temp->prev->next = temp->next;
			if (temp->next)
				temp->next->prev = temp->prev;
			if (kvm->prefetch_cache_head == temp)
				kvm->prefetch_cache_head = temp->next;
			kfree(temp);
			mutex_unlock(&kvm->prefetch_cache_lock);
			return 1;
		}
		temp = temp->next;
	}
	mutex_unlock(&kvm->prefetch_cache_lock);
	return 0;
}

void dump_prefetch_cache(struct kvm *kvm) {
	struct kvm_prefetch_cache_t *temp;
	mutex_lock(&kvm->prefetch_cache_lock);
	if(kvm->prefetch_cache_head) {
		printk(KERN_INFO "Prefetch Cache Dump of dsm_id %d: ", kvm->arch.dsm_id);
		temp = kvm->prefetch_cache_head;
		while (temp) {
			printk(KERN_INFO "gfn: %llu, page: %p, copyset: %lx, version: %u", temp->gfn, temp->page, temp->copyset, temp->version);
			temp = temp->next;
		}
	}
	mutex_unlock(&kvm->prefetch_cache_lock);
}

int handle_prefetch_req(struct kvm *kvm, const struct dsm_request *req, char *target_page, int target_length, char *resp_data)
{
	int iterator;
	struct kvm_memory_slot *memslot;
	struct kvm_dsm_memory_slot *slot;
	hfn_t vfn;
	int ret;
	int resp_length;
	int prefetch_count = 0;
	int temp;
	struct {
		gfn_t gfn;         // uint64
		copyset_t copyset; // uint16
		version_t version; // uint32
		int length;
		char *page;
	} prefetched_pages[KVM_PREFETCH_MAX_WINDOW_SIZE];

	for (iterator = 0; iterator < KVM_PREFETCH_MAX_WINDOW_SIZE; iterator++) {
		prefetched_pages[iterator].page = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (prefetched_pages[iterator].page == NULL) {
			for (temp = 0; temp < iterator; temp++) {
				kfree(prefetched_pages[temp].page);
			}
			return -ENOMEM;
		}
	}

	for (iterator = 0; iterator < req->prefetch_size; iterator++)
	{
		if(read_prefetch_cache(kvm, req->prefetch_gfns[iterator], &prefetched_pages[prefetch_count].copyset, &prefetched_pages[prefetch_count].version, prefetched_pages[prefetch_count].page)) {
			prefetched_pages[prefetch_count].gfn = req->prefetch_gfns[iterator];
			prefetched_pages[prefetch_count].length = PAGE_SIZE;
			prefetch_count++;
			continue;
		}
		// ivy_kvm_dsm_handle_req, identifying private memslots
		// FIXME: argument is_smm of __kvm_memslots() is fixed to 0, find out the real meaning in the future
		memslot = __gfn_to_memslot(__kvm_memslots(kvm, 0), req->prefetch_gfns[iterator]);
		if (!memslot || memslot->id >= KVM_USER_MEM_SLOTS || memslot->flags & KVM_MEMSLOT_INVALID)
		{
			continue;
		}
		// ivy_kvm_dsm_handle_req, identifying slot existance
		vfn = __gfn_to_vfn_memslot(memslot, req->prefetch_gfns[iterator]);
		slot = gfn_to_hvaslot(kvm, memslot, req->prefetch_gfns[iterator]);
		if (!slot)
		{
			continue;
		}
		// ivy_kvm_dsm_handle_req, lock vfn
		if (!dsm_trylock(kvm, slot, vfn))
		{
			continue;
		}
		// dsm_handle_read_req, identifying pinned gfn
		if (dsm_is_pinned_read(slot, vfn) && !kvm->arch.dsm_stopped)
		{
			dsm_unlock(kvm, slot, vfn);
			continue;
		}
		// dsm_handle_read_req, identifying ownership of gfn
		if (!dsm_is_owner(slot, vfn))
		{
			dsm_unlock(kvm, slot, vfn);
			continue;
		}
		// dsm_handle_read_req, read page
		BUG_ON(dsm_get_prob_owner(slot, vfn) != kvm->arch.dsm_id);
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		printk(KERN_INFO "handle_prefetch_req: dsm_id: %d, transmitting owner of gfn: %llu, vfn: %llu, to %d, change state to SHARED", kvm->arch.dsm_id, req->prefetch_gfns[iterator], vfn, req->msg_sender);
		dsm_change_state(slot, vfn, DSM_SHARED);
		kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_SHARED);
		ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->prefetch_gfns[iterator], prefetched_pages[prefetch_count].page, 0, PAGE_SIZE);
		if (ret < 0) {
			dsm_unlock(kvm, slot, vfn);
			continue;
		}
		dsm_unlock(kvm, slot, vfn);
		prefetched_pages[prefetch_count].gfn = req->prefetch_gfns[iterator];
		prefetched_pages[prefetch_count].copyset = *dsm_get_copyset(slot, vfn);
		BUG_ON(!(test_bit(kvm->arch.dsm_id, &prefetched_pages[prefetch_count].copyset)));
		prefetched_pages[prefetch_count].version = dsm_get_version(slot, vfn);
		prefetched_pages[prefetch_count].length = dsm_encode_diff(slot, vfn, req->msg_sender,
		            prefetched_pages[prefetch_count].page, memslot, req->prefetch_gfns[iterator],
					req->prefetch_versions[iterator]);

		prefetch_count++;
	}

	// Calculate length of response data
	resp_length = 1                     // prefetch_count (How many pages are prefetched)
	              + 2                   // length (Length of target page)
				  + target_length       // Data of target page
				  + 8 * prefetch_count  // gfns (gfn_t is uint64)
				  + 2 * prefetch_count  // copysets (copyset_t is uint16)
				  + 4 * prefetch_count  // versions (version_t is uint32)
				  + 2 * prefetch_count; // Lengths of prefetched pages
	for(iterator = 0; iterator < prefetch_count; iterator++) {
		resp_length += prefetched_pages[iterator].length; // Data of prefetched pages
	}

	// Fill in response data
	memset(resp_data, 0, resp_length);
	memcpy(resp_data, &prefetch_count, 1);
	memcpy(resp_data + 1, &target_length, 2);
	memcpy(resp_data + 3, target_page, target_length);
	temp = 0;
	for(iterator = 0; iterator < prefetch_count; iterator++) {
		memcpy(resp_data + 3 + target_length + iterator * 8, &(prefetched_pages[iterator].gfn), 8);
		memcpy(resp_data + 3 + target_length + prefetch_count * 8 + iterator * 2, &(prefetched_pages[iterator].copyset), 2);
		memcpy(resp_data + 3 + target_length + prefetch_count * 10 + iterator * 4, &(prefetched_pages[iterator].version), 4);
		memcpy(resp_data + 3 + target_length + prefetch_count * 14 + iterator * 2, &(prefetched_pages[iterator].length), 2);
		memcpy(resp_data + 3 + target_length + prefetch_count * 16 + temp, prefetched_pages[iterator].page, prefetched_pages[iterator].length);
		temp += prefetched_pages[iterator].length;
	}

	for (iterator = 0; iterator < KVM_PREFETCH_MAX_WINDOW_SIZE; iterator++) {
		kfree(prefetched_pages[iterator].page);
	}
	return resp_length;
}

void handle_prefetch_resp_owner_transmission(struct kvm *kvm, const struct dsm_request *req, char *resp_data) {
	int iterator;
	struct kvm_memory_slot *memslot;
	struct kvm_dsm_memory_slot *slot;
	hfn_t vfn;

	int prefetch_count = 0;
	int target_page_length_from_resp = 0;
	int temp;
	gfn_t gfn;
	int length;

	memcpy(&prefetch_count, resp_data, 1);
	memcpy(&target_page_length_from_resp, resp_data + 1, 2);
	temp = 0;
	for(iterator = 0; iterator < prefetch_count; iterator++) {
		gfn = 0;
		length = 0;
		memcpy(&gfn, resp_data + 3 + target_page_length_from_resp + iterator * 8, 8);
		memcpy(&length, resp_data + 3 + target_page_length_from_resp + prefetch_count * 14 + iterator * 2, 2);
		temp += length;
	 	
		// FIXME: argument is_smm of __kvm_memslots() is fixed to 0, find out the real meaning in the future
		memslot = __gfn_to_memslot(__kvm_memslots(kvm, 0), gfn);
		if (!memslot || memslot->id >= KVM_USER_MEM_SLOTS || memslot->flags & KVM_MEMSLOT_INVALID)
		{
			continue;
		}
		vfn = __gfn_to_vfn_memslot(memslot, gfn);
		slot = gfn_to_hvaslot(kvm, memslot, gfn);
		if (!slot)
		{
			continue;
		}
		dsm_lock(kvm, slot, vfn);
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		dsm_unlock(kvm, slot, vfn);
		printk(KERN_INFO "handle_prefetch_resp_owner_transmission: dsm_id: %d, transmitting owner of gfn: %llu, vfn: %llu, to %d", kvm->arch.dsm_id, gfn, vfn, req->msg_sender);
	}
}

int handle_prefetch_resp(struct kvm *kvm, struct kvm_memory_slot *memslot, char *target_page, char *resp_data, int prefetch_locked_vfns_num, hfn_t *prefetch_locked_vfns) {
	int iterator;
	int prefetch_count;
	int target_page_length;
	int temp;
	int length;
	struct kvm_prefetch_cache_t *seg_head = NULL, *seg_tail = NULL, *temp_node = NULL;
	struct kvm_dsm_memory_slot *slot;

	prefetch_count = target_page_length = 0;
	memcpy(&prefetch_count, resp_data, 1);
	memcpy(&target_page_length, resp_data + 1, 2);
	memset(target_page, 0, PAGE_SIZE);
	memcpy(target_page, resp_data + 3, target_page_length);
	mutex_lock(&kvm->prefetch_cache_lock);
	temp = 0;
	for (iterator = 0; iterator < prefetch_count; iterator++) {
		length = 0;
		temp_node = kmalloc(sizeof(struct kvm_prefetch_cache_t), GFP_KERNEL);
		temp_node->page = kmalloc(PAGE_SIZE, GFP_KERNEL);
		memset(temp_node->page, 0, PAGE_SIZE);

		memcpy(&(temp_node->gfn), resp_data + 3 + target_page_length + iterator * 8, 8);
		memcpy(&(temp_node->copyset), resp_data + 3 + target_page_length + prefetch_count * 8 + iterator * 2, 2);
		memcpy(&(temp_node->version), resp_data + 3 + target_page_length + prefetch_count * 10 + iterator * 4, 4);
		memcpy(&length, resp_data + 3 + target_page_length + prefetch_count * 14 + iterator * 2, 2);
		memcpy(temp_node->page, resp_data + 3 + target_page_length + prefetch_count * 16 + temp, length);
		dsm_decode_diff(temp_node->page, length, memslot, temp_node->gfn);
		temp += length;

		if (!seg_head && !seg_tail) {
			temp_node->prev = temp_node->next = NULL;
			seg_head = seg_tail = temp_node;
		} else if (seg_head && seg_tail){
			temp_node->prev = seg_tail;
			temp_node->next = NULL;
			seg_tail->next = temp_node;
			seg_tail = temp_node;
		} else {
			printk(KERN_ERR "handle_prefetch_resp: linked list error");
			BUG();
		}
	}
	if (seg_head) {
		seg_tail->next = kvm->prefetch_cache_head;
		if (kvm->prefetch_cache_head)
			kvm->prefetch_cache_head->prev = seg_tail;
		kvm->prefetch_cache_head = seg_head;
	}
	mutex_unlock(&kvm->prefetch_cache_lock);

	printk(KERN_INFO "handle_prefetch_resp: dsm_id: %d, unlocking dsm:", kvm->arch.dsm_id);
	for (iterator = 0; iterator < prefetch_locked_vfns_num; iterator++) {
		slot = vfn_to_hvaslot(kvm, prefetch_locked_vfns[iterator]);
		dsm_unlock(kvm, slot, prefetch_locked_vfns[iterator]);
		printk(KERN_INFO "handle_prefetch_resp: dsm_id: %d, unlocked vfn: %llu", kvm->arch.dsm_id, prefetch_locked_vfns[iterator]);
	}
	return target_page_length;
}

void record_gfn_to_access_history(struct kvm *kvm, gfn_t gfn, int write)
{
	mutex_lock(&kvm->prefetch_access_history_lock);
	kvm->prefetch_access_history[kvm->prefetch_access_history_head].gfn_delta = gfn - kvm->prefetch_last_gfn;
	kvm->prefetch_access_history[kvm->prefetch_access_history_head].write = write;
	kvm->prefetch_last_gfn = gfn;
	kvm->prefetch_access_history_head++;
	if (kvm->prefetch_access_history_head >= KVM_PREFETCH_ACCESS_HISTORY_SIZE) {
		kvm->prefetch_access_history_head -= KVM_PREFETCH_ACCESS_HISTORY_SIZE;
	}
	mutex_unlock(&kvm->prefetch_access_history_lock);
}

long long find_trend(struct kvm *kvm)
{
	int w = KVM_PREFETCH_ACCESS_HISTORY_SIZE / KVM_PREFETCH_TREND_WINDOW_SPLIT;
	long long majority = 0;
	int iterator, count, index;

	mutex_lock(&kvm->prefetch_access_history_lock);
	while(w <= KVM_PREFETCH_ACCESS_HISTORY_SIZE) {
		// Boyer–Moore majority vote algorithm
		count = 0;
		for(iterator = 1; iterator <= w; iterator++) {
			index = kvm->prefetch_access_history_head - iterator;
			if(index < 0) {
				index += KVM_PREFETCH_ACCESS_HISTORY_SIZE;
			}
			if(count == 0) {
				majority = kvm->prefetch_access_history[index].gfn_delta;
			} else if (majority == kvm->prefetch_access_history[index].gfn_delta) {
				count++;
			} else {
				count--;
			}
		}
		// Check whether the majority is a real majority
		count = 0;
		for(iterator = 1; iterator <= w; iterator++) {
			index = kvm->prefetch_access_history_head - iterator;
			if(index < 0) {
				index += KVM_PREFETCH_ACCESS_HISTORY_SIZE;
			}
			if(majority == kvm->prefetch_access_history[index].gfn_delta) {
				count++;
			}
		}
		if(count < w / 2 + 1) {
			majority = 0;
		}
		// Increase window size
		w *= 2;
		// Return majority
		if(majority != 0) {
			mutex_unlock(&kvm->prefetch_access_history_lock);
			return majority;
		}
	}
	mutex_unlock(&kvm->prefetch_access_history_lock);
	return majority;
}

int get_prefetch_window_size(struct kvm *kvm, gfn_t gfn)
{
	int window_size = 0, temp;
	if(kvm->prefetch_cache_hits == 0) {
		temp = kvm->prefetch_access_history_head - 1;
		temp = temp < 0 ? temp + KVM_PREFETCH_ACCESS_HISTORY_SIZE : temp;
		if(kvm->prefetch_access_history[temp].gfn_delta == kvm->prefetch_last_trend) {
			window_size = 1;
		} else {
			window_size = 0;
		}
	} else {
		if(KVM_PREFETCH_MAX_WINDOW_SIZE <= 16) {
			switch(kvm->prefetch_cache_hits + 1) {
				case 2: window_size = 2; break;
				case 3:
				case 4:
				case 5:
				case 6:
				case 7:
				case 8: window_size = 8; break;
				case 9:
				case 10:
				case 11:
				case 12:
				case 13:
				case 14:
				case 15:
				case 16: window_size = 16; break;
			}
		} else {
			temp = 0;
			while(kvm->prefetch_cache_hits != 0) {
				kvm->prefetch_cache_hits /= 2;
				temp++;
			}
			window_size = 2;
			while(temp > 1) {
				window_size *= 2;
				temp--;
			}
		}
	}
	window_size = window_size < KVM_PREFETCH_MAX_WINDOW_SIZE ? window_size : KVM_PREFETCH_MAX_WINDOW_SIZE;
	if(window_size < kvm->prefetch_last_window_size / 2) {
		window_size = kvm->prefetch_last_window_size / 2;
	}
	kvm->prefetch_cache_hits = 0;
	kvm->prefetch_last_window_size = window_size;
	kvm->prefetch_stat_prefetched_pages += window_size;
	return window_size;
}

void write_prefetch_to_req(struct kvm *kvm, struct kvm_memory_slot *memslot, gfn_t gfn, struct dsm_request *req, int *prefetch_locked_vfns_num, hfn_t *prefetch_locked_vfns)
{
	int iterator;
	hfn_t vfn;
	struct kvm_dsm_memory_slot *slot;
	int window_size = get_prefetch_window_size(kvm, gfn);
	int majority = find_trend(kvm);
	if (window_size != 0)
	{
		if (majority != 0)
		{
			req->prefetch_size = 0;
			printk(KERN_INFO "write_prefetch_to_req: dsm_id: %d, locking dsm and put to request:", kvm->arch.dsm_id);
			for (iterator = 0; iterator < window_size; iterator++)
			{
				vfn = __gfn_to_vfn_memslot(memslot, gfn + (iterator + 1) * majority);
				slot = gfn_to_hvaslot(kvm, memslot, gfn + (iterator + 1) * majority);
				if(!dsm_trylock(kvm, slot, vfn)) {
					continue;
				}
				printk(KERN_INFO "dsm_id: %d, locking gfn: %llu, vfn: %llu", kvm->arch.dsm_id, gfn + (iterator + 1) * majority, vfn);
				req->prefetch_gfns[iterator] = gfn + (iterator + 1) * majority;
				req->prefetch_versions[iterator] = dsm_get_version(slot, vfn);
				req->prefetch_size++;
				prefetch_locked_vfns[*prefetch_locked_vfns_num] = vfn;
				(*prefetch_locked_vfns_num)++;
			}
		}
		else
		{
			if (kvm->prefetch_last_trend == 0)
			{
				req->prefetch_size = 0;
			}
			else
			{
				req->prefetch_size = 0;
				printk(KERN_INFO "write_prefetch_to_req: dsm_id: %d, target page: %llu, locking dsm and put to request:", kvm->arch.dsm_id, gfn);
				for (iterator = 0; iterator < window_size; iterator++)
				{
					vfn = __gfn_to_vfn_memslot(memslot, gfn + (iterator + 1) * majority);
					slot = gfn_to_hvaslot(kvm, memslot, gfn + (iterator + 1) * majority);
					if(!dsm_trylock(kvm, slot, vfn)) {
						continue;
					}
					printk(KERN_INFO "write_prefetch_to_req: dsm_id: %d, locking gfn: %llu, vfn: %llu", req->prefetch_gfns[iterator], kvm->arch.dsm_id, gfn + (iterator + 1) * majority, vfn);
					req->prefetch_gfns[iterator] = gfn + (iterator + 1) * majority;
					req->prefetch_versions[iterator] = dsm_get_version(slot, vfn);
					req->prefetch_size++;
					prefetch_locked_vfns[*prefetch_locked_vfns_num] = vfn;
					(*prefetch_locked_vfns_num)++;
				}
			}
		}
	}
	else // window_size == 0
	{
		req->prefetch_size = 0;
	}
	kvm->prefetch_last_trend = majority;
}

void do_prefetch_demo(struct kvm *kvm, gfn_t gfn)
{
	int iterator;
	int window_size = get_prefetch_window_size(kvm, gfn);
	int majority = find_trend(kvm);
	if(window_size != 0) {
		if(majority != 0) {
			for(iterator = 0; iterator < window_size; iterator++) {
				kvm->prefetch_cache_demo[iterator] = gfn + (iterator + 1) * majority;
			}
		} else {
			for(iterator = 0; iterator < window_size; iterator++) {
				kvm->prefetch_cache_demo[iterator] = gfn + (iterator + 1) * kvm->prefetch_last_trend;
			}
		}
	}
	kvm->prefetch_last_trend = majority;
}

int cache_demo(struct kvm *kvm, gfn_t gfn) {
	int i;
	for(i = 0; i < kvm->prefetch_last_window_size; i++) {
		if(gfn == kvm->prefetch_cache_demo[i]) {
			kvm->prefetch_cache_hits++;
			kvm->prefetch_stat_cache_hits++;
			return 1;
		}
	}
	return 0;
}

/***************************
 * Prefetch Functions Ends *
 ***************************/
#endif

/*
 * @msg_sender: the message may be delegated by manager (or other probOwners)
 * (kvm->arch.dsm_id) and real sender can be appointed here.
 * @inv_copyset: if req_type = DSM_REQ_WRITE, the requester becomes owner and has duty
 * to broadcast invalidate.
 * @return: the length of response
 */
static int kvm_dsm_fetch(struct kvm *kvm, uint16_t dest_id, bool from_server,
		const struct dsm_request *req, void *data, struct dsm_response *resp)
{
	kconnection_t **conn_sock;
	int ret;
	tx_add_t tx_add = {
		.txid = generate_txid(kvm, dest_id),
	};
	int retry_cnt = 0;

	if (kvm->arch.dsm_stopped)
		return -EINVAL;

	if (!from_server)
		conn_sock = &kvm->arch.dsm_conn_socks[dest_id];
	else {
		conn_sock = &kvm->arch.dsm_conn_socks[DSM_MAX_INSTANCES + dest_id];
	}

	/*
	 * Mutiple vCPUs/servers may connect to a remote node simultaneously.
	 */
	if (*conn_sock == NULL) {
		mutex_lock(&kvm->arch.conn_init_lock);
		if (*conn_sock == NULL) {
			ret = kvm_dsm_connect(kvm, dest_id, conn_sock);
			if (ret < 0) {
				mutex_unlock(&kvm->arch.conn_init_lock);
				return ret;
			}
		}
		mutex_unlock(&kvm->arch.conn_init_lock);
	}

	dsm_debug_v("kvm[%d] sent request[0x%x] to kvm[%d] req_type[%s] gfn[%llu,%d]",
			kvm->arch.dsm_id, tx_add.txid, dest_id, req_desc[req->req_type],
			req->gfn, req->is_smm);

	ret = network_ops.send(*conn_sock, (const char *)req, sizeof(struct
				dsm_request), 0, &tx_add);
	if (ret < 0)
		goto done;

	retry_cnt = 0;
	if (req->req_type == DSM_REQ_INVALIDATE) {
		ret = network_ops.receive(*conn_sock, data, 0, &tx_add);
	}
	else {
retry:
		ret = network_ops.receive(*conn_sock, data, SOCK_NONBLOCK, &tx_add);
		if (ret == -EAGAIN) {
			retry_cnt++;
			if (retry_cnt > 100000) {
				printk("%s: DEADLOCK kvm %d wait for gfn %llu response from "
						"kvm %d for too LONG",
						__func__, kvm->arch.dsm_id, req->gfn, dest_id);
				retry_cnt = 0;
			}
			goto retry;
		}
		resp->inv_copyset = tx_add.inv_copyset;
		resp->version = tx_add.version;
	}
	if (ret < 0)
		goto done;

done:
	return ret;
}

/*
 * kvm_dsm_invalidate - issued by owner of a page to invalidate all of its copies
 * @cpyset: given copyset. NULL means using its own copyset.
 */
static int kvm_dsm_invalidate(struct kvm *kvm, gfn_t gfn, bool is_smm,
		struct kvm_dsm_memory_slot *slot, hfn_t vfn, copyset_t *cpyset, int req)
{
	int holder;
	int ret = 0;
	char r = 1;
	copyset_t *copyset;
	struct dsm_response resp;

	copyset = cpyset ? cpyset : dsm_get_copyset(slot, vfn);

	/*
	 * A given copyset has been properly tailored so that no redundant INVs will
	 * be sent to invalid nodes (nodes in the call-chain).
	 */
	for_each_set_bit(holder, copyset, DSM_MAX_INSTANCES) {
		struct dsm_request req = {
			.req_type = DSM_REQ_INVALIDATE,
			.requester = kvm->arch.dsm_id,
			.msg_sender = kvm->arch.dsm_id,
			.gfn = gfn,
			.is_smm = is_smm,
			.version = dsm_get_version(slot, vfn),
		};
		if (kvm->arch.dsm_id == holder)
			continue;
		/* Santiy check on copyset consistency. */
		BUG_ON(holder >= kvm->arch.cluster_iplist_len);

		ret = kvm_dsm_fetch(kvm, holder, false, &req, &r, &resp);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int dsm_handle_invalidate_req(struct kvm *kvm, kconnection_t *conn_sock,
		struct kvm_memory_slot *memslot, struct kvm_dsm_memory_slot *slot,
		const struct dsm_request *req, bool *retry, hfn_t vfn, char *page,
		tx_add_t *tx_add)
{
	int ret = 0;
	char r;

	// Invalidate page inside prefetch cache
	if (invalidate_prefetch_cache(kvm, req->gfn)) {
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		printk(KERN_INFO "dsm_handle_invalidate_req: dsm_id: %d, cache hit, invalidating and transmitting owner of gfn: %llu, vfn: %llu, to %d, dumping", kvm->arch.dsm_id, req->gfn, vfn, req->msg_sender);
		dump_prefetch_cache(kvm);
		ret = network_ops.send(conn_sock, &r, 1, 0, tx_add);
		return ret;
	}
	printk(KERN_INFO "dsm_handle_invalidate_req: dsm_id: %d, fail to invalidate gfn: %llu, vfn: %llu, in cache, dumping:", kvm->arch.dsm_id, req->gfn, vfn);
	dump_prefetch_cache(kvm);

	if (dsm_is_pinned(slot, vfn) && !kvm->arch.dsm_stopped) {
		*retry = true;
		dsm_debug("kvm[%d] REQ_INV blocked by pinned gfn[%llu,%d], sleep then retry\n",
				kvm->arch.dsm_id, req->gfn, req->is_smm);
		return 0;
	}

	/*
	 * The vfn->gfn rmap can be inconsistent with kvm_memslots when
	 * we're setting memslot, but this will not affect the correctness.
	 * If the old memslot is deleted, then the sptes will be zapped
	 * anyway, so nothing should be done with this case. On the other
	 * hand, if the new memslot is inserted (freshly created or moved),
	 * its sptes are yet to be constructed in tdp_page_fault, and that
	 * is protected by dsm_lock and cannot happen concurrently with the
	 * server side transaction, so the correct DSM state will be seen
	 * in spte construction.
	 *
	 * For usual cases, order between these two operations (change DSM state and
	 * modify page table right) counts. After spte is zapped, DSM software
	 * should make sure that #PF handler read the correct DSM state.
	 */
	if(dsm_is_modified(slot, vfn)) {
		printk(KERN_INFO "dsm_handle_invalidate_req: dsm_id: %d, page modified. gfn: %llu, vfn: %llu", kvm->arch.dsm_id, req->gfn, vfn);
	}
	BUG_ON(dsm_is_modified(slot, vfn));

	dsm_lock_fast_path(slot, vfn, true);

	printk(KERN_INFO "dsm_handle_invalidate_req: dsm_id: %d, gfn: %llu, vfn: %llu change state to INVALID", kvm->arch.dsm_id, req->gfn, vfn);
	dsm_change_state(slot, vfn, DSM_INVALID);
	kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_INVALID);
	dsm_set_prob_owner(slot, vfn, req->msg_sender);
	dsm_clear_copyset(slot, vfn);
	ret = network_ops.send(conn_sock, &r, 1, 0, tx_add);

	dsm_unlock_fast_path(slot, vfn, true);

	return ret < 0 ? ret : 0;
}

static int dsm_handle_write_req(struct kvm *kvm, kconnection_t *conn_sock,
		struct kvm_memory_slot *memslot, struct kvm_dsm_memory_slot *slot,
		const struct dsm_request *req, bool *retry, hfn_t vfn, char *page,
		tx_add_t *tx_add)
{
	int ret = 0, length = 0;
	int owner = -1;

	struct dsm_response resp;
	char *resp_data;
	int resp_length;
	int iterator;
	copyset_t copyset;
	version_t version;
	
	resp_data = kmalloc(KVM_PREFETCH_MAX_RESPONSE_SIZE, GFP_KERNEL);
	if (resp_data == NULL) {
		return -ENOMEM;
	}

	if(read_prefetch_cache(kvm, req->gfn, &copyset, &version, page)) {
		printk(KERN_INFO "dsm_handle_write_req: dsm_id: %d, hit cache, transmitting owner of gfn: %llu, vfn: %llu, to %d", kvm->arch.dsm_id, req->gfn, vfn, req->msg_sender);
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		clear_bit(kvm->arch.dsm_id, &copyset);
		length = PAGE_SIZE;
		ret = resp_length = handle_prefetch_req(kvm, req, page, length, resp_data);
		if (ret < 0) {
			kfree(resp_data);
			return ret;
		}
		tx_add->inv_copyset = copyset;
		tx_add->version = version;
		ret = network_ops.send(conn_sock, resp_data, resp_length, 0, tx_add);
		kfree(resp_data);
		if (ret < 0)
			return ret;
		return 0;
	}
	printk(KERN_INFO "dsm_handle_write_req: dsm_id: %d, gfn: %llu, vfn: %llu, cache miss, dumping:", kvm->arch.dsm_id, req->gfn, vfn);
	dump_prefetch_cache(kvm);

	if (dsm_is_pinned(slot, vfn) && !kvm->arch.dsm_stopped) {
		*retry = true;
		dsm_debug("kvm[%d] REQ_WRITE blocked by pinned gfn[%llu,%d], sleep then retry\n",
				kvm->arch.dsm_id, req->gfn, req->is_smm);
		return 0;
	}

	if (dsm_is_owner(slot, vfn)) {
		BUG_ON(dsm_get_prob_owner(slot, vfn) != kvm->arch.dsm_id);

		/* I'm owner */
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		dsm_debug_v("kvm[%d](M1) changed owner of gfn[%llu,%d] "
				"from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
				req->is_smm, kvm->arch.dsm_id, req->msg_sender);
		printk(KERN_INFO "dsm_handle_write_req: dsm_id: %d, I'm owner. gfn: %llu, vfn: %llu change state to INVALID", kvm->arch.dsm_id, req->gfn, vfn);
		dsm_change_state(slot, vfn, DSM_INVALID);
		kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_INVALID);
		/* Send back copyset to new owner. */
		resp.inv_copyset = *dsm_get_copyset(slot, vfn);
		resp.version = dsm_get_version(slot, vfn);
		clear_bit(kvm->arch.dsm_id, &resp.inv_copyset);
		ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
		if (ret < 0) {
			kfree(resp_data);
			return ret;
		}
		// Moved this line up here
		length = dsm_encode_diff(slot, vfn, req->msg_sender, page, memslot,
				req->gfn, req->version);

		// Prefetch
		ret = resp_length = handle_prefetch_req(kvm, req, page, length, resp_data);
		if (ret < 0) {
			kfree(resp_data);
			return ret;
		}
	}
	else if (dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0) {
		/* Send back a dummy copyset. */
		resp.inv_copyset = 0;
		resp.version = dsm_get_version(slot, vfn);
		ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
		if (ret < 0) {
			kfree(resp_data);
			return ret;
		}
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		printk(KERN_INFO "dsm_handle_write_req: dsm_id: %d Initialize page. gfn: %llu, vfn: %llu change state to INVALID", kvm->arch.dsm_id, req->gfn, vfn);
		dsm_change_state(slot, vfn, DSM_INVALID);

        // Prefetch
		ret = resp_length = handle_prefetch_req(kvm, req, page, length, resp_data);
		if (ret < 0) {
			kfree(resp_data);
			return ret;
		}
	}
	else {
		struct dsm_request new_req = {
			.req_type = DSM_REQ_WRITE,
			.requester = kvm->arch.dsm_id,
			.msg_sender = req->msg_sender,
			.gfn = req->gfn,
			.is_smm = req->is_smm,
			.version = req->version,

			.prefetch_size = req->prefetch_size,
		};
		for(iterator = 0; iterator < req->prefetch_size; iterator++) {
			new_req.prefetch_gfns[iterator] = req->prefetch_gfns[iterator];
			new_req.prefetch_versions[iterator] = req->prefetch_versions[iterator];
		}
		printk(KERN_INFO "dsm_handle_write_req: forwarding. dsm_id: %d, gfn: %llu, vfn: %llu, prob_owner: %d", kvm->arch.dsm_id, req->gfn, vfn, dsm_get_prob_owner(slot, vfn));
		owner = dsm_get_prob_owner(slot, vfn);
		ret = resp_length = kvm_dsm_fetch(kvm, owner, true, &new_req, resp_data, &resp);
		if (ret < 0) {
			kfree(resp_data);
			return ret;
		}

		dsm_change_state(slot, vfn, DSM_INVALID);
		kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_INVALID);
		printk(KERN_INFO "dsm_handle_write_req: dsm_id: %d, after forwarding, transmitting owner of gfn: %llu, vfn: %llu, to %d, change state to INVALID", kvm->arch.dsm_id, req->gfn, vfn, req->msg_sender);
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		dsm_debug_v("kvm[%d](M3) changed owner of gfn[%llu,%d] "
				"from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
				req->is_smm, owner, req->msg_sender);

		clear_bit(kvm->arch.dsm_id, &resp.inv_copyset);

		// Prefetch
		handle_prefetch_resp_owner_transmission(kvm, req, resp_data);
	}

	tx_add->inv_copyset = resp.inv_copyset;
	tx_add->version = resp.version;
	// ret = network_ops.send(conn_sock, page, length, 0, tx_add);
	ret = network_ops.send(conn_sock, resp_data, resp_length, 0, tx_add);
	kfree(resp_data);
	if (ret < 0)
		return ret;
	dsm_debug_v("kvm[%d] sent page[%llu,%d] to kvm[%d] length %d hash: 0x%x\n",
			kvm->arch.dsm_id, req->gfn, req->is_smm, req->requester, length,
			jhash(page, length, JHASH_INITVAL));
	return 0;
}

/*
 * A read fault causes owner transmission, too. It's different from original MSI
 * protocol. It mainly addresses a subtle data-race that *AFTER* DSM page fault
 * and *BEFORE* setting appropriate right a write requests (invalidation
 * request) issued by owner will be 'swallowed'. Specifically, in
 * mmu.c:tdp_page_fault:
 * // A read fault
 * [pf handler] dsm_access = kvm_dsm_vcpu_acquire_page()
 * .
 * . [server] dsm_handle_invalidate_req()
 * .
 * [pf handler] __direct_map(dsm_access)
 * [pf handler] kvm_dsm_vcpu_release_page()
 * dsm_handle_invalidate_req() takes no effects then (Note that invalidate
 * handler is lock-free). And if a read fault changes owner too, others write
 * faults will be synchronized by this node.
 */
static int dsm_handle_read_req(struct kvm *kvm, kconnection_t *conn_sock,
		struct kvm_memory_slot *memslot, struct kvm_dsm_memory_slot *slot,
		const struct dsm_request *req, bool *retry, hfn_t vfn, char *page,
		tx_add_t *tx_add)
{
	int ret = 0, length = 0;
	int owner = -1;
	struct dsm_response resp = {
		.version = 0,
	};
	char *resp_data;
	int resp_length;
	int iterator;
	copyset_t copyset;
	version_t version;

	resp_data = kmalloc(KVM_PREFETCH_MAX_RESPONSE_SIZE, GFP_KERNEL);
	if (resp_data == NULL) {
		return -ENOMEM;
	}

	if (read_prefetch_cache(kvm, req->gfn, &copyset, &version, page)) {
		printk(KERN_INFO "dsm_handle_read_req: dsm_id: %d, hit cache, transmitting owner of gfn: %llu, vfn: %llu, to %d", kvm->arch.dsm_id, req->gfn, vfn, req->msg_sender);
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		clear_bit(kvm->arch.dsm_id, &copyset);
		length = PAGE_SIZE;
		ret = resp_length = handle_prefetch_req(kvm, req, page, length, resp_data);
		if (ret < 0) {
			kfree(resp_data);
			return ret;
		}
		tx_add->inv_copyset = copyset;
		tx_add->version = version;
		
		ret = network_ops.send(conn_sock, resp_data, resp_length, 0, tx_add);
		kfree(resp_data);
		if (ret < 0)
			return ret;
		return 0;
	}
	printk(KERN_INFO "dsm_handle_read_req: dsm_id: %d, gfn: %llu, vfn: %llu, cache miss, dumping:", kvm->arch.dsm_id, req->gfn, vfn);
	dump_prefetch_cache(kvm);

	if (dsm_is_pinned_read(slot, vfn) && !kvm->arch.dsm_stopped) {
		*retry = true;
		dsm_debug("kvm[%d] REQ_READ blocked by pinned gfn[%llu,%d], sleep then retry\n",
				kvm->arch.dsm_id, req->gfn, req->is_smm);
		return 0;
	}

	if (dsm_is_owner(slot, vfn)) {
		BUG_ON(dsm_get_prob_owner(slot, vfn) != kvm->arch.dsm_id);

		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		dsm_debug_v("kvm[%d](S1) changed owner of gfn[%llu,%d] "
				"from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
				req->is_smm, kvm->arch.dsm_id, req->msg_sender);
		/* TODO: if modified */
		printk(KERN_INFO "dsm_handle_read_req: dsm_id: %d I'm the owner. gfn: %llu, vfn: %llu change state to SHARED", kvm->arch.dsm_id, req->gfn, vfn);
		dsm_change_state(slot, vfn, DSM_SHARED);
		kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_SHARED);

		ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
		if (ret < 0) {
			kfree(resp_data);
			return ret;
		}
		/*
		 * read fault causes owner transmission, too. Send copyset back to new
		 * owner.
		 */
		resp.inv_copyset = *dsm_get_copyset(slot, vfn);
		BUG_ON(!(test_bit(kvm->arch.dsm_id, &resp.inv_copyset)));
		resp.version = dsm_get_version(slot, vfn);

		// Moved this line up here
		length = dsm_encode_diff(slot, vfn, req->msg_sender, page, memslot,
			req->gfn, req->version);
		
		// Prefetch
		ret = resp_length = handle_prefetch_req(kvm, req, page, length, resp_data);
		if (ret < 0) {
			kfree(resp_data);
			return ret;
		}
	}
	else if (dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0) {
		ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
		if (ret < 0) {
			kfree(resp_data);
			return ret;
		}

		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		printk(KERN_INFO "dsm_handle_read_req: dsm_id: %d Initialize page. gfn: %llu, vfn: %llu change state to SHARED", kvm->arch.dsm_id, req->gfn, vfn);
		dsm_change_state(slot, vfn, DSM_SHARED);
		dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);
		resp.inv_copyset = *dsm_get_copyset(slot, vfn);
		resp.version = dsm_get_version(slot, vfn);

		// Prefetch
		ret = resp_length = handle_prefetch_req(kvm, req, page, length, resp_data);
		if (ret < 0) {
			kfree(resp_data);
			return ret;
		}
	}
	else {
		struct dsm_request new_req = {
			.req_type = DSM_REQ_READ,
			.requester = kvm->arch.dsm_id,
			.msg_sender = req->msg_sender,
			.gfn = req->gfn,
			.is_smm = req->is_smm,
			.version = req->version,

			.prefetch_size = req->prefetch_size,
		};
		for(iterator = 0; iterator < req->prefetch_size; iterator++) {
			new_req.prefetch_gfns[iterator] = req->prefetch_gfns[iterator];
			new_req.prefetch_versions[iterator] = req->prefetch_versions[iterator];
		}
		printk(KERN_INFO "dsm_handle_read_req: dsm_id: %d, gfn: %llu, vfn: %llu, prob_owner: %d", kvm->arch.dsm_id, req->gfn, vfn, dsm_get_prob_owner(slot, vfn));
		owner = dsm_get_prob_owner(slot, vfn);
		ret = resp_length = kvm_dsm_fetch(kvm, owner, true, &new_req, resp_data, &resp);
		if (ret < 0) {
			kfree(resp_data);
			return ret;
		}
		BUG_ON(dsm_is_readable(slot, vfn) && !(test_bit(kvm->arch.dsm_id,
						&resp.inv_copyset)));
		/* Even read fault changes owner now. May the force be with you. */
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		printk(KERN_INFO "dsm_handle_read_req: dsm_id: %d, after forwarding, transmitting owner of gfn: %llu, vfn: %llu, to %d", kvm->arch.dsm_id, req->gfn, vfn, req->msg_sender);

		// Prefetch
		handle_prefetch_resp_owner_transmission(kvm, req, resp_data);

		dsm_debug_v("kvm[%d](S3) changed owner of gfn[%llu,%d] vfn[%llu] "
				"from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
				req->is_smm, vfn, owner, req->msg_sender);
	}

	tx_add->inv_copyset = resp.inv_copyset;
	tx_add->version = resp.version;

	ret = network_ops.send(conn_sock, resp_data, resp_length, 0, tx_add);
	// ret = network_ops.send(conn_sock, page, length, 0, tx_add);
	kfree(resp_data); // Free data no matter what return value is
	if (ret < 0)
		return ret;
	dsm_debug_v("kvm[%d] sent page[%llu,%d] to kvm[%d] length %d hash: 0x%x\n",
			kvm->arch.dsm_id, req->gfn, req->is_smm, req->requester, length,
			jhash(page, length, JHASH_INITVAL));

	return 0;
}

int ivy_kvm_dsm_handle_req(void *data)
{
	int ret = 0, idx;

	struct dsm_conn *conn = (struct dsm_conn *)data;
	struct kvm *kvm = conn->kvm;
	kconnection_t *conn_sock = conn->sock;

	struct kvm_memory_slot *memslot;
	struct kvm_dsm_memory_slot *slot;
	struct dsm_request req;
	bool retry = false;
	hfn_t vfn;
	char comm[TASK_COMM_LEN];

	char *page;
	int len;

	/* Size of the maximum buffer is PAGE_SIZE */
	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (page == NULL)
		return -ENOMEM;

	while (1) {
		tx_add_t tx_add = {
			/* Accept any incoming requests. */
			.txid = 0xFF,
		};

		if (kthread_should_stop()) {
			ret = -EPIPE;
			goto out;
		}

		len = network_ops.receive(conn_sock, (char*)&req, 0, &tx_add);
		BUG_ON(len > 0 && len != sizeof(struct dsm_request));

		if (len <= 0) {
			ret = len;
			goto out;
		}

		BUG_ON(req.requester == kvm->arch.dsm_id);

retry_handle_req:
		idx = srcu_read_lock(&kvm->srcu);
		memslot = __gfn_to_memslot(__kvm_memslots(kvm, req.is_smm), req.gfn);
		/*
		 * We should ignore private memslots since they are not really visible
		 * to guest and thus are not part of guest state that should be
		 * distributedly shared.
		 */
		if (!memslot || memslot->id >= KVM_USER_MEM_SLOTS ||
				memslot->flags & KVM_MEMSLOT_INVALID) {
			printk(KERN_WARNING "%s: kvm %d invalid gfn %llu!\n",
					__func__, kvm->arch.dsm_id, req.gfn);
			srcu_read_unlock(&kvm->srcu, idx);
			schedule();
			goto retry_handle_req;
		}

		vfn = __gfn_to_vfn_memslot(memslot, req.gfn);
		slot = gfn_to_hvaslot(kvm, memslot, req.gfn);
		if (!slot) {
			printk(KERN_WARNING "%s: kvm %d slot of gfn %llu doesn't exist!\n",
					__func__, kvm->arch.dsm_id, req.gfn);
			srcu_read_unlock(&kvm->srcu, idx);
			schedule();
			goto retry_handle_req;
		}

		dsm_debug_v("kvm[%d] received request[0x%x] from kvm[%d->%d] req_type[%s] "
				"gfn[%llu,%d] vfn[%llu] version %d myversion %d\n",
				kvm->arch.dsm_id, tx_add.txid, req.msg_sender, req.requester,
				req_desc[req.req_type], req.gfn, req.is_smm, vfn, req.version,
				dsm_get_version(slot, vfn));

		BUG_ON(dsm_is_initial(slot, vfn) && dsm_get_prob_owner(slot, vfn) != 0);
		/*
		 * All #PF transactions begin with acquiring owner's (global visble)
		 * dsm_lock. Since only owner can issue DSM_REQ_INVALIDATE, there's no
		 * need to acquire lock. And locking here is prone to cause deadlock.
		 *
		 * If the thread waits for the lock for too long, just buffer the
		 * request and finds whether there's some more requests.
		 */
		if (req.req_type != DSM_REQ_INVALIDATE) {
			printk(KERN_INFO "ivy_kvm_dsm_handle_req: dispatching. dsm_id: %d, waiting for lock, gfn: %llu, vfn: %llu", kvm->arch.dsm_id, req.gfn, vfn);
			// dump_prefetch_cache(kvm);
			dsm_lock(kvm, slot, vfn);
		}

		switch (req.req_type) {
		case DSM_REQ_INVALIDATE:
			ret = dsm_handle_invalidate_req(kvm, conn_sock, memslot, slot, &req,
					&retry, vfn, page, &tx_add);
			if (ret < 0)
				goto out_unlock;
			break;

		case DSM_REQ_WRITE:
			ret = dsm_handle_write_req(kvm, conn_sock, memslot, slot, &req,
					&retry, vfn, page, &tx_add);
			if (ret < 0)
				goto out_unlock;
			break;

		case DSM_REQ_READ:
			ret = dsm_handle_read_req(kvm, conn_sock, memslot, slot, &req,
					&retry, vfn, page, &tx_add);
			if (ret < 0)
				goto out_unlock;
			break;

		default:
			BUG();
		}

		/* Once a request has been completed, this node isn't owner then. */
		if (req.req_type != DSM_REQ_INVALIDATE)
			dsm_clear_copyset(slot, vfn);

		if (req.req_type != DSM_REQ_INVALIDATE)
			dsm_unlock(kvm, slot, vfn);

		srcu_read_unlock(&kvm->srcu, idx);

		if (retry) {
			retry = false;
			schedule();
			goto retry_handle_req;
		}
	}
out_unlock:
	if (req.req_type != DSM_REQ_INVALIDATE)
		dsm_unlock(kvm, slot, vfn);
	srcu_read_unlock(&kvm->srcu, idx);
out:
	kfree(page);
	/* return zero since we quit voluntarily */
	if (kvm->arch.dsm_stopped) {
		ret = 0;
	}
	else {
		get_task_comm(comm, current);
		dsm_debug("kvm[%d] %s exited server loop, error %d\n",
				kvm->arch.dsm_id, comm, ret);
	}

	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	return ret;
}

/*
 * A faulting vCPU can fill in the EPT correctly without network operations.
 * There're two scenerios:
 * 1. spte is dropped (swap, ksm, etc.)
 * 2. The faulting page has been updated by another vCPU.
 */
static bool is_fast_path(struct kvm *kvm, struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, bool write)
{
	/*
	 * DCL is required here because the invalidation server may change the DSM
	 * state too.
	 * Futher, a data race ocurrs when an invalidation request
	 * arrives, the client is between kvm_dsm_page_fault and __direct_map (see
	 * the comment of dsm_handle_read_req). By then EPT is readable while DSM
	 * state is invalid. This causes invalidation request, i.e., a remote write
	 * is omitted.
	 * All transactions should be synchorized by the owner, which is a basic
	 * rule of IVY. But the fast path breaks it. To keep consistency, the fast
	 * path should not be interrupted by an invalidation request. So both fast
	 * path and dsm_handle_invalidate_req should hold a per-page fast_path_lock.
	 */
	if (write && dsm_is_modified(slot, vfn)) {
		dsm_lock_fast_path(slot, vfn, false);
		if (write && dsm_is_modified(slot, vfn)) {
			return true;
		}
		else {
			dsm_unlock_fast_path(slot, vfn, false);
			return false;
		}
	}
	if (!write && dsm_is_readable(slot, vfn)) {
		dsm_lock_fast_path(slot, vfn, false);
		if (!write && dsm_is_readable(slot, vfn)) {
			return true;
		}
		else {
			dsm_unlock_fast_path(slot, vfn, false);
			return false;
		}
	}
	return false;
}

/*
 * copyset rules:
 * 1. Only copyset residing on the owner side is valid, so when owner
 * transmission occurs, copyset of the old one should be cleared.
 * 2. Copyset of a fresh write fault owner is zero.
 * 3. Every node can only operate its own bit of a copyset. For example, in a
 * typical msg_sender->manager->owner (write fault) chain, both owner and
 * manager should clear their own bit in the copyset sent back to the new
 * owner (msg_sender). In the current implementation, the chain may becomes
 * msg_sender->probOwner0->probOwner1->...->requester->owner, each probOwner
 * should clear their own bit.
 *
 * version rules:
 * Overview: Each page (gfn) has a version. If versions of two pages on different
 * nodes are the same, the data of two pages are the same.
 * 1. Upon a write fault, the version of requster is resp.version (old owner) + 1
 * 2. Upon a read fault, the version of requester is the same as resp.version
 */
int ivy_kvm_dsm_page_fault(struct kvm *kvm, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write)
{
	int ret, target_page_length = 0;
	struct kvm_dsm_memory_slot *slot;
	hfn_t vfn;
	char *page = NULL;
	char *resp_data = NULL;
	int prefetch_locked_vfns_num = 0;
	hfn_t prefetch_locked_vfns[KVM_PREFETCH_MAX_WINDOW_SIZE];
	int resp_length = 0;
	struct dsm_response resp;
	int owner;
	copyset_t copyset;
	version_t version;

	ret = 0;
	vfn = __gfn_to_vfn_memslot(memslot, gfn);
	slot = gfn_to_hvaslot(kvm, memslot, gfn);

	if (is_fast_path(kvm, slot, vfn, write)) {
		if (write) {
			return ACC_ALL;
		}
		else {
			return ACC_EXEC_MASK | ACC_USER_MASK;
		}
	}

	BUG_ON(dsm_is_initial(slot, vfn) && dsm_get_prob_owner(slot, vfn) != 0);

	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (page == NULL) {
		ret = -ENOMEM;
		goto out_error;
	}

	resp_data = kmalloc(KVM_PREFETCH_MAX_RESPONSE_SIZE, GFP_KERNEL);
	if (resp_data == NULL) {
		ret = -ENOMEM;
		goto out_error;
	}

	memset(prefetch_locked_vfns, 0, KVM_PREFETCH_MAX_WINDOW_SIZE * sizeof(hfn_t));

	printk(KERN_INFO "ivy_kvm_dsm_page_fault: kvm id: %d, acquiring gfn: %llu, vfn: %llu, prob_owner: %d", kvm->arch.dsm_id, gfn, vfn, dsm_get_prob_owner(slot, vfn));

	/*
	 * If #PF is owner write fault, then issue invalidate by itself.
	 * Or this node will be owner after #PF, it still issue invalidate by
	 * receiving copyset from old owner.
	 */
	if (write) {
		struct dsm_request req = {
			.req_type = DSM_REQ_WRITE,
			.requester = kvm->arch.dsm_id,
			.msg_sender = kvm->arch.dsm_id,
			.gfn = gfn,
			.is_smm = is_smm,
			.prefetch_size = 0,
			.version = dsm_get_version(slot, vfn),
		};
		if (dsm_is_owner(slot, vfn)) {
			BUG_ON(dsm_get_prob_owner(slot, vfn) != kvm->arch.dsm_id);

			ret = kvm_dsm_invalidate(kvm, gfn, is_smm, slot, vfn, NULL, kvm->arch.dsm_id);
			if (ret < 0)
				goto out_error;
			resp.version = dsm_get_version(slot, vfn);
			target_page_length = PAGE_SIZE;

			dsm_incr_version(slot, vfn);
		}
		else {
			owner = dsm_get_prob_owner(slot, vfn);
			/* Owner of all pages is 0 on init. */
			if (unlikely(dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0)) {
				dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
				printk(KERN_INFO "ivy_kvm_dsm_page_fault: write PF, dsm_id: %d Initialize page. gfn: %llu, vfn: %llu change state to OWNER | MODIFIED", kvm->arch.dsm_id, gfn, vfn);
				dsm_change_state(slot, vfn, DSM_OWNER | DSM_MODIFIED);
				dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);
				ret = ACC_ALL;
				goto out;
			}
		
			// Prefetch related
			kvm->prefetch_stat_total++;
			record_gfn_to_access_history(kvm, gfn, 1);
			if (read_prefetch_cache(kvm, gfn, &copyset, &version, page))
			{
				ret = kvm_dsm_invalidate(kvm, gfn, is_smm, slot, vfn, &copyset, owner);
				if (ret < 0)
					goto out_error;
				dsm_set_version(slot, vfn, version + 1);
				dsm_clear_copyset(slot, vfn);
				dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);
				dsm_set_twin_conditionally(slot, vfn, page, memslot, gfn, dsm_is_owner(slot, vfn), version);
				ret = __kvm_write_guest_page(memslot, gfn, page, 0, PAGE_SIZE);
				if (ret < 0) {
					goto out_error;
				}
				printk(KERN_INFO "ivy_kvm_dsm_page_fault: dsm_id: %d, hit cache, transmitting owner of gfn: %llu, vfn: %llu, to myself, change state to OWNER | MODIFIED", kvm->arch.dsm_id, gfn, vfn);
				dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
				dsm_change_state(slot, vfn, DSM_OWNER | DSM_MODIFIED);
				ret = ACC_ALL;
				goto out;
			}
			else
			{
				printk(KERN_INFO "ivy_kvm_dsm_page_fault: dsm_id: %d, gfn: %llu, vfn: %llu, cache miss, dumping:", kvm->arch.dsm_id, gfn, vfn);
				dump_prefetch_cache(kvm);
				write_prefetch_to_req(kvm, memslot, gfn, &req, &prefetch_locked_vfns_num, prefetch_locked_vfns);
			}
			
			/*
			 * Ask the probOwner. The prob(ably) owner is probably true owner,
			 * or not. If not, forward the request to next probOwner until find
			 * the true owner.
			 */
			// ret = target_page_length = kvm_dsm_fetch(kvm, owner, false, &req, page,
			// 		&resp);
			// if (ret < 0)
			// 	goto out_error;
			ret = resp_length = kvm_dsm_fetch(kvm, owner, false, &req, resp_data, &resp);
			if (ret < 0)
				goto out_error;
			target_page_length = handle_prefetch_resp(kvm, memslot, page, resp_data, prefetch_locked_vfns_num, prefetch_locked_vfns);
			printk(KERN_INFO "ivy_kvm_dsm_page_fault: dsm_id: %d, after handling write prefetch, dumping:", kvm->arch.dsm_id);
			dump_prefetch_cache(kvm);
			dump_prefetch_cache(kvm);
			ret = kvm_dsm_invalidate(kvm, gfn, is_smm, slot, vfn,
					&resp.inv_copyset, owner);
			if (ret < 0)
				goto out_error;

			dsm_set_version(slot, vfn, resp.version + 1);
		}

		dsm_clear_copyset(slot, vfn);
		dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);

		dsm_decode_diff(page, target_page_length, memslot, gfn);
		dsm_set_twin_conditionally(slot, vfn, page, memslot, gfn,
				dsm_is_owner(slot, vfn), resp.version);

		if (!dsm_is_owner(slot, vfn) && target_page_length > 0) {
			ret = __kvm_write_guest_page(memslot, gfn, page, 0, PAGE_SIZE);
			if (ret < 0) {
				goto out_error;
			}
		}

		printk(KERN_INFO "ivy_kvm_dsm_page_fault: dsm_id: %d, after fetching, transmitting owner of gfn: %llu, vfn: %llu, to myself, change state to OWNER | MODIFIED", kvm->arch.dsm_id, gfn, vfn);
		dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
		dsm_change_state(slot, vfn, DSM_OWNER | DSM_MODIFIED);
		ret = ACC_ALL;
	} else {
		struct dsm_request req = {
			.req_type = DSM_REQ_READ,
			.requester = kvm->arch.dsm_id,
			.msg_sender = kvm->arch.dsm_id,
			.gfn = gfn,
			.is_smm = is_smm,
			.prefetch_size = 0,
			.version = dsm_get_version(slot, vfn),
		};
		owner = dsm_get_prob_owner(slot, vfn);
		/*
		 * If I'm the owner, then I would have already been in Shared or
		 * Modified state.
		 */
		BUG_ON(dsm_is_owner(slot, vfn));

		/* Owner of all pages is 0 on init. */
		if (unlikely(dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0)) {
			dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
			printk(KERN_INFO "ivy_kvm_dsm_page_fault: dsm_id: %d read PF, Initialize page. gfn: %llu, vfn: %llu change state to OWNER | SHARED", kvm->arch.dsm_id, gfn, vfn);
			dsm_change_state(slot, vfn, DSM_OWNER | DSM_SHARED);
			dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);
			ret = ACC_EXEC_MASK | ACC_USER_MASK;
			goto out;
		}
		
		// Prefetch related
		kvm->prefetch_stat_total++;
		record_gfn_to_access_history(kvm, gfn, 1);
		if (read_prefetch_cache(kvm, gfn, &copyset, &version, page))
		{
			dsm_set_version(slot, vfn, version);
			memcpy(dsm_get_copyset(slot, vfn), &copyset, sizeof(copyset_t));
			dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);
			ret = __kvm_write_guest_page(memslot, gfn, page, 0, PAGE_SIZE);
			if (ret < 0) {
				goto out_error;
			}
			printk(KERN_INFO "ivy_kvm_dsm_page_fault: dsm_id: %d, hit cache, transmitting owner of gfn: %llu, vfn: %llu, to myself, change state to OWNER | SHARED", kvm->arch.dsm_id, gfn, vfn);
			dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
			dsm_change_state(slot, vfn, DSM_OWNER | DSM_SHARED);
			ret = ACC_EXEC_MASK | ACC_USER_MASK;
			goto out;
		}
		else
		{
			printk(KERN_INFO "ivy_kvm_dsm_page_fault: dsm_id: %d, gfn: %llu, vfn: %llu, cache miss, dumping:", kvm->arch.dsm_id, gfn, vfn);
			dump_prefetch_cache(kvm);
			write_prefetch_to_req(kvm, memslot, gfn, &req, &prefetch_locked_vfns_num, prefetch_locked_vfns);
		}

		/* Ask the probOwner */
		// ret = target_page_length = kvm_dsm_fetch(kvm, owner, false, &req, page, &resp);
		// if (ret < 0)
		// 	goto out_error;
		ret = resp_length = kvm_dsm_fetch(kvm, owner, false, &req, resp_data, &resp);
		if (ret < 0)
			goto out_error;
		target_page_length = handle_prefetch_resp(kvm, memslot, page, resp_data, prefetch_locked_vfns_num, prefetch_locked_vfns);
		printk(KERN_INFO "ivy_kvm_dsm_page_fault: dsm_id: %d, after handling read prefetch, dumping:", kvm->arch.dsm_id);
		dump_prefetch_cache(kvm);

		dsm_set_version(slot, vfn, resp.version);
		memcpy(dsm_get_copyset(slot, vfn), &resp.inv_copyset, sizeof(copyset_t));
		dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);

		dsm_decode_diff(page, target_page_length, memslot, gfn);

		ret = __kvm_write_guest_page(memslot, gfn, page, 0, PAGE_SIZE);
		if (ret < 0)
			goto out_error;

		printk(KERN_INFO "ivy_kvm_dsm_page_fault: dsm_id: %d, after fetching, transmitting owner of gfn: %llu, vfn: %llu, to myself", kvm->arch.dsm_id, gfn, vfn);
		dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
		/*
		 * The node becomes owner after read fault because of data locality,
		 * i.e. a write fault may occur soon. It's not designed to avoid annoying
		 * bugs, right? See comments of dsm_handle_read_req.
		 */
		printk(KERN_INFO "ivy_kvm_dsm_page_fault: dsm_id: %d read PF, after fetching. gfn: %llu, vfn: %llu change state to OWNER | SHARED", kvm->arch.dsm_id, gfn, vfn);
		dsm_change_state(slot, vfn, DSM_OWNER | DSM_SHARED);
		ret = ACC_EXEC_MASK | ACC_USER_MASK;
	}

out:
	kvm_dsm_pf_trace(kvm, slot, vfn, write, target_page_length);
	kfree(page);
	kfree(resp_data);
	return ret;

out_error:
	dump_stack();
	printk(KERN_ERR "kvm-dsm: node-%d failed to handle page fault on gfn[%llu,%d], "
			"error: %d\n", kvm->arch.dsm_id, gfn, is_smm, ret);
	kfree(page);
	kfree(resp_data);
	return ret;
}
