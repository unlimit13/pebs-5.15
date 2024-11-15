#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/page-flags.h>
#include <linux/perf_event.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/memcontrol.h>
#include <linux/mempolicy.h>
#include <linux/sched/cputime.h>
#include <uapi/linux/perf_event.h>
#include "../kernel/events/internal.h"
#include <linux/swap.h>
#include <linux/migrate.h>
#include <linux/list.h>
#include <linux/mmzone.h>
#include <linux/mm_inline.h>
#include <linux/rmap.h>
#include <linux/node.h>


#define FILE_PATH "/home/hjcho/pebs/result"



#define SAMPLE_PERIOD 500
#define __BUFFER_SIZE	32

#define LOAD    0
#define STORE   1



struct perf_event ***mem_event;


__u64 ip;
__u32 pid, tid;
__u64 addr;
struct page* __page;
int node;
unsigned int nr_migrated=0;
unsigned int nr_candidate=0;
unsigned int nr_samples=0;

static int num_cpus;
static struct task_struct *kmigrated_thread;


static int target_pid=-1;
module_param(target_pid, int, 0644);
MODULE_PARM_DESC(target_pid, "An integer");

struct htmm_event {
    struct perf_event_header header;
    __u64 ip;
    __u32 pid, tid;
    __u64 addr;


};
bool is_page_active(struct page *page) {
    // Check if the page is on an LRU list and is active
    return PageActive(page);
}

// Function to check if the page is in the Inactive list
bool is_page_inactive(struct page *page) {
    // Check if the page is on an LRU list and is not active
    return !PageActive(page) && PageLRU(page);
}
static struct page *alloc_migrate_page(struct page *page, unsigned long node)
{
    int nid = (int) node;
    int zidx;
    struct page *newpage = NULL;
    gfp_t mask = (GFP_HIGHUSER_MOVABLE |
		  __GFP_THISNODE | __GFP_NOMEMALLOC |
		  __GFP_NORETRY | __GFP_NOWARN) &
		  ~__GFP_RECLAIM;


    zidx = zone_idx(page_zone(page));
    if (is_highmem_idx(zidx) || zidx == ZONE_MOVABLE)
	    mask |= __GFP_HIGHMEM;


	newpage = __alloc_pages_node(nid, mask, 0);

    return newpage;
}
static int migrate_page_to_node(struct page *page, int target_node) {
    struct page *new_page;
    int ret = 1;
    bool is_lru = !__PageMovable(page);

    if (!page || !page_mapped(page)) {
        return -EINVAL;
    }

    //list_add(&page->lru,&promote_page);

    new_page = alloc_migrate_page(page, target_node);
    if (!new_page) {
        return -ENOMEM;
    }

    //ret = migrate_pages(&promote_page,alloc_migrate_page,NULL,99,MIGRATE_SYNC,MR_NUMA_MISPLACED,&nr_succeeded);
	/*ClearPageActive(page);
	ClearPageUnevictable(page);
	if (unlikely(__PageMovable(page))) {
		lock_page(page);
		if (!PageMovable(page))
			__ClearPageIsolated(page);
		unlock_page(page);
	}*/
    //ret = unmap_and_move(alloc_migrate_page,NULL,0,page,0,MIGRATE_ASYNC,MR_NUMA_MISPLACED,&ret_pages);

	if (!trylock_page(page)) {

		lock_page(page);
	}
	/*if (PageWriteback(page) && page_count(page)>2) {

		wait_on_page_writeback(page);
	}*/


	//if (unlikely(!trylock_page(new_page))){}
	//	goto out_unlock;
    ret = move_to_new_page(new_page, page, MIGRATE_SYNC);
    


	/* Drop an anon_vma reference if we took one */

	unlock_page(page);
    //struct address_space *mapping = page_mapping(page);
    //ret = migrate_page(mapping, new_page, page, MIGRATE_SYNC);
    /*if (ret) {
        __free_page(new_page);
    }*/
	if (ret == MIGRATEPAGE_SUCCESS) {
		if (unlikely(!is_lru))
			put_page(new_page);
		else{
            lru_cache_add(new_page);
			put_page(new_page);
        }

	}
    else{
        __free_page(new_page);
    }
    return ret;
}


static int kmigrated_fn(void *data) {

    /*const struct cpumask *cpumask = cpumask_of_node(0);
    if (!cpumask_empty(cpumask))
	    __do_set_cpus_allowed(kmigrated_thread, cpumask,0);*/

    unsigned sleep_timeout = usecs_to_jiffies(2000);
    while (!kthread_should_stop()) {
        
        int cpu, event,cond = false;
        for_each_online_cpu(cpu){
            if(cpu==24) break;
            for(event=0;event<2;event++){
                do {
                    struct perf_buffer *rb;
                    struct perf_event_mmap_page *up;
                    struct perf_event_header *ph;
                    struct htmm_event *he;
                    unsigned long pg_index, offset;
                    int page_shift;
                    __u64 head;
                    if (!mem_event[cpu] || !mem_event[cpu][event]) {
                        printk(KERN_INFO "ERROR 1: mem_event[cpu] or mem_event[cpu][event] is NULL\n");
                        break;
                    }


                    __sync_synchronize();

                    rb = mem_event[cpu][event]->rb;
                    if (!rb) {
                        printk("ERROR 2: event->rb is NULL\n");
                        return -1;
                    }
                    /* perf_buffer is ring buffer */
                    up = READ_ONCE(rb->user_page);
                    if (!up) {
                        printk("ERROR 3: rb->user_page is NULL\n");
                        break;
                    }
                    head = READ_ONCE(up->data_head);
                    if (head == up->data_tail) {
                        
                        break;
                    }
                    head -= up->data_tail;
                    if (head > (__BUFFER_SIZE * 50 / 100)) {
                        cond = true;
                    } else if (head < (__BUFFER_SIZE * 10 / 100)) {
                        cond = false;
                    }
                    /* read barrier */
                    smp_rmb();


                    page_shift = PAGE_SHIFT + page_order(rb);
                    /* get address of a tail sample */
                    offset = READ_ONCE(up->data_tail);
                    pg_index = (offset >> page_shift) & (rb->nr_pages - 1);
                    if (pg_index >= rb->nr_pages) {
                        printk("ERROR 4: pg_index out of bounds\n");
                        break;
                    }
                    offset &= (1 << page_shift) - 1;

                    ph = (void*)(rb->data_pages[pg_index] + offset);
                    switch (ph->type) {
                        case PERF_RECORD_SAMPLE:
                            he = (struct htmm_event *)ph;
                            ip = he->ip;
                            pid=he->pid;
                            tid=he->tid;
                            addr = he->addr;
                            nr_samples++;
                            
                            if((target_pid==tid || target_pid==pid)&&pfn_valid((he->addr) >> PAGE_SHIFT)){
                                //pr_info("event= %d, ip=%llx, pid = %u, tid=%d, addr = %llx\n", event, ip, pid, tid, addr);
                                __page= pfn_to_page(addr >> PAGE_SHIFT);
                                node = page_to_nid(__page);
                                if(node == 1){
                                    
                                    if(is_page_active(__page)){
                                        nr_candidate++;
                                        int ret = migrate_page_to_node(__page,0);
                                        if (ret){
                                        }
                                        else{
                                            nr_migrated++;
                                        }
                                    }
                                    else if(is_page_inactive(__page)){
                                        mark_page_accessed(__page);
                                    }
                                    else{

                                    }
                                    
                                }

                            }
                             else{
                                //printk(KERN_INFO "---------------------invalid");
                            }
                                

                            break;
                        case PERF_RECORD_THROTTLE:
                        case PERF_RECORD_UNTHROTTLE:
                        case PERF_RECORD_LOST_SAMPLES:
                        default:
                            break;
                    }
                    /* read, write barrier */
                    smp_mb();
                    WRITE_ONCE(up->data_tail, up->data_tail + ph->size);
                } while (cond);          
            }

        }
        schedule_timeout_interruptible(sleep_timeout);
    }
    return 0;
}
static int __perf_event_open(__u64 config1, __u64 cpu,int type,
	 __u32 pid)
{
    struct perf_event_attr attr;
    struct file *file;
    int event_fd, __pid;

    memset(&attr, 0, sizeof(struct perf_event_attr));

    attr.type = PERF_TYPE_RAW;
    attr.size = sizeof(struct perf_event_attr);
    if (type==LOAD)
        attr.config = 0x20d1;
    else if (type==STORE)
        attr.config = 0x12d0;
    attr.config1 = config1;
	attr.sample_period = SAMPLE_PERIOD;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_PHYS_ADDR | PERF_SAMPLE_TID  ;
    attr.disabled = 0;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.exclude_callchain_kernel = 1;
    attr.exclude_callchain_user = 1;
    attr.precise_ip = 1;
    attr.enable_on_exec = 1;

    if (pid == 0)
	__pid = -1;
    else
	__pid = pid;
    //event_fd = htmm__perf_event_open(&attr, target_pid, cpu, -1, 0);
    event_fd = htmm__perf_event_open(&attr, -1, cpu, -1, 0);
    if (event_fd <= 0) {
	    printk("[error htmm__perf_event_open failure] event_fd: %d\n", event_fd);
	    return 1;
    }

    file = fget(event_fd);
    if (!file) {
	printk("invalid file\n");
	return 1;
    }

    mem_event[cpu][type] = fget(event_fd)->private_data;

    return 0;
}



static int __init pebs_migrater_init(void) {
    int cpu,event;


    //num_cpus = num_online_cpus();
    num_cpus = 12;
    mem_event = kzalloc(sizeof(struct perf_event **) * num_cpus, GFP_KERNEL);
    for_each_online_cpu(cpu) {
        if(cpu==24) break;
        mem_event[cpu] = kzalloc(sizeof(struct perf_event *) * 2, GFP_KERNEL);
        if(!mem_event[cpu]){
            printk(KERN_ERR "Failed to allocate memory events\n");
            return -ENOMEM;
        }
    }

    
    for_each_online_cpu(cpu) {
        if(cpu==24) break;
        for(event=0;event<2;event++){
            if(__perf_event_open(0,cpu,event,target_pid)){
                printk(KERN_INFO "open failed - 1");
                return -1;
            }
            if (htmm__perf_event_init(mem_event[cpu][event], __BUFFER_SIZE)){
                printk(KERN_INFO "init failed - 1");
                return -1;
            }
        }
		    

    }


    // 커널 스레드 생성 및 실행
    kmigrated_thread = kthread_run(kmigrated_fn, NULL, "kmigrated");
    if (IS_ERR(kmigrated_thread)) {
        printk(KERN_ERR "Failed to create kmigrated thread\n");
        return PTR_ERR(kmigrated_thread);
    }

    printk(KERN_INFO "PEBS Migrater Module Initialized\n");
    return 0;
}

static void __exit pebs_migrater_exit(void) {
    int cpu,event;

    for_each_online_cpu(cpu) {
        if(cpu==24) break;
        for(event=0;event<2;event++){
            if(mem_event[cpu][event]) perf_event_disable(mem_event[cpu][event]);
        }
    }
    // 커널 스레드 종료
    if (kmigrated_thread) {


        kthread_stop(kmigrated_thread);

    }


    pr_info("total promotion : %d",nr_migrated);
    pr_info("total candidate : %d",nr_candidate);
    pr_info("total sample : %d",nr_samples);
    kfree(mem_event);

    printk(KERN_INFO "PEBS Migrater Module Removed\n");
}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("hjcho");
MODULE_DESCRIPTION("PEBS Migrater Module");
MODULE_VERSION("0.1");


module_init(pebs_migrater_init);
module_exit(pebs_migrater_exit);
