#include <linux/perf_event.h>
#include <linux/ftrace_event.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>

// perf 이벤트를 위한 전역 변수 추가
static struct perf_event * __percpu *cpu_perf_event;

// 이벤트 콜백 함수
static void perf_event_overflow(struct perf_event *event,
                                struct perf_sample_data *data,
                                struct pt_regs *regs)
{
    char buf[128];
    int len;
    struct file *file;
    mm_segment_t old_fs;

    // 기록할 데이터 형식 지정
    len = snprintf(buf, sizeof(buf), "CPU: %d, Cycles: %llu\n",
                   smp_processor_id(), data->period);

    // 파일에 쓰기
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    file = filp_open("/var/log/perf.log", O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (!IS_ERR(file)) {
        kernel_write(file, buf, len, &file->f_pos);
        filp_close(file, NULL);
    }
    set_fs(old_fs);
}

// 커널 초기화 시 perf 이벤트 설정
static int __init init_perf_event(void)
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_HARDWARE,
        .config = PERF_COUNT_HW_CPU_CYCLES,
        .size = sizeof(struct perf_event_attr),
        .sample_period = 1000000,
        .pinned = 1,
        .disabled = 0,
    };

    // CPU 별로 perf 이벤트 설정
    cpu_perf_event = alloc_percpu(struct perf_event *);
    for_each_possible_cpu(cpu) {
        *per_cpu_ptr(cpu_perf_event, cpu) = perf_event_create_kernel_counter(
            &attr, cpu, NULL, perf_event_overflow);
    }

    return 0;
}
late_initcall(init_perf_event);
