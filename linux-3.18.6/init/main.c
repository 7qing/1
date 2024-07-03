/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  GK 2/5/95  -  Changed to support mounting root fs via NFS
 *  Added initrd & change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Moan early if gcc is old, avoiding bogus kernels - Paul Gortmaker, May '96
 *  Simplified starting of init:  Michael A. Griffith <grif@acm.org>
 */

#define DEBUG		/* Enable initcall_debug */

#include <linux/types.h>                  // �����������Ͷ���
#include <linux/module.h>                 // ģ����غ����ͺ궨��
#include <linux/proc_fs.h>                // proc �ļ�ϵͳ��غ����ͽṹ��
#include <linux/kernel.h>                 // �ں˳��ú����ͺ궨��
#include <linux/syscalls.h>               // ϵͳ������غ궨��
#include <linux/stackprotector.h>         // ջ������غ궨��ͺ�������
#include <linux/string.h>                 // �ַ���������������
#include <linux/ctype.h>                  // �ַ��������ͺ궨��
#include <linux/delay.h>                  // ��ʱ��������
#include <linux/ioport.h>                 // IO �˿ڲ��������ͺ궨��
#include <linux/init.h>                   // �ں˳�ʼ����ģ����غ����궨��
#include <linux/initrd.h>                 // ��ʼ RAM ����֧����غ궨��
#include <linux/bootmem.h>                // �����ڴ������غ궨��ͺ�������
#include <linux/acpi.h>                   // ACPI ��غ��������ݽṹ����
#include <linux/tty.h>                    // �ն��豸��غ��������ݽṹ����
#include <linux/percpu.h>                 // �� CPU ϵͳ�µľֲ��洢��������
#include <linux/kmod.h>                   // �ں�ģ����غ͹�����غ��������ݽṹ����
#include <linux/vmalloc.h>                // �����ڴ������غ����ͺ궨��
#include <linux/kernel_stat.h>            // �ں�ͳ����Ϣ��غ��������ݽṹ����
#include <linux/start_kernel.h>           // �ں������ͳ�ʼ����غ�������
#include <linux/security.h>               // �ں˰�ȫģ����غ��������ݽṹ����
#include <linux/smp.h>                    // �Գƶദ������غ����ͺ궨��
#include <linux/profile.h>                // ϵͳ���ܷ�����غ����ͺ궨��
#include <linux/rcupdate.h>               // RCU��Read-Copy-Update����غ����ͺ궨��
#include <linux/moduleparam.h>            // ģ�������غ����ͺ궨��
#include <linux/kallsyms.h>               // �ں˷��ű��ѯ��غ�������
#include <linux/writeback.h>              // ��ҳ���д��غ�������
#include <linux/cpu.h>                    // CPU ��غ��������ݽṹ����
#include <linux/cpuset.h>                 // CPU ����غ��������ݽṹ����
#include <linux/cgroup.h>                 // �����飨Cgroup����غ��������ݽṹ����
#include <linux/efi.h>                    // EFI ϵͳ��غ��������ݽṹ����
#include <linux/tick.h>                   // ϵͳʱ���¼���غ��������ݽṹ����
#include <linux/interrupt.h>              // �жϴ�����غ��������ݽṹ����
#include <linux/taskstats_kern.h>         // ����ͳ����Ϣ��غ��������ݽṹ����
#include <linux/delayacct.h>              // ��ʱ�˻���غ��������ݽṹ����
#include <linux/unistd.h>                 // ϵͳ���ú�����
#include <linux/rmap.h>                   // ����ӳ����غ��������ݽṹ����
#include <linux/mempolicy.h>              // �ڴ������غ��������ݽṹ����
#include <linux/key.h>                    // ��Կ������غ��������ݽṹ����
#include <linux/buffer_head.h>            // ������ͷ��غ��������ݽṹ����
#include <linux/page_cgroup.h>            // ҳ���������غ��������ݽṹ����
#include <linux/debug_locks.h>            // ��������غ��������ݽṹ����
#include <linux/debugobjects.h>           // ���Զ�����غ��������ݽṹ����
#include <linux/lockdep.h>                // ��������ϵ������غ��������ݽṹ����
#include <linux/kmemleak.h>               // �ڴ�й©�����غ��������ݽṹ����
#include <linux/pid_namespace.h>          // ���� ID �����ռ���غ��������ݽṹ����
#include <linux/device.h>                 // �豸ģ����غ��������ݽṹ����
#include <linux/kthread.h>                // �ں��߳���غ��������ݽṹ����
#include <linux/sched.h>                  // ���̵�����غ��������ݽṹ����
#include <linux/signal.h>                 // �źŴ�����غ��������ݽṹ����
#include <linux/idr.h>                    // IDR ��������غ��������ݽṹ����
#include <linux/kgdb.h>                   // KGDB ������غ��������ݽṹ����
#include <linux/ftrace.h>                 // ����������غ��������ݽṹ����
#include <linux/async.h>                  // �첽�¼�������غ��������ݽṹ����
#include <linux/kmemcheck.h>              // �ڴ�����غ��������ݽṹ����
#include <linux/sfi.h>                    // �򵥹̼��ӿ���غ��������ݽṹ����
#include <linux/shmem_fs.h>               // �����ڴ��ļ�ϵͳ��غ��������ݽṹ����
#include <linux/slab.h>                   // �ڴ����͹�����غ����ͺ궨��
#include <linux/perf_event.h>             // �����¼���غ��������ݽṹ����
#include <linux/file.h>                   // �ļ�������غ��������ݽṹ����
#include <linux/ptrace.h>                 // ���̸�����غ��������ݽṹ����
#include <linux/blkdev.h>                 // ���豸��غ��������ݽṹ����
#include <linux/elevator.h>               // IO ��������غ��������ݽṹ����
#include <linux/sched_clock.h>            // ϵͳʱ����غ��������ݽṹ����
#include <linux/context_tracking.h>       // ������׷����غ��������ݽṹ����
#include <linux/random.h>                 // �����������غ��������ݽṹ����
#include <linux/list.h>                   // ˫��������غ��������ݽṹ����

#include <asm/io.h>                       // IO ������غ궨��ͺ����������ض��ܹ���
#include <asm/bugs.h>                     // ����Ӳ��������쳣��غ����ͺ궨�壨�ض��ܹ���
#include <asm/setup.h>                    // Ӳ����ʼ��������������غ����ͺ궨�壨�ض��ܹ���
#include <asm/sections.h>                 // �ڴ����ζ���Ͳ�����غ궨�壨�ض��ܹ���
#include <asm/cacheflush.h>               // CPU ����ˢ����غ����ͺ궨�壨�ض��ܹ���


#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/smp.h>  // �����ദ������ص�ͷ�ļ�
#endif


// �ں˳�ʼ��������ԭ������
static int kernel_init(void *);
// �����ⲿ���������ڳ�ʼ���ж�����IRQ��
extern void init_IRQ(void);
// �����ⲿ���������ڳ�ʼ�����̵�fork����
extern void fork_init(unsigned long);
// �����ⲿ���������ڳ�ʼ����������radix tree��
extern void radix_tree_init(void);

#ifndef CONFIG_DEBUG_RODATA
// ���û�ж���CONFIG_DEBUG_RODATA������һ���յ���������
static inline void mark_rodata_ro(void) { }
#endif


/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
/*
 * �������֣�ͨ�������־����֪����ǰ���ڡ������������롱�׶Σ�
 * ��ʱֻ�����������������У������ж�����IRQ�������á�
 * ����ζ�������¡����ڱ�־�����֮ǰ���ж������ܱ����ã�
 * �����ڱ�־����ʱ��һЩ���ж��������ʱ������Ĳ����Ǳ�����ġ�
 */

 /*
 * �����־����ϵͳ�Ƿ������������׶ν������ж�����IRQ����
 * __read_mostly ��һ��������ָʾ������ʾ�ñ����������ڼ伸�����ᱻ�޸ģ�
 * ��Ҫ�Ƕ�ȡ�������Ӷ������Ż���
 */
bool early_boot_irqs_disabled __read_mostly;

/*
 * ö�����͵ı��������ڱ�ʾϵͳ�ĵ�ǰ״̬��
 * __read_mostly ��ʾ�ñ����������ڼ伸�����ᱻ�޸ģ���Ҫ�Ƕ�ȡ������
 * EXPORT_SYMBOL(system_state) ��������ŵ�����ʹ����Ա������ں�ģ��ʹ�á�
 */
enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/*
 * ���������в���
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/* Ĭ�ϵ��ӳ�ʱ���ʼ��ΪNULL���ܹ������Ժ󸲸����ֵ�� */
void (*__initdata late_time_init)(void);

/* ���ض��ܹ����뱣���ԭʼ�����С� */
char __initdata boot_command_line[COMMAND_LINE_SIZE];
/* �����ԭʼ�����У��������� /proc�� */
char *saved_command_line;
/* ���ڲ��������������� */
static char *static_command_line;
/* ����ÿ����ʼ�����õĲ��������������� */
static char *initcall_command_line;

static char *execute_command;
static char *ramdisk_execute_command;

/*
 * ����ڵ��� jump_label_init ֮ǰʹ���� static_key ����������
 * ���������ɾ��档
 */
bool static_key_initialized __read_mostly;
EXPORT_SYMBOL_GPL(static_key_initialized);

/*
 * If set, this is an indication to the drivers that reset the underlying
 * device before going ahead with the initialization otherwise driver might
 * rely on the BIOS and skip the reset operation.
 *
 * This is useful if kernel is booting in an unreliable environment.
 * For ex. kdump situaiton where previous kernel has crashed, BIOS has been
 * skipped and devices will be in unknown state.
 */
/*
 * ������ã��ñ�־ָʾ���������ڼ�����ʼ��֮ǰ���õײ��豸��
 * ��������������������� BIOS ���������ò�����
 *
 * �����ں��ڲ��ɿ�����������ʱ�ǳ����á�
 * ���磺kdump ����£�ǰһ���ں˱�����BIOS ���������豸����δ֪״̬��
 */
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static int __init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

__setup("reset_devices", set_reset_devices);

static const char *argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

extern const struct obs_kernel_param __setup_start[], __setup_end[];

static int __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	int had_early_param = 0;

	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (parameqn(line, p->str, n)) {
			if (p->early) {
				/* �Ƿ��Ѿ��� parse_early_param �д���
				 * ����Ҫ�ڲ������־�ȷƥ�䣩��
				 * ������������Ϊ���ǿ�������ͬ���Ƶ����ڲ����� __setup */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = 1;
			} else if (!p->setup_func) {
				pr_warn("���� %s �ѹ�ʱ���Ѻ���\n", p->str);
				return 1;
			} else if (p->setup_func(line + n))
				return 1;
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}


/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
/*
 * ��Ӧ���Ǵ�Լ 2 Bo*oMips ��ʼ��ע���ʼ��λ������ʹ��ʼֵ��������Ȼ���Թ�����ֻ����΢��һ��
 */
unsigned long loops_per_jiffy = (1<<12);
EXPORT_SYMBOL(loops_per_jiffy);

static int __init debug_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_DEBUG;
	return 0;
}

static int __init quiet_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_QUIET;
	return 0;
}

early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);

static int __init loglevel(char *str)
{
	int newlevel;

	/*
	 * ֻ���ڴ�������ȷ������ʱ�Ÿ�����־����ֵ��
	 * �Է�ֹäĿ��������־��������Ϊ 0����������ǳ����Ե���
	 */
	if (get_option(&str, &newlevel)) {
		console_loglevel = newlevel;
		return 0;
	}

	return -EINVAL;
}

early_param("loglevel", loglevel);

/* �� NUL term ���Ļ� "="��ʹ "param" ��Ϊ�����ַ��� */
static int __init repair_env_string(char *param, char *val, const char *unused)
{
	if (val) {
		/* param=val �� param="val"? */
		if (val == param+strlen(param)+1)
			val[-1] = '=';
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
			val--;
		} else
			BUG();
	}
	return 0;
}

/* -- ֮����κ����ݶ�ֱ�Ӵ��ݸ� init */
static int __init set_init_arg(char *param, char *val, const char *unused)
{
	unsigned int i;

	if (panic_later)
		return 0;

	repair_env_string(param, val, unused);

	for (i = 0; argv_init[i]; i++) {
		if (i == MAX_INIT_ARGS) {
			panic_later = "init";
			panic_param = param;
			return 0;
		}
	}
	argv_init[i] = param;
	return 0;
}


/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
/*
 * δ֪������ѡ����ݸ� init���������ǿ�������δʹ�õĲ���
 * ��modprobe ���� /proc/cmdline ���ҵ����ǣ���
 */
static int __init unknown_bootoption(char *param, char *val, const char *unused)
{
	repair_env_string(param, val, unused);

	/* �����ʱ�Ĳ��� */
	if (obsolete_checksetup(param))
		return 0;

	/* δʹ�õ�ģ������� */
	if (strchr(param, '.') && (!val || strchr(param, '.') < val))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* ����ѡ�� */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "env";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], val - param))
				break;
		}
		envp_init[i] = param;
	} else {
		/* ������ѡ�� */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "init";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

static int __init init_setup(char *str)
{
	unsigned int i;

	execute_command = str;
	/*
	 * ��� LILO Ҫ��Ĭ���������������ǣ�
	 * ���������� cmdline ֮ǰ���� "auto"�����ʹ
	 * shell ��Ϊ��Ӧ��ִ��һ�������Ľű���
	 * ������Ǻ��� init= ֮ǰ��������в��� [MJ]
	 */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
	unsigned int i;

	ramdisk_execute_command = str;
	/* �μ� init_setup �е� "auto" ע�� */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("rdinit=", rdinit_setup);

#ifndef CONFIG_SMP
static const unsigned int setup_max_cpus = NR_CPUS;
#ifdef CONFIG_X86_LOCAL_APIC
static void __init smp_init(void)
{
	APIC_init_uniprocessor();
}
#else
#define smp_init()	do { } while (0)
#endif

static inline void setup_nr_cpu_ids(void) { }
static inline void smp_prepare_cpus(unsigned int maxcpus) { }
#endif


/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 */
/*
 * ������Ҫ�洢δ�޸ĵ��������Թ������ο���
 * ���ǻ���Ҫ�洢���޸ĵ������У���Ϊ���������Ǿ͵�ִ�еģ�
 * ����Ӧ����������洢����/ֵ�������Թ������ο���
 */
static void __init setup_command_line(char *command_line)
{
	saved_command_line =
		memblock_virt_alloc(strlen(boot_command_line) + 1, 0);
	initcall_command_line =
		memblock_virt_alloc(strlen(boot_command_line) + 1, 0);
	static_command_line = memblock_virt_alloc(strlen(command_line) + 1, 0);
	strcpy(saved_command_line, boot_command_line);
	strcpy(static_command_line, command_line);
}

/*
 * We need to finalize in a non-__init function or else race conditions
 * between the root thread and the init thread may cause start_kernel to
 * be reaped by free_initmem before the root thread has proceeded to
 * cpu_idle.
 *
 * gcc-3.4 accidentally inlines this function, so use noinline.
 */

/*
 * ������Ҫ��һ���� __init ��������ɳ�ʼ����������̺߳� init �߳�֮��ľ�̬�������ܻᵼ�� start_kernel �� free_initmem ���գ�
 * �ڸ��߳̽��� cpu_idle ֮ǰ��
 *
 * gcc-3.4 ������������������������ʹ�� noinline��
 */

static __initdata DECLARE_COMPLETION(kthreadd_done);

static noinline void __init_refok rest_init(void)
{
	int pid;

	rcu_scheduler_starting();
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	/*
	 * ������Ҫ������ init �Ա������ pid 1������
	 * init �������ջ���Ҫ���� kthreads�����
	 * �����ڴ��� kthreadd ֮ǰ���������ᵼ�� OOPS��
	 */
	kernel_thread(kernel_init, NULL, CLONE_FS);
	numa_default_policy();
	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
	rcu_read_lock();
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();
	complete(&kthreadd_done);

	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving:
	 */
	/*
	 * ���������̱߳�������ִ��һ�� schedule()
	 * ����ʹ����˳�����У�
	 */
	init_idle_bootup_task(current);
	schedule_preempt_disabled();
	/* Call into cpu_idle with preempt disabled */
	/* �ڽ�����ռ������µ��� cpu_idle */
	cpu_startup_entry(CPUHP_ONLINE);
}

/* Check for early params. */
/* ������ڲ����� */
static int __init do_early_param(char *param, char *val, const char *unused)
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if ((p->early && parameq(param, p->str)) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	/* ������׶����ǽ������в����� */
	return 0;
}

void __init parse_early_options(char *cmdline)
{
	parse_args("early options", cmdline, NULL, 0, 0, 0, do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
/* �ܹ����������ڵ��ô˺��������û�У�������������֮ǰ���á� */
void __init parse_early_param(void)
{
	static int done __initdata;
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

	if (done)
		return;

	/* All fall through to do_early_param. */
	/* ���в��������ݸ� do_early_param�� */
	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	done = 1;
}

/*
 *	Activate the first processor.
 */
/*
 * �����һ����������
 */

static void __init boot_cpu_init(void)
{
	int cpu = smp_processor_id();
	/* Mark the boot cpu "present", "online" etc for SMP and UP case */
	/* ������� CPU Ϊ "present"��"online" �ȣ�����Ӧ SMP �� UP ��� */
	set_cpu_online(cpu, true);
	set_cpu_active(cpu, true);
	set_cpu_present(cpu, true);
	set_cpu_possible(cpu, true);
}

void __init __weak smp_setup_processor_id(void)
{
}

# if THREAD_SIZE >= PAGE_SIZE
void __init __weak thread_info_cache_init(void)
{
}
#endif

/*
 * Set up kernel memory allocators
 */
/*
 * ��ʼ���ں��ڴ������
 */
static void __init mm_init(void)
{
	/*
	 * page_cgroup requires contiguous pages,
	 * bigger than MAX_ORDER unless SPARSEMEM.
	 */
	/*
	 * page_cgroup ��Ҫ����ҳ�棬
	 * ���� MAX_ORDER�������� SPARSEMEM��
	 */
	page_cgroup_init_flatmem();
	/*
	* ��ʼ��ҳ������飨page cgroup�������������ڴ���ƺ͹���Ļ��ơ�
	* �������ڴ�����У���Ҫ��������ҳ�棬�ر��Ǵ��� MAX_ORDER�������� SPARSEMEM��
	*/

	mem_init();
	/*
	* ��ʼ���ڴ������ϵͳ��
	* �������ú͹����ڴ�Ļ����ṹ�����ݡ�
	*/

	kmem_cache_init();
	/*
	* ��ʼ���ں��ڴ滺�棨slab ����������
	* slab ���������ڸ�Ч�ط���͹���С�ڴ����
	*/

	percpu_init_late();
	/*
	* �ӳٳ�ʼ�� per-CPU��ÿ�� CPU �����ģ�������
	* ����ÿ�� CPU ӵ�ж������ڴ����򣬼��پ�����������ܡ�
	*/

	pgtable_init();
	/*
	* ��ʼ��ҳ��ṹ��
	* ҳ�����ڴ����Ԫ��MMU�����ڽ������ַת��Ϊ�����ַ�����ݽṹ��
	*/

	vmalloc_init();
	/*
	* ��ʼ�������ڴ��������vmalloc����
	* vmalloc ���ڷ��������������ڴ�ռ䣬�ÿռ���ܲ��������ڴ���������
	*/
}

asmlinkage __visible void __init start_kernel(void)
{
	char *command_line;
	char *after_dashes;

	/*
	 * Need to run as early as possible, to initialize the
	 * lockdep hash:
	 */
	/*
	 * ��Ҫ���������Գ�ʼ��
	 * lockdep ��ϣ��
	 */
	lockdep_init();
	set_task_stack_end_magic(&init_task);
	smp_setup_processor_id();
	debug_objects_early_init();

	/*
	 * Set up the the initial canary ASAP:
	 */
	/*
	 * �������ó�ʼ canary��
	 */
	boot_init_stack_canary();

	cgroup_init_early();

	local_irq_disable();
	early_boot_irqs_disabled = true;

/*
 * Interrupts are still disabled. Do necessary setups, then
 * enable them
 */
/*
 * �ж���Ȼ���á����б�Ҫ�����ã�Ȼ��
 * ��������
 */
	boot_cpu_init();
	page_address_init();
	pr_notice("%s", linux_banner);
	setup_arch(&command_line);
	mm_init_cpumask(&init_mm);
	setup_command_line(command_line);
	setup_nr_cpu_ids();
	setup_per_cpu_areas();
	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */
	/* �ض��ܹ������� CPU ���� */

	build_all_zonelists(NULL, NULL);
	page_alloc_init();

	pr_notice("Kernel command line: %s\n", boot_command_line);
	parse_early_param();
	after_dashes = parse_args("Booting kernel",
				  static_command_line, __start___param,
				  __stop___param - __start___param,
				  -1, -1, &unknown_bootoption);
	if (!IS_ERR_OR_NULL(after_dashes))
		parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
			   set_init_arg);

	jump_label_init();

	/*
	 * These use large bootmem allocations and must precede
	 * kmem_cache_init()
	 */
	/*
	 * ��Щʹ�ô��� bootmem ���䣬������ kmem_cache_init() ֮ǰ
	 */
	setup_log_buf(0);
	pidhash_init();
	vfs_caches_init_early();
	sort_main_extable();
	trap_init();
	mm_init();

	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 */
	/*
	 * �������κ��жϣ����ʱ���жϣ�֮ǰ���õ�������
	 * �������������÷����� smp_init() ʱ�� - �����ͬʱ������Ȼ��һ�����������ĵ�������
	 */
	sched_init();
	/*
	 * Disable preemption - early bootup scheduling is extremely
	 * fragile until we cpu_idle() for the first time.
	 */
	/*
	 * ������ռ - �����������ȷǳ�������ֱ�����ǵ�һ�ε��� cpu_idle()��
	 */
	preempt_disable();
	/*
	* Disable preemption.
	* ������ռ��
	*/

	if (WARN(!irqs_disabled(), "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();
	/*
	* Check if interrupts are disabled and log a warning if they are not.
	* ����ж�û�б����ã���¼���档
	*/

	idr_init_cache();
	/*
	* Initialize IDR cache.
	* ��ʼ�� IDR ���档
	*/

	rcu_init();
	/*
	* Initialize Read-Copy-Update (RCU) subsystem.
	* ��ʼ�� RCU ��ϵͳ��
	*/

	context_tracking_init();
	/*
	* Initialize context tracking.
	* ��ʼ�������ĸ��١�
	*/

	radix_tree_init();
	/*
	* Initialize radix tree data structure.
	* ��ʼ�����������ݽṹ��
	*/


	/* init some links before init_ISA_irqs() */

	early_irq_init();
	/*
	* Initialize early interrupt handling.
	* ��ʼ�������жϴ���
	*/

	init_IRQ();
	/*
	* Initialize interrupt request (IRQ) subsystem.
	* ��ʼ���ж�������ϵͳ��
	*/

	tick_init();
	/*
	* Initialize system tick.
	* ��ʼ��ϵͳʱ�ӡ�
	*/

	rcu_init_nohz();
	/*
	* Initialize RCU for nohz mode (tickless operation).
	* Ϊ nohz ģʽ����ʱ�Ӳ�������ʼ�� RCU��
	*/

	init_timers();
	/*
	* Initialize timer subsystem.
	* ��ʼ����ʱ����ϵͳ��
	*/

	hrtimers_init();
	/*
	* Initialize high-resolution timers.
	* ��ʼ���߷ֱ��ʶ�ʱ����
	*/

	softirq_init();
	/*
	* Initialize software interrupts.
	* ��ʼ������жϡ�
	*/

	timekeeping_init();
	/*
	* Initialize timekeeping subsystem.
	* ��ʼ��ʱ�������ϵͳ��
	*/

	time_init();
	/*
	* Initialize system time.
	* ��ʼ��ϵͳʱ�䡣
	*/

	sched_clock_postinit();
	/*
	* Perform post-initialization for scheduler clock.
	* ִ�е�����ʱ�ӵĺ��ʼ����
	*/

	perf_event_init();
	/*
	* Initialize performance events subsystem.
	* ��ʼ�������¼���ϵͳ��
	*/

	profile_init();
	/*
	* Initialize profiling subsystem.
	* ��ʼ��������ϵͳ��
	*/

	call_function_init();
	/*
	* Initialize call function subsystem.
	* ��ʼ�����ú�����ϵͳ��
	*/

	WARN(!irqs_disabled(), "Interrupts were enabled early\n");
	/*
	* Check if interrupts are disabled and log a warning if they are not.
	* ����ж�û�б����ã���¼���档
	*/

	early_boot_irqs_disabled = false;
	/*
	* Mark that early boot interrupts are no longer disabled.
	* ������������жϲ��ٱ����á�
	*/

	local_irq_enable();
	/*
	* Enable local interrupts.
	* ���ñ����жϡ�
	*/

	kmem_cache_init_late();
	/*
	* Perform late initialization of kernel memory cache (slab allocator).
	* ִ���ں��ڴ滺�棨slab ���������ĺ��ڳ�ʼ����
	*/

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	/*
	* HACK ALERT! �������ڵĲ����������ڽ��� PCI ���õȲ���֮ǰ�������˿���̨��
	* console_init() ������ʶ����һ�㡣��������ϣ�����������Ϣ���Է��������⡣
	*/

	console_init();
	/*
	* ��ǰ��ʼ������̨��ϵͳ����δ����豸��ʼ����
	*/
	if (panic_later)
		panic("Too many boot %s vars at `%s'", panic_later,
		      panic_param);
	/*
	* ����Ƿ��й����������������Ҫʱ�����ں˿ֻš�
	*/
	lockdep_info();
	/*
	* ��ʼ�����ڵ��Ե���������Ϣ��
	*/

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	/*
	* ��Ҫ�������ж�ʱ���д˲�������Ϊ��Ҳϣ���� [Ӳ/��] �жϿ�������ת��������Բ⣺
	*/
	locking_selftest();
	/*
	* ���ж�����ʱִ������ת������Բ⡣
	*/
#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif
	page_cgroup_init();
	debug_objects_mem_init();
	kmemleak_init();
	setup_per_cpu_pageset();
	numa_policy_init();
	if (late_time_init)
		late_time_init();
	sched_clock_init();
	calibrate_delay();
	pidmap_init();
	anon_vma_init();
	acpi_early_init();
#ifdef CONFIG_X86
	if (efi_enabled(EFI_RUNTIME_SERVICES))
		efi_enter_virtual_mode();
#endif
#ifdef CONFIG_X86_ESPFIX64
	/* Should be run before the first non-init thread is created */
	init_espfix_bsp();
#endif
	thread_info_cache_init();
	cred_init();
	fork_init(totalram_pages);
	proc_caches_init();
	buffer_init();
	key_init();
	security_init();
	dbg_late_init();
	vfs_caches_init(totalram_pages);
	signals_init();
	/* rootfs populating might need page-writeback */
	page_writeback_init();
	proc_root_init();
	cgroup_init();
	cpuset_init();
	taskstats_init_early();
	delayacct_init();

	check_bugs();

	sfi_init_late();

	if (efi_enabled(EFI_RUNTIME_SERVICES)) {
		efi_late_init();
		efi_free_boot_services();
	}

	ftrace_init();

	/* Do the rest non-__init'ed, we're now alive */
	rest_init();
}

/* Call all constructor functions linked into the kernel. */
/* �������ӵ��ں��е����й��캯���� */
static void __init do_ctors(void)
{
#ifdef CONFIG_CONSTRUCTORS
    // Iterate through the array of constructor functions and call each one.
    // �������캯�����飬�����ε���ÿ�����캯����
    ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

    for (; fn < (ctor_fn_t *) __ctors_end; fn++)
        (*fn)();
#endif
}

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

#ifdef CONFIG_KALLSYMS
// Code related to kernel symbol handling when CONFIG_KALLSYMS is enabled.
// ������ CONFIG_KALLSYMS ʱ�������ں˷��ŵ���ش��롣
#endif

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

#ifdef CONFIG_KALLSYMS
struct blacklist_entry {
    struct list_head next;  // ����ڵ�
    char *buf;  // �洢��������
};

static __initdata_or_module LIST_HEAD(blacklisted_initcalls);  // ��������ʼ����������

static int __init initcall_blacklist(char *str)
{
    char *str_entry;
    struct blacklist_entry *entry;

    // str ������һ���Զ��ŷָ��ĺ����б�
    do {
        str_entry = strsep(&str, ",");
        if (str_entry) {
            pr_debug("blacklisting initcall %s\n", str_entry);
            entry = alloc_bootmem(sizeof(*entry));
            entry->buf = alloc_bootmem(strlen(str_entry) + 1);
            strcpy(entry->buf, str_entry);
            list_add(&entry->next, &blacklisted_initcalls);  // ��ӵ�����������
        }
    } while (str_entry);

    return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
    struct list_head *tmp;
    struct blacklist_entry *entry;
    char *fn_name;

    fn_name = kasprintf(GFP_KERNEL, "%pf", fn);  // ��ȡ��������
    if (!fn_name)
        return false;

    // ����������������麯���Ƿ��ں�������
    list_for_each(tmp, &blacklisted_initcalls) {
        entry = list_entry(tmp, struct blacklist_entry, next);
        if (!strcmp(fn_name, entry->buf)) {
            pr_debug("initcall %s blacklisted\n", fn_name);
            kfree(fn_name);
            return true;
        }
    }

    kfree(fn_name);
    return false;
}
#else
static int __init initcall_blacklist(char *str)
{
    pr_warn("initcall_blacklist requires CONFIG_KALLSYMS\n");  // ��ʾ��Ҫ CONFIG_KALLSYMS
    return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
    return false;
}
#endif

__setup("initcall_blacklist=", initcall_blacklist);  // �����ں˲���������

static int __init_or_module do_one_initcall_debug(initcall_t fn)
{
    ktime_t calltime, delta, rettime;
    unsigned long long duration;
    int ret;

    printk(KERN_DEBUG "calling %pF @ %i\n", fn, task_pid_nr(current));  // ������Ϣ�����ú������� PID
    calltime = ktime_get();  // ��ȡ����ʱ��
    ret = fn();  // ���ú���
    rettime = ktime_get();  // ��ȡ����ʱ��
    delta = ktime_sub(rettime, calltime);  // ����ʱ���
    duration = (unsigned long long) ktime_to_ns(delta) >> 10;  // ת��Ϊ΢��
    printk(KERN_DEBUG "initcall %pF returned %d after %lld usecs\n",
           fn, ret, duration);  // ������Ϣ����������ֵ��ִ��ʱ��

    return ret;
}


int __init_or_module do_one_initcall(initcall_t fn)
{
    int count = preempt_count();
    int ret;
    char msgbuf[64];

    // ��������ں������У����� -EPERM
    if (initcall_blacklisted(fn))
        return -EPERM;

    // ���� initcall_debug ��ֵ���ò�ͬ�ĺ���
    if (initcall_debug)
        ret = do_one_initcall_debug(fn);
    else
        ret = fn();

    msgbuf[0] = 0;

    // �����ռ�����Ƿ�仯
    if (preempt_count() != count) {
        sprintf(msgbuf, "preemption imbalance ");
        preempt_count_set(count);
    }
    // ����ж��Ƿ����
    if (irqs_disabled()) {
        strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
        local_irq_enable();
    }
    // ��� msgbuf ��Ϊ�գ���������
    WARN(msgbuf[0], "initcall %pF returned with %s\n", fn, msgbuf);

    return ret;
}

extern initcall_t __initcall_start[];
extern initcall_t __initcall0_start[];
extern initcall_t __initcall1_start[];
extern initcall_t __initcall2_start[];
extern initcall_t __initcall3_start[];
extern initcall_t __initcall4_start[];
extern initcall_t __initcall5_start[];
extern initcall_t __initcall6_start[];
extern initcall_t __initcall7_start[];
extern initcall_t __initcall_end[];

static initcall_t *initcall_levels[] __initdata = {
    __initcall0_start,
    __initcall1_start,
    __initcall2_start,
    __initcall3_start,
    __initcall4_start,
    __initcall5_start,
    __initcall6_start,
    __initcall7_start,
    __initcall_end,
};

/* Keep these in sync with initcalls in include/linux/init.h */
/* ������ include/linux/init.h �е� initcall һ�� */
static char *initcall_level_names[] __initdata = {
	"early",
	"core",
	"postcore",
	"arch",
	"subsys",
	"fs",
	"device",
	"late",
};

static void __init do_initcall_level(int level)
{
    initcall_t *fn;

    // ���Ʋ����������в���
    strcpy(initcall_command_line, saved_command_line);
    parse_args(initcall_level_names[level],
               initcall_command_line, __start___param,
               __stop___param - __start___param,
               level, level,
               &repair_env_string);

    // ������ǰ��������г�ʼ�����ò�ִ��
    for (fn = initcall_levels[level]; fn < initcall_levels[level + 1]; fn++)
        do_one_initcall(*fn);
}

static void __init do_initcalls(void)
{
    int level;

    // �������г�ʼ�����ü���ִ����Ӧ�ĳ�ʼ������
    for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++)
        do_initcall_level(level);
}

/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 */
/*
 * ���ڻ����Ѿ���ʼ����ɡ�
 * ������δ�����κ��豸����CPU��ϵͳ�Ѿ������������ڴ�ͽ��̹����Ѿ�����������
 *
 * �����������ڿ��Կ�ʼ��һЩ�����Ĺ�����...
 */
static void __init do_basic_setup(void)
{
	cpuset_init_smp();
	usermodehelper_init();
	shmem_init();
	driver_init();
	init_irq_proc();
	do_ctors();
	usermodehelper_enable();
	do_initcalls();
	random_int_secret_init();
}

static void __init do_pre_smp_initcalls(void)
{
    initcall_t *fn;

    // ִ�� __initcall_start �� __initcall0_start ֮�������Ԥ SMP ��ʼ������
    for (fn = __initcall_start; fn < __initcall0_start; fn++)
        do_one_initcall(*fn);
}


/*
 * This function requests modules which should be loaded by default and is
 * called twice right after initrd is mounted and right before init is
 * exec'd.  If such modules are on either initrd or rootfs, they will be
 * loaded before control is passed to userland.
 */
/*
 * �˺�������Ĭ�ϼ��ص�ģ�飬�� initrd ���غ�� init ִ��֮ǰ�������Ρ�
 * �����Щģ������� initrd �� rootfs �ϣ����ǽ��ڿ���Ȩ�ƽ����û��ռ�֮ǰ���ء�
 */
void __init load_default_modules(void)
{
    // ����Ĭ�ϵĵ���ģ��
    load_default_elevator_module();
}

static int run_init_process(const char *init_filename)
{
    // ���� init ���̵��ļ���
    argv_init[0] = init_filename;
    // ִ�� init ����
    return do_execve(getname_kernel(init_filename),
        (const char __user *const __user *)argv_init,
        (const char __user *const __user *)envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
    int ret;

    // �������� init ����
    ret = run_init_process(init_filename);

    // ������ش����Ҵ����� ENOENT����ӡ������Ϣ
    if (ret && ret != -ENOENT) {
        pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
               init_filename, ret);
    }

    return ret;
}

static noinline void __init kernel_init_freeable(void);

static int __ref kernel_init(void *unused)
{
    int ret;

    // ִ�п��ͷŵ��ں˳�ʼ��
    kernel_init_freeable();
    // ��Ҫ���ͷ��ڴ�ǰ��������첽�� __init ����
    async_synchronize_full();
    free_initmem();
    mark_rodata_ro();
    system_state = SYSTEM_RUNNING;
    numa_default_policy();

    flush_delayed_fput();

    // ������� ramdisk ִ���������������
    if (ramdisk_execute_command) {
        ret = run_init_process(ramdisk_execute_command);
        if (!ret)
            return 0;
        pr_err("Failed to execute %s (error %d)\n",
               ramdisk_execute_command, ret);
    }
    
    // ���Ĭ�Ϸ���ֵ����ֹ����������
    return -1;
}

	/*
	 * We try each of these until one succeeds.
	 *
	 * The Bourne shell can be used instead of init if we are
	 * trying to recover a really broken machine.
	 */
	/*
	* �������γ�����Щ���ֱ����һ���ɹ�Ϊֹ��
	*
	* ����������ڳ��Իָ�һ̨�����𻵵Ļ���������ʹ�� Bourne shell ���� init��
	*/
	if (execute_command) {
		// �����ָ��ִ�е��������������
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;
		// �������ִ��ʧ�ܣ���ӡ������Ϣ������Ĭ�ϵ� init ����
		pr_err("Failed to execute %s (error %d).  Attempting defaults...\n",
			execute_command, ret);
	}

	// ���γ�������Ĭ�ϵ� init ���̣������һ���ɹ��򷵻� 0
	if (!try_to_run_init_process("/sbin/init") ||
		!try_to_run_init_process("/etc/init") ||
		!try_to_run_init_process("/bin/init") ||
		!try_to_run_init_process("/bin/sh"))
		return 0;

	// ������� init ���̶��޷����У����� panic ����ʾ�û����� init= ѡ��
	panic("No working init found.  Try passing init= option to kernel. "
		"See Linux Documentation/init.txt for guidance.");
}

static noinline void __init kernel_init_freeable(void)
{
	/*
	 * Wait until kthreadd is all set-up.
	 */
	 /*
     * �ȴ� kthreadd ��ȫ���úá�
     */
	wait_for_completion(&kthreadd_done);

	/* Now the scheduler is fully set up and can do blocking allocations */
	/* ���ڵ��ȳ�������ȫ���ã����Խ����������� */
	gfp_allowed_mask = __GFP_BITS_MASK;

	/*
	 * init can allocate pages on any node
	 */
	/*
     * init �������κνڵ��Ϸ���ҳ��
     */
	set_mems_allowed(node_states[N_MEMORY]);
	/*
	 * init can run on any cpu.
	 */
	/*
     * init �������κ� CPU �����С�
     */
	set_cpus_allowed_ptr(current, cpu_all_mask);

	cad_pid = task_pid(current);

	smp_prepare_cpus(setup_max_cpus);

	do_pre_smp_initcalls();
	lockup_detector_init();

	smp_init();
	sched_init_smp();

	do_basic_setup();

	/* Open the /dev/console on the rootfs, this should never fail */
	/* �� rootfs �ϴ� /dev/console���ⲻӦ��ʧ�� */
	if (sys_open((const char __user *) "/dev/console", O_RDWR, 0) < 0)
		pr_err("Warning: unable to open an initial console.\n");

	(void) sys_dup(0);
	(void) sys_dup(0);
	/*
	 * check if there is an early userspace init.  If yes, let it do all
	 * the work
	 */
	 /*
     * ����Ƿ���������û��ռ�� init������У������������й���
     */

	if (!ramdisk_execute_command)
		ramdisk_execute_command = "/init";

	if (sys_access((const char __user *) ramdisk_execute_command, 0) != 0) {
		ramdisk_execute_command = NULL;
		prepare_namespace();
	}

	/*
	 * Ok, we have completed the initial bootup, and
	 * we're essentially up and running. Get rid of the
	 * initmem segments and start the user-mode stuff..
	 */
	/*
     * �õģ������Ѿ�����˳�ʼ����������
     * ���ǻ������Ѿ������������ˡ����� initmem �β������û�ģʽ�Ĺ�����
     */
	/* rootfs is available now, try loading default modules */
	load_default_modules();
}
