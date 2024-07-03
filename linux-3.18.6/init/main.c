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

#include <linux/types.h>                  // 基本数据类型定义
#include <linux/module.h>                 // 模块相关函数和宏定义
#include <linux/proc_fs.h>                // proc 文件系统相关函数和结构体
#include <linux/kernel.h>                 // 内核常用函数和宏定义
#include <linux/syscalls.h>               // 系统调用相关宏定义
#include <linux/stackprotector.h>         // 栈保护相关宏定义和函数声明
#include <linux/string.h>                 // 字符串操作函数声明
#include <linux/ctype.h>                  // 字符处理函数和宏定义
#include <linux/delay.h>                  // 延时函数声明
#include <linux/ioport.h>                 // IO 端口操作函数和宏定义
#include <linux/init.h>                   // 内核初始化和模块加载函数宏定义
#include <linux/initrd.h>                 // 初始 RAM 磁盘支持相关宏定义
#include <linux/bootmem.h>                // 引导内存管理相关宏定义和函数声明
#include <linux/acpi.h>                   // ACPI 相关函数和数据结构声明
#include <linux/tty.h>                    // 终端设备相关函数和数据结构声明
#include <linux/percpu.h>                 // 多 CPU 系统下的局部存储变量声明
#include <linux/kmod.h>                   // 内核模块加载和管理相关函数和数据结构声明
#include <linux/vmalloc.h>                // 虚拟内存分配相关函数和宏定义
#include <linux/kernel_stat.h>            // 内核统计信息相关函数和数据结构声明
#include <linux/start_kernel.h>           // 内核启动和初始化相关函数声明
#include <linux/security.h>               // 内核安全模块相关函数和数据结构声明
#include <linux/smp.h>                    // 对称多处理器相关函数和宏定义
#include <linux/profile.h>                // 系统性能分析相关函数和宏定义
#include <linux/rcupdate.h>               // RCU（Read-Copy-Update）相关函数和宏定义
#include <linux/moduleparam.h>            // 模块参数相关函数和宏定义
#include <linux/kallsyms.h>               // 内核符号表查询相关函数声明
#include <linux/writeback.h>              // 脏页面回写相关函数声明
#include <linux/cpu.h>                    // CPU 相关函数和数据结构声明
#include <linux/cpuset.h>                 // CPU 集相关函数和数据结构声明
#include <linux/cgroup.h>                 // 控制组（Cgroup）相关函数和数据结构声明
#include <linux/efi.h>                    // EFI 系统相关函数和数据结构声明
#include <linux/tick.h>                   // 系统时钟事件相关函数和数据结构声明
#include <linux/interrupt.h>              // 中断处理相关函数和数据结构声明
#include <linux/taskstats_kern.h>         // 任务统计信息相关函数和数据结构声明
#include <linux/delayacct.h>              // 延时账户相关函数和数据结构声明
#include <linux/unistd.h>                 // 系统调用号声明
#include <linux/rmap.h>                   // 反向映射相关函数和数据结构声明
#include <linux/mempolicy.h>              // 内存策略相关函数和数据结构声明
#include <linux/key.h>                    // 密钥管理相关函数和数据结构声明
#include <linux/buffer_head.h>            // 缓冲区头相关函数和数据结构声明
#include <linux/page_cgroup.h>            // 页面控制组相关函数和数据结构声明
#include <linux/debug_locks.h>            // 调试锁相关函数和数据结构声明
#include <linux/debugobjects.h>           // 调试对象相关函数和数据结构声明
#include <linux/lockdep.h>                // 锁依赖关系分析相关函数和数据结构声明
#include <linux/kmemleak.h>               // 内存泄漏检测相关函数和数据结构声明
#include <linux/pid_namespace.h>          // 进程 ID 命名空间相关函数和数据结构声明
#include <linux/device.h>                 // 设备模型相关函数和数据结构声明
#include <linux/kthread.h>                // 内核线程相关函数和数据结构声明
#include <linux/sched.h>                  // 进程调度相关函数和数据结构声明
#include <linux/signal.h>                 // 信号处理相关函数和数据结构声明
#include <linux/idr.h>                    // IDR 分配器相关函数和数据结构声明
#include <linux/kgdb.h>                   // KGDB 调试相关函数和数据结构声明
#include <linux/ftrace.h>                 // 函数跟踪相关函数和数据结构声明
#include <linux/async.h>                  // 异步事件处理相关函数和数据结构声明
#include <linux/kmemcheck.h>              // 内存检查相关函数和数据结构声明
#include <linux/sfi.h>                    // 简单固件接口相关函数和数据结构声明
#include <linux/shmem_fs.h>               // 共享内存文件系统相关函数和数据结构声明
#include <linux/slab.h>                   // 内存分配和管理相关函数和宏定义
#include <linux/perf_event.h>             // 性能事件相关函数和数据结构声明
#include <linux/file.h>                   // 文件操作相关函数和数据结构声明
#include <linux/ptrace.h>                 // 进程跟踪相关函数和数据结构声明
#include <linux/blkdev.h>                 // 块设备相关函数和数据结构声明
#include <linux/elevator.h>               // IO 调度器相关函数和数据结构声明
#include <linux/sched_clock.h>            // 系统时钟相关函数和数据结构声明
#include <linux/context_tracking.h>       // 上下文追踪相关函数和数据结构声明
#include <linux/random.h>                 // 随机数生成相关函数和数据结构声明
#include <linux/list.h>                   // 双向链表相关函数和数据结构声明

#include <asm/io.h>                       // IO 操作相关宏定义和函数声明（特定架构）
#include <asm/bugs.h>                     // 处理硬件错误和异常相关函数和宏定义（特定架构）
#include <asm/setup.h>                    // 硬件初始化和引导参数相关函数和宏定义（特定架构）
#include <asm/sections.h>                 // 内存区段定义和操作相关宏定义（特定架构）
#include <asm/cacheflush.h>               // CPU 缓存刷新相关函数和宏定义（特定架构）


#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/smp.h>  // 包含多处理器相关的头文件
#endif


// 内核初始化函数的原型声明
static int kernel_init(void *);
// 声明外部函数，用于初始化中断请求（IRQ）
extern void init_IRQ(void);
// 声明外部函数，用于初始化进程的fork功能
extern void fork_init(unsigned long);
// 声明外部函数，用于初始化基数树（radix tree）
extern void radix_tree_init(void);

#ifndef CONFIG_DEBUG_RODATA
// 如果没有定义CONFIG_DEBUG_RODATA，则定义一个空的内联函数
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
 * 调试助手：通过这个标志我们知道当前处于“早期启动代码”阶段，
 * 此时只有引导处理器在运行，并且中断请求（IRQ）被禁用。
 * 这意味着两件事——在标志被清除之前，中断请求不能被启用，
 * 并且在标志设置时，一些在中断请求禁用时不允许的操作是被允许的。
 */

 /*
 * 这个标志表明系统是否在早期启动阶段禁用了中断请求（IRQ）。
 * __read_mostly 是一个编译器指示符，表示该变量在运行期间几乎不会被修改，
 * 主要是读取操作，从而帮助优化。
 */
bool early_boot_irqs_disabled __read_mostly;

/*
 * 枚举类型的变量，用于表示系统的当前状态。
 * __read_mostly 表示该变量在运行期间几乎不会被修改，主要是读取操作。
 * EXPORT_SYMBOL(system_state) 将这个符号导出，使其可以被其他内核模块使用。
 */
enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/*
 * 启动命令行参数
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/* 默认的延迟时间初始化为NULL。架构可以稍后覆盖这个值。 */
void (*__initdata late_time_init)(void);

/* 由特定架构代码保存的原始命令行。 */
char __initdata boot_command_line[COMMAND_LINE_SIZE];
/* 保存的原始命令行（例如用于 /proc） */
char *saved_command_line;
/* 用于参数解析的命令行 */
static char *static_command_line;
/* 用于每个初始化调用的参数解析的命令行 */
static char *initcall_command_line;

static char *execute_command;
static char *ramdisk_execute_command;

/*
 * 如果在调用 jump_label_init 之前使用了 static_key 操作函数，
 * 则用于生成警告。
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
 * 如果设置，该标志指示驱动程序在继续初始化之前重置底层设备，
 * 否则驱动程序可能依赖于 BIOS 并跳过重置操作。
 *
 * 这在内核在不可靠环境中启动时非常有用。
 * 例如：kdump 情况下，前一个内核崩溃，BIOS 被跳过，设备处于未知状态。
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
				/* 是否已经在 parse_early_param 中处理？
				 * （需要在参数部分精确匹配）。
				 * 继续迭代，因为我们可以有相同名称的早期参数和 __setup */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = 1;
			} else if (!p->setup_func) {
				pr_warn("参数 %s 已过时，已忽略\n", p->str);
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
 * 这应该是大约 2 Bo*oMips 开始（注意初始移位），即使初始值过大，它仍然可以工作，只是稍微慢一点
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
	 * 只有在传递了正确的设置时才更新日志级别值，
	 * 以防止盲目崩溃（日志级别被设置为 0）这种情况非常难以调试
	 */
	if (get_option(&str, &newlevel)) {
		console_loglevel = newlevel;
		return 0;
	}

	return -EINVAL;
}

early_param("loglevel", loglevel);

/* 将 NUL term 更改回 "="，使 "param" 成为整个字符串 */
static int __init repair_env_string(char *param, char *val, const char *unused)
{
	if (val) {
		/* param=val 或 param="val"? */
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

/* -- 之后的任何内容都直接传递给 init */
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
 * 未知的启动选项将传递给 init，除非它们看起来像未使用的参数
 * （modprobe 会在 /proc/cmdline 中找到它们）。
 */
static int __init unknown_bootoption(char *param, char *val, const char *unused)
{
	repair_env_string(param, val, unused);

	/* 处理过时的参数 */
	if (obsolete_checksetup(param))
		return 0;

	/* 未使用的模块参数。 */
	if (strchr(param, '.') && (!val || strchr(param, '.') < val))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* 环境选项 */
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
		/* 命令行选项 */
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
	 * 如果 LILO 要用默认命令行启动我们，
	 * 它会在整个 cmdline 之前加上 "auto"，这会使
	 * shell 认为它应该执行一个这样的脚本。
	 * 因此我们忽略 init= 之前输入的所有参数 [MJ]
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
	/* 参见 init_setup 中的 "auto" 注释 */
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
 * 我们需要存储未修改的命令行以供将来参考。
 * 我们还需要存储已修改的命令行，因为参数解析是就地执行的，
 * 我们应该允许组件存储名称/值的引用以供将来参考。
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
 * 我们需要在一个非 __init 函数中完成初始化，否则根线程和 init 线程之间的竞态条件可能会导致 start_kernel 被 free_initmem 回收，
 * 在根线程进入 cpu_idle 之前。
 *
 * gcc-3.4 意外地内联了这个函数，所以使用 noinline。
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
	 * 我们需要先生成 init 以便它获得 pid 1，但是
	 * init 任务最终会想要创建 kthreads，如果
	 * 我们在创建 kthreadd 之前调度它，会导致 OOPS。
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
	 * 启动空闲线程必须至少执行一次 schedule()
	 * 才能使事情顺利进行：
	 */
	init_idle_bootup_task(current);
	schedule_preempt_disabled();
	/* Call into cpu_idle with preempt disabled */
	/* 在禁用抢占的情况下调用 cpu_idle */
	cpu_startup_entry(CPUHP_ONLINE);
}

/* Check for early params. */
/* 检查早期参数。 */
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
	/* 在这个阶段我们接受所有参数。 */
	return 0;
}

void __init parse_early_options(char *cmdline)
{
	parse_args("early options", cmdline, NULL, 0, 0, 0, do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
/* 架构代码在早期调用此函数，如果没有，则在其他解析之前调用。 */
void __init parse_early_param(void)
{
	static int done __initdata;
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

	if (done)
		return;

	/* All fall through to do_early_param. */
	/* 所有参数都传递给 do_early_param。 */
	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	done = 1;
}

/*
 *	Activate the first processor.
 */
/*
 * 激活第一个处理器。
 */

static void __init boot_cpu_init(void)
{
	int cpu = smp_processor_id();
	/* Mark the boot cpu "present", "online" etc for SMP and UP case */
	/* 标记引导 CPU 为 "present"、"online" 等，以适应 SMP 和 UP 情况 */
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
 * 初始化内核内存分配器
 */
static void __init mm_init(void)
{
	/*
	 * page_cgroup requires contiguous pages,
	 * bigger than MAX_ORDER unless SPARSEMEM.
	 */
	/*
	 * page_cgroup 需要连续页面，
	 * 大于 MAX_ORDER，除非是 SPARSEMEM。
	 */
	page_cgroup_init_flatmem();
	/*
	* 初始化页面控制组（page cgroup），这是用于内存控制和管理的机制。
	* 在物理内存管理中，它要求连续的页面，特别是大于 MAX_ORDER，除非是 SPARSEMEM。
	*/

	mem_init();
	/*
	* 初始化内存管理子系统。
	* 负责设置和管理内存的基本结构和数据。
	*/

	kmem_cache_init();
	/*
	* 初始化内核内存缓存（slab 分配器）。
	* slab 分配器用于高效地分配和管理小内存对象。
	*/

	percpu_init_late();
	/*
	* 延迟初始化 per-CPU（每个 CPU 独立的）变量。
	* 允许每个 CPU 拥有独立的内存区域，减少竞争和提高性能。
	*/

	pgtable_init();
	/*
	* 初始化页表结构。
	* 页表是内存管理单元（MMU）用于将虚拟地址转换为物理地址的数据结构。
	*/

	vmalloc_init();
	/*
	* 初始化虚拟内存分配器（vmalloc）。
	* vmalloc 用于分配连续的虚拟内存空间，该空间可能不在物理内存中连续。
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
	 * 需要尽早运行以初始化
	 * lockdep 哈希：
	 */
	lockdep_init();
	set_task_stack_end_magic(&init_task);
	smp_setup_processor_id();
	debug_objects_early_init();

	/*
	 * Set up the the initial canary ASAP:
	 */
	/*
	 * 尽快设置初始 canary：
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
 * 中断仍然禁用。进行必要的设置，然后
 * 启用它们
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
	/* 特定架构的引导 CPU 钩子 */

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
	 * 这些使用大型 bootmem 分配，必须在 kmem_cache_init() 之前
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
	 * 在启动任何中断（如计时器中断）之前设置调度器。
	 * 完整的拓扑设置发生在 smp_init() 时间 - 但与此同时我们仍然有一个功能正常的调度器。
	 */
	sched_init();
	/*
	 * Disable preemption - early bootup scheduling is extremely
	 * fragile until we cpu_idle() for the first time.
	 */
	/*
	 * 禁用抢占 - 早期启动调度非常脆弱，直到我们第一次调用 cpu_idle()。
	 */
	preempt_disable();
	/*
	* Disable preemption.
	* 禁用抢占。
	*/

	if (WARN(!irqs_disabled(), "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();
	/*
	* Check if interrupts are disabled and log a warning if they are not.
	* 如果中断没有被禁用，记录警告。
	*/

	idr_init_cache();
	/*
	* Initialize IDR cache.
	* 初始化 IDR 缓存。
	*/

	rcu_init();
	/*
	* Initialize Read-Copy-Update (RCU) subsystem.
	* 初始化 RCU 子系统。
	*/

	context_tracking_init();
	/*
	* Initialize context tracking.
	* 初始化上下文跟踪。
	*/

	radix_tree_init();
	/*
	* Initialize radix tree data structure.
	* 初始化基数树数据结构。
	*/


	/* init some links before init_ISA_irqs() */

	early_irq_init();
	/*
	* Initialize early interrupt handling.
	* 初始化早期中断处理。
	*/

	init_IRQ();
	/*
	* Initialize interrupt request (IRQ) subsystem.
	* 初始化中断请求子系统。
	*/

	tick_init();
	/*
	* Initialize system tick.
	* 初始化系统时钟。
	*/

	rcu_init_nohz();
	/*
	* Initialize RCU for nohz mode (tickless operation).
	* 为 nohz 模式（无时钟操作）初始化 RCU。
	*/

	init_timers();
	/*
	* Initialize timer subsystem.
	* 初始化定时器子系统。
	*/

	hrtimers_init();
	/*
	* Initialize high-resolution timers.
	* 初始化高分辨率定时器。
	*/

	softirq_init();
	/*
	* Initialize software interrupts.
	* 初始化软件中断。
	*/

	timekeeping_init();
	/*
	* Initialize timekeeping subsystem.
	* 初始化时间管理子系统。
	*/

	time_init();
	/*
	* Initialize system time.
	* 初始化系统时间。
	*/

	sched_clock_postinit();
	/*
	* Perform post-initialization for scheduler clock.
	* 执行调度器时钟的后初始化。
	*/

	perf_event_init();
	/*
	* Initialize performance events subsystem.
	* 初始化性能事件子系统。
	*/

	profile_init();
	/*
	* Initialize profiling subsystem.
	* 初始化分析子系统。
	*/

	call_function_init();
	/*
	* Initialize call function subsystem.
	* 初始化调用函数子系统。
	*/

	WARN(!irqs_disabled(), "Interrupts were enabled early\n");
	/*
	* Check if interrupts are disabled and log a warning if they are not.
	* 如果中断没有被禁用，记录警告。
	*/

	early_boot_irqs_disabled = false;
	/*
	* Mark that early boot interrupts are no longer disabled.
	* 标记早期启动中断不再被禁用。
	*/

	local_irq_enable();
	/*
	* Enable local interrupts.
	* 启用本地中断。
	*/

	kmem_cache_init_late();
	/*
	* Perform late initialization of kernel memory cache (slab allocator).
	* 执行内核内存缓存（slab 分配器）的后期初始化。
	*/

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	/*
	* HACK ALERT! 这是早期的操作。我们在进行 PCI 设置等操作之前就启用了控制台，
	* console_init() 必须意识到这一点。但是我们希望尽早输出信息，以防出现问题。
	*/

	console_init();
	/*
	* 提前初始化控制台子系统，还未完成设备初始化。
	*/
	if (panic_later)
		panic("Too many boot %s vars at `%s'", panic_later,
		      panic_param);
	/*
	* 检查是否有过多的引导变量，必要时触发内核恐慌。
	*/
	lockdep_info();
	/*
	* 初始化用于调试的锁依赖信息。
	*/

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	/*
	* 需要在启用中断时运行此操作，因为它也希望对 [硬/软] 中断开关锁反转错误进行自测：
	*/
	locking_selftest();
	/*
	* 在中断启用时执行锁反转错误的自测。
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
/* 调用链接到内核中的所有构造函数。 */
static void __init do_ctors(void)
{
#ifdef CONFIG_CONSTRUCTORS
    // Iterate through the array of constructor functions and call each one.
    // 遍历构造函数数组，并依次调用每个构造函数。
    ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

    for (; fn < (ctor_fn_t *) __ctors_end; fn++)
        (*fn)();
#endif
}

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

#ifdef CONFIG_KALLSYMS
// Code related to kernel symbol handling when CONFIG_KALLSYMS is enabled.
// 当启用 CONFIG_KALLSYMS 时，处理内核符号的相关代码。
#endif

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

#ifdef CONFIG_KALLSYMS
struct blacklist_entry {
    struct list_head next;  // 链表节点
    char *buf;  // 存储函数名称
};

static __initdata_or_module LIST_HEAD(blacklisted_initcalls);  // 黑名单初始化调用链表

static int __init initcall_blacklist(char *str)
{
    char *str_entry;
    struct blacklist_entry *entry;

    // str 参数是一个以逗号分隔的函数列表
    do {
        str_entry = strsep(&str, ",");
        if (str_entry) {
            pr_debug("blacklisting initcall %s\n", str_entry);
            entry = alloc_bootmem(sizeof(*entry));
            entry->buf = alloc_bootmem(strlen(str_entry) + 1);
            strcpy(entry->buf, str_entry);
            list_add(&entry->next, &blacklisted_initcalls);  // 添加到黑名单链表
        }
    } while (str_entry);

    return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
    struct list_head *tmp;
    struct blacklist_entry *entry;
    char *fn_name;

    fn_name = kasprintf(GFP_KERNEL, "%pf", fn);  // 获取函数名称
    if (!fn_name)
        return false;

    // 遍历黑名单链表，检查函数是否在黑名单中
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
    pr_warn("initcall_blacklist requires CONFIG_KALLSYMS\n");  // 提示需要 CONFIG_KALLSYMS
    return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
    return false;
}
#endif

__setup("initcall_blacklist=", initcall_blacklist);  // 设置内核参数处理函数

static int __init_or_module do_one_initcall_debug(initcall_t fn)
{
    ktime_t calltime, delta, rettime;
    unsigned long long duration;
    int ret;

    printk(KERN_DEBUG "calling %pF @ %i\n", fn, task_pid_nr(current));  // 调试信息，调用函数及其 PID
    calltime = ktime_get();  // 获取调用时间
    ret = fn();  // 调用函数
    rettime = ktime_get();  // 获取返回时间
    delta = ktime_sub(rettime, calltime);  // 计算时间差
    duration = (unsigned long long) ktime_to_ns(delta) >> 10;  // 转换为微秒
    printk(KERN_DEBUG "initcall %pF returned %d after %lld usecs\n",
           fn, ret, duration);  // 调试信息，函数返回值及执行时间

    return ret;
}


int __init_or_module do_one_initcall(initcall_t fn)
{
    int count = preempt_count();
    int ret;
    char msgbuf[64];

    // 如果函数在黑名单中，返回 -EPERM
    if (initcall_blacklisted(fn))
        return -EPERM;

    // 根据 initcall_debug 的值调用不同的函数
    if (initcall_debug)
        ret = do_one_initcall_debug(fn);
    else
        ret = fn();

    msgbuf[0] = 0;

    // 检查抢占计数是否变化
    if (preempt_count() != count) {
        sprintf(msgbuf, "preemption imbalance ");
        preempt_count_set(count);
    }
    // 检查中断是否禁用
    if (irqs_disabled()) {
        strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
        local_irq_enable();
    }
    // 如果 msgbuf 不为空，发出警告
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
/* 保持与 include/linux/init.h 中的 initcall 一致 */
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

    // 复制并解析命令行参数
    strcpy(initcall_command_line, saved_command_line);
    parse_args(initcall_level_names[level],
               initcall_command_line, __start___param,
               __stop___param - __start___param,
               level, level,
               &repair_env_string);

    // 遍历当前级别的所有初始化调用并执行
    for (fn = initcall_levels[level]; fn < initcall_levels[level + 1]; fn++)
        do_one_initcall(*fn);
}

static void __init do_initcalls(void)
{
    int level;

    // 遍历所有初始化调用级别并执行相应的初始化调用
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
 * 现在机器已经初始化完成。
 * 尽管尚未触及任何设备，但CPU子系统已经启动，并且内存和进程管理已经正常工作。
 *
 * 现在我们终于可以开始做一些真正的工作了...
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

    // 执行 __initcall_start 到 __initcall0_start 之间的所有预 SMP 初始化调用
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
 * 此函数请求默认加载的模块，在 initrd 挂载后和 init 执行之前调用两次。
 * 如果这些模块存在于 initrd 或 rootfs 上，它们将在控制权移交给用户空间之前加载。
 */
void __init load_default_modules(void)
{
    // 加载默认的电梯模块
    load_default_elevator_module();
}

static int run_init_process(const char *init_filename)
{
    // 设置 init 进程的文件名
    argv_init[0] = init_filename;
    // 执行 init 进程
    return do_execve(getname_kernel(init_filename),
        (const char __user *const __user *)argv_init,
        (const char __user *const __user *)envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
    int ret;

    // 尝试运行 init 进程
    ret = run_init_process(init_filename);

    // 如果返回错误且错误不是 ENOENT，打印错误信息
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

    // 执行可释放的内核初始化
    kernel_init_freeable();
    // 需要在释放内存前完成所有异步的 __init 代码
    async_synchronize_full();
    free_initmem();
    mark_rodata_ro();
    system_state = SYSTEM_RUNNING;
    numa_default_policy();

    flush_delayed_fput();

    // 如果存在 ramdisk 执行命令，尝试运行它
    if (ramdisk_execute_command) {
        ret = run_init_process(ramdisk_execute_command);
        if (!ret)
            return 0;
        pr_err("Failed to execute %s (error %d)\n",
               ramdisk_execute_command, ret);
    }
    
    // 添加默认返回值，防止编译器警告
    return -1;
}

	/*
	 * We try each of these until one succeeds.
	 *
	 * The Bourne shell can be used instead of init if we are
	 * trying to recover a really broken machine.
	 */
	/*
	* 我们依次尝试这些命令，直到有一个成功为止。
	*
	* 如果我们正在尝试恢复一台严重损坏的机器，可以使用 Bourne shell 代替 init。
	*/
	if (execute_command) {
		// 如果有指定执行的命令，尝试运行它
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;
		// 如果命令执行失败，打印错误信息并尝试默认的 init 进程
		pr_err("Failed to execute %s (error %d).  Attempting defaults...\n",
			execute_command, ret);
	}

	// 依次尝试运行默认的 init 进程，如果有一个成功则返回 0
	if (!try_to_run_init_process("/sbin/init") ||
		!try_to_run_init_process("/etc/init") ||
		!try_to_run_init_process("/bin/init") ||
		!try_to_run_init_process("/bin/sh"))
		return 0;

	// 如果所有 init 进程都无法运行，触发 panic 并提示用户传递 init= 选项
	panic("No working init found.  Try passing init= option to kernel. "
		"See Linux Documentation/init.txt for guidance.");
}

static noinline void __init kernel_init_freeable(void)
{
	/*
	 * Wait until kthreadd is all set-up.
	 */
	 /*
     * 等待 kthreadd 完全设置好。
     */
	wait_for_completion(&kthreadd_done);

	/* Now the scheduler is fully set up and can do blocking allocations */
	/* 现在调度程序已完全设置，可以进行阻塞分配 */
	gfp_allowed_mask = __GFP_BITS_MASK;

	/*
	 * init can allocate pages on any node
	 */
	/*
     * init 可以在任何节点上分配页面
     */
	set_mems_allowed(node_states[N_MEMORY]);
	/*
	 * init can run on any cpu.
	 */
	/*
     * init 可以在任何 CPU 上运行。
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
	/* 在 rootfs 上打开 /dev/console，这不应该失败 */
	if (sys_open((const char __user *) "/dev/console", O_RDWR, 0) < 0)
		pr_err("Warning: unable to open an initial console.\n");

	(void) sys_dup(0);
	(void) sys_dup(0);
	/*
	 * check if there is an early userspace init.  If yes, let it do all
	 * the work
	 */
	 /*
     * 检查是否存在早期用户空间的 init。如果有，让它处理所有工作
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
     * 好的，我们已经完成了初始引导，并且
     * 我们基本上已经启动并运行了。清理 initmem 段并启动用户模式的工作。
     */
	/* rootfs is available now, try loading default modules */
	load_default_modules();
}
