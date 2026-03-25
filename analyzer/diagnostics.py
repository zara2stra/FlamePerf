"""
Diagnostic analysis engine for perf profiling data.

Two layers:
  1. Generic Linux analysis (hot functions, kernel/user split, idle detection)
  2. Nutanix CVM-aware analysis (service-level insights, known patterns)
"""

SEVERITY_INFO = 'info'
SEVERITY_WARNING = 'warning'
SEVERITY_CRITICAL = 'critical'

NUTANIX_SERVICES = {
    'stargate':   'I/O path service (data read/write)',
    'cassandra':  'Metadata store (Medusa ring)',
    'curator':    'Background data management (compression, dedup, ILM, scrub)',
    'chronos':    'Job scheduler and admission control for Curator tasks',
    'cerebro':    'Replication and DR manager',
    'acropolis':  'VM management service (AHV)',
    'genesis':    'Cluster bootstrap and service lifecycle manager',
    'prism':      'Web console and API gateway',
    'zookeeper':  'Distributed coordination service',
    'vhost':      'Virtio host backend for VM I/O',
    'qemu':       'VM hypervisor process',
    'nfs_server': 'NFS datastore handler',
}

# perf reports Linux thread names (max 15 chars), not process names.
# Order matters: first match wins.
THREAD_TO_SERVICE = [
    # Stargate threads
    ('control_',        'stargate'),
    ('epoll_',          'stargate'),
    ('oplog_disk_',     'stargate'),
    ('ssd_aio',         'stargate'),
    ('ssd_aio_reaper',  'stargate'),
    ('PaxosScan',       'stargate'),
    ('PaxosLeader',     'stargate'),
    ('PaxosReplica',    'stargate'),
    ('HTTP_PROTO_STAG', 'stargate'),
    ('Incoming_TCP_',   'stargate'),
    ('WRITE-/',         'stargate'),
    ('READ-/',          'stargate'),
    ('RequestResponse', 'stargate'),
    ('Stats',           'stargate'),
    ('Pithos',          'stargate'),
    ('nfs_',            'stargate'),
    ('iscsi_',          'stargate'),
    ('stargate',        'stargate'),
    ('admctl_',         'stargate'),
    ('extent_',         'stargate'),
    ('vdisk_',          'stargate'),
    ('rangemap_',       'stargate'),

    # Cassandra / Medusa threads
    ('medusa_',         'cassandra'),
    ('cass_epd',        'cassandra'),
    ('CompactionExe',   'cassandra'),
    ('MemtableFlu',     'cassandra'),
    ('ReadStage',       'cassandra'),
    ('MutationStage',   'cassandra'),
    ('GossipStage',     'cassandra'),
    ('AntiEntropy',     'cassandra'),
    ('HintedHandoff',   'cassandra'),

    # Curator threads
    ('CurMR',           'curator'),
    ('CurFg',           'curator'),
    ('CurBg',           'curator'),
    ('curator',         'curator'),

    # Cerebro
    ('cerebro',         'cerebro'),

    # Chronos
    ('chronos',         'chronos'),

    # Genesis and monitors (must be before generic 'cassandra'/'stargate' matches)
    ('genesis',         'genesis'),
    ('zookeeper_monit', 'genesis'),
    ('cassandra_monit', 'genesis'),
    ('stargate_monit',  'genesis'),
    ('curator_monit',   'genesis'),
    ('cerebro_monit',   'genesis'),

    # Generic cassandra match (after monitors)
    ('cassandra',       'cassandra'),

    # Prism / Arithmos / Insights
    ('arithmos',        'prism'),
    ('insights_server', 'prism'),
    ('prism',           'prism'),
    ('http-nio-',       'prism'),
    ('C2_CompilerThre', 'prism'),
    ('C1_CompilerThre', 'prism'),

    # Acropolis
    ('acropolis',       'acropolis'),

    # Zookeeper
    ('zookeeper',       'zookeeper'),

    # VM I/O
    ('vhost',           'vhost'),
    ('qemu',            'qemu'),
]

LOCK_CONTENTION_SYMBOLS = [
    'futex_wait', '__lll_lock_wait', 'pthread_mutex_lock',
    'pthread_cond_wait', 'pthread_rwlock', '__GI___lll_lock_wait',
    'LockSlow', 'mutex_lock', 'rwsem_down',
    'sema_wait', 'sem_wait',
]

IO_WAIT_SYMBOLS = [
    'io_schedule', 'wait_on_page', 'blk_mq_run_hw_queue',
    'submit_bio', 'generic_file_read_iter', 'do_blockdev_direct_IO',
    'nvme_queue_rq', 'scsi_dispatch_cmd',
]

IRQ_SYMBOLS = [
    'do_IRQ', 'irq_handler', '__do_softirq', 'net_rx_action',
    'tasklet_action', 'irq_exit',
]

NUMA_SYMBOLS = [
    'numa_migrate', 'migrate_pages', 'do_numa_page',
    'task_numa_fault', 'numamigrate_isolate_page',
]

IDLE_SYMBOLS = [
    'cpu_idle', 'default_idle', 'native_safe_halt',
    'intel_idle', 'mwait_idle', 'poll_idle',
    'cpuidle_enter', 'acpi_idle',
]

SCHEDULER_SYMBOLS = [
    'schedule', '__schedule', 'dequeue_task', 'enqueue_task',
    'pick_next_task', 'context_switch', '__switch_to',
    'finish_task_switch',
]

OVERHEAD_PROCESSES = [
    'perf', 'python', 'python3', 'python3.9', 'python3.10', 'python3.11',
    'grep', 'find', 'awk', 'sed', 'xargs', 'bash', 'sh',
    'top', 'htop', 'vmstat', 'iostat', 'sar', 'dstat', 'mpstat',
    'pidstat', 'nmon', 'collectd', 'telegraf', 'node_exporter',
]

STACK_PATTERNS = {
    'protobuf_serialization': {
        'markers': ['protobuf', 'Serialize', 'SerializeToString', 'ParseFrom',
                    'MergeFrom', 'SerializePartialToCodedStream',
                    'google::protobuf', 'InternalSerialize', 'ByteSizeLong'],
        'threshold': 5.0,
        'severity': SEVERITY_WARNING,
        'title': 'Protobuf serialization hotspot ({pct:.1f}% of active CPU)',
        'detail': 'Significant CPU is spent in protobuf serialization/deserialization. '
                  'This is common when services exchange large messages frequently.',
        'recommendation': 'Consider batching RPC calls to reduce per-message overhead, '
                          'using Arena allocation for protobuf messages, or reducing message size '
                          'by filtering unnecessary fields before serialization.',
        'category': 'code_pattern',
    },
    'sched_yield_spin': {
        'markers': ['sched_yield', 'sys_sched_yield', 'do_sched_yield'],
        'threshold': 2.0,
        'severity': SEVERITY_WARNING,
        'title': 'sched_yield spin loop detected ({pct:.1f}% of active CPU)',
        'detail': 'Threads are actively yielding CPU in a spin loop. '
                  'This is a busy-wait anti-pattern where threads poll instead of blocking.',
        'recommendation': 'Replace spin-wait loops with proper synchronization primitives '
                          '(condition variables, eventfd, epoll). If this is in Nutanix code, '
                          'check for tight polling loops in RPC or task queues.',
        'category': 'code_pattern',
    },
    'page_faults': {
        'markers': ['do_page_fault', 'handle_mm_fault', '__do_page_fault',
                    'do_wp_page', 'do_anonymous_page', 'handle_pte_fault'],
        'threshold': 3.0,
        'severity': SEVERITY_WARNING,
        'title': 'Significant page fault overhead ({pct:.1f}% of active CPU)',
        'detail': 'The kernel is spending notable CPU handling page faults. '
                  'This may indicate frequent memory allocation/deallocation or mmap churn.',
        'recommendation': 'Consider enabling Transparent Huge Pages (THP) if disabled, '
                          'pre-faulting memory at startup with madvise(MADV_WILLNEED), '
                          'or using memory pools to reduce allocation frequency. '
                          'Check if services are mmapping/munmapping files frequently.',
        'category': 'memory',
    },
    'memory_allocation': {
        'markers': ['__alloc_pages', 'kmalloc', 'kfree', '__kmalloc', 'slab_alloc',
                    'slab_free', 'malloc', 'free', 'tc_malloc', 'tcmalloc',
                    'jemalloc', '__libc_malloc', '__libc_free', 'mmap_region'],
        'threshold': 3.0,
        'severity': SEVERITY_WARNING,
        'title': 'Memory allocation pressure ({pct:.1f}% of active CPU)',
        'detail': 'Substantial CPU time is spent in memory allocation or deallocation paths. '
                  'Frequent small allocations cause allocator contention.',
        'recommendation': 'Profile memory allocation patterns with tools like tcmalloc heap profiler. '
                          'Use object pools or arena allocation for frequently allocated objects. '
                          'Consider switching to tcmalloc or jemalloc if using glibc malloc.',
        'category': 'memory',
    },
    'epoll_churn': {
        'markers': ['sys_epoll_wait', 'ep_poll', 'eventpoll', 'sys_epoll_ctl',
                    'ep_insert', 'ep_remove'],
        'threshold': 2.0,
        'severity': SEVERITY_INFO,
        'title': 'Epoll activity overhead ({pct:.1f}% of active CPU)',
        'detail': 'Noticeable CPU in epoll event loop management. '
                  'This is expected for event-driven I/O services but may indicate '
                  'excessive file descriptor churn if combined with epoll_ctl calls.',
        'recommendation': 'Ensure connections are long-lived rather than frequently created/destroyed. '
                          'Reduce wakeup frequency by batching events. '
                          'If using level-triggered epoll, consider switching to edge-triggered.',
        'category': 'code_pattern',
    },
    'netfilter': {
        'markers': ['nf_hook', 'iptable', 'nf_iterate', 'nf_conntrack',
                    'nft_do_chain', 'ipt_do_table', 'nf_nat'],
        'threshold': 2.0,
        'severity': SEVERITY_WARNING,
        'title': 'Netfilter/iptables overhead ({pct:.1f}% of active CPU)',
        'detail': 'Network filtering (iptables/nftables) is consuming notable CPU. '
                  'This may indicate a large firewall ruleset or heavy connection tracking.',
        'recommendation': 'Audit iptables rules with "iptables -L -v -n | wc -l" to check rule count. '
                          'Consider using ipset for large allow/deny lists. '
                          'Reduce conntrack table pressure with shorter timeouts for inactive connections.',
        'category': 'network',
    },
    'copy_overhead': {
        'markers': ['copy_user_generic', 'copy_to_user', 'copy_from_user',
                    '_copy_to_user', '_copy_from_user', 'memcpy', '__memcpy',
                    'copy_page'],
        'threshold': 5.0,
        'severity': SEVERITY_WARNING,
        'title': 'Data copy overhead ({pct:.1f}% of active CPU)',
        'detail': 'Significant CPU time is spent copying data between kernel and user space '
                  'or in general memory copies.',
        'recommendation': 'Consider zero-copy I/O techniques (splice, sendfile, io_uring). '
                          'Check if read/write buffer sizes are optimal. '
                          'Large memcpy overhead may indicate inefficient data structures or '
                          'unnecessary data marshalling between layers.',
        'category': 'code_pattern',
    },
    'tlb_overhead': {
        'markers': ['flush_tlb', 'native_flush_tlb', '__flush_tlb_one',
                    'tlb_flush', 'flush_tlb_mm_range'],
        'threshold': 1.5,
        'severity': SEVERITY_WARNING,
        'title': 'TLB flush overhead ({pct:.1f}% of active CPU)',
        'detail': 'CPU time is being spent flushing TLBs. '
                  'This can indicate excessive mmap/munmap operations or process churn.',
        'recommendation': 'Enable Transparent Huge Pages to reduce TLB pressure. '
                          'Reduce process creation/destruction frequency. '
                          'Consider using PCID if the kernel supports it.',
        'category': 'memory',
    },
}


def run_diagnostics(parsed_data, metadata=None):
    """
    Run full diagnostic analysis.

    Args:
        parsed_data: output from parser.parse_and_process()
        metadata: optional dict from metadata.json in the bundle

    Returns: {
        'findings': [{
            'severity': str, 'title': str, 'detail': str,
            'category': str, 'recommendation': str
        }, ...],
        'service_breakdown': [...],
        'active_service_breakdown': [...],
        'summary': str,
    }
    """
    findings = []
    samples = parsed_data['samples']
    folded = parsed_data['folded']
    total = parsed_data['total_samples'] or 1
    process_breakdown = parsed_data['process_breakdown']
    kernel_user_split = parsed_data['kernel_user_split']
    active_samples = parsed_data.get('active_samples', total)
    active_pct = parsed_data.get('active_pct', 100.0)
    idle_pct = parsed_data.get('idle_pct', 0.0)
    active_process_breakdown = parsed_data.get('active_process_breakdown', process_breakdown)

    findings.extend(_check_idle_ratio(idle_pct))
    findings.extend(_check_kernel_user_ratio(kernel_user_split))
    findings.extend(_check_lock_contention(samples, total, active_samples))
    findings.extend(_check_io_wait(samples, total, active_samples))
    findings.extend(_check_irq_load(samples, total, active_samples))
    findings.extend(_check_numa_issues(samples, total, active_samples))
    findings.extend(_check_scheduler_overhead(samples, total, active_samples))

    service_breakdown = _nutanix_service_breakdown(process_breakdown, total)
    active_service_breakdown = _nutanix_service_breakdown(
        active_process_breakdown, active_samples)
    findings.extend(_nutanix_service_findings(active_service_breakdown, active_samples))
    findings.extend(_check_top_function_dominance(parsed_data['top_functions'], total))

    findings.extend(_check_collection_overhead(active_process_breakdown, active_samples))
    findings.extend(_check_stack_patterns(samples, active_samples))

    if metadata and metadata.get('system_context'):
        findings.extend(_check_system_context(metadata['system_context']))

    findings.sort(key=lambda f: {
        SEVERITY_CRITICAL: 0, SEVERITY_WARNING: 1, SEVERITY_INFO: 2
    }[f['severity']])

    summary = _build_summary(total, active_samples, idle_pct,
                             kernel_user_split, active_service_breakdown, findings)

    return {
        'findings': findings,
        'service_breakdown': service_breakdown,
        'active_service_breakdown': active_service_breakdown,
        'summary': summary,
    }


def _count_samples_matching(samples, symbol_list):
    count = 0
    for s in samples:
        for frame in s['frames']:
            if any(sym in frame for sym in symbol_list):
                count += 1
                break
    return count


def _finding(severity, title, detail, category, recommendation=''):
    return {
        'severity': severity,
        'title': title,
        'detail': detail,
        'category': category,
        'recommendation': recommendation,
    }


def _check_idle_ratio(idle_pct):
    findings = []
    if idle_pct > 80:
        findings.append(_finding(
            SEVERITY_INFO,
            f'System mostly idle ({idle_pct:.1f}% idle)',
            'The system appears to be largely idle during the profiling window. '
            'The performance issue may be intermittent or not active during capture.',
            'general',
            'Try capturing during peak load or when the issue is actively occurring. '
            'Use a longer capture window if the workload is bursty.',
        ))
    elif idle_pct > 50:
        findings.append(_finding(
            SEVERITY_INFO,
            f'Moderate idle time ({idle_pct:.1f}% idle)',
            'About half the CPU time is idle. The active workload is using the remaining capacity. '
            'Switch to "Active CPU" view to focus on what is actually consuming CPU.',
            'general',
            'Use the "Active CPU" toggle to see the true workload distribution '
            'without idle dilution.',
        ))
    return findings


def _check_kernel_user_ratio(ku_split):
    findings = []
    kpct = ku_split['kernel_pct']
    if kpct > 70:
        findings.append(_finding(
            SEVERITY_WARNING,
            f'High kernel CPU usage ({kpct:.1f}%)',
            'Most CPU time is spent in kernel space. This often indicates heavy syscall activity, '
            'I/O processing, or interrupt handling.',
            'general',
            'Check for: (1) excessive context switches (vmstat cs column), '
            '(2) I/O storms (iostat -x), (3) network interrupt storms. '
            'Look at the flamegraph kernel stacks (green bars) to identify specific syscalls.',
        ))
    elif kpct > 50:
        findings.append(_finding(
            SEVERITY_INFO,
            f'Elevated kernel CPU usage ({kpct:.1f}%)',
            'A significant portion of CPU is in kernel mode. '
            'This is common on storage-heavy workloads but worth investigating if unexpected.',
            'general',
            'Run "perf stat -d" for hardware counter breakdown if available. '
            'Check "vmstat 1" for context switch rate.',
        ))
    return findings


def _check_lock_contention(samples, total, active_samples):
    findings = []
    lock_count = _count_samples_matching(samples, LOCK_CONTENTION_SYMBOLS)
    active_total = active_samples or 1
    pct = 100.0 * lock_count / active_total

    if pct > 10:
        findings.append(_finding(
            SEVERITY_CRITICAL,
            f'Significant lock contention ({pct:.1f}% of active CPU)',
            'Threads are spending substantial time waiting on locks (futex/mutex). '
            'This is a concurrency bottleneck.',
            'contention',
            'In the flamegraph, search for "futex" or "mutex" to identify which code paths '
            'are blocked. Common causes: (1) single global mutex protecting a shared data structure, '
            '(2) too many threads competing for the same lock, '
            '(3) lock held during slow I/O operations. '
            'Consider lock-free data structures or finer-grained locking.',
        ))
    elif pct > 3:
        findings.append(_finding(
            SEVERITY_WARNING,
            f'Lock contention detected ({pct:.1f}% of active CPU)',
            'Some threads are blocked on locks.',
            'contention',
            'Search the flamegraph for "futex" or "mutex" to see which mutexes are hot. '
            'If correlating with latency spikes, reduce lock scope or use reader-writer locks.',
        ))
    return findings


def _check_io_wait(samples, total, active_samples):
    findings = []
    io_count = _count_samples_matching(samples, IO_WAIT_SYMBOLS)
    active_total = active_samples or 1
    pct = 100.0 * io_count / active_total

    if pct > 15:
        findings.append(_finding(
            SEVERITY_CRITICAL,
            f'Heavy I/O wait ({pct:.1f}% of active CPU)',
            'A large fraction of active CPU is in I/O submission or wait paths. '
            'Storage or network I/O is a major bottleneck.',
            'io',
            'Run "iostat -x 1 5" to check disk utilization and latency. '
            'Key metrics: await (avg I/O latency), %util (disk busy time). '
            'If await > 10ms on SSDs, check for: (1) failing drives, '
            '(2) write-ahead log (oplog) pressure, (3) metadata disk bottleneck.',
        ))
    elif pct > 5:
        findings.append(_finding(
            SEVERITY_WARNING,
            f'I/O wait activity ({pct:.1f}% of active CPU)',
            'Noticeable I/O-related CPU usage.',
            'io',
            'Monitor disk latency with "iostat -x 1" and check for slow drives. '
            'On Nutanix, check Prism > Hardware for disk health status.',
        ))
    return findings


def _check_irq_load(samples, total, active_samples):
    findings = []
    irq_count = _count_samples_matching(samples, IRQ_SYMBOLS)
    active_total = active_samples or 1
    pct = 100.0 * irq_count / active_total

    if pct > 15:
        findings.append(_finding(
            SEVERITY_WARNING,
            f'High interrupt/softirq load ({pct:.1f}% of active CPU)',
            'Significant CPU time consumed by interrupt handling.',
            'interrupts',
            'Check "cat /proc/interrupts" for interrupt distribution across CPUs. '
            'Use "mpstat -P ALL 1" to see if IRQs are concentrated on a few cores. '
            'Consider IRQ affinity tuning with irqbalance or manual SMP affinity.',
        ))
    elif pct > 5:
        findings.append(_finding(
            SEVERITY_INFO,
            f'Notable interrupt activity ({pct:.1f}% of active CPU)',
            'Interrupt handling is visible in the profile. Normal for I/O-heavy workloads.',
            'interrupts',
        ))
    return findings


def _check_numa_issues(samples, total, active_samples):
    findings = []
    numa_count = _count_samples_matching(samples, NUMA_SYMBOLS)
    active_total = active_samples or 1
    pct = 100.0 * numa_count / active_total

    if pct > 3:
        findings.append(_finding(
            SEVERITY_WARNING,
            f'NUMA migration activity ({pct:.1f}% of active CPU)',
            'The kernel is migrating pages between NUMA nodes, causing latency spikes.',
            'numa',
            'Verify CVM NUMA pinning: "numactl --show" should show a single node. '
            'Check "numastat -c" for cross-node memory access. '
            'On AHV: ensure CVM vCPUs and memory are pinned to the correct NUMA node '
            'via "virsh numatune" and "virsh vcpupin".',
        ))
    elif pct > 0.5:
        findings.append(_finding(
            SEVERITY_INFO,
            f'Minor NUMA activity ({pct:.1f}% of active CPU)',
            'Some NUMA-related kernel activity. Usually benign unless on a dual-socket server.',
            'numa',
        ))
    return findings


def _check_scheduler_overhead(samples, total, active_samples):
    findings = []
    sched_count = _count_samples_matching(samples, SCHEDULER_SYMBOLS)
    active_total = active_samples or 1
    pct = 100.0 * sched_count / active_total

    if pct > 20:
        findings.append(_finding(
            SEVERITY_WARNING,
            f'High scheduler overhead ({pct:.1f}% of active CPU)',
            'The CPU scheduler is consuming significant CPU. '
            'Too many runnable threads are competing for CPU, '
            'or the CVM is experiencing CPU steal time.',
            'scheduler',
            'Check "vmstat 1" for high context switch rates (cs column). '
            'Check "cat /proc/stat | grep cpu" for steal time (st). '
            'If steal > 5%, the hypervisor is overcommitting CPU. '
            'Consider reducing CVM thread counts or increasing vCPU allocation.',
        ))
    return findings


def _check_top_function_dominance(top_functions, total):
    findings = []
    if not top_functions:
        return findings

    top = top_functions[0]
    is_idle = any(sym in top['function'] for sym in IDLE_SYMBOLS)
    if top['pct'] > 30 and not is_idle:
        findings.append(_finding(
            SEVERITY_WARNING,
            f'Single function dominates CPU: {top["function"]} ({top["pct"]:.1f}%)',
            f'The function "{top["function"]}" accounts for {top["pct"]:.1f}% of all samples. '
            'This is a strong optimization target.',
            'hotspot',
            'Click on this function in the flamegraph to see its full call chain. '
            'Determine if the time is spent in the function itself (self time) '
            'or propagated from callees. Check if this is a known library function '
            'that could be replaced with a more efficient alternative.',
        ))
    return findings


def _check_collection_overhead(active_breakdown, active_samples):
    """Detect if perf collection or monitoring tools are consuming significant CPU."""
    findings = []
    active_total = active_samples or 1
    overhead_samples = 0
    overhead_procs = []

    for proc in active_breakdown:
        name_lower = proc['name'].lower()
        is_overhead = any(
            name_lower == oh or name_lower.startswith(oh)
            for oh in OVERHEAD_PROCESSES
        )
        if is_overhead:
            overhead_samples += proc['samples']
            if proc['pct'] >= 0.5:
                overhead_procs.append(f"{proc['name']} ({proc['pct']:.1f}%)")

    overhead_pct = 100.0 * overhead_samples / active_total
    if overhead_pct > 10:
        procs_str = ', '.join(overhead_procs[:5])
        findings.append(_finding(
            SEVERITY_WARNING,
            f'Collection/monitoring overhead: {overhead_pct:.1f}% of active CPU',
            f'Profiling and monitoring tools are consuming notable CPU: {procs_str}. '
            'This inflates the active CPU picture and may affect workload behavior.',
            'overhead',
            'The overhead comes from the perf collector and any concurrent monitoring. '
            'For production profiling, use a lower frequency (e.g., --freq 49) '
            'to reduce overhead. Consider stopping monitoring agents (top, collectd) '
            'during perf capture if precise measurements are needed.',
        ))
    elif overhead_pct > 3:
        procs_str = ', '.join(overhead_procs[:5])
        findings.append(_finding(
            SEVERITY_INFO,
            f'Minor collection overhead: {overhead_pct:.1f}% of active CPU',
            f'Profiling tools visible in trace: {procs_str}.',
            'overhead',
            'This is normal. Overhead is low enough to not significantly '
            'distort the profiling results.',
        ))
    return findings


def _check_stack_patterns(samples, active_samples):
    """Scan call stacks for known performance anti-patterns."""
    findings = []
    active_total = active_samples or 1

    for pattern_name, pattern in STACK_PATTERNS.items():
        match_count = _count_samples_matching(samples, pattern['markers'])
        pct = 100.0 * match_count / active_total

        if pct >= pattern['threshold']:
            findings.append(_finding(
                pattern['severity'],
                pattern['title'].format(pct=pct),
                pattern['detail'],
                pattern.get('category', 'code_pattern'),
                pattern.get('recommendation', ''),
            ))
    return findings


def _check_system_context(ctx):
    """Generate findings from top_snapshot system context data."""
    findings = []

    load_1 = ctx.get('load_avg_1')
    load_5 = ctx.get('load_avg_5')
    load_15 = ctx.get('load_avg_15')

    if load_1 is not None and load_5 is not None:
        if load_1 > 2 * load_5:
            findings.append(_finding(
                SEVERITY_WARNING,
                f'Load average spiking: {load_1:.1f} (1m) vs {load_5:.1f} (5m)',
                'The 1-minute load average is significantly higher than the 5-minute average, '
                'indicating a load spike during or just before capture.',
                'system',
                'This spike may be causing the performance issue. '
                'Capture correlating data: "dmesg -T | tail -50", "vmstat 1 10".',
            ))

    cpu_wa = ctx.get('cpu_wa', 0)
    if cpu_wa > 10:
        findings.append(_finding(
            SEVERITY_WARNING,
            f'High I/O wait: {cpu_wa:.1f}% (from top snapshot)',
            'The system is spending significant time waiting for I/O to complete.',
            'system',
            'Run "iostat -x 1 5" to identify which disk(s) are slow. '
            'Check "dmesg" for disk errors.',
        ))

    cpu_st = ctx.get('cpu_st', 0)
    if cpu_st > 3:
        findings.append(_finding(
            SEVERITY_CRITICAL if cpu_st > 10 else SEVERITY_WARNING,
            f'CPU steal time: {cpu_st:.1f}%',
            'The hypervisor is reclaiming CPU from this VM. '
            'The CVM is not getting the CPU it expects.',
            'system',
            'This is a host-level issue. Check: (1) host CPU overcommitment ratio, '
            '(2) other VMs on the same host consuming excessive CPU, '
            '(3) AHV host "top" for total CPU usage. '
            'Consider reducing VM density on this host or increasing CVM vCPU reservation.',
        ))

    mem_total = ctx.get('mem_total_kb', 0)
    mem_avail = ctx.get('mem_avail_kb', 0)
    if mem_total > 0 and mem_avail > 0:
        mem_used_pct = 100.0 * (1 - mem_avail / mem_total)
        if mem_used_pct > 95:
            findings.append(_finding(
                SEVERITY_CRITICAL,
                f'Memory pressure: {mem_used_pct:.0f}% used ({mem_avail // 1024}MB available)',
                'Almost all memory is consumed. The system may be swapping, '
                'which causes severe performance degradation.',
                'system',
                'Check "free -h" and "cat /proc/meminfo | grep Swap". '
                'If swap is active, identify the largest memory consumers with '
                '"ps aux --sort=-%mem | head -20". '
                'Consider increasing CVM memory allocation.',
            ))
        elif mem_used_pct > 85:
            findings.append(_finding(
                SEVERITY_WARNING,
                f'Elevated memory usage: {mem_used_pct:.0f}% ({mem_avail // 1024}MB available)',
                'Memory is mostly consumed. Not critical yet, but leaves little headroom.',
                'system',
                'Monitor memory trends. If this is a new pattern, '
                'check for memory leaks with "pmap -x <PID>".',
            ))

    return findings


def _classify_thread(comm_name):
    for prefix, service in THREAD_TO_SERVICE:
        if comm_name.startswith(prefix) or prefix in comm_name:
            return service
    return None


def _nutanix_service_breakdown(process_breakdown, total):
    service_samples = {}
    thread_detail = {}
    unmatched = []

    for proc in process_breakdown:
        svc = _classify_thread(proc['name'])
        if svc:
            if svc not in service_samples:
                service_samples[svc] = 0
                thread_detail[svc] = []
            service_samples[svc] += proc['samples']
            thread_detail[svc].append(proc['name'])
        else:
            unmatched.append(proc)

    service_list = []
    for svc_name, samples_count in sorted(service_samples.items(), key=lambda x: -x[1]):
        desc = NUTANIX_SERVICES.get(svc_name, svc_name)
        threads = thread_detail[svc_name]
        thread_str = ', '.join(sorted(set(threads))[:8])
        if len(set(threads)) > 8:
            thread_str += f' (+{len(set(threads)) - 8} more)'
        pct = round(100.0 * samples_count / total, 2) if total else 0
        service_list.append({
            'name': svc_name,
            'process': thread_str,
            'pid': 0,
            'samples': samples_count,
            'pct': pct,
            'description': desc,
        })

    for proc in unmatched:
        service_list.append({
            'name': proc['name'],
            'process': proc['name'],
            'pid': proc['pid'],
            'samples': proc['samples'],
            'pct': proc['pct'],
            'description': '',
        })

    service_list.sort(key=lambda x: x['samples'], reverse=True)
    return service_list


def _nutanix_service_findings(service_breakdown, active_samples):
    """Generate findings based on active-CPU percentages."""
    findings = []
    svc_map = {s['name']: s for s in service_breakdown}

    sg = svc_map.get('stargate')
    if sg and sg['pct'] > 35:
        findings.append(_finding(
            SEVERITY_WARNING if sg['pct'] > 50 else SEVERITY_INFO,
            f'Stargate consuming {sg["pct"]:.1f}% of active CPU',
            f'Stargate (I/O path) is a major CPU consumer. '
            f'Threads: {sg["process"]}.',
            'nutanix',
            'Check Prism > Analysis for IOPS and latency trends. '
            'If IOPS are normal but CPU is high, look for: '
            '(1) extent store fragmentation, (2) metadata overhead, '
            '(3) oplog drain pressure. Run "nodetool status" to check '
            'Cassandra health which affects Stargate metadata ops.',
        ))

    cs = svc_map.get('cassandra')
    if cs and cs['pct'] > 15:
        findings.append(_finding(
            SEVERITY_WARNING if cs['pct'] > 25 else SEVERITY_INFO,
            f'Cassandra/Medusa consuming {cs["pct"]:.1f}% of active CPU',
            f'Metadata store is actively using CPU. Threads: {cs["process"]}.',
            'nutanix',
            'Check for: (1) compaction activity with "nodetool compactionstats", '
            '(2) ring status with "nodetool ring", '
            '(3) large CFs with "nodetool cfstats | grep -A5 \'Table:\'". '
            'If CompactionExe threads are dominant, a major compaction is in progress.',
        ))

    cu = svc_map.get('curator')
    if cu and cu['pct'] > 8:
        findings.append(_finding(
            SEVERITY_WARNING if cu['pct'] > 20 else SEVERITY_INFO,
            f'Curator consuming {cu["pct"]:.1f}% of active CPU',
            f'Curator background tasks running. Threads: {cu["process"]}.',
            'nutanix',
            'Check Curator status: "links http://0:2010/h/tasks" to see active tasks. '
            'If a full scan is running and impacting foreground I/O, consider '
            'throttling with "curator_cli throttle_curator --throttle_percent=50".',
        ))

    for vname in ('vhost', 'qemu'):
        v = svc_map.get(vname)
        if v and v['pct'] > 20:
            findings.append(_finding(
                SEVERITY_WARNING,
                f'VM I/O backend ({vname}) consuming {v["pct"]:.1f}% of active CPU',
                'vhost/QEMU threads handling VM I/O are using significant CPU.',
                'nutanix',
                'Identify which VM(s) are generating heavy I/O: '
                '"virsh list --all" then check per-VM stats in Prism. '
                'Consider storage tiering or QoS limits for noisy-neighbor VMs.',
            ))

    cb = svc_map.get('cerebro')
    if cb and cb['pct'] > 8:
        findings.append(_finding(
            SEVERITY_INFO,
            f'Cerebro (replication) consuming {cb["pct"]:.1f}% of active CPU',
            'Cerebro is actively replicating data.',
            'nutanix',
            'Check active protection domain replications in Prism > Data Protection. '
            'If replication is unexpected, check for DR schedule conflicts.',
        ))

    gn = svc_map.get('genesis')
    if gn and gn['pct'] > 8:
        findings.append(_finding(
            SEVERITY_WARNING if gn['pct'] > 15 else SEVERITY_INFO,
            f'Genesis consuming {gn["pct"]:.1f}% of active CPU',
            'Genesis (service manager) is using more CPU than typical.',
            'nutanix',
            'Check "genesis status" for service state. '
            'High Genesis CPU often means services are restarting. '
            'Check /home/nutanix/data/logs/genesis.out for crash loops.',
        ))

    pr = svc_map.get('prism')
    if pr and pr['pct'] > 15:
        findings.append(_finding(
            SEVERITY_INFO,
            f'Prism/Arithmos consuming {pr["pct"]:.1f}% of active CPU',
            'Prism web console and analytics services are using notable CPU.',
            'nutanix',
            'Check if heavy API automation is hitting Prism. '
            'Review /home/nutanix/data/logs/prism_gateway.log for high-rate callers.',
        ))

    return findings


def _build_summary(total, active_samples, idle_pct, kernel_user_split,
                   active_service_breakdown, findings):
    critical = sum(1 for f in findings if f['severity'] == SEVERITY_CRITICAL)
    warnings = sum(1 for f in findings if f['severity'] == SEVERITY_WARNING)

    top_active = active_service_breakdown[0] if active_service_breakdown else None
    top_str = f'{top_active["name"]} ({top_active["pct"]:.1f}%)' if top_active else 'N/A'

    parts = [
        f'Analyzed {total} samples ({active_samples} active, {idle_pct:.0f}% idle).',
        f'Kernel/User: {kernel_user_split["kernel_pct"]:.0f}%/{kernel_user_split["user_pct"]:.0f}%.',
        f'Top active consumer: {top_str}.',
    ]

    if critical > 0:
        parts.append(f'{critical} critical finding(s).')
    if warnings > 0:
        parts.append(f'{warnings} warning(s).')
    if critical == 0 and warnings == 0:
        parts.append('No significant issues detected.')

    return ' '.join(parts)
