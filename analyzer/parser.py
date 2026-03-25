"""
Pure Python parser for `perf script` text output.

Converts perf script output -> folded stacks -> d3-flame-graph hierarchical JSON.
No Perl or external FlameGraph tools required.
"""

import re
from collections import defaultdict


# Matches the header line of each sample block from `perf script` output.
# Example: "  stargate 12345 [003] 12345.678: cpu-clock:  ffffffff810..."
#      or: "  swapper     0 [000]  1234.567890:     cycles: ..."
_HEADER_RE = re.compile(
    r'^\s*(?P<comm>.+?)\s+(?P<pid>\d+)(?:/(?P<tid>\d+))?\s+'
    r'\[(?P<cpu>\d+)\]\s+'
    r'(?:(?P<time>\d+\.\d+):\s+)?'
    r'(?P<period>\d+\s+)?'
    r'(?P<event>[\w:-]+)'
)

_FRAME_RE = re.compile(
    r'^\s+(?P<addr>[0-9a-fA-F]+)\s+(?P<sym>.+?)\s+\((?P<dso>.+)\)\s*$'
)


def parse_perf_script(text):
    """
    Parse raw `perf script` text into a list of samples.

    Each sample is a dict:
      {
        'comm': str,       # process name
        'pid': int,
        'tid': int or None,
        'event': str,
        'frames': [str],   # stack frames, caller first (bottom-up)
      }
    """
    samples = []
    current_sample = None
    current_frames = []

    for line in text.splitlines():
        if not line.strip():
            if current_sample is not None:
                current_sample['frames'] = list(reversed(current_frames))
                samples.append(current_sample)
                current_sample = None
                current_frames = []
            continue

        frame_match = _FRAME_RE.match(line)
        if frame_match and current_sample is not None:
            sym = frame_match.group('sym')
            dso = frame_match.group('dso')
            sym = _tidy_symbol(sym, dso)
            current_frames.append(sym)
            continue

        header_match = _HEADER_RE.match(line)
        if header_match:
            if current_sample is not None:
                current_sample['frames'] = list(reversed(current_frames))
                samples.append(current_sample)
                current_frames = []

            comm = header_match.group('comm').replace(' ', '_')
            current_sample = {
                'comm': comm,
                'pid': int(header_match.group('pid')),
                'tid': int(header_match.group('tid')) if header_match.group('tid') else None,
                'event': header_match.group('event'),
                'frames': [],
            }

    if current_sample is not None:
        current_sample['frames'] = list(reversed(current_frames))
        samples.append(current_sample)

    return samples


def _tidy_symbol(sym, dso):
    """Clean up symbol names, preserving DSO when the symbol itself is unknown."""
    is_unknown = sym is None or sym == '[unknown]' or sym.startswith('0x')

    if is_unknown:
        if dso and dso not in ('[unknown]', '[vdso]', '[vsyscall]'):
            # Preserve the binary name so the flamegraph shows e.g. [stargate]
            # instead of a generic [unknown]
            basename = dso.rsplit('/', 1)[-1]
            return f'[{basename}]'
        return '[unknown]'

    sym = sym.replace(';', ':')
    if dso == '[kernel.kallsyms]':
        sym = sym + '_[k]'
    return sym


def samples_to_folded(samples):
    """
    Convert parsed samples to folded stacks format.

    Returns a dict: { "comm;frame1;frame2;...": count, ... }
    """
    folded = defaultdict(int)
    for sample in samples:
        frames = sample['frames'] if sample['frames'] else ['[unknown]']
        stack = sample['comm'] + ';' + ';'.join(frames)
        folded[stack] += 1
    return dict(folded)


def folded_to_flamegraph_json(folded):
    """
    Convert folded stacks dict into the hierarchical JSON structure
    that d3-flame-graph expects:

    {
      "name": "root",
      "value": 0,
      "children": [
        { "name": "func_a", "value": 5, "children": [...] },
        ...
      ]
    }
    """
    root = {'name': 'root', 'value': 0, 'children': []}

    for stack_str, count in folded.items():
        frames = stack_str.split(';')
        node = root
        for frame in frames:
            child = None
            for c in node['children']:
                if c['name'] == frame:
                    child = c
                    break
            if child is None:
                child = {'name': frame, 'value': 0, 'children': []}
                node['children'].append(child)
            child['value'] += count
            node = child

    _propagate_values(root)
    return root


def _propagate_values(node):
    """Ensure parent value >= sum of children values (for correct rendering)."""
    if not node['children']:
        return
    child_sum = 0
    for child in node['children']:
        _propagate_values(child)
        child_sum += child['value']
    if node['value'] < child_sum:
        node['value'] = child_sum


def compute_process_breakdown(samples):
    """
    Return per-process sample counts sorted descending.

    Returns: [{'name': str, 'pid': int, 'samples': int, 'pct': float}, ...]
    """
    counts = defaultdict(lambda: {'samples': 0, 'pid': 0})
    for s in samples:
        key = s['comm']
        counts[key]['samples'] += 1
        counts[key]['pid'] = s['pid']

    total = len(samples) or 1
    result = []
    for name, info in counts.items():
        result.append({
            'name': name,
            'pid': info['pid'],
            'samples': info['samples'],
            'pct': round(100.0 * info['samples'] / total, 2),
        })
    result.sort(key=lambda x: x['samples'], reverse=True)
    return result


def compute_top_functions(folded, top_n=20):
    """
    Return the top N hottest leaf functions by sample count.

    Returns: [{'function': str, 'samples': int, 'pct': float}, ...]
    """
    func_counts = defaultdict(int)
    total = 0
    for stack_str, count in folded.items():
        frames = stack_str.split(';')
        leaf = frames[-1] if frames else '[unknown]'
        func_counts[leaf] += count
        total += count

    total = total or 1
    result = []
    for func, cnt in func_counts.items():
        result.append({
            'function': func,
            'samples': cnt,
            'pct': round(100.0 * cnt / total, 2),
        })
    result.sort(key=lambda x: x['samples'], reverse=True)
    return result[:top_n]


def compute_kernel_user_split(samples):
    """
    Return kernel vs userspace sample ratio.

    Returns: {'kernel_samples': int, 'user_samples': int,
              'kernel_pct': float, 'user_pct': float, 'total': int}
    """
    kernel = 0
    user = 0
    for s in samples:
        has_kernel = any('_[k]' in f for f in s['frames'])
        if has_kernel:
            kernel += 1
        else:
            user += 1
    total = kernel + user or 1
    return {
        'kernel_samples': kernel,
        'user_samples': user,
        'kernel_pct': round(100.0 * kernel / total, 2),
        'user_pct': round(100.0 * user / total, 2),
        'total': kernel + user,
    }


IDLE_FRAME_MARKERS = [
    'cpu_idle', 'default_idle', 'native_safe_halt',
    'intel_idle', 'mwait_idle', 'poll_idle',
    'cpuidle_enter', 'acpi_idle',
]


def _is_idle_sample(sample):
    """Check if a sample is an idle/swapper sample."""
    return any(
        marker in frame
        for frame in sample['frames']
        for marker in IDLE_FRAME_MARKERS
    )


def compute_active_breakdown(samples):
    """
    Compute idle/active split and per-process breakdown excluding idle samples.

    Returns: {
        'idle_samples': int,
        'active_samples': int,
        'idle_pct': float,
        'active_pct': float,
        'active_process_breakdown': list,  # same format as compute_process_breakdown
    }
    """
    active = []
    idle_count = 0
    for s in samples:
        if _is_idle_sample(s):
            idle_count += 1
        else:
            active.append(s)

    total = len(samples) or 1
    active_total = len(active) or 1

    counts = defaultdict(lambda: {'samples': 0, 'pid': 0})
    for s in active:
        key = s['comm']
        counts[key]['samples'] += 1
        counts[key]['pid'] = s['pid']

    breakdown = []
    for name, info in counts.items():
        breakdown.append({
            'name': name,
            'pid': info['pid'],
            'samples': info['samples'],
            'pct': round(100.0 * info['samples'] / active_total, 2),
        })
    breakdown.sort(key=lambda x: x['samples'], reverse=True)

    return {
        'idle_samples': idle_count,
        'active_samples': len(active),
        'idle_pct': round(100.0 * idle_count / total, 2),
        'active_pct': round(100.0 * len(active) / total, 2),
        'active_process_breakdown': breakdown,
    }


def parse_top_snapshot(text):
    """
    Parse the top_snapshot.txt output to extract system context.

    Returns: {
        'load_avg_1': float, 'load_avg_5': float, 'load_avg_15': float,
        'cpu_us': float, 'cpu_sy': float, 'cpu_id': float,
        'cpu_wa': float, 'cpu_st': float, 'cpu_hi': float, 'cpu_si': float,
        'mem_total_kb': int, 'mem_used_kb': int, 'mem_free_kb': int, 'mem_avail_kb': int,
        'tasks_total': int, 'tasks_running': int,
        'uptime': str,
        'top_processes': [{'pid': int, 'user': str, 'cpu_pct': float, 'mem_pct': float,
                           'command': str, 'threads': int}, ...]
    }
    """
    if not text or not text.strip():
        return {}

    result = {}
    lines = text.strip().splitlines()

    for line in lines:
        # Load average: "top - 14:19:46 up 133 days, 2:24, ... load average: 5.28, 3.83, 3.36"
        if 'load average:' in line:
            try:
                la_part = line.split('load average:')[1].strip()
                parts = [x.strip() for x in la_part.split(',')]
                result['load_avg_1'] = float(parts[0])
                result['load_avg_5'] = float(parts[1])
                result['load_avg_15'] = float(parts[2])
            except (IndexError, ValueError):
                pass
            up_match = re.search(r'up\s+(.+?),\s+\d+\s+user', line)
            if up_match:
                result['uptime'] = up_match.group(1).strip()

        # Tasks: "Tasks: 516 total, 4 running, 512 sleeping, ..."
        if line.strip().startswith('Tasks:'):
            m = re.search(r'(\d+)\s+total.*?(\d+)\s+running', line)
            if m:
                result['tasks_total'] = int(m.group(1))
                result['tasks_running'] = int(m.group(2))

        # CPU: "%Cpu(s): 29.0 us, 13.8 sy, 1.4 ni, 54.5 id, 0.7 wa, 0.0 hi, 0.7 si, 0.0 st"
        if '%Cpu' in line:
            for key, label in [('cpu_us', 'us'), ('cpu_sy', 'sy'), ('cpu_id', 'id'),
                               ('cpu_wa', 'wa'), ('cpu_st', 'st'), ('cpu_hi', 'hi'),
                               ('cpu_si', 'si'), ('cpu_ni', 'ni')]:
                m = re.search(r'([\d.]+)\s+' + label, line)
                if m:
                    result[key] = float(m.group(1))

        # Memory: "KiB Mem : 63523484 total, 1502600 free, 58484296 used, 3536588 buff/cache"
        if 'KiB Mem' in line or 'MiB Mem' in line:
            mult = 1 if 'KiB' in line else 1024
            m_total = re.search(r'([\d.]+)\s+total', line)
            m_free = re.search(r'([\d.]+)\s+free', line)
            m_used = re.search(r'([\d.]+)\s+used', line)
            if m_total:
                result['mem_total_kb'] = int(float(m_total.group(1)) * mult)
            if m_free:
                result['mem_free_kb'] = int(float(m_free.group(1)) * mult)
            if m_used:
                result['mem_used_kb'] = int(float(m_used.group(1)) * mult)

        # Avail mem: "... 3327040 avail Mem"
        if 'avail Mem' in line or 'avail mem' in line.lower():
            mult = 1 if 'KiB' in line or 'avail Mem' in line else 1024
            m = re.search(r'([\d.]+)\s+avail', line, re.IGNORECASE)
            if m:
                result['mem_avail_kb'] = int(float(m.group(1)) * mult)

    # Parse top process table (lines after the header row with PID)
    top_procs = []
    in_table = False
    header_cols = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('PID'):
            in_table = True
            header_cols = stripped.split()
            continue
        if in_table and stripped:
            parts = stripped.split(None, len(header_cols) - 1)
            if len(parts) >= 7:
                try:
                    pid_idx = 0
                    user_idx = header_cols.index('USER') if 'USER' in header_cols else 2
                    cpu_idx = header_cols.index('%CPU') if '%CPU' in header_cols else -3
                    mem_idx = header_cols.index('%MEM') if '%MEM' in header_cols else -2
                    nth_idx = header_cols.index('nTH') if 'nTH' in header_cols else None

                    proc = {
                        'pid': int(parts[pid_idx]),
                        'user': parts[user_idx] if user_idx < len(parts) else '',
                        'cpu_pct': float(parts[cpu_idx]),
                        'mem_pct': float(parts[mem_idx]),
                        'command': parts[-1] if len(parts) >= len(header_cols) else '',
                    }
                    if nth_idx is not None and nth_idx < len(parts):
                        try:
                            proc['threads'] = int(parts[nth_idx])
                        except ValueError:
                            pass
                    top_procs.append(proc)
                except (ValueError, IndexError):
                    pass
            if len(top_procs) >= 10:
                break

    result['top_processes'] = top_procs
    return result


def parse_and_process(perf_script_text):
    """
    Full pipeline: raw perf script text -> all analysis artifacts.
    """
    samples = parse_perf_script(perf_script_text)
    folded = samples_to_folded(samples)
    flamegraph_json = folded_to_flamegraph_json(folded)
    process_breakdown = compute_process_breakdown(samples)
    top_functions = compute_top_functions(folded)
    kernel_user_split = compute_kernel_user_split(samples)
    active_breakdown = compute_active_breakdown(samples)

    return {
        'samples': samples,
        'folded': folded,
        'flamegraph_json': flamegraph_json,
        'process_breakdown': process_breakdown,
        'top_functions': top_functions,
        'kernel_user_split': kernel_user_split,
        'total_samples': len(samples),
        'idle_samples': active_breakdown['idle_samples'],
        'active_samples': active_breakdown['active_samples'],
        'idle_pct': active_breakdown['idle_pct'],
        'active_pct': active_breakdown['active_pct'],
        'active_process_breakdown': active_breakdown['active_process_breakdown'],
    }
