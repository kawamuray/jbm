#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_bpf::{
    bindings::BPF_F_USER_STACK,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read,
        bpf_send_signal_thread,
    },
    macros::{kprobe, map},
    maps::{HashMap, PerfEventArray, StackTrace},
    programs::ProbeContext,
};
use jbm_common::{BlockEvent, Config, STACK_STORAGE_SIZE};
use vmlinux::{pid_t, task_struct};

#[map(name = "START_TIMES")]
static mut START_TIMES: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(10240, 0);

#[map(name = "STACK_TRACES")]
static mut STACK_TRACES: StackTrace = StackTrace::with_max_entries(STACK_STORAGE_SIZE as u32, 0);

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<BlockEvent> = PerfEventArray::new(0);

// The actual value is set at initialization phase by the control application
#[no_mangle]
static CONFIG: Config = Config {
    target_tgid: 0,
    min_block_us: 0,
    max_block_us: 0,
};

#[kprobe(name = "jbm")]
pub fn jbm(ctx: ProbeContext) -> u32 {
    match unsafe { try_jbm(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_jbm(ctx: ProbeContext) -> Result<u32, i64> {
    let prev: *const task_struct = ctx.arg(0).ok_or(1u32)?;
    let prev_pid = bpf_probe_read(&(*prev).pid as *const pid_t)?;
    let prev_tgid = bpf_probe_read(&(*prev).tgid as *const pid_t)?;

    let config = core::ptr::read_volatile(&CONFIG);

    // record previous thread sleep time
    if prev_tgid as u32 == config.target_tgid {
        let ts = bpf_ktime_get_ns();
        START_TIMES.insert(&(prev_pid as u32), &ts, 0)?;
    }

    // get the current thread's start time
    let pid = bpf_get_current_pid_tgid() as u32;
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let t_start = if let Some(tsp) = START_TIMES.get(&pid) {
        *tsp
    } else {
        return Ok(0);
    };

    // calculate current thread's delta time
    let t_end = bpf_ktime_get_ns();
    START_TIMES.remove(&pid)?;
    if tgid != config.target_tgid {
        // There's a possibility such a task id that previously belonged to tgid = 1234
        // is now re-used and is a task id of a different process.
        return Ok(0);
    }
    if t_start > t_end {
        return Ok(0);
    }
    let offtime = (t_end - t_start) / 1000;

    if offtime < config.min_block_us || offtime > config.max_block_us {
        return Ok(0);
    }

    // create and submit an event
    let kernel_stack_id = STACK_TRACES.get_stackid(&ctx, 0)?;
    let user_stack_id = STACK_TRACES.get_stackid(&ctx, BPF_F_USER_STACK as u64)?;

    let event = BlockEvent {
        pid,
        tgid,
        user_stack_id,
        kernel_stack_id,
        name: bpf_get_current_comm()?,
        offtime,
        t_start,
        t_end,
    };
    EVENTS.output(&ctx, &event, 0);

    // Signal target thread for taking call trace
    // bpf_send_signal_thread(27);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
