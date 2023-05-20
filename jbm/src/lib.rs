pub mod async_profiler;
mod symbol;

use async_trait::async_trait;
use aya::{
    include_bytes_aligned,
    maps::{
        perf::{AsyncPerfEventArray, AsyncPerfEventArrayBuffer},
        MapRefMut, StackTraceMap,
    },
    programs::KProbe,
    util::{kernel_symbols, online_cpus},
    Bpf, BpfLoader, Btf,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use chrono::{Local, TimeZone};
use futures::future::join_all;
use jbm_common::{BlockEvent, Config};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    ffi::CStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use symbol::Resolver;

const EVENT_MATCH_TIME_THRESHOLD_TIME: Duration = Duration::from_millis(5000);
const EVENT_MATCH_GIVEUP_TIME: Duration = Duration::from_millis(30000);

pub type Result<T> = std::result::Result<T, anyhow::Error>;

pub struct Jbm<JvmStackP: JvmStackTraceProvider> {
    bpf: Bpf,
    perf_buffers: Vec<AsyncPerfEventArrayBuffer<MapRefMut>>,
    stream: EventStream,
    jvm_stack_provider: JvmStackP,
}

impl<JvmStackP: JvmStackTraceProvider> Jbm<JvmStackP> {
    pub fn new(config: Config, jvm_stack_provider: JvmStackP) -> Result<Self> {
        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        #[cfg(debug_assertions)]
        let bpf_binary = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/jbm");
        #[cfg(not(debug_assertions))]
        let bpf_binary = include_bytes_aligned!("../../target/bpfel-unknown-none/release/jbm");

        let mut bpf = BpfLoader::new()
            .btf(Btf::from_sys_fs().ok().as_ref())
            .set_global("CONFIG", &config)
            .load(bpf_binary)?;

        if let Err(e) = BpfLogger::init(&mut bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }
        let program: &mut KProbe = bpf.program_mut("jbm").expect("program 'jbm'").try_into()?;
        program.load()?;
        program.attach("finish_task_switch", 0)?;

        let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

        let mut perf_buffers = Vec::new();
        for cpu in online_cpus()? {
            let perf_buf = perf_array.open(cpu, None)?;
            perf_buffers.push(perf_buf);
        }

        Ok(Self {
            bpf,
            perf_buffers,
            stream: EventStream::new(),
            jvm_stack_provider,
        })
    }

    pub async fn process(&mut self) -> Result<Vec<(BpfEvent, Option<JvmEvent>)>> {
        let mut futures = Vec::new();
        for perf_buf in &mut self.perf_buffers {
            futures.push(tokio::time::timeout(Duration::from_millis(1000), async {
                let mut read_bufs = [BytesMut::with_capacity(1024)]; // TODO: buf size and count
                debug!("Consuming eBPF events");
                let info = match perf_buf.read_events(&mut read_bufs).await {
                    Ok(info) => info,
                    Err(e) => {
                        warn!("Failed to poll eBPF buffer: {:?}", e);
                        return None;
                    }
                };
                if info.lost > 0 {
                    warn!(
                        "{} events from eBPF lost due to slow-paced consumption",
                        info.lost
                    );
                }
                debug!("Consumed {} events from eBPF", info.read);

                let mut event: BlockEvent = unsafe { std::mem::zeroed() };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        read_bufs[0].as_ptr(),
                        &mut event as *mut BlockEvent as *mut u8,
                        std::mem::size_of::<BlockEvent>(),
                    );
                }
                Some(event)
            }));
        }
        let buckets = join_all(futures).await;
        for bucket in buckets {
            if let Ok(bucket) = bucket {
                let bpf_event = bucket.unwrap();
                debug!("Consumed eBPF events");
                // #[cfg(kernel3x)]
                Self::send_signal(bpf_event.pid as i32);
                self.stream.add_bpf_event(&self.bpf, bpf_event)?;
            }
        }

        self.jvm_stack_provider
            .fill_queue(&mut self.stream.jvm_events)
            .await?;
        Ok(self.stream.sweep())
    }

    fn send_signal(pid: i32) {
        debug!("Signaling {}", pid);
        let error = unsafe { libc::kill(pid, libc::SIGPROF) };
        if error != 0 {
            eprintln!("Failed to signal TID {}: error = {}", pid, error);
        }
    }
}

#[async_trait]
pub trait JvmStackTraceProvider {
    async fn fill_queue(&mut self, queues: &mut HashMap<u32, VecDeque<JvmEvent>>) -> Result<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JvmEvent {
    pub timestamp: u64,
    pub tid: u32,
    pub frames: Vec<JvmFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JvmFrame {
    pub bci: i64,
    pub method_id: u64,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BpfEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    pub duration: Duration,
    pub stacktrace: Vec<(u64, String)>,
}

pub struct EventStream {
    bpf_events: HashMap<u32, VecDeque<BpfEvent>>,
    jvm_events: HashMap<u32, VecDeque<JvmEvent>>,
    ksyms: BTreeMap<u64, String>,
    symbol_resolver: Resolver,
}

impl EventStream {
    pub fn new() -> Self {
        Self {
            bpf_events: HashMap::new(),
            jvm_events: HashMap::new(),
            ksyms: kernel_symbols().expect("kernel symbols"),
            symbol_resolver: Resolver::new(),
        }
    }

    pub fn add_bpf_event(&mut self, bpf: &Bpf, event: BlockEvent) -> Result<()> {
        let stack_traces = StackTraceMap::try_from(bpf.map("STACK_TRACES")?)?;
        let mut frames = Vec::new();

        let mut kernel_stack = stack_traces.get(&(event.kernel_stack_id as u32), 0)?;
        for frame in kernel_stack.resolve(&self.ksyms).frames() {
            frames.push((
                frame.ip,
                frame
                    .symbol_name
                    .clone()
                    .unwrap_or("[unknown symbol name]".to_string()),
            ));
        }

        let user_stack = stack_traces.get(&(event.user_stack_id as u32), 0)?;
        let user_frames = self.symbol_resolver.resolve(
            event.tgid,
            &user_stack
                .frames()
                .iter()
                .map(|f| f.ip as usize)
                .collect::<Vec<_>>(),
        )?;
        for (addr, symbol) in user_frames {
            frames.push((addr, symbol.unwrap_or("[unknown symbol name]".to_string())));
        }

        let comm = CStr::from_bytes_until_nul(&event.name)?
            .to_string_lossy()
            .to_string();
        self.bpf_events
            .entry(event.pid)
            .or_insert_with(|| VecDeque::new())
            .push_back(BpfEvent {
                timestamp: time_now(),
                pid: event.tgid,
                tid: event.pid,
                comm,
                duration: Duration::from_micros(event.offtime),
                stacktrace: frames,
            });
        // TODO: stack storage size check?

        Ok(())
    }

    pub fn sweep(&mut self) -> Vec<(BpfEvent, Option<JvmEvent>)> {
        let now = time_now();

        let mut empty = VecDeque::with_capacity(0);
        let mut ret = Vec::new();
        let tids = self.bpf_events.keys().map(|x| *x).collect::<Vec<_>>();
        for tid in tids {
            let bpf_queue = self.bpf_events.get_mut(&tid).expect("bpf queue present");
            let jvm_queue = self.jvm_events.get_mut(&tid).unwrap_or(&mut empty);
            while let Some(bpf_event) = bpf_queue.front() {
                debug!(
                    "Finding match from {} JVM events for tid {}",
                    jvm_queue.len(),
                    tid
                );
                if let Some(jvm_event) =
                    Self::find_matching_jvm_event(bpf_event.timestamp, jvm_queue)
                {
                    ret.push((bpf_queue.pop_front().unwrap(), Some(jvm_event)));
                } else if now - bpf_event.timestamp >= EVENT_MATCH_GIVEUP_TIME.as_millis() as u64 {
                    ret.push((bpf_queue.pop_front().unwrap(), None));
                } else {
                    break;
                }
            }
            if jvm_queue.is_empty() {
                self.jvm_events.remove(&tid);
            }
            if bpf_queue.is_empty() {
                self.bpf_events.remove(&tid);
            }
        }
        debug!("Swept {} events at {}", ret.len(), now);
        ret
    }

    fn find_matching_jvm_event(
        timestamp: u64,
        jvm_queue: &mut VecDeque<JvmEvent>,
    ) -> Option<JvmEvent> {
        while let Some(jvm_event) = jvm_queue.pop_front() {
            debug!(
                "Finding match, ebpf={}, jvm={}",
                timestamp, jvm_event.timestamp
            );
            let ts_diff = jvm_event.timestamp as i64 - timestamp as i64;
            if ts_diff.abs() < EVENT_MATCH_TIME_THRESHOLD_TIME.as_millis() as i64 {
                return Some(jvm_event);
            } else if ts_diff < -(EVENT_MATCH_GIVEUP_TIME.as_millis() as i64 / 2) {
                Self::trash_jvm_event(&jvm_event);
            }
        }
        None
    }

    fn trash_jvm_event(event: &JvmEvent) {
        let mut out = format!(
            "{} DISCARDED AP EVENT TID: {}\n",
            format_time(event.timestamp),
            event.tid
        );
        for (i, frame) in event.frames.iter().enumerate() {
            out.push_str(&format!(
                "  {}: [0x{:x}] {}",
                i, frame.method_id, frame.symbol
            ));
            if i > 0 {
                out.push('\n');
            }
        }
        info!("{}", out);
    }
}

pub fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

pub fn time_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix epoch")
        .as_millis() as u64
}

pub fn format_time(timestamp: u64) -> String {
    Local
        .timestamp_millis_opt(timestamp as i64)
        .single()
        .expect("local time")
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}
