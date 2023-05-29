pub mod async_profiler;
mod symbol;

use async_trait::async_trait;
use aya::{
    include_bytes_aligned,
    maps::{
        perf::{AsyncPerfEventArray, AsyncPerfEventArrayBuffer},
        MapData, StackTraceMap,
    },
    programs::KProbe,
    util::{kernel_symbols, online_cpus},
    Bpf, BpfError, BpfLoader, Btf,
};
use bytes::BytesMut;
use chrono::{Local, TimeZone};
use futures::future::join_all;
use jbm_common::{BlockEvent, Config, STACK_STORAGE_SIZE};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    ffi::CStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use symbol::Resolver;

const EVENT_MATCH_TIME_THRESHOLD_TIME: Duration = Duration::from_millis(8000);
const EVENT_MATCH_GIVEUP_TIME: Duration = Duration::from_millis(30000);
const STACK_STORAGE_SIZE_CHECK_COUNT: usize = 100;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

pub struct Jbm<JvmStackP: JvmStackTraceProvider> {
    bpf: Bpf,
    perf_buffers: Vec<AsyncPerfEventArrayBuffer<MapData>>,
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

        let mut bpf = match Self::load_bpf(&bpf_binary, &config) {
            Ok(bpf) => bpf,
            Err(e) => {
                if let BpfError::MapError(_) = e {
                    // On some platform BPF map creation can fail with EPERM by lack of
                    // MEMLOCK resource limit. bcc work-around by increasing resource limit
                    // when map creation fails with EPERM.
                    if let Ok(_) = nix::sys::resource::setrlimit(
                        nix::sys::resource::Resource::RLIMIT_MEMLOCK,
                        nix::sys::resource::RLIM_INFINITY,
                        nix::sys::resource::RLIM_INFINITY,
                    ) {
                        Self::load_bpf(&bpf_binary, &config)?
                    } else {
                        return Err(e.into());
                    }
                } else {
                    return Err(e.into());
                }
            }
        };

        let program: &mut KProbe = bpf.program_mut("jbm").expect("program 'jbm'").try_into()?;
        program.load()?;
        program.attach("finish_task_switch", 0)?;

        let mut perf_array =
            AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").expect("EVENTS map"))?;

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

    fn load_bpf(bpf_binary: &[u8], config: &Config) -> std::result::Result<Bpf, BpfError> {
        BpfLoader::new()
            .btf(Btf::from_sys_fs().ok().as_ref())
            .set_max_entries("STACK_TRACES", config.stack_storage_size)
            .set_global("CONFIG", config)
            .load(bpf_binary)
    }

    pub async fn process(&mut self) -> Result<Vec<(BpfEvent, Option<JvmEvent>)>> {
        let mut futures = Vec::new();
        for perf_buf in &mut self.perf_buffers {
            futures.push(tokio::time::timeout(Duration::from_millis(1000), async {
                let mut read_bufs =
                    vec![BytesMut::with_capacity(std::mem::size_of::<BlockEvent>()); 5];
                debug!("Consuming eBPF events");
                let info = match perf_buf.read_events(&mut read_bufs).await {
                    Ok(info) => info,
                    Err(e) => {
                        error!("Failed to poll eBPF buffer: {:?}", e);
                        return vec![];
                    }
                };
                if info.lost > 0 {
                    warn!(
                        "{} events from eBPF lost due to slow-paced consumption",
                        info.lost
                    );
                }
                debug!("Consumed {} events from eBPF", info.read);

                read_bufs[..info.read]
                    .into_iter()
                    .map(|buf| {
                        let mut event: BlockEvent = unsafe { std::mem::zeroed() };
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                buf.as_ptr(),
                                &mut event as *mut BlockEvent as *mut u8,
                                std::mem::size_of::<BlockEvent>(),
                            );
                        }
                        event
                    })
                    .collect()
            }));
        }
        let bpf_results = join_all(futures).await;
        for bpf_result in bpf_results {
            if let Ok(bpf_events) = bpf_result {
                for bpf_event in bpf_events {
                    debug!("Consumed eBPF events");
                    #[cfg(kernel3x)]
                    let pid = bpf_event.pid as i32;
                    // This calling order is important because event matching relies on timestamp order before/after
                    self.stream.add_bpf_event(&self.bpf, bpf_event)?;
                    #[cfg(kernel3x)]
                    Self::send_signal(pid);
                }
            }
        }

        self.jvm_stack_provider
            .fill_queue(&mut self.stream.jvm_events)
            .await?;
        Ok(self.stream.sweep())
    }

    #[cfg(kernel3x)]
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
    event_count: usize,
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
            event_count: 0,
        }
    }

    pub fn add_bpf_event(&mut self, bpf: &Bpf, event: BlockEvent) -> Result<()> {
        let stack_traces =
            StackTraceMap::try_from(bpf.map("STACK_TRACES").expect("STACK_TRACES map"))?;
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

        let timestamp = Self::compute_timestamp(event.t_end);
        self.bpf_events
            .entry(event.pid)
            .or_insert_with(|| VecDeque::new())
            .push_back(BpfEvent {
                timestamp,
                pid: event.tgid,
                tid: event.pid,
                comm,
                duration: Duration::from_micros(event.offtime),
                stacktrace: frames,
            });

        self.event_count += 1;
        if self.event_count % STACK_STORAGE_SIZE_CHECK_COUNT == 0 {
            let cur_size = stack_traces.iter().count();
            if cur_size >= STACK_STORAGE_SIZE {
                warn!(
                    "Stacktraces storage is full, some stacks may be missing in output: {}/{}",
                    cur_size, STACK_STORAGE_SIZE
                );
            }
        }

        Ok(())
    }

    fn compute_timestamp(bpf_ktime: u64) -> u64 {
        let now_ktime = Duration::from(
            nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
                .expect("clock_gettime(MONOTONIC)"),
        )
        .as_nanos() as u64;
        let offset = now_ktime - bpf_ktime;
        let now = time_now();
        let timestamp = now - Duration::from_nanos(offset).as_millis() as u64;
        debug!(
            "Event time compute, offset={}, now={}, timestamp={}",
            offset, now, timestamp
        );
        timestamp
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
                } else if !jvm_queue.is_empty()
                    || now - bpf_event.timestamp >= EVENT_MATCH_GIVEUP_TIME.as_millis() as u64
                {
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
        while let Some(jvm_event) = jvm_queue.front() {
            debug!(
                "Finding match, ebpf={}, jvm={}",
                timestamp, jvm_event.timestamp
            );
            let ts_diff = jvm_event.timestamp as i64 - timestamp as i64;
            if ts_diff < 0 {
                // There should be no corresponding event for this, trash it.
                Self::trash_jvm_event(&jvm_queue.pop_front().unwrap());
            } else if ts_diff < EVENT_MATCH_TIME_THRESHOLD_TIME.as_millis() as i64 {
                return Some(jvm_queue.pop_front().unwrap());
            } else {
                // ts_diff is too large, meaning that there's no chance for the bpf event to get a corresponding
                // JVM event anymore.
                break;
            }
        }
        None
    }

    fn trash_jvm_event(event: &JvmEvent) {
        let mut out = format!(
            "DISCARDED AP EVENT tid={}, timestamp={}\n",
            event.tid, event.timestamp
        );
        for (i, frame) in event.frames.iter().enumerate() {
            out.push_str(&format!(
                "{}: [0x{:x}] {}",
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

#[cfg(test)]
mod integration_tests {
    use std::{
        process::{Child, Command},
        time::Duration,
    };

    use jbm_common::Config;

    use crate::{async_profiler::AsyncProfilerStackTraceProvider, BpfEvent, Jbm, JvmEvent};

    #[tokio::test]
    async fn test_detect_blocking() -> Result<(), anyhow::Error> {
        let java_proc = start_test_java();
        std::thread::sleep(Duration::from_secs(1));

        let config = Config {
            target_tgid: java_proc.id(),
            min_block_us: Duration::from_secs(1).as_micros() as u64,
            max_block_us: Duration::from_secs(10).as_micros() as u64,
            stack_storage_size: 10240,
        };

        let async_profiler = AsyncProfilerStackTraceProvider::start(
            config.target_tgid,
            "../async-profiler/profiler.sh".to_string(),
        )
        .await?;

        let mut jbm = Jbm::new(config, async_profiler)?;
        std::thread::sleep(Duration::from_secs(20));

        let events = jbm.process().await?;

        let (bpf_event, jvm_event) = find_event(&events, "LOCKER").unwrap();

        assert_ne!(java_proc.id(), bpf_event.tid);
        assert_eq!(java_proc.id(), bpf_event.pid);
        assert_eq!("LOCKER", bpf_event.comm);
        assert!(
            bpf_event.duration.as_micros() as u64 >= config.min_block_us
                && bpf_event.duration.as_micros() as u64 <= config.max_block_us
        );
        assert!(bpf_event
            .stacktrace
            .iter()
            .find(|(_, sym)| sym.contains("pthread_cond_wait"))
            .is_some());

        let jvm_event = jvm_event.unwrap();
        assert_eq!(bpf_event.tid, jvm_event.tid);
        assert!(jvm_event
            .frames
            .iter()
            .find(|f| f.symbol.contains("TestJavaApp.locker"))
            .is_some());

        Ok(())
    }

    fn start_test_java() -> Child {
        Command::new("java")
            .args(&["-cp", "./test", "TestJavaApp"])
            .spawn()
            .expect("failed to execute java")
    }

    fn find_event<'a>(
        events: &'a [(BpfEvent, Option<JvmEvent>)],
        comm: &str,
    ) -> Option<(&'a BpfEvent, Option<&'a JvmEvent>)> {
        for (bpf_event, jvm_event) in events {
            if bpf_event.comm == comm {
                return Some((bpf_event, jvm_event.as_ref()));
            }
        }
        None
    }
}
