use crate::{pid_alive, JvmEvent, JvmStackTraceProvider};
use anyhow::anyhow;
use async_trait::async_trait;
use futures::FutureExt;
use log::{debug, info, warn};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::process::Command;
use tempfile::{Builder, NamedTempFile};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};

pub struct AsyncProfilerStackTraceProvider {
    pid: u32,
    profiler_cmd_path: String,
    output_file: NamedTempFile,
    lines: Lines<BufReader<File>>,
}

impl AsyncProfilerStackTraceProvider {
    pub async fn start(pid: u32, profiler_cmd_path: String) -> Result<Self, anyhow::Error> {
        let tmpfile = Builder::new().prefix("jbm-ap-").tempfile()?;
        let file = File::open(tmpfile.path()).await?;
        let reader = BufReader::new(file);
        unsafe {
            let path =
                CString::new(tmpfile.path().to_string_lossy().to_string()).expect("valid C-string");
            libc::chmod(
                path.as_ptr(),
                libc::S_IRUSR
                    | libc::S_IWUSR
                    | libc::S_IRGRP
                    | libc::S_IWGRP
                    | libc::S_IROTH
                    | libc::S_IWOTH,
            )
        };
        let this = Self {
            pid,
            profiler_cmd_path,
            output_file: tmpfile,
            lines: reader.lines(),
        };

        this.exec_profiler_cmd("start")?;
        Ok(this)
    }

    fn exec_profiler_cmd(&self, subcommand: &str) -> Result<(), anyhow::Error> {
        let args = &[
            "-e",
            "none",
            "-o",
            "stream",
            "-f",
            &self.output_file.path().to_string_lossy().to_string(),
            subcommand,
            &format!("{}", self.pid),
        ];
        info!("Executing async-profiler: {:?}", args);
        let status = Command::new(&self.profiler_cmd_path)
            .args(args)
            .spawn()?
            .wait()?;
        let code = status.code().unwrap_or(-1);
        if code != 0 {
            return Err(anyhow!("async-profiler command exit with error: {}", code));
        }
        Ok(())
    }
}

#[async_trait]
impl JvmStackTraceProvider for AsyncProfilerStackTraceProvider {
    async fn fill_queue(
        &mut self,
        queues: &mut HashMap<u32, VecDeque<JvmEvent>>,
    ) -> Result<(), anyhow::Error> {
        let mut count = 0;
        while let Some(line) = self.lines.next_line().await? {
            debug!("Read line from AsyncProfiler stream: {}", line);
            match serde_json::from_str::<JvmEvent>(&line) {
                Ok(jvm_event) => {
                    count += 1;
                    queues
                        .entry(jvm_event.tid)
                        .or_insert_with(|| VecDeque::new())
                        .push_back(jvm_event);
                }
                Err(e) => {
                    warn!("Skipping malformed AsyncProfiler event {}: {}", line, e);
                }
            }
        }
        debug!("Filled up JVM event queue with {} events", count);

        Ok(())
    }
}

impl Drop for AsyncProfilerStackTraceProvider {
    fn drop(&mut self) {
        if pid_alive(self.pid) {
            if let Err(e) = self.exec_profiler_cmd("stop") {
                warn!(
                    "Failed to stop async-profiler on process {}: {}",
                    self.pid, e
                );
            }
        }
    }
}
