use super::args::Args;
use clap::ValueEnum;
use serde::Deserialize;
use std::{
    io::{self, IsTerminal, Write},
    sync::{Arc, Mutex},
};
use tracing_subscriber::{EnvFilter, fmt::MakeWriter};

#[derive(Clone, Copy, Debug, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(super) enum LogFormat {
    Text,
    Json,
}

#[derive(Clone)]
struct LogWriter(Arc<Mutex<Box<dyn Write + Send>>>);
struct LogGuard<'a>(std::sync::MutexGuard<'a, Box<dyn Write + Send>>);
impl Write for LogGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl<'a> MakeWriter<'a> for LogWriter {
    type Writer = LogGuard<'a>;
    fn make_writer(&'a self) -> Self::Writer {
        LogGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}
pub(super) fn init_logging(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let level = args.log_level.clone().unwrap_or_else(|| {
        match args.verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }
        .into()
    });
    let filter = EnvFilter::try_new(level).map_err(|_| "invalid --log-level filter")?;
    let file = args.log_file.is_some();
    let writer: Box<dyn Write + Send> = if let Some(path) = &args.log_file {
        Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?,
        )
    } else {
        Box::new(io::stderr())
    };
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(!file && io::stderr().is_terminal())
        .with_writer(LogWriter(Arc::new(Mutex::new(writer))));
    match args.log_format.unwrap_or(LogFormat::Text) {
        LogFormat::Json => builder
            .json()
            .try_init()
            .map_err(|_| "cannot initialize logging")?,
        LogFormat::Text => builder
            .try_init()
            .map_err(|_| "cannot initialize logging")?,
    }
    Ok(())
}
