use log::{Level, Metadata, Record};

pub struct Logger {
    level: Level,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if record.target().starts_with("portier_broker") {
            eprintln!("{: <6} {}", record.level(), record.args());
        } else {
            eprintln!(
                "{: <6} [{}] {}",
                record.level(),
                record.target(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

pub fn init() {
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|level| level.parse().ok())
        .unwrap_or(log::Level::Warn);
    let logger = Box::new(Logger { level });
    log::set_boxed_logger(logger).expect("Failed to initialize logger");
    log::set_max_level(level.to_level_filter());
}
