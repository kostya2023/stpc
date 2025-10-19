use chrono::{Utc, Local};
use colored::*;
use lazy_static::lazy_static;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

// Logging levels
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl LogLevel {
    fn to_color(&self) -> Color {
        match self {
            LogLevel::Debug => Color::Cyan,
            LogLevel::Info => Color::Green,
            LogLevel::Warning => Color::Yellow,
            LogLevel::Error => Color::Red,
            LogLevel::Critical => Color::Magenta,
        }
    }

    fn to_string(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARNING",
            LogLevel::Error => "ERROR",
            LogLevel::Critical => "CRITICAL",
        }
    }
}

// Time mode
#[derive(Debug, Clone, Copy)]
pub enum TimeMode {
    Utc,
    Local,
}

// Logger configuration
pub struct LoggerConfig {
    pub console_enabled: bool,
    pub file_enabled: bool,
    pub file_path: PathBuf,
    pub max_file_size: u64,
    pub min_level: LogLevel,
    pub debug_enabled: bool,
    pub format: String,
    pub time_mode: TimeMode,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            console_enabled: true,
            file_enabled: false,
            file_path: PathBuf::from("app.log"),
            max_file_size: 5 * 1024 * 1024,
            min_level: LogLevel::Info,
            debug_enabled: false,
            format: "[{level}] ({timestamp}) - {message}".to_string(),
            time_mode: TimeMode::Local,
        }
    }
}

// Global logger
lazy_static! {
    pub static ref LOGGER: Mutex<Logger> = Mutex::new(Logger::new(LoggerConfig::default()));
}

// Logger struct
pub struct Logger {
    config: LoggerConfig,
    file_handle: Option<File>,
}

impl Logger {
    pub fn new(config: LoggerConfig) -> Self {
        let file_handle = if config.file_enabled {
            Self::open_file(&config.file_path)
        } else {
            None
        };
        Logger { config, file_handle }
    }

    fn open_file(path: &PathBuf) -> Option<File> {
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("Failed to open log file: {}", e);
                None
            }
        }
    }

    fn rotate_file_if_needed(&mut self) {
        if let Some(file) = &mut self.file_handle {
            if let Ok(metadata) = file.metadata() {
                if metadata.len() >= self.config.max_file_size {
                    let rotated = self.config.file_path.with_extension("log.old");
                    if let Err(e) = std::fs::rename(&self.config.file_path, rotated) {
                        eprintln!("Failed to rotate log file: {}", e);
                        return;
                    }
                    self.file_handle = Self::open_file(&self.config.file_path);
                }
            }
        }
    }

    pub fn log(&mut self, level: LogLevel, message: &str) {
        if level < self.config.min_level {
            return;
        }
        if level == LogLevel::Debug && !self.config.debug_enabled {
            return;
        }

        let timestamp = match self.config.time_mode {
            TimeMode::Utc => Utc::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            TimeMode::Local => Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        };

        let log_line = self
            .config
            .format
            .replace("{level}", level.to_string())
            .replace("{timestamp}", &timestamp)
            .replace("{message}", message)
            + "\n";

        if self.config.console_enabled {
            let colored_level = format!("[{}]", level.to_string()).color(level.to_color());
            println!(
                "{}",
                log_line.replace(&format!("[{}]", level.to_string()), &colored_level.to_string())
            );
        }

        if self.config.file_enabled {
            self.rotate_file_if_needed();
            if let Some(file) = &mut self.file_handle {
                let _ = file.write_all(log_line.as_bytes());
                let _ = file.flush();
            }
        }
    }

    pub fn debug(&mut self, message: &str) { self.log(LogLevel::Debug, message); }
    pub fn info(&mut self, message: &str) { self.log(LogLevel::Info, message); }
    pub fn warning(&mut self, message: &str) { self.log(LogLevel::Warning, message); }
    pub fn error(&mut self, message: &str) { self.log(LogLevel::Error, message); }
    pub fn critical(&mut self, message: &str) { self.log(LogLevel::Critical, message); }

    pub fn reconfigure(&mut self, config: LoggerConfig) {
        self.config = config;
        self.file_handle = if self.config.file_enabled {
            Self::open_file(&self.config.file_path)
        } else {
            None
        };
    }
}

// Macros
#[macro_export]
macro_rules! debug { ($($arg:tt)*) => { $crate::LOGGER.lock().unwrap().debug(&format!($($arg)*)) }; }
#[macro_export]
macro_rules! info { ($($arg:tt)*) => { $crate::LOGGER.lock().unwrap().info(&format!($($arg)*)) }; }
#[macro_export]
macro_rules! warning { ($($arg:tt)*) => { $crate::LOGGER.lock().unwrap().warning(&format!($($arg)*)) }; }
#[macro_export]
macro_rules! error { ($($arg:tt)*) => { $crate::LOGGER.lock().unwrap().error(&format!($($arg)*)) }; }
#[macro_export]
macro_rules! critical { ($($arg:tt)*) => { $crate::LOGGER.lock().unwrap().critical(&format!($($arg)*)) }; }

// Init function
pub fn init_logger(config: LoggerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut logger = LOGGER.lock().unwrap();
    logger.reconfigure(config);
    Ok(())
}
