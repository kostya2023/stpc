use stpc_logging::{init_logger, LoggerConfig, LogLevel, TimeMode};
use stpc_logging::{info, debug, warning, error, critical};
use std::path::PathBuf;
use std::sync::Once;

#[cfg(test)]
mod tests {
    use super::*;

    static INIT: Once = Once::new();

    fn init_once() {
        INIT.call_once(|| {
            let config = LoggerConfig {
                console_enabled: true,
                file_enabled: true,
                file_path: PathBuf::from("mytest.log"),
                max_file_size: 5 * 1024 * 1024,
                min_level: LogLevel::Debug,
                debug_enabled: true,
                time_mode: TimeMode::Local,
                ..Default::default()
            };

            init_logger(config).unwrap();
        });
    }

    #[test]
    fn test_info() {
        init_once();
        info!("Info test!");
    }

    #[test]
    fn test_debug() {
        init_once();
        debug!("Debug test!");
    }

    #[test]
    fn test_warning() {
        init_once();
        warning!("Warning test!");
    }

    #[test]
    fn test_error() {
        init_once();
        error!("Error test!");
    }

    #[test]
    fn test_critical() {
        init_once();
        critical!("Critical test!");
    }
}
