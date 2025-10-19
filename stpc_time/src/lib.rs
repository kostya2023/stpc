use stpc_core::NtpServers;
use stpc_core::StpcError;

use ntp::request;

use std::sync::Arc;
use std::thread;
use std::sync::atomic::{AtomicU64, AtomicBool};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};



pub struct TimeManager {
    current_time: Arc<AtomicU64>,
    stop_signal: Arc<AtomicBool>
}


impl TimeManager {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            current_time: Arc::new(AtomicU64::new(now)),
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }


    pub fn get_time(&self) -> u64 {
        self.current_time.load(std::sync::atomic::Ordering::SeqCst)
    }


    pub fn start(&self) {
        let current_time = Arc::clone(&self.current_time);
        let stop_signal = Arc::clone(&self.stop_signal);

        thread::spawn(move || {
            TimeManager::time_update(current_time, stop_signal);
        });
    }


    pub fn stop (&self) {
        self.stop_signal.store(true, std::sync::atomic::Ordering::SeqCst);
    }


    fn time_update(current_time: Arc<AtomicU64>, stop_signal: Arc<AtomicBool>) {
        
        if let Some(ntp_time) = TimeManager::fetch_ntp() {
            current_time.store(ntp_time, std::sync::atomic::Ordering::SeqCst);
        }

        let mut last_update = Instant::now();
        let mut last_sync = Instant::now();
        let update_interval = Duration::from_millis(1000);
        let sync_interval = Duration::from_secs(600);

        while !stop_signal.load(std::sync::atomic::Ordering::SeqCst) {
            let now = Instant::now();

            if now.duration_since(last_sync) >= sync_interval {
                if let Some(ntp_time) = TimeManager::fetch_ntp() {
                    current_time.store(ntp_time, std::sync::atomic::Ordering::SeqCst);
                    last_sync = now;
                } else {
                    last_sync = now - Duration::from_secs(540);
                }
            }

            if now.duration_since(last_update) >= update_interval {
                let current = current_time.load(std::sync::atomic::Ordering::SeqCst) as f64;
                let new_time = (current + 1.0) as u64;
                current_time.store(new_time, std::sync::atomic::Ordering::SeqCst);
                last_update = now;
            }
            
            thread::sleep(Duration::from_millis(10));
        }
        
    }

    fn fetch_ntp() -> Option<u64> {
        for &server in NtpServers::all() {
            match TimeManager::try_fetch_ntp(server) {
                Ok(time) => return Some(time),
                Err(_) => continue,
            }

        }
        None
    }

    fn try_fetch_ntp(server: NtpServers) -> Result<u64, StpcError> {
        let response = request(server.address())
            .map_err(|e| StpcError::TimeServiceError(format!("Error for request to server: {}", e)))?;

        let unix_time = response.transmit_time.sec as u64 - 2_208_988_800;
        Ok(unix_time)
    }
}

impl Drop for TimeManager {
    fn drop(&mut self) {
        self.stop();
    }
}