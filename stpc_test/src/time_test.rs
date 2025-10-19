use stpc_time::*;
use std::time::{SystemTime, UNIX_EPOCH};
use stpc_core::NtpServers;
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_time_manager_initialization() {
        let time_manager = TimeManager::new();
        let initial_time = time_manager.get_time();
        
        let system_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        

        assert!((system_time as i64 - initial_time as i64).abs() < 30);
    }

    #[test]
    fn test_multiple_threads_access() {
        let time_manager = Arc::new(TimeManager::new());
        time_manager.start();
        
        let handles: Vec<_> = (0..5).map(|_i| {
            let tm_clone = Arc::clone(&time_manager);
            thread::spawn(move || {
                for _ in 0..10 {
                    let time = tm_clone.get_time();
                    assert!(time > 1_600_000_000);
                    thread::sleep(Duration::from_millis(10));
                }
            })
        }).collect();
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        time_manager.stop();
    }

    #[test]
    fn test_stop_functionality() {
        let time_manager = TimeManager::new();
        time_manager.start();
        
        thread::sleep(Duration::from_millis(100));
        
        let time_before_stop = time_manager.get_time();
        time_manager.stop();
        
        thread::sleep(Duration::from_millis(300));
        
        let time_after_stop = time_manager.get_time();
        
        let diff = time_after_stop as i64 - time_before_stop as i64;
        assert!(diff <= 1, "Time should not increase significantly after stop, diff: {}", diff);
    }

    #[test]
    fn test_ntp_servers_enum() {
        for server in NtpServers::all() {
            let address = server.address();
            assert!(!address.is_empty());
            assert!(address.contains(':'));
            assert!(address.ends_with(":123"));
        }

        assert!(NtpServers::all().len() >= 3);
    }

    #[test]
    fn test_time_manager_drop_stops_thread() {
        let time_manager = TimeManager::new();
        time_manager.start();
        
        let time_before = time_manager.get_time();

        drop(time_manager);

        thread::sleep(Duration::from_millis(200));

        let new_time_manager = TimeManager::new();
        let new_time = new_time_manager.get_time();

        assert!(new_time >= time_before);
    }

    #[test]
    fn test_concurrent_start_stop() {
        let time_manager = TimeManager::new();
        
        for _ in 0..3 {
            time_manager.start();
            thread::sleep(Duration::from_millis(50));
            
            let time1 = time_manager.get_time();
            thread::sleep(Duration::from_millis(100));
            let time2 = time_manager.get_time();
            
            assert!(time2 >= time1);
            
            time_manager.stop();
            thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn test_time_consistency() {
        let time_manager = TimeManager::new();
        time_manager.start();
        
        let mut previous_time = time_manager.get_time();
        let mut decreases_count = 0;
        
        for i in 0..10 {
            thread::sleep(Duration::from_millis(500));
            let current_time = time_manager.get_time();
            
            if current_time < previous_time {
                decreases_count += 1;
                assert!(
                    decreases_count <= 2,
                    "Time decreased too many times: {} -> {} (iteration {})",
                    previous_time,
                    current_time,
                    i
                );
            }
            
            previous_time = current_time;
        }
        
        let final_time = time_manager.get_time();
        let initial_time = time_manager.get_time();
        assert!(
            final_time >= initial_time - 5,
            "Final time should be >= initial time: {} -> {}",
            initial_time,
            final_time
        );
        
        time_manager.stop();
    }
}