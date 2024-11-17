use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const TARGET_URL: &str = "https://www.rust-lang.org"; // The URL to test against
const SOCKS5_PROXY: &str = "socks5://localhost:1080"; // The SOCKS5 proxy URL
const NUM_REQUESTS: usize = 10000; // Number of requests to send
const CONCURRENT_LIMIT: usize = 100; // Maximum number of concurrent requests

// Run this function with `cargo test -- --nocapture` to see output
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn benchmark_socks5_proxy() {
    let semaphore =
        Arc::new(Semaphore::new(CONCURRENT_LIMIT));
    let client = Client::builder()
        .proxy(reqwest::Proxy::all(SOCKS5_PROXY).unwrap())
        .build()
        .expect("Failed to build HTTP client");

    let mut handles = vec![];
    let mut timings = vec![];

    for _ in 0..NUM_REQUESTS {
        let client = client.clone();
        let semaphore = Arc::clone(&semaphore); // Clone the Arc to share with the task

        let handle = tokio::spawn(async move {
            let permit = semaphore.acquire().await.unwrap(); // Acquire a permit
            let start = Instant::now();
            let result =
                client.get(TARGET_URL).send().await;
            drop(permit); // Release permit after request completes

            match result {
                Ok(response) => {
                    if response.status().is_success() {
                        let elapsed = start.elapsed();
                        Some(elapsed)
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete and collect successful timings
    for handle in handles {
        if let Ok(Some(duration)) = handle.await {
            timings.push(duration);
        }
    }

    // Calculate statistics
    let success_count = timings.len();
    let avg_response_time = if success_count > 0 {
        let total_time: Duration = timings.iter().sum();
        total_time / success_count as u32
    } else {
        Duration::from_secs(0)
    };

    // Output statistics
    println!("Total requests: {}", NUM_REQUESTS);
    println!("Successful requests: {}", success_count);
    println!(
        "Average response time: {:.2?}",
        avg_response_time
    );
}
