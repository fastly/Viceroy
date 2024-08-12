use anyhow::anyhow;
use fastly::{Error, Request, Response};
use fastly_shared::FastlyStatus;
use hex_literal::hex;
use sha2::{Sha512, Digest};
use std::time::{Duration, Instant};

#[link(wasm_import_module = "fastly_compute_runtime")]
extern "C" {
    #[link_name = "get_vcpu_ms"]
    pub fn get_vcpu_ms(ms_out: *mut u64) -> FastlyStatus;
}

fn current_vcpu_ms() -> Result<u64, anyhow::Error> {
    let mut vcpu_time = 0u64;
    let vcpu_time_result = unsafe { get_vcpu_ms(&mut vcpu_time) };
    if vcpu_time_result != FastlyStatus::OK {
        return Err(anyhow!("Got bad response from get_vcpu_ms: {:?}", vcpu_time_result));
    }
    Ok(vcpu_time)
}

fn test_that_waiting_for_servers_increases_only_wall_time(client_req: Request) -> Result<(), Error> {
    let wall_initial_time = Instant::now();
    let vcpu_initial_time = current_vcpu_ms()?;
    let Ok(_) = client_req.send("slow-server") else {
        Response::from_status(500).send_to_client();
        return Ok(());
    };
    let wall_elapsed_time = wall_initial_time.elapsed().as_millis();
    let vcpu_final_time = current_vcpu_ms()?;

    assert!( (vcpu_final_time - vcpu_initial_time) < 1000 );
    assert!(wall_elapsed_time > 3000 );

    Ok(())
}

fn test_that_computing_factorial_increases_vcpu_time() -> Result<(), Error> {
    let vcpu_initial_time = current_vcpu_ms()?;

    let block = vec![0; 4096];
    let mut written = 0;
    let mut hasher = Sha512::new();
    while written < (1024 * 1024 * 1024) {
        hasher.update(&block);
        written += block.len();
    }
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("
c5041ae163cf0f65600acfe7f6a63f212101687
d41a57a4e18ffd2a07a452cd8175b8f5a4868dd
2330bfe5ae123f18216bdbc9e0f80d131e64b94
913a7b40bb5
")[..]);

    let vcpu_final_time = current_vcpu_ms()?;
    assert!(vcpu_final_time - vcpu_initial_time > 10000);
    Ok(())
}

fn main() -> Result<(), Error> {
    let client_req = Request::from_client();

    test_that_waiting_for_servers_increases_only_wall_time(client_req);
    test_that_computing_factorial_increases_vcpu_time();

    Response::from_status(200).send_to_client();
    Ok(())
}
