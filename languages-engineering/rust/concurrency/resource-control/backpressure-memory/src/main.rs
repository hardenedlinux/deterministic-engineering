// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Controlled resource-lifecycle observations, without network or timing gold.
use rayon::ThreadPoolBuilder;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Arc, Mutex,
};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
struct Observe {
    live: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    events: Arc<Mutex<Vec<Value>>>,
}
impl Observe {
    fn new() -> Self {
        Self {
            live: Arc::new(AtomicUsize::new(0)),
            drops: Arc::new(AtomicUsize::new(0)),
            events: Arc::new(Mutex::new(vec![])),
        }
    }
    fn event(&self, name: &str) {
        self.events.lock().unwrap().push(json!({"event":name}));
    }
    fn cut(&self, name: &str, sem: &Semaphore) {
        self.events.lock().unwrap().push(json!({"event":name,"live":self.live.load(Ordering::SeqCst),"drops":self.drops.load(Ordering::SeqCst),"available":sem.available_permits()}));
    }
}
struct Payload {
    bytes: Option<Vec<u8>>,
    observe: Observe,
}
impl Payload {
    fn new(observe: Observe, size: usize) -> Self {
        observe.live.fetch_add(1, Ordering::SeqCst);
        observe.event("payload-created");
        Self {
            bytes: Some(vec![7; size]),
            observe,
        }
    }
}
impl Drop for Payload {
    fn drop(&mut self) {
        drop(self.bytes.take());
        self.observe.live.fetch_sub(1, Ordering::SeqCst);
        self.observe.drops.fetch_add(1, Ordering::SeqCst);
        self.observe.event("payload-dropped");
    }
}
// Field order makes payload disposal precede returning its resource permit.
struct OwnedWork {
    payload: Payload,
    _permit: Option<OwnedSemaphorePermit>,
}

async fn run_case(name: &str, bytes: usize, pool: &rayon::ThreadPool) -> Value {
    let observe = Observe::new();
    let sem = Arc::new(Semaphore::new(1));
    let mut permit = Some(sem.clone().acquire_owned().await.unwrap());
    if name == "M02" {
        let payload = Payload::new(observe.clone(), bytes);
        let acquired = Arc::new(AtomicUsize::new(0));
        let (pending_tx, pending_rx) = oneshot::channel();
        let s = sem.clone();
        let o = observe.clone();
        let a = acquired.clone();
        let task = tokio::spawn(async move {
            let acquire = s.acquire_owned();
            tokio::pin!(acquire);
            let mut pending_tx = Some(pending_tx);
            let p = std::future::poll_fn(|cx| match acquire.as_mut().poll(cx) {
                std::task::Poll::Pending => {
                    if let Some(tx) = pending_tx.take() {
                        o.event("waiter-pending");
                        let _ = tx.send(());
                    }
                    std::task::Poll::Pending
                }
                ready => ready,
            })
            .await
            .unwrap();
            a.fetch_add(1, Ordering::SeqCst);
            drop(p);
        });
        pending_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        observe.event("waiter-cancelled");
        observe.cut("held", &sem);
        assert_eq!(acquired.load(Ordering::SeqCst), 0);
        drop(payload);
        drop(permit.take());
        observe.cut("final", &sem);
        return json!({"case":name,"acquiredByWaiter":acquired.load(Ordering::SeqCst),"events":observe.events.lock().unwrap().clone()});
    }
    let work = OwnedWork {
        payload: Payload::new(observe.clone(), bytes),
        _permit: if name == "M06" { None } else { permit.take() },
    };
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(0);
    let (result_tx, result_rx) = oneshot::channel::<OwnedWork>();
    let (done_tx, done_rx) = oneshot::channel();
    let o = observe.clone();
    let (cleanup_tx, cleanup_rx) = mpsc::sync_channel::<Option<OwnedWork>>(1);
    if name == "M05" {
        cleanup_tx.send(None).unwrap_or_else(|_| panic!("prefill"));
    }
    let case = name.to_owned();
    pool.spawn(move || {
        o.event("cpu-started");
        started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        o.event("cpu-released");
        assert_eq!(
            work.payload
                .bytes
                .as_ref()
                .unwrap()
                .iter()
                .map(|b| *b as usize)
                .sum::<usize>(),
            bytes * 7
        );
        if case == "M05" {
            match cleanup_tx.try_send(Some(work)) {
                Err(mpsc::TrySendError::Full(retained)) => {
                    o.event("cleanup-full-retained");
                    drop(retained);
                }
                _ => panic!("cleanup must remain full"),
            }
        } else if let Err(retained) = result_tx.send(work) {
            o.event("delivery-failed-retained");
            drop(retained);
        }
        o.event("cpu-finished");
        done_tx.send(()).unwrap();
    });
    // The negative variant intentionally puts the permit in the async caller.
    // An Option permits this explicit ownership split without a duplicate permit.
    let mut result_rx = Some(result_rx);
    let mut caller = None;
    let (waiting_tx, waiting_rx) = oneshot::channel();
    if name == "M04" || name == "M06" {
        let rx = result_rx.take().unwrap();
        let o = observe.clone();
        // M06 acquires its permit above through the separately selected branch.
        let caller_permit = if name == "M06" { permit.take() } else { None };
        caller = Some(tokio::spawn(async move {
            let _p = caller_permit;
            o.event("caller-waiting");
            waiting_tx.send(()).unwrap();
            let _ = rx.await;
        }));
    }
    started_rx.await.unwrap();
    observe.cut("started", &sem);
    if let Some(task) = caller {
        waiting_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        observe.event("caller-cancelled");
    }
    if name == "M03" {
        drop(result_rx.take());
        observe.event("receiver-dropped");
    }
    observe.cut("held", &sem);
    release_tx.send(()).unwrap();
    if name == "M01" {
        let result = result_rx
            .take()
            .unwrap()
            .await
            .unwrap_or_else(|_| panic!("result"));
        observe.cut("returned", &sem);
        drop(result);
    }
    done_rx.await.unwrap();
    drop(result_rx);
    drop(cleanup_rx);
    observe.cut("final", &sem);
    json!({"case":name,"events":observe.events.lock().unwrap().clone()})
}
use std::future::Future;
fn main() {
    let output = std::env::args().nth(1).expect("output.json");
    let bytes: usize = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "64".into())
        .parse()
        .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let cases = runtime.block_on(async {
        let mut cases = vec![];
        for name in ["M01", "M02", "M03", "M04", "M05", "M06"] {
            cases.push(run_case(name, bytes, &pool).await);
        }
        cases
    });
    std::fs::write(output, serde_json::to_vec_pretty(&json!({"schema":"rust.resource-lifecycle.v1","payloadBytes":bytes,"capacity":1,"tokioFlavor":"current_thread","rayonThreads":1,"panic":"unwind","cases":cases})).unwrap()).unwrap();
    println!("RUST-RESOURCE-LIFECYCLE-OBSERVED");
}
