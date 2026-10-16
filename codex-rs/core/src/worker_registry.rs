//! Runtime ownership for bounded process-wide worker attestations.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

struct Entry {
    owner: Weak<AtomicBool>,
    attestation: serde_json::Value,
}
static REGISTRIES: Mutex<BTreeMap<String, Entry>> = Mutex::new(BTreeMap::new());

/// Non-cloneable identity owned by exactly one Session runtime. Retiring it is
/// permanent, including when an in-flight router finishes after thread removal.
pub(crate) struct WorkerRegistryOwner { live: Arc<AtomicBool> }
impl Default for WorkerRegistryOwner {
    fn default() -> Self { Self { live: Arc::new(AtomicBool::new(true)) } }
}
impl WorkerRegistryOwner {
    pub(crate) fn retire(&self) {
        self.live.store(false, Ordering::Release);
        if let Ok(mut registries) = REGISTRIES.lock() {
            let owner = Arc::downgrade(&self.live);
            registries.retain(|_, entry| !Weak::ptr_eq(&entry.owner, &owner));
        }
    }
}
impl Drop for WorkerRegistryOwner {
    fn drop(&mut self) { self.retire(); }
}
fn live(entry: &Entry) -> bool {
    entry.owner.upgrade().is_some_and(|owner| owner.load(Ordering::Acquire))
}

pub(crate) fn publish(thread: String, owner: &WorkerRegistryOwner, attestation: serde_json::Value) -> Result<(), String> {
    let mut registries = REGISTRIES.lock().map_err(|_| "worker registry state unavailable")?;
    if !owner.live.load(Ordering::Acquire) { return Err("worker runtime already retired".to_string()); }
    registries.retain(|_, entry| live(entry));
    if !registries.contains_key(&thread) && registries.len() >= 64 {
        return Err("worker attestation capacity exceeded".to_string());
    }
    registries.insert(thread, Entry { owner: Arc::downgrade(&owner.live), attestation });
    Ok(())
}

pub(crate) fn read(thread: &str) -> Option<serde_json::Value> {
    REGISTRIES.lock().ok().and_then(|registries| registries.get(thread)
        .filter(|entry| live(entry)).map(|entry| entry.attestation.clone()))
}

pub(crate) fn contains(thread: &str, owner: &WorkerRegistryOwner) -> Result<bool, String> {
    let registries = REGISTRIES.lock().map_err(|_| "worker registry state unavailable")?;
    Ok(registries.get(thread).is_some_and(|entry| live(entry)
        && Weak::ptr_eq(&entry.owner, &Arc::downgrade(&owner.live))))
}

pub(crate) fn invalidate(thread: &str, owner: &WorkerRegistryOwner) -> Result<(), String> {
    let mut registries = REGISTRIES.lock().map_err(|_| "worker registry state unavailable")?;
    if registries.get(thread).is_some_and(|entry| Weak::ptr_eq(&entry.owner, &Arc::downgrade(&owner.live))) {
        registries.remove(thread);
    }
    Ok(())
}
