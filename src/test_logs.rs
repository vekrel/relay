// Test-only log capture, shared by every test that greps logs for secrets.
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);
impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `f` and returns every log line (all levels) the test binary has emitted so far.
/// A global subscriber, because tracing caches callsite interest across threads and a
/// scoped one misses events when parallel tests hit the same callsite first.
pub fn capture_logs(f: impl FnOnce()) -> String {
    static BUF: std::sync::OnceLock<Buf> = std::sync::OnceLock::new();
    let buf = BUF.get_or_init(|| {
        let buf = Buf::default();
        let w = buf.clone();
        let sub = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || w.clone())
            .finish();
        tracing::subscriber::set_global_default(sub).expect("only this test sets one");
        buf
    });
    f();
    String::from_utf8(buf.0.lock().unwrap().clone()).unwrap()
}
