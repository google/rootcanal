use std::sync::Arc;
use std::task::{Wake, Waker};

pub use pin_utils::pin_mut as pin;

// Create a `Waker` that
// does nothing when `wake`
// is called
pub fn noop_waker() -> Waker {
    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    Arc::new(NoopWaker).into()
}
