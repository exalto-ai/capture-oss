//! Defense in depth, not the parser fix: JSON transcript parsing is bounded
//! by the vendored spansy patch (see vendor/tlsn-utils/README.md), which the
//! `json_stack_safety` suite proves on default-runtime-sized stacks. The
//! larger worker stack remains as containment so that any future
//! input-proportional stack consumer returns an error for one request instead
//! of aborting every in-flight capture in the daemon process.
const WORKER_STACK_BYTES: usize = 32 << 20;

fn main() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(WORKER_STACK_BYTES)
        .build()?
        .block_on(capture_server::run_daemon())
}
