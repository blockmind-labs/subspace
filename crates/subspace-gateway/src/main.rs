//! Subspace gateway implementation.

mod commands;
mod node_client;
mod piece_getter;
mod piece_validator;

use crate::commands::{init_logger, raise_fd_limit, set_exit_on_panic, Command};
use clap::Parser;
use std::time::Duration;
use tokio::runtime::Builder;
use tracing::info;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// During shutdown, the amount of time the tokio runtime will wait for async tasks to yield, or
/// `spawn_blocking()` tasks to complete, before exiting the process.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);

fn main() -> anyhow::Result<()> {
    set_exit_on_panic();
    init_logger();
    raise_fd_limit();

    // TODO: consider only using the executor for commands which run async code.
    let runtime = Builder::new_multi_thread().enable_all().build()?;

    runtime.block_on(tokio_main())?;

    // Usually tasks finish within a few seconds, but if a task is slow, let the user know what
    // we're waiting for.
    info!("Waiting for running tasks to finish...");
    runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);

    Ok(())
}

/// The main future that's run by tokio.
async fn tokio_main() -> anyhow::Result<()> {
    set_exit_on_panic();
    init_logger();
    raise_fd_limit();

    let command = Command::parse();

    match command {
        Command::Run(run_options) => {
            commands::run::run(run_options).await?;
        }
    }
    Ok(())
}
