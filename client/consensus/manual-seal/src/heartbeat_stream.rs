// Library shortcuts

use std::{pin::Pin};
use futures::{
	prelude::*,
	task::{Context, Poll},
};
use tokio::time::{Duration, Instant, Delay};

use crate::rpc::{EngineCommand};

// ---
// Constant Definition

const DEFAULT_TIMEOUT: u64 = 30;
const DEFAULT_MIN_BLOCKTIME: u64 = 1;
const DEFAULT_FINALIZE: bool = false;

// ---
pub struct HeartbeatOptions {
	// the amount of time passed that a new heartbeat block will be generated, in sec.
	pub timeout: u64,
	// the minimum amount of time to pass before generating another block, in sec.
	pub min_blocktime: u64,
	// whether the generated heartbeat block is finalized
	pub finalize: bool,
}

impl Default for HeartbeatOptions {
	fn default() -> Self {
		Self {
			timeout: DEFAULT_TIMEOUT,
			min_blocktime: DEFAULT_MIN_BLOCKTIME,
			finalize: DEFAULT_FINALIZE,
		}
	}
}

pub struct HeartbeatStream<Hash> {
	pool_stream: Box<dyn Stream<Item = EngineCommand<Hash>> + Unpin + Send>,
	delay_future: Delay,
	last_heartbeat: Option<Instant>,
	opts: HeartbeatOptions,
}

impl<Hash> HeartbeatStream<Hash> {
	pub fn new(
		pool_stream: Box<dyn Stream<Item = EngineCommand<Hash>> + Unpin + Send>,
		opts: HeartbeatOptions
	) -> Self {
		if opts.min_blocktime > opts.timeout {
			panic!("Heartbeat options `min_blocktime` value must not be larger than `timeout` value.");
		}
		Self {
			pool_stream,
			delay_future: tokio::time::delay_for(Duration::from_secs(opts.timeout)),
			last_heartbeat: None,
			opts
		}
	}
}

impl<Hash> Stream for HeartbeatStream<Hash> {

	type Item = EngineCommand<Hash>;

	fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
		let mut hbs = self.get_mut();
		match hbs.pool_stream.poll_next_unpin(cx) {
			Poll::Ready(Some(ec)) => {
				if let Some(last_heartbeat) = hbs.last_heartbeat {
					// If the last heartbeat happened within min_blocktime time, we want to wait at least
					//   until `min_blocktime` has passed.
					if Instant::now() - last_heartbeat < Duration::from_secs(hbs.opts.min_blocktime) {
						// We set `delay_future` here so those txs arrived after heartbeats doesn't have to wait
						//   for `timeout`s to get processed, but only `min_blocktime`s.
						hbs.delay_future = tokio::time::delay_for(Duration::from_secs(hbs.opts.min_blocktime));
						return Poll::Pending;
					}
				}

				// reset the timer and delay future
				hbs.delay_future = tokio::time::delay_for(Duration::from_secs(hbs.opts.timeout));
				hbs.last_heartbeat = Some(Instant::now());
				Poll::Ready(Some(ec))
			},

			// The pool stream ends
			Poll::Ready(None) => Poll::Ready(None),

			Poll::Pending => {
				// We check if the delay for heartbeat has reached
				if let Poll::Ready(_) = hbs.delay_future.poll_unpin(cx) {
					// reset the timer and delay future
					hbs.delay_future = tokio::time::delay_for(Duration::from_secs(hbs.opts.timeout));
					hbs.last_heartbeat = Some(Instant::now());

					return Poll::Ready(Some(EngineCommand::SealNewBlock {
						create_empty: true, // heartbeat blocks are empty by definition
						finalize: hbs.opts.finalize,
						parent_hash: None, // QUESTION: no parent hash here? Is this block still conneected with the whole chain?
						sender: None,
					}));
				}
				Poll::Pending
			},
		}
	}
}
