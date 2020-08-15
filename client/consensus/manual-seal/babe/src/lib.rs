// This file is part of Substrate.

// Copyright (C) 2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! A manual sealing engine: the engine listens for rpc calls to seal blocks and create forks.
//! This is suitable for a testing environment.


use std::collections::HashMap;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::{Future, FutureExt, Stream, StreamExt, TryFutureExt};

use sc_client_api::{AuxStore, Backend, Finalizer};
use sc_consensus_babe::{
	authorship, aux_schema::load_epoch_changes, CompatibleDigestItem,
	Config, Epoch,
};
use sc_consensus_babe as sc_babe;
use sc_consensus_epochs::descendent_query;
use sc_consensus_manual_seal::{
	rpc, CreatedBlock, EngineCommand, Error, finalize_block,
	FinalizeBlockParams, MAX_PROPOSAL_DURATION,
};
use sc_keystore::KeyStorePtr;
use sc_transaction_pool::txpool;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::{
	BlockImport, BlockImportParams, BlockOrigin, Environment, ForkChoiceStrategy,
	ImportResult, Proposer, SelectChain,
};
use sp_consensus_babe::inherents::BabeInherentData;
use sp_inherents::InherentDataProviders;
use sp_runtime::{
	generic::Digest,
	traits::{Block as BlockT, Header},
};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::DigestItemFor;

/// Params required to start the instant sealing authorship task.
pub struct BabeManualSealParams<B, BI, E, C, A: txpool::ChainApi, SC, CS> {
	/// Block import instance for well. importing blocks.
	pub block_import: BI,

	/// The environment we are producing blocks for.
	pub env: E,

	/// Client instance
	pub client: Arc<C>,

	/// Shared reference to the transaction pool.
	pub pool: Arc<txpool::Pool<A>>,

	/// Stream<Item = EngineCommands>, Basically the receiving end of a channel for sending commands to
	/// the authorship task.
	pub commands_stream: CS,

	/// SelectChain strategy.
	pub select_chain: SC,

	/// Shared reference to the keystore.
	pub keystore: KeyStorePtr,

	/// Provider for inherents to include in blocks.
	pub inherent_data_providers: InherentDataProviders,

	/// Phantom type to pin the marker type
	pub phantom: PhantomData<B>,
}

type Result<T> = std::result::Result<T, Error>;


const SLOT_DURATION: u64 = 6;

pub fn start_babe_manual_seal<B, BI, CB, E, C, A, SC, CS>(
	BabeManualSealParams {
		mut block_import,
		mut env,
		client,
		pool,
		mut commands_stream,
		select_chain,
		inherent_data_providers,
		keystore,
		..
	}: BabeManualSealParams<B, BI, E, C, A, SC, CS>
) -> Result<Pin<Box<dyn Future<Output=Result<()>>>>>
	where
		A: txpool::ChainApi<Block=B> + 'static,
		B: BlockT + 'static,
		BI: BlockImport<B, Error=sp_consensus::Error, Transaction=sp_api::TransactionFor<C, B>>
		+ Send + Sync + 'static,
		C: AuxStore + HeaderBackend<B> + HeaderMetadata<B, Error=sp_blockchain::Error> + Finalizer<B, CB>
		+ ProvideRuntimeApi<B> + 'static,
		C::Api: sp_consensus_babe::BabeApi<B, Error=sp_blockchain::Error>,
		CB: Backend<B> + 'static,
		E: Environment<B> + Send + 'static,
		E::Error: std::fmt::Display,
		<E::Proposer as Proposer<B>>::Error: std::fmt::Display,
		CS: Stream<Item=EngineCommand<<B as BlockT>::Hash>> + Unpin + Send + 'static,
		SC: SelectChain<B> + 'static,
{
	let babe_config = Config::get_or_compute(&*client)?;
	let epoch_changes = load_epoch_changes::<B, _>(&*client, &babe_config)?;
	sc_babe::register_babe_inherent_data_provider(&inherent_data_providers, SLOT_DURATION)?;

	let future = async move {
		while let Some(command) = commands_stream.next().await {
			match command {
				EngineCommand::SealNewBlock {
					create_empty,
					finalize,
					parent_hash,
					mut sender,
				} => {
					let future = async {
						if pool.validated_pool().status().ready == 0 && !create_empty {
							return Err(Error::EmptyTransactionPool);
						}

						// get the header to build this new block on.
						// use the parent_hash supplied via `EngineCommand`
						// or fetch the best_block.
						let header = match parent_hash {
							Some(hash) => {
								match client.header(BlockId::Hash(hash))? {
									Some(header) => header,
									None => return Err(Error::BlockNotFound(format!("{}", hash))),
								}
							}
							None => select_chain.best_chain()?
						};

						let proposer = env.init(&header)
							.map_err(|err| Error::StringError(format!("{}", err)))
							.await?;
						let id = inherent_data_providers.create_inherent_data()?;
						let inherents_len = id.len();
						let slot_number = id.babe_inherent_data()?;

						let epoch = epoch_changes.lock()
							.epoch_data_for_child_of(
								descendent_query(&*client),
								&header.hash(),
								header.number().clone(),
								slot_number,
								|slot| Epoch::genesis(&babe_config, slot),
							)
							.map_err(|e| Error::StringError(format!("failed to fetch epoch data: {}", e)))?
							.ok_or_else(|| sp_consensus::Error::InvalidAuthoritiesSet)?;
						// this is a dev node environment, we should always be able to claim a slot.
						let (predigest, _) = authorship::claim_slot(slot_number, &epoch, &keystore)
							.ok_or_else(|| Error::StringError("failed to claim slot for authorship".into()))?;

						let digest = Digest {
							logs: vec![
								<DigestItemFor<B> as CompatibleDigestItem>::babe_pre_digest(predigest),
							],
						};
						let max_duration = Duration::from_secs(MAX_PROPOSAL_DURATION);

						let proposal = proposer.propose(id, digest, max_duration, false.into())
							.map_err(|err| Error::StringError(format!("{}", err)))
							.await?;

						if proposal.block.extrinsics().len() == inherents_len && !create_empty {
							return Err(Error::EmptyTransactionPool);
						}

						let (header, body) = proposal.block.deconstruct();
						let mut params = BlockImportParams::new(BlockOrigin::Own, header.clone());
						params.body = Some(body);
						params.finalized = finalize;
						params.fork_choice = Some(ForkChoiceStrategy::LongestChain);

						match block_import.import_block(params, HashMap::new())? {
							ImportResult::Imported(aux) => {
								Ok(CreatedBlock { hash: <B as BlockT>::Header::hash(&header), aux })
							}
							other => Err(other.into()),
						}
					};

					rpc::send_result(&mut sender, future.await);
				}
				EngineCommand::FinalizeBlock { hash, sender, justification } => {
					finalize_block(
						FinalizeBlockParams {
							hash,
							sender,
							justification,
							finalizer: client.clone(),
							_phantom: PhantomData,
						}
					).await
				}
			}
		};

		Ok(())
	}.boxed();

	Ok(future)
}