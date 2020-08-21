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

//! BABE compatible digest provider

use std::sync::Arc;
use sc_keystore::KeyStorePtr;
use crate::consensus_data_provider::ConsensusDataProvider;
use crate::Error;
use sc_consensus_babe::{
	Config, Epoch, authorship, CompatibleDigestItem, aux_schema::load_epoch_changes,
	register_babe_inherent_data_provider, INTERMEDIATE_KEY, BabeIntermediate,
};
use sp_consensus_babe::{BabeApi, inherents::BabeInherentData};
use sp_inherents::{InherentDataProviders, InherentData};
use sp_runtime::traits::{DigestItemFor, DigestFor, Block as BlockT, Header as _};
use sp_runtime::generic::Digest;
use sc_client_api::AuxStore;
use sp_api::{ProvideRuntimeApi, TransactionFor};
use sc_consensus_epochs::{SharedEpochChanges, descendent_query};
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::BlockImportParams;
use std::borrow::Cow;
use std::any::Any;

/// Provides BABE compatible predigests for inclusion in blocks.
/// Intended to be used with BABE runtimes.
pub struct BabeDigestProvider<B: BlockT, C> {
	/// shared reference to keystore
	keystore: KeyStorePtr,

	/// Shared reference to the client.
	client: Arc<C>,

	/// Shared epoch changes
	epoch_changes: SharedEpochChanges<B, Epoch>,

	/// BABE config, gotten from the runtime.
	config: Config,
}

/// num of blocks per slot
const SLOT_DURATION: u64 = 6;

impl<B, C> BabeDigestProvider<B, C>
	where
		B: BlockT,
		C: AuxStore + ProvideRuntimeApi<B>,
		C::Api: BabeApi<B, Error = sp_blockchain::Error>,
{
	pub fn new(client: Arc<C>, keystore: KeyStorePtr, provider: &InherentDataProviders) -> Result<Self, Error> {
		let config = Config::get_or_compute(&*client)?;
		let epoch_changes = load_epoch_changes::<B, _>(&*client, &config)?;
		register_babe_inherent_data_provider(provider, SLOT_DURATION)?;

		Ok(Self {
			config,
			client,
			keystore,
			epoch_changes,
		})
	}
}

impl<B, C> ConsensusDataProvider<B> for BabeDigestProvider<B, C>
	where
		B: BlockT,
		C: AuxStore + HeaderBackend<B> + HeaderMetadata<B, Error = sp_blockchain::Error> + ProvideRuntimeApi<B>,
		C::Api: BabeApi<B, Error = sp_blockchain::Error>,
{
	type Transaction = TransactionFor<C, B>;

	fn create_digest(&self, parent: &B::Header, inherents: &InherentData) -> Result<DigestFor<B>, Error> {
		log::info!(target: "babe", "Header {:#?}", parent);

		let slot_number = inherents.babe_inherent_data()?;

		let epoch = self.epoch_changes.lock()
			.epoch_data_for_child_of(
				descendent_query(&*self.client),
				&parent.hash(),
				parent.number().clone(),
				slot_number,
				|slot| Epoch::genesis(&self.config, slot),
			)
			.map_err(|e| Error::StringError(format!("failed to fetch epoch data: {}", e)))?
			.ok_or_else(|| {
				log::info!(target: "babe", "no epoch data :(");
				sp_consensus::Error::InvalidAuthoritiesSet
			})?;

		// this is a dev node environment, we should always be able to claim a slot.
		let (predigest, _) = authorship::claim_slot(slot_number, &epoch, &self.keystore)
			.ok_or_else(|| Error::StringError("failed to claim slot for authorship".into()))?;

		Ok(Digest {
			logs: vec![
				<DigestItemFor<B> as CompatibleDigestItem>::babe_pre_digest(predigest),
			],
		})
	}

	fn append_block_import(
		&self,
		parent: &B::Header,
		params: &mut BlockImportParams<B, Self::Transaction>,
		inherents: &InherentData
	) -> Result<(), Error> {
		let slot_number = inherents.babe_inherent_data()?;

		let epoch_descriptor = self.epoch_changes.lock()
			.epoch_descriptor_for_child_of(
				descendent_query(&*self.client),
				&parent.hash(),
				parent.number().clone(),
				slot_number,
			)
			.map_err(|e| Error::StringError(format!("failed to fetch epoch data: {}", e)))?
			.ok_or_else(|| {
				log::info!(target: "babe", "no epoch data :(");
				sp_consensus::Error::InvalidAuthoritiesSet
			})?;

		params.intermediates.insert(
			Cow::from(INTERMEDIATE_KEY),
			Box::new(BabeIntermediate::<B> { epoch_descriptor }) as Box<dyn Any>,
		);

		Ok(())
	}
}
