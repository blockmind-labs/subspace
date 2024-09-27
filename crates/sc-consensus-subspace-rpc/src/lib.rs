// Copyright (C) 2020-2021 Parity Technologies (UK) Ltd.
// Copyright (C) 2021 Subspace Labs, Inc.
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

//! RPC api for Subspace.

#![feature(try_blocks)]

use futures::channel::mpsc;
use futures::{future, stream, FutureExt, StreamExt};
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::{ErrorObject, ErrorObjectOwned};
use jsonrpsee::PendingSubscriptionSink;
use parking_lot::Mutex;
use sc_client_api::{AuxStore, BlockBackend};
use sc_consensus_subspace::archiver::{
    recreate_genesis_segment, ArchivedSegmentNotification, SegmentHeadersStore,
};
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::slot_worker::{
    NewSlotNotification, RewardSigningNotification, SubspaceSyncOracle,
};
use sc_rpc::utils::pipe_from_stream;
use sc_rpc::SubscriptionTaskExecutor;
use sc_rpc_api::{DenyUnsafe, UnsafeRpcError};
use sc_utils::mpsc::TracingUnboundedSender;
use schnellru::{ByLength, LruMap};
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_consensus_subspace::{ChainConstants, SubspaceApi};
use sp_core::H256;
use sp_objects::ObjectsApi;
use sp_runtime::traits::Block as BlockT;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use subspace_archiving::archiver::NewArchivedSegment;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::objects::{GlobalObject, GlobalObjectMapping};
use subspace_core_primitives::{
    Blake3Hash, BlockHash, HistorySize, Piece, PieceIndex, PublicKey, SegmentHeader, SegmentIndex,
    SlotNumber, Solution,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_networking::libp2p::Multiaddr;
use subspace_rpc_primitives::{
    FarmerAppInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
    MAX_SEGMENT_HEADERS_PER_REQUEST,
};
use tracing::{debug, error, warn};

const SUBSPACE_ERROR: i32 = 9000;
/// This is essentially equal to expected number of votes per block, one more is added implicitly by
/// the fact that channel sender exists
const SOLUTION_SENDER_CHANNEL_CAPACITY: usize = 9;
const REWARD_SIGNING_TIMEOUT: Duration = Duration::from_millis(500);

/// The number of object mappings to include in each subscription response message.
///
/// This is a tradeoff between `RPC_DEFAULT_MESSAGE_CAPACITY_PER_CONN` and
/// `RPC_DEFAULT_MAX_RESPONSE_SIZE_MB`. We estimate 500K mappings per segment,
///  and the minimum hex-encoded mapping size is 88 bytes.
// TODO: make this into a CLI option, or calculate this from other CLI options
const OBJECT_MAPPING_BATCH_SIZE: usize = 10_000;

/// The maximum number of object hashes allowed in a subscription filter.
///
/// Each hash takes up 64 bytes in JSON, and 32 bytes in memory.
// TODO: make this into a CLI option, or calculate this from other CLI options
const MAX_OBJECT_HASHES_PER_SUBSCRIPTION: usize = 1000;

// TODO: More specific errors instead of `StringError`
/// Top-level error type for the RPC handler.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Errors that can be formatted as a String
    #[error("{0}")]
    StringError(String),
    /// Call to an unsafe RPC was denied.
    #[error(transparent)]
    UnsafeRpcCalled(#[from] UnsafeRpcError),
}

impl From<Error> for ErrorObjectOwned {
    fn from(error: Error) -> Self {
        match error {
            Error::StringError(e) => ErrorObject::owned(SUBSPACE_ERROR + 1, e, None::<()>),
            Error::UnsafeRpcCalled(e) => e.into(),
        }
    }
}

// TESTING ONLY, DO NOT MERGE
/// Hex-encoded object data.
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize)]
#[serde(into = "VerboseHexData")]
pub struct HexData(pub Vec<u8>);

impl std::fmt::Debug for HexData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl From<HexData> for VerboseHexData {
    fn from(object: HexData) -> Self {
        Self {
            len: object.0.len(),
            utf8: Self::summarise(String::from_utf8_lossy(&object.0).to_string()),
            hex: Self::summarise(hex::encode(object.0)),
        }
    }
}

/// Lossy summary serialization of an object stored in the history of the blockchain
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, serde::Serialize)]
pub struct VerboseHexData {
    pub len: usize,
    pub utf8: String,
    pub hex: String,
}

impl VerboseHexData {
    pub const MAX_SUMMARY_LEN: usize = 100;
    pub fn summarise(s: String) -> String {
        if s.len() > Self::MAX_SUMMARY_LEN + "...".len() {
            let end_part = s
                .chars()
                .rev()
                .take(Self::MAX_SUMMARY_LEN / 2)
                .collect::<String>();
            format!(
                "{}...{}",
                s.chars()
                    .take(Self::MAX_SUMMARY_LEN / 2)
                    .collect::<String>(),
                end_part.chars().rev().collect::<String>()
            )
        } else {
            s
        }
    }
}

/// Provides rpc methods for interacting with Subspace.
#[rpc(client, server)]
pub trait SubspaceRpcApi {
    /// Get metadata necessary for farmer operation
    #[method(name = "subspace_getFarmerAppInfo")]
    fn get_farmer_app_info(&self) -> Result<FarmerAppInfo, Error>;

    #[method(name = "subspace_submitSolutionResponse")]
    fn submit_solution_response(&self, solution_response: SolutionResponse) -> Result<(), Error>;

    /// Slot info subscription
    #[subscription(
        name = "subspace_subscribeSlotInfo" => "subspace_slot_info",
        unsubscribe = "subspace_unsubscribeSlotInfo",
        item = SlotInfo,
    )]
    fn subscribe_slot_info(&self);

    /// Sign block subscription
    #[subscription(
        name = "subspace_subscribeRewardSigning" => "subspace_reward_signing",
        unsubscribe = "subspace_unsubscribeRewardSigning",
        item = RewardSigningInfo,
    )]
    fn subscribe_reward_signing(&self);

    #[method(name = "subspace_submitRewardSignature")]
    fn submit_reward_signature(
        &self,
        reward_signature: RewardSignatureResponse,
    ) -> Result<(), Error>;

    /// Archived segment header subscription
    #[subscription(
        name = "subspace_subscribeArchivedSegmentHeader" => "subspace_archived_segment_header",
        unsubscribe = "subspace_unsubscribeArchivedSegmentHeader",
        item = SegmentHeader,
    )]
    fn subscribe_archived_segment_header(&self);

    #[method(name = "subspace_segmentHeaders")]
    async fn segment_headers(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<SegmentHeader>>, Error>;

    #[method(name = "subspace_piece")]
    async fn piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, Error>;

    #[method(name = "subspace_acknowledgeArchivedSegmentHeader")]
    async fn acknowledge_archived_segment_header(
        &self,
        segment_index: SegmentIndex,
    ) -> Result<(), Error>;

    #[method(name = "subspace_lastSegmentHeaders")]
    async fn last_segment_headers(&self, limit: u32) -> Result<Vec<Option<SegmentHeader>>, Error>;

    /// Block/transaction archived object mappings subscription
    #[subscription(
        name = "subspace_subscribeArchivedObjectMappings" => "subspace_archived_object_mappings",
        unsubscribe = "subspace_unsubscribeArchivedObjectMappings",
        item = GlobalObjectMapping,
    )]
    fn subscribe_archived_object_mappings(&self);

    /// Filtered block/transaction archived object mappings subscription
    #[subscription(
        name = "subspace_subscribeFilteredObjectMappings" => "subspace_filtered_object_mappings",
        unsubscribe = "subspace_unsubscribeFilteredObjectMappings",
        item = GlobalObjectMapping,
    )]
    fn subscribe_filtered_object_mappings(&self, hashes: Vec<Blake3Hash>);

    #[method(name = "subspace_fetchArchivedObjects")]
    async fn fetch_archived_objects(
        &self,
        mappings: Vec<subspace_core_primitives::objects::GlobalObject>,
    ) -> Result<Vec<Option<HexData>>, Error>;
}

#[derive(Default)]
struct ArchivedSegmentHeaderAcknowledgementSenders {
    segment_index: SegmentIndex,
    senders: HashMap<u64, TracingUnboundedSender<()>>,
}

#[derive(Default)]
struct BlockSignatureSenders {
    current_hash: H256,
    senders: Vec<async_oneshot::Sender<RewardSignatureResponse>>,
}

/// In-memory cache of last archived segment, such that when request comes back right after
/// archived segment notification, RPC server is able to answer quickly.
///
/// We store weak reference, such that archived segment is not persisted for longer than
/// necessary occupying RAM.
#[derive(Default, Debug)]
struct CachedArchivedSegment(std::collections::BTreeMap<SegmentIndex, Arc<NewArchivedSegment>>);

impl CachedArchivedSegment {
    fn insert(&mut self, segment: Arc<NewArchivedSegment>) {
        self.0
            .insert(segment.segment_header.segment_index(), segment);
    }

    fn get(&self) -> Vec<Arc<NewArchivedSegment>> {
        self.0.values().map(Arc::clone).collect()
    }

    fn segment_indexes(&self) -> Vec<SegmentIndex> {
        self.0.keys().cloned().collect()
    }
}

/// Subspace RPC configuration
pub struct SubspaceRpcConfig<Client, SO, AS>
where
    SO: SyncOracle + Send + Sync + Clone + 'static,
    AS: AuxStore + Send + Sync + 'static,
{
    /// Substrate client
    pub client: Arc<Client>,
    /// Task executor that is being used by RPC subscriptions
    pub subscription_executor: SubscriptionTaskExecutor,
    /// New slot notification stream
    pub new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    /// Reward signing notification stream
    pub reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    /// Archived segment notification stream
    pub archived_segment_notification_stream:
        SubspaceNotificationStream<ArchivedSegmentNotification>,
    /// DSN bootstrap nodes
    pub dsn_bootstrap_nodes: Vec<Multiaddr>,
    /// Segment headers store
    pub segment_headers_store: SegmentHeadersStore<AS>,
    /// Subspace sync oracle
    pub sync_oracle: SubspaceSyncOracle<SO>,
    /// Signifies whether a potentially unsafe RPC should be denied
    pub deny_unsafe: DenyUnsafe,
    /// Kzg instance
    pub kzg: Kzg,
    /// Erasure coding instance
    pub erasure_coding: ErasureCoding,

    // TESTING ONLY, DO NOT MERGE
    /// DSN object piece getter
    pub object_piece_getter:
        Arc<dyn subspace_data_retrieval::piece_getter::ObjectPieceGetter + Send + Sync + 'static>,
}

/// Implements the [`SubspaceRpcApiServer`] trait for interacting with Subspace.
pub struct SubspaceRpc<Block, Client, SO, AS>
where
    Block: BlockT,
    SO: SyncOracle + Send + Sync + Clone + 'static,
{
    client: Arc<Client>,
    subscription_executor: SubscriptionTaskExecutor,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegmentNotification>,
    #[allow(clippy::type_complexity)]
    solution_response_senders: Arc<Mutex<LruMap<SlotNumber, mpsc::Sender<Solution<PublicKey>>>>>,
    reward_signature_senders: Arc<Mutex<BlockSignatureSenders>>,
    dsn_bootstrap_nodes: Vec<Multiaddr>,
    segment_headers_store: SegmentHeadersStore<AS>,
    cached_archived_segment: Arc<Mutex<CachedArchivedSegment>>,
    archived_segment_acknowledgement_senders:
        Arc<Mutex<ArchivedSegmentHeaderAcknowledgementSenders>>,
    next_subscription_id: AtomicU64,
    sync_oracle: SubspaceSyncOracle<SO>,
    genesis_hash: BlockHash,
    chain_constants: ChainConstants,
    max_pieces_in_sector: u16,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    deny_unsafe: DenyUnsafe,
    _block: PhantomData<Block>,
    object_fetcher: subspace_data_retrieval::object_fetcher::ObjectFetcher,
}

/// [`SubspaceRpc`] is used for notifying subscribers about arrival of new slots and for
/// submission of solutions (or lack thereof).
///
/// Internally every time slot notifier emits information about new slot, notification is sent to
/// every subscriber, after which RPC server waits for the same number of
/// `subspace_submitSolutionResponse` requests with `SolutionResponse` in them or until
/// timeout is exceeded. The first valid solution for a particular slot wins, others are ignored.
impl<Block, Client, SO, AS> SubspaceRpc<Block, Client, SO, AS>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: SubspaceApi<Block, PublicKey>,
    SO: SyncOracle + Send + Sync + Clone + 'static,
    AS: AuxStore + Send + Sync + 'static,
{
    /// Creates a new instance of the `SubspaceRpc` handler.
    pub fn new(config: SubspaceRpcConfig<Client, SO, AS>) -> Result<Self, ApiError> {
        let info = config.client.info();
        let best_hash = info.best_hash;
        let genesis_hash = BlockHash::try_from(info.genesis_hash.as_ref())
            .expect("Genesis hash must always be convertable into BlockHash; qed");
        let runtime_api = config.client.runtime_api();
        let chain_constants = runtime_api.chain_constants(best_hash)?;
        // While the number can technically change in runtime, farmer will not adjust to it on the
        // fly and previous value will remain valid (number only expected to increase), so it is
        // fine to query it only once
        let max_pieces_in_sector = runtime_api.max_pieces_in_sector(best_hash)?;
        let block_authoring_delay = u64::from(chain_constants.block_authoring_delay());
        let block_authoring_delay = usize::try_from(block_authoring_delay)
            .expect("Block authoring delay will never exceed usize on any platform; qed");
        let solution_response_senders_capacity = u32::try_from(block_authoring_delay)
            .expect("Always a tiny constant in the protocol; qed");

        Ok(Self {
            client: config.client,
            subscription_executor: config.subscription_executor,
            new_slot_notification_stream: config.new_slot_notification_stream,
            reward_signing_notification_stream: config.reward_signing_notification_stream,
            archived_segment_notification_stream: config.archived_segment_notification_stream,
            solution_response_senders: Arc::new(Mutex::new(LruMap::new(ByLength::new(
                solution_response_senders_capacity,
            )))),
            reward_signature_senders: Arc::default(),
            dsn_bootstrap_nodes: config.dsn_bootstrap_nodes,
            segment_headers_store: config.segment_headers_store,
            cached_archived_segment: Arc::default(),
            archived_segment_acknowledgement_senders: Arc::default(),
            next_subscription_id: AtomicU64::default(),
            sync_oracle: config.sync_oracle,
            genesis_hash,
            chain_constants,
            max_pieces_in_sector,
            kzg: config.kzg,
            erasure_coding: config.erasure_coding.clone(),
            deny_unsafe: config.deny_unsafe,
            _block: PhantomData,
            object_fetcher: subspace_data_retrieval::object_fetcher::ObjectFetcher::new(
                config.object_piece_getter,
                config.erasure_coding,
                Some(5 * 1024 * 1024),
            ),
        })
    }
}

#[async_trait]
impl<Block, Client, SO, AS> SubspaceRpcApiServer for SubspaceRpc<Block, Client, SO, AS>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + HeaderBackend<Block>
        + BlockBackend<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: ObjectsApi<Block>,
    SO: SyncOracle + Send + Sync + Clone + 'static,
    AS: AuxStore + Send + Sync + 'static,
{
    fn get_farmer_app_info(&self) -> Result<FarmerAppInfo, Error> {
        let last_segment_index = self
            .segment_headers_store
            .max_segment_index()
            .unwrap_or(SegmentIndex::ZERO);

        let farmer_app_info: Result<FarmerAppInfo, ApiError> = try {
            let chain_constants = &self.chain_constants;
            let protocol_info = FarmerProtocolInfo {
                history_size: HistorySize::from(last_segment_index),
                max_pieces_in_sector: self.max_pieces_in_sector,
                recent_segments: chain_constants.recent_segments(),
                recent_history_fraction: chain_constants.recent_history_fraction(),
                min_sector_lifetime: chain_constants.min_sector_lifetime(),
            };

            FarmerAppInfo {
                genesis_hash: self.genesis_hash,
                dsn_bootstrap_nodes: self.dsn_bootstrap_nodes.clone(),
                syncing: self.sync_oracle.is_major_syncing(),
                farming_timeout: chain_constants
                    .slot_duration()
                    .as_duration()
                    .mul_f64(SlotNumber::from(chain_constants.block_authoring_delay()) as f64),
                protocol_info,
            }
        };

        farmer_app_info.map_err(|error| {
            error!("Failed to get data from runtime API: {}", error);
            Error::StringError("Internal error".to_string())
        })
    }

    fn submit_solution_response(&self, solution_response: SolutionResponse) -> Result<(), Error> {
        self.deny_unsafe.check_if_safe()?;

        let slot = solution_response.slot_number;
        let mut solution_response_senders = self.solution_response_senders.lock();

        let success = solution_response_senders
            .peek_mut(&slot)
            .and_then(|sender| sender.try_send(solution_response.solution).ok())
            .is_some();

        if !success {
            warn!(
                %slot,
                "Solution was ignored, likely because farmer was too slow"
            );

            return Err(Error::StringError("Solution was ignored".to_string()));
        }

        Ok(())
    }

    fn subscribe_slot_info(&self, pending: PendingSubscriptionSink) {
        let executor = self.subscription_executor.clone();
        let solution_response_senders = self.solution_response_senders.clone();
        let allow_solutions = self.deny_unsafe.check_if_safe().is_ok();

        let handle_slot_notification = move |new_slot_notification| {
            let NewSlotNotification {
                new_slot_info,
                mut solution_sender,
            } = new_slot_notification;

            let slot_number = SlotNumber::from(new_slot_info.slot);

            // Only handle solution responses in case unsafe APIs are allowed
            if allow_solutions {
                // Store solution sender so that we can retrieve it when solution comes from
                // the farmer
                let mut solution_response_senders = solution_response_senders.lock();
                if solution_response_senders.peek(&slot_number).is_none() {
                    let (response_sender, mut response_receiver) =
                        mpsc::channel(SOLUTION_SENDER_CHANNEL_CAPACITY);

                    solution_response_senders.insert(slot_number, response_sender);

                    // Wait for solutions and transform proposed proof of space solutions
                    // into data structure `sc-consensus-subspace` expects
                    let forward_solution_fut = async move {
                        while let Some(solution) = response_receiver.next().await {
                            let public_key = solution.public_key;
                            let sector_index = solution.sector_index;

                            let solution = Solution {
                                public_key,
                                reward_address: solution.reward_address,
                                sector_index,
                                history_size: solution.history_size,
                                piece_offset: solution.piece_offset,
                                record_commitment: solution.record_commitment,
                                record_witness: solution.record_witness,
                                chunk: solution.chunk,
                                chunk_witness: solution.chunk_witness,
                                proof_of_space: solution.proof_of_space,
                            };

                            if solution_sender.try_send(solution).is_err() {
                                warn!(
                                    slot = %slot_number,
                                    %sector_index,
                                    %public_key,
                                    "Solution receiver is closed, likely because farmer was too slow"
                                );
                            }
                        }
                    };

                    executor.spawn(
                        "subspace-slot-info-forward",
                        Some("rpc"),
                        Box::pin(forward_solution_fut),
                    );
                }
            }

            let global_challenge = new_slot_info
                .proof_of_time
                .derive_global_randomness()
                .derive_global_challenge(slot_number);

            // This will be sent to the farmer
            SlotInfo {
                slot_number,
                global_challenge,
                solution_range: new_slot_info.solution_range,
                voting_solution_range: new_slot_info.voting_solution_range,
            }
        };
        let stream = self
            .new_slot_notification_stream
            .subscribe()
            .map(handle_slot_notification);

        self.subscription_executor.spawn(
            "subspace-slot-info-subscription",
            Some("rpc"),
            pipe_from_stream(pending, stream).boxed(),
        );
    }

    fn subscribe_reward_signing(&self, pending: PendingSubscriptionSink) {
        if self.deny_unsafe.check_if_safe().is_err() {
            debug!("Unsafe subscribe_reward_signing ignored");
            return;
        }

        let executor = self.subscription_executor.clone();
        let reward_signature_senders = self.reward_signature_senders.clone();

        let stream = self.reward_signing_notification_stream.subscribe().map(
            move |reward_signing_notification| {
                let RewardSigningNotification {
                    hash,
                    public_key,
                    signature_sender,
                } = reward_signing_notification;

                let (response_sender, response_receiver) = async_oneshot::oneshot();

                // Store signature sender so that we can retrieve it when solution comes from
                // the farmer
                {
                    let mut reward_signature_senders = reward_signature_senders.lock();

                    if reward_signature_senders.current_hash != hash {
                        reward_signature_senders.current_hash = hash;
                        reward_signature_senders.senders.clear();
                    }

                    reward_signature_senders.senders.push(response_sender);
                }

                // Wait for solutions and transform proposed proof of space solutions into
                // data structure `sc-consensus-subspace` expects
                let forward_signature_fut = async move {
                    if let Ok(reward_signature) = response_receiver.await {
                        if let Some(signature) = reward_signature.signature {
                            let _ = signature_sender.unbounded_send(signature);
                        }
                    }
                };

                // Run above future with timeout
                executor.spawn(
                    "subspace-block-signing-forward",
                    Some("rpc"),
                    future::select(
                        futures_timer::Delay::new(REWARD_SIGNING_TIMEOUT),
                        Box::pin(forward_signature_fut),
                    )
                    .map(|_| ())
                    .boxed(),
                );

                // This will be sent to the farmer
                RewardSigningInfo {
                    hash: hash.into(),
                    public_key,
                }
            },
        );

        self.subscription_executor.spawn(
            "subspace-block-signing-subscription",
            Some("rpc"),
            pipe_from_stream(pending, stream).boxed(),
        );
    }

    fn submit_reward_signature(
        &self,
        reward_signature: RewardSignatureResponse,
    ) -> Result<(), Error> {
        self.deny_unsafe.check_if_safe()?;

        let reward_signature_senders = self.reward_signature_senders.clone();

        // TODO: This doesn't track what client sent a solution, allowing some clients to send
        //  multiple (https://github.com/paritytech/jsonrpsee/issues/452)
        let mut reward_signature_senders = reward_signature_senders.lock();

        if reward_signature_senders.current_hash == reward_signature.hash.into() {
            if let Some(mut sender) = reward_signature_senders.senders.pop() {
                let _ = sender.send(reward_signature);
            }
        }

        Ok(())
    }

    fn subscribe_archived_segment_header(&self, pending: PendingSubscriptionSink) {
        let archived_segment_acknowledgement_senders =
            self.archived_segment_acknowledgement_senders.clone();

        let cached_archived_segment = Arc::clone(&self.cached_archived_segment);
        let subscription_id = self.next_subscription_id.fetch_add(1, Ordering::Relaxed);
        let allow_acknowledgements = self.deny_unsafe.check_if_safe().is_ok();

        let stream = self
            .archived_segment_notification_stream
            .subscribe()
            .filter_map(move |archived_segment_notification| {
                let ArchivedSegmentNotification {
                    archived_segment,
                    acknowledgement_sender,
                } = archived_segment_notification;

                let segment_index = archived_segment.segment_header.segment_index();

                // Store acknowledgment sender so that we can retrieve it when acknowledgement
                // comes from the farmer, but only if unsafe APIs are allowed
                let maybe_archived_segment_header = if allow_acknowledgements {
                    let mut archived_segment_acknowledgement_senders =
                        archived_segment_acknowledgement_senders.lock();

                    if archived_segment_acknowledgement_senders.segment_index != segment_index {
                        archived_segment_acknowledgement_senders.segment_index = segment_index;
                        archived_segment_acknowledgement_senders.senders.clear();
                    }

                    let maybe_archived_segment_header =
                        match archived_segment_acknowledgement_senders
                            .senders
                            .entry(subscription_id)
                        {
                            Entry::Occupied(_) => {
                                // No need to do anything, farmer is processing request
                                None
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(acknowledgement_sender);

                                // This will be sent to the farmer
                                Some(archived_segment.segment_header)
                            }
                        };

                    cached_archived_segment
                        .lock()
                        .insert(archived_segment.clone());

                    maybe_archived_segment_header
                } else {
                    // In case unsafe APIs are not allowed, just return segment header without
                    // requiring it to be acknowledged
                    Some(archived_segment.segment_header)
                };

                Box::pin(async move { maybe_archived_segment_header })
            });

        let archived_segment_acknowledgement_senders =
            self.archived_segment_acknowledgement_senders.clone();
        let fut = async move {
            pipe_from_stream(pending, stream).await;

            let mut archived_segment_acknowledgement_senders =
                archived_segment_acknowledgement_senders.lock();

            archived_segment_acknowledgement_senders
                .senders
                .remove(&subscription_id);
        };

        self.subscription_executor.spawn(
            "subspace-archived-segment-header-subscription",
            Some("rpc"),
            fut.boxed(),
        );
    }

    async fn acknowledge_archived_segment_header(
        &self,
        segment_index: SegmentIndex,
    ) -> Result<(), Error> {
        self.deny_unsafe.check_if_safe()?;

        let archived_segment_acknowledgement_senders =
            self.archived_segment_acknowledgement_senders.clone();

        let maybe_sender = {
            let mut archived_segment_acknowledgement_senders_guard =
                archived_segment_acknowledgement_senders.lock();

            (archived_segment_acknowledgement_senders_guard.segment_index == segment_index)
                .then(|| {
                    let last_key = *archived_segment_acknowledgement_senders_guard
                        .senders
                        .keys()
                        .next()?;

                    archived_segment_acknowledgement_senders_guard
                        .senders
                        .remove(&last_key)
                })
                .flatten()
        };

        if let Some(sender) = maybe_sender {
            if let Err(error) = sender.unbounded_send(()) {
                if !error.is_closed() {
                    warn!("Failed to acknowledge archived segment: {error}");
                }
            }
        }

        debug!(%segment_index, "Acknowledged archived segment.");

        Ok(())
    }

    // Note: this RPC uses the cached archived segment, which is only updated by archived segments subscriptions
    async fn piece(&self, requested_piece_index: PieceIndex) -> Result<Option<Piece>, Error> {
        use subspace_data_retrieval::piece_getter::ObjectPieceGetter;

        self.deny_unsafe.check_if_safe()?;

        let cached_archive_segments = {
            let cached_archived_segments = self.cached_archived_segment.lock().get();

            match cached_archived_segments
                .get_piece(requested_piece_index)
                .await
            {
                Ok(Some(piece)) => return Ok(Some(piece)),
                Ok(None) | Err(_) => {
                    if requested_piece_index > SegmentIndex::ZERO.last_piece_index() {
                        return Ok(None);
                    }

                    // TODO: handle multiple requests recreating the genesis segment at the same time
                    debug!(%requested_piece_index, "Re-creating genesis segment on demand");

                    // Try to re-create genesis segment on demand
                    let client = self.client.clone();
                    let kzg = self.kzg.clone();
                    let erasure_coding = self.erasure_coding.clone();
                    match tokio::task::spawn_blocking(move || {
                        recreate_genesis_segment(&*client, kzg, erasure_coding)
                            .map_err(|_error| "genesis segment recreation failed")
                    })
                    .await
                    {
                        Ok(Ok(Some(archived_segment))) => {
                            let mut cached_archived_segments = self.cached_archived_segment.lock();

                            let archived_segment = Arc::<NewArchivedSegment>::new(archived_segment);
                            cached_archived_segments.insert(archived_segment.clone());
                            cached_archived_segments.get()
                        }
                        Ok(Ok(None)) => {
                            return Ok(None);
                        }
                        Ok(Err(error)) => {
                            error!(%error, "Failed to re-create genesis segment");

                            return Err(Error::StringError(
                                "Failed to re-create genesis segment".to_string(),
                            ));
                        }
                        Err(join_error) => match join_error.try_into_panic() {
                            Ok(panic) => {
                                std::panic::resume_unwind(panic);
                            }
                            Err(cancelled) => {
                                error!(%cancelled, "Task re-creating the genesis segment was cancelled");
                                return Err(Error::StringError(
                                        format!("Task re-creating the genesis segment was cancelled: {cancelled}"),
                                    ));
                            }
                        },
                    }
                }
            }
        };

        cached_archive_segments
            .get_piece(requested_piece_index)
            .await
            .map_err(|error| {
                error!(%error, "Failed to get piece from cached archived segments");
                Error::StringError(format!(
                    "Failed to get piece from cached archived segments: {error:?}"
                ))
            })
    }

    async fn segment_headers(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<SegmentHeader>>, Error> {
        if segment_indexes.len() > MAX_SEGMENT_HEADERS_PER_REQUEST {
            error!(
                "segment_indexes length exceed the limit: {} ",
                segment_indexes.len()
            );

            return Err(Error::StringError(format!(
                "segment_indexes length exceed the limit {MAX_SEGMENT_HEADERS_PER_REQUEST}"
            )));
        };

        Ok(segment_indexes
            .into_iter()
            .map(|segment_index| self.segment_headers_store.get_segment_header(segment_index))
            .collect())
    }

    async fn last_segment_headers(&self, limit: u32) -> Result<Vec<Option<SegmentHeader>>, Error> {
        if limit as usize > MAX_SEGMENT_HEADERS_PER_REQUEST {
            error!(
                "Request limit ({}) exceed the server limit: {} ",
                limit, MAX_SEGMENT_HEADERS_PER_REQUEST
            );

            return Err(Error::StringError(format!(
                "Request limit ({}) exceed the server limit: {} ",
                limit, MAX_SEGMENT_HEADERS_PER_REQUEST
            )));
        };

        let last_segment_index = self
            .segment_headers_store
            .max_segment_index()
            .unwrap_or(SegmentIndex::ZERO);

        let mut last_segment_headers = (SegmentIndex::ZERO..=last_segment_index)
            .rev()
            .take(limit as usize)
            .map(|segment_index| self.segment_headers_store.get_segment_header(segment_index))
            .collect::<Vec<_>>();

        last_segment_headers.reverse();

        Ok(last_segment_headers)
    }

    // TODO:
    // - the number of object mappings in each segment can be very large (hundreds or thousands).
    //   To avoid RPC connection failures, limit the number of mappings returned in each response,
    //   or the number of in-flight responses.
    fn subscribe_archived_object_mappings(&self, pending: PendingSubscriptionSink) {
        // TODO: deny unsafe subscriptions?

        let cached_archived_segment = Arc::clone(&self.cached_archived_segment);

        // The genesis segment isn't included in this stream. In other methods we recreate is as the first segment,
        // but there aren't any mappings in it, so we don't need to recreate it as part of this subscription.

        let mapping_stream = self
            .archived_segment_notification_stream
            .subscribe()
            .flat_map(move |archived_segment_notification| {
                let objects = archived_segment_notification
                    .archived_segment
                    .global_object_mappings();

                // TESTING ONLY, DO NOT MERGE
                cached_archived_segment
                    .lock()
                    .insert(archived_segment_notification.archived_segment.clone());

                stream::iter(objects)
            })
            .ready_chunks(OBJECT_MAPPING_BATCH_SIZE)
            .map(|objects| GlobalObjectMapping::V0 { objects });

        // TESTING ONLY, DO NOT MERGE
        let fake_mapping = vec![GlobalObject::default(); 3];
        let mapping_stream = stream::iter(fake_mapping)
            .ready_chunks(OBJECT_MAPPING_BATCH_SIZE)
            .map(|objects| GlobalObjectMapping::V0 { objects })
            .chain(mapping_stream);

        self.subscription_executor.spawn(
            "subspace-archived-object-mappings-subscription",
            Some("rpc"),
            pipe_from_stream(pending, mapping_stream).boxed(),
        );
    }

    fn subscribe_filtered_object_mappings(
        &self,
        pending: PendingSubscriptionSink,
        hashes: Vec<Blake3Hash>,
    ) {
        // TODO: deny unsafe subscriptions?

        if hashes.len() > MAX_OBJECT_HASHES_PER_SUBSCRIPTION {
            error!(
                "Request hash count ({}) exceed the server limit: {} ",
                hashes.len(),
                MAX_OBJECT_HASHES_PER_SUBSCRIPTION
            );

            let err_fut = pending.reject(Error::StringError(format!(
                "Request hash count ({}) exceed the server limit: {} ",
                hashes.len(),
                MAX_OBJECT_HASHES_PER_SUBSCRIPTION
            )));

            self.subscription_executor.spawn(
                "subspace-filtered-object-mappings-subscription",
                Some("rpc"),
                err_fut.boxed(),
            );

            return;
        };

        let mut hashes = HashSet::<Blake3Hash>::from_iter(hashes);
        let hash_count = hashes.len();

        let cached_archived_segment = Arc::clone(&self.cached_archived_segment);

        // The genesis segment isn't included in this stream, see
        // `subscribe_archived_object_mappings` for details.
        let mapping_stream = self
            .archived_segment_notification_stream
            .subscribe()
            .flat_map(move |archived_segment_notification| {
                let objects = archived_segment_notification
                    .archived_segment
                    .global_object_mappings();

                // TESTING ONLY, DO NOT MERGE
                cached_archived_segment
                    .lock()
                    .insert(archived_segment_notification.archived_segment.clone());

                // TESTING ONLY, DO NOT MERGE
                let fake_mapping = vec![GlobalObject::default(); 3];
                let objects = objects.chain(fake_mapping);

                let objects = objects
                    .filter(|object| hashes.remove(&object.hash))
                    .collect::<Vec<_>>();

                stream::iter(objects)
            })
            // Stop when we've returned mappings for all the hashes. Since we only yield each hash
            // once, we don't need to check if hashes is empty here.
            .take(hash_count)
            // Typically batches will be larger than the hash limit, but we want to allow CLI
            // options to change that.
            .ready_chunks(OBJECT_MAPPING_BATCH_SIZE)
            .map(|objects| GlobalObjectMapping::V0 { objects });

        self.subscription_executor.spawn(
            "subspace-filtered-object-mappings-subscription",
            Some("rpc"),
            pipe_from_stream(pending, mapping_stream).boxed(),
        );
    }

    // TESTING ONLY, DO NOT MERGE
    async fn fetch_archived_objects(
        &self,
        mappings: Vec<subspace_core_primitives::objects::GlobalObject>,
    ) -> Result<Vec<Option<HexData>>, Error> {
        self.deny_unsafe.check_if_safe()?;

        let mut last_error = None;

        let (archived_segments, segment_indexes) = {
            let cache = self.cached_archived_segment.lock();
            (cache.get(), cache.segment_indexes())
        };

        if archived_segments.is_empty() {
            tracing::warn!("No cached segments to fetch objects from");
        }

        let cached_object_fetcher = subspace_data_retrieval::object_fetcher::ObjectFetcher::new(
            Arc::new(archived_segments),
            self.erasure_coding.clone(),
            Some(5 * 1024 * 1024),
        );

        let mut objects = Vec::with_capacity(mappings.len());
        for mapping in &mappings {
            match cached_object_fetcher
                .fetch_object(mapping.piece_index, mapping.offset)
                .await
            {
                Ok(object) => {
                    tracing::info!(
                        ?mapping,
                        len = %object.len(),
                        ?segment_indexes,
                        first_piece_index = ?segment_indexes.first().map(|segment_index| segment_index.first_piece_index()),
                        last_piece_index = ?segment_indexes.last().map(|segment_index| segment_index.last_piece_index()),
                        "Fetched object from cached segments",
                    );
                    objects.push(Some(HexData(object)));
                }
                Err(error) => {
                    tracing::warn!(
                        ?mapping,
                        first_piece_index = ?segment_indexes.first().map(|segment_index| segment_index.first_piece_index()),
                        last_piece_index = ?segment_indexes.last().map(|segment_index| segment_index.last_piece_index()),
                        "Failed to fetch object from cached segments: {}",
                        error
                    );

                    let object = self
                        .object_fetcher
                        .fetch_object(mapping.piece_index, mapping.offset)
                        .await
                        .inspect_err(|error| {
                            error!(
                                "Failed to fetch object from local cache or network: {}",
                                error
                            );
                        });

                    match object {
                        Ok(object) => {
                            tracing::info!(
                                ?mapping,
                                len = %object.len(),
                                "Fetched object from local cache or network",
                            );
                            objects.push(Some(HexData(object)));
                        }
                        Err(error) => {
                            last_error = Some(Error::StringError(format!(
                                "Failed to fetch object from local cache or network: {error:?}"
                            )));
                            objects.push(None);
                        }
                    }
                }
            }
        }

        for (mapping, object) in mappings.iter().zip(objects.iter()) {
            if let Some(object) = object {
                let hash = subspace_core_primitives::crypto::blake3_hash_parallel(&object.0);
                if hash != mapping.hash {
                    // TODO: remove the full object data (`object`) from the logs, replace it with a summary?
                    tracing::error!(
                        ?mapping,
                        object_hash = ?hash,
                        ?object,
                        "Fetched object data hash does not match expected hash"
                    );
                    last_error = Some(Error::StringError(format!(
                        "Fetched object data hash: {hash:?} does not match expected hash: {mapping:?}, object: {object:?}"
                    )));
                }
            }
        }

        if objects.iter().all(Option::is_none) {
            Err(Error::StringError(format!(
                "No objects available, last error: {last_error:?}"
            )))
        } else {
            Ok(objects)
        }
    }
}
