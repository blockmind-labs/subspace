//! This module exposed implementation of caches maintenance.
//!
//! The goal is to observe caches in a particular cache group and keep controller's data structures
//! about which pieces are stored where up to date. Implementation automatically handles dynamic
//! cache addition and removal, tries to reduce number of reinitializations that result in potential
//! piece cache sync, etc.

use crate::cluster::cache::{ClusterCacheIdentifyBroadcast, ClusterPieceCache};
use crate::cluster::controller::ClusterControllerCacheIdentifyBroadcast;
use crate::cluster::nats_client::NatsClient;
use crate::farm::{PieceCache, PieceCacheId};
use crate::farmer_cache::FarmerCache;
use anyhow::anyhow;
use futures::channel::oneshot;
use futures::future::FusedFuture;
use futures::{select, FutureExt, StreamExt};
use parking_lot::Mutex;
use std::future::{ready, Future};
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::MissedTickBehavior;
use tracing::{info, trace, warn};

const SCHEDULE_REINITIALIZATION_DELAY: Duration = Duration::from_secs(3);

#[derive(Debug)]
struct KnownCache {
    cache_id: PieceCacheId,
    last_identification: Instant,
    piece_cache: Arc<ClusterPieceCache>,
}

#[derive(Debug)]
struct KnownCaches {
    identification_broadcast_interval: Duration,
    known_caches: Vec<KnownCache>,
}

impl KnownCaches {
    fn new(identification_broadcast_interval: Duration) -> Self {
        Self {
            identification_broadcast_interval,
            known_caches: Vec::new(),
        }
    }

    fn get_all(&self) -> Vec<Arc<dyn PieceCache>> {
        self.known_caches
            .iter()
            .map(|known_cache| Arc::clone(&known_cache.piece_cache) as Arc<_>)
            .collect()
    }

    /// Return `true` if farmer cache reinitialization is required
    fn update(
        &mut self,
        cache_id: PieceCacheId,
        max_num_elements: u32,
        nats_client: &NatsClient,
    ) -> bool {
        if self.known_caches.iter_mut().any(|known_cache| {
            if known_cache.cache_id == cache_id {
                known_cache.last_identification = Instant::now();
                true
            } else {
                false
            }
        }) {
            return false;
        }

        let piece_cache = Arc::new(ClusterPieceCache::new(
            cache_id,
            max_num_elements,
            nats_client.clone(),
        ));
        self.known_caches.push(KnownCache {
            cache_id,
            last_identification: Instant::now(),
            piece_cache,
        });
        true
    }

    fn remove_expired(&mut self) -> impl Iterator<Item = KnownCache> + '_ {
        self.known_caches.extract_if(|known_cache| {
            known_cache.last_identification.elapsed() > self.identification_broadcast_interval * 2
        })
    }
}

/// Utility function for maintaining caches by controller in a cluster environment
pub async fn maintain_caches(
    cache_group: &str,
    nats_client: &NatsClient,
    farmer_cache: FarmerCache,
    identification_broadcast_interval: Duration,
) -> anyhow::Result<()> {
    let mut known_caches = KnownCaches::new(identification_broadcast_interval);

    let mut scheduled_reinitialization_for = None;
    // Farm that is being added/removed right now (if any)
    let mut cache_reinitialization =
        (Box::pin(ready(())) as Pin<Box<dyn Future<Output = ()>>>).fuse();

    let cache_identify_subscription = pin!(nats_client
        .subscribe_to_broadcasts::<ClusterCacheIdentifyBroadcast>(Some(cache_group), None)
        .await
        .map_err(|error| anyhow!("Failed to subscribe to cache identify broadcast: {error}"))?);

    // Request cache to identify themselves
    if let Err(error) = nats_client
        .broadcast(&ClusterControllerCacheIdentifyBroadcast, cache_group)
        .await
    {
        warn!(%error, "Failed to send cache identification broadcast");
    }

    let mut cache_identify_subscription = cache_identify_subscription.fuse();
    let mut cache_pruning_interval = tokio::time::interval_at(
        (Instant::now() + identification_broadcast_interval * 2).into(),
        identification_broadcast_interval * 2,
    );
    cache_pruning_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        if cache_reinitialization.is_terminated()
            && let Some(time) = scheduled_reinitialization_for
            && time <= Instant::now()
        {
            scheduled_reinitialization_for.take();

            let new_piece_caches = known_caches.get_all();
            let new_cache_reinitialization = async {
                let (sync_finish_sender, sync_finish_receiver) = oneshot::channel::<()>();
                let sync_finish_sender = Mutex::new(Some(sync_finish_sender));

                let _handler_id = farmer_cache.on_sync_progress(Arc::new(move |&progress| {
                    if progress == 100.0 {
                        if let Some(sync_finish_sender) = sync_finish_sender.lock().take() {
                            // Result doesn't matter
                            let _ = sync_finish_sender.send(());
                        }
                    }
                }));

                farmer_cache
                    .replace_backing_caches(new_piece_caches, Vec::new())
                    .await;

                // Wait for piece cache sync to finish before potentially staring a new one, result
                // doesn't matter
                let _ = sync_finish_receiver.await;
            };

            cache_reinitialization =
                (Box::pin(new_cache_reinitialization) as Pin<Box<dyn Future<Output = ()>>>).fuse();
        }

        select! {
            maybe_identify_message = cache_identify_subscription.next() => {
                let Some(identify_message) = maybe_identify_message else {
                    return Err(anyhow!("Cache identify stream ended"));
                };

                let ClusterCacheIdentifyBroadcast {
                    cache_id,
                    max_num_elements,
                } = identify_message;
                if known_caches.update(cache_id, max_num_elements, nats_client) {
                    info!(
                        %cache_id,
                        "New cache discovered, scheduling reinitialization"
                    );
                    scheduled_reinitialization_for.replace(
                        Instant::now() + SCHEDULE_REINITIALIZATION_DELAY,
                    );
                } else {
                    trace!(
                        %cache_id,
                        "Received identification for already known cache"
                    );
                }
            }
            _ = cache_pruning_interval.tick().fuse() => {
                let mut reinit = false;
                for removed_cache in known_caches.remove_expired() {
                    reinit = true;

                    warn!(
                        cache_id = %removed_cache.cache_id,
                        "Cache expired and removed, scheduling reinitialization"
                    );
                }

                if reinit {
                    scheduled_reinitialization_for.replace(
                        Instant::now() + SCHEDULE_REINITIALIZATION_DELAY,
                    );
                }
            }
            _ = cache_reinitialization => {
                // Nothing left to do
            }
        }
    }
}
