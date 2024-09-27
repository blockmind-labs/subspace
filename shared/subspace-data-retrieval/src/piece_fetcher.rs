// Copyright (C) 2024 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Fetching pieces of the archived history of Subspace Network.

use crate::piece_getter::{ObjectPieceGetter, PieceGetterError};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use subspace_core_primitives::{Piece, PieceIndex};
use tracing::{debug, trace};

/// Concurrently downloads the exact pieces in `piece_indexes`, returning them in that order.
/// Each piece index must be unique.
///
/// If any piece can't be downloaded, returns an error.
// This code was copied and modified from subspace_service::sync_from_dsn::download_and_reconstruct_blocks():
// <https://github.com/autonomys/subspace/blob/d71ca47e45e1b53cd2e472413caa23472a91cd74/crates/subspace-service/src/sync_from_dsn/import_blocks.rs#L236-L322>
pub async fn download_pieces<PG>(
    piece_indexes: impl IntoIterator<Item = PieceIndex>,
    piece_getter: &PG,
) -> Result<Vec<Piece>, PieceGetterError>
where
    PG: ObjectPieceGetter,
{
    let piece_indexes = piece_indexes.into_iter().collect::<Vec<_>>();

    debug!(
        count = piece_indexes.len(),
        ?piece_indexes,
        "Retrieving exact pieces"
    );

    // TODO:
    // - consider using a semaphore to limit the number of concurrent requests, like
    //   download_segment_pieces()
    // - if we're close to the number of pieces in a segment, use segment downloading and piece
    //   reconstruction instead
    // Currently most objects are limited to 4 pieces, so this isn't needed yet.
    let mut received_pieces = piece_indexes
        .iter()
        .map(|piece_index| async move {
            let piece = match piece_getter.get_piece(*piece_index).await {
                Ok(Some(piece)) => {
                    trace!(?piece_index, "Piece request succeeded",);
                    Ok(piece)
                }
                Ok(None) => {
                    // TODO: retry before failing
                    trace!(?piece_index, "Piece request temporarily failed",);
                    return Err(PieceGetterError::NotFound {
                        piece_index: *piece_index,
                    });
                }
                Err(error) => {
                    trace!(
                        %error,
                        ?piece_index,
                        "Piece request permanently failed",
                    );
                    return Err(PieceGetterError::NotFoundWithError {
                        piece_index: *piece_index,
                        source: error,
                    });
                }
            };

            piece.map(|received_piece| (piece_index, received_piece))
        })
        .collect::<FuturesUnordered<_>>();

    let mut pieces = vec![Piece::default(); piece_indexes.len()];

    while let Some(maybe_result) = received_pieces.next().await {
        // We want exact pieces, so any errors are final.
        let (piece_index, piece) = maybe_result?;

        // Each piece index is unique, so the positions will also be unique.
        let position = piece_indexes
            .iter()
            .position(|index| index == piece_index)
            .expect("All piece indexes are from this vec; qed");

        pieces[position] = piece;
    }

    trace!(
        count = piece_indexes.len(),
        ?piece_indexes,
        "Successfully retrieved exact pieces"
    );

    Ok(pieces)
}
