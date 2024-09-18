// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

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

//! Subspace chain configurations.

use crate::chain_spec_utils::{chain_spec_properties, get_account_id_from_seed};
use crate::domain::auto_id_chain_spec;
use crate::domain::cli::{GenesisDomain, SpecId};
use crate::domain::evm_chain_spec::{self};
use sc_chain_spec::GenericChainSpec;
use sc_service::ChainType;
use sc_subspace_chain_specs::{DEVNET_CHAIN_SPEC, GEMINI_3H_CHAIN_SPEC};
use sc_telemetry::TelemetryEndpoints;
use sp_consensus_subspace::FarmerPublicKey;
use sp_core::crypto::{Ss58Codec, UncheckedFrom};
use sp_domains::PermissionedActionAllowedBy;
use sp_runtime::Percent;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use subspace_core_primitives::PotKey;
use subspace_runtime::{
    AllowAuthoringBy, BalancesConfig, CouncilConfig, DemocracyConfig, DomainsConfig,
    EnableRewardsAt, HistorySeedingConfig, MaxDomainBlockSize, MaxDomainBlockWeight, RewardsConfig,
    RuntimeConfigsConfig, RuntimeGenesisConfig, SubspaceConfig, SudoConfig, SystemConfig,
    WASM_BINARY,
};
use subspace_runtime_primitives::{
    AccountId, Balance, BlockNumber, CouncilDemocracyConfigParams, SSC,
};

const SUBSPACE_TELEMETRY_URL: &str = "wss://telemetry.subspace.network/submit/";

/// Additional subspace specific genesis parameters.
struct GenesisParams {
    enable_rewards_at: EnableRewardsAt<BlockNumber>,
    allow_authoring_by: AllowAuthoringBy,
    pot_slot_iterations: NonZeroU32,
    enable_domains: bool,
    enable_dynamic_cost_of_storage: bool,
    enable_balance_transfers: bool,
    enable_non_root_calls: bool,
    confirmation_depth_k: u32,
    rewards_config: RewardsConfig,
}

struct GenesisDomainParams {
    permissioned_action_allowed_by: PermissionedActionAllowedBy<AccountId>,
    genesis_domains: Vec<GenesisDomain>,
}

pub fn gemini_3h_compiled() -> Result<GenericChainSpec, String> {
    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Wasm binary must be built for Gemini".to_string())?,
        None,
    )
    .with_name("Subspace Gemini 3h")
    // ID
    .with_id("subspace_gemini_3h")
    .with_chain_type(ChainType::Custom("Subspace Gemini 3h".to_string()))
    .with_telemetry_endpoints(
        TelemetryEndpoints::new(vec![(SUBSPACE_TELEMETRY_URL.into(), 1)])
            .map_err(|error| error.to_string())?,
    )
    .with_protocol_id("subspace-gemini-3h")
    .with_properties({
        let mut properties = chain_spec_properties();
        properties.insert(
            "potExternalEntropy".to_string(),
            serde_json::to_value(None::<PotKey>).expect("Serialization is infallible; qed"),
        );
        properties
    })
    .with_genesis_config({
        let sudo_account =
            AccountId::from_ss58check("5DNwQTHfARgKoa2NdiUM51ZUow7ve5xG9S2yYdSbVQcnYxBA")
                .expect("Wrong root account address");

        let balances = vec![(sudo_account.clone(), 1_000 * SSC)];
        patch_domain_runtime_version(
            serde_json::to_value(subspace_genesis_config(
                sudo_account.clone(),
                balances,
                GenesisParams {
                    enable_rewards_at: EnableRewardsAt::Manually,
                    allow_authoring_by: AllowAuthoringBy::RootFarmer(
                        FarmerPublicKey::unchecked_from(hex_literal::hex!(
                            "8aecbcf0b404590ddddc01ebacb205a562d12fdb5c2aa6a4035c1a20f23c9515"
                        )),
                    ),
                    // TODO: Adjust once we bench PoT on faster hardware
                    // About 1s on 6.0 GHz Raptor Lake CPU (14900K)
                    pot_slot_iterations: NonZeroU32::new(200_032_000).expect("Not zero; qed"),
                    enable_domains: false,
                    enable_dynamic_cost_of_storage: false,
                    enable_balance_transfers: true,
                    enable_non_root_calls: false,
                    // TODO: Proper value here
                    confirmation_depth_k: 100,
                    // TODO: Proper value here
                    rewards_config: RewardsConfig {
                        remaining_issuance: 1_000_000_000 * SSC,
                        proposer_subsidy_points: Default::default(),
                        voter_subsidy_points: Default::default(),
                    },
                },
                GenesisDomainParams {
                    permissioned_action_allowed_by: PermissionedActionAllowedBy::Accounts(vec![
                        sudo_account.clone(),
                    ]),
                    genesis_domains: vec![
                        evm_chain_spec::get_genesis_domain(SpecId::Gemini, sudo_account.clone())?,
                        auto_id_chain_spec::get_genesis_domain(
                            SpecId::Gemini,
                            sudo_account.clone(),
                        )?,
                    ],
                },
                CouncilDemocracyConfigParams::<BlockNumber>::production_params(),
                // TODO: Proper value here
                sudo_account.clone(),
            )?)
            .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
        )
    })
    .build())
}

pub fn gemini_3h_config() -> Result<GenericChainSpec, String> {
    GenericChainSpec::from_json_bytes(GEMINI_3H_CHAIN_SPEC.as_bytes())
}

pub fn devnet_config() -> Result<GenericChainSpec, String> {
    GenericChainSpec::from_json_bytes(DEVNET_CHAIN_SPEC.as_bytes())
}

pub fn devnet_config_compiled() -> Result<GenericChainSpec, String> {
    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Wasm binary must be built for Devnet".to_string())?,
        None,
    )
    .with_name("Subspace Dev network")
    .with_id("subspace_devnet")
    .with_chain_type(ChainType::Custom("Testnet".to_string()))
    .with_telemetry_endpoints(
        TelemetryEndpoints::new(vec![(SUBSPACE_TELEMETRY_URL.into(), 1)])
            .map_err(|error| error.to_string())?,
    )
    .with_protocol_id("subspace-devnet")
    .with_properties({
        let mut properties = chain_spec_properties();
        properties.insert(
            "potExternalEntropy".to_string(),
            serde_json::to_value(None::<PotKey>).expect("Serialization is infallible; qed"),
        );
        properties
    })
    .with_genesis_config({
        let sudo_account = get_account_id_from_seed("Alice");

        let balances = vec![(sudo_account.clone(), Balance::MAX / 2)];
        patch_domain_runtime_version(
            serde_json::to_value(subspace_genesis_config(
                sudo_account.clone(),
                balances,
                GenesisParams {
                    enable_rewards_at: EnableRewardsAt::Manually,
                    allow_authoring_by: AllowAuthoringBy::FirstFarmer,
                    pot_slot_iterations: NonZeroU32::new(150_000_000).expect("Not zero; qed"),
                    enable_domains: true,
                    enable_dynamic_cost_of_storage: false,
                    enable_balance_transfers: true,
                    enable_non_root_calls: false,
                    // TODO: Proper value here
                    confirmation_depth_k: 100,
                    // TODO: Proper value here
                    rewards_config: RewardsConfig {
                        remaining_issuance: 1_000_000_000 * SSC,
                        proposer_subsidy_points: Default::default(),
                        voter_subsidy_points: Default::default(),
                    },
                },
                GenesisDomainParams {
                    permissioned_action_allowed_by: PermissionedActionAllowedBy::Accounts(vec![
                        sudo_account.clone(),
                    ]),
                    genesis_domains: vec![
                        evm_chain_spec::get_genesis_domain(SpecId::DevNet, sudo_account.clone())?,
                        auto_id_chain_spec::get_genesis_domain(
                            SpecId::DevNet,
                            sudo_account.clone(),
                        )?,
                    ],
                },
                CouncilDemocracyConfigParams::<BlockNumber>::fast_params(),
                sudo_account.clone(),
            )?)
            .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
        )
    })
    .build())
}

pub fn dev_config() -> Result<GenericChainSpec, String> {
    let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;
    let sudo_account = get_account_id_from_seed("Alice");
    let history_seeder = get_account_id_from_seed("Bob");

    Ok(GenericChainSpec::builder(wasm_binary, None)
        .with_name("Subspace development")
        .with_id("subspace_dev")
        .with_chain_type(ChainType::Development)
        .with_properties({
            let mut properties = chain_spec_properties();
            properties.insert(
                "potExternalEntropy".to_string(),
                serde_json::to_value(None::<PotKey>).expect("Serialization is infallible; qed"),
            );
            properties
        })
        .with_genesis_config(patch_domain_runtime_version(
            serde_json::to_value(subspace_genesis_config(
                // Sudo account
                sudo_account.clone(),
                // Pre-funded accounts
                vec![
                    (sudo_account.clone(), Balance::MAX / 2),
                    (get_account_id_from_seed("Bob"), 1_000 * SSC),
                    (get_account_id_from_seed("Alice//stash"), 1_000 * SSC),
                    (get_account_id_from_seed("Bob//stash"), 1_000 * SSC),
                ],
                GenesisParams {
                    enable_rewards_at: EnableRewardsAt::Manually,
                    allow_authoring_by: AllowAuthoringBy::Anyone,
                    pot_slot_iterations: NonZeroU32::new(100_000_000).expect("Not zero; qed"),
                    enable_domains: true,
                    enable_dynamic_cost_of_storage: false,
                    enable_balance_transfers: true,
                    enable_non_root_calls: true,
                    confirmation_depth_k: 5,
                    rewards_config: RewardsConfig {
                        remaining_issuance: 1_000_000 * SSC,
                        proposer_subsidy_points: Default::default(),
                        voter_subsidy_points: Default::default(),
                    },
                },
                GenesisDomainParams {
                    permissioned_action_allowed_by: PermissionedActionAllowedBy::Accounts(vec![
                        sudo_account.clone(),
                    ]),
                    genesis_domains: vec![evm_chain_spec::get_genesis_domain(
                        SpecId::Dev,
                        sudo_account,
                    )?],
                },
                CouncilDemocracyConfigParams::<BlockNumber>::fast_params(),
                history_seeder,
            )?)
            .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
        ))
        .build())
}

/// Configure initial storage state for FRAME modules.
fn subspace_genesis_config(
    sudo_account: AccountId,
    balances: Vec<(AccountId, Balance)>,
    genesis_params: GenesisParams,
    genesis_domain_params: GenesisDomainParams,
    council_democracy_config_params: CouncilDemocracyConfigParams<BlockNumber>,
    history_seeder_account: AccountId,
) -> Result<RuntimeGenesisConfig, String> {
    let GenesisParams {
        enable_rewards_at,
        allow_authoring_by,
        pot_slot_iterations,
        enable_domains,
        enable_dynamic_cost_of_storage,
        enable_balance_transfers,
        enable_non_root_calls,
        confirmation_depth_k,
        rewards_config,
    } = genesis_params;

    let genesis_domains = if enable_domains {
        genesis_domain_params
            .genesis_domains
            .into_iter()
            .map(|genesis_domain| {
                sp_domains::GenesisDomain {
                    runtime_name: genesis_domain.runtime_name,
                    runtime_type: genesis_domain.runtime_type,
                    runtime_version: genesis_domain.runtime_version,
                    raw_genesis_storage: genesis_domain.raw_genesis,

                    // Domain config, mainly for placeholder the concrete value TBD
                    owner_account_id: sudo_account.clone(),
                    domain_name: genesis_domain.domain_name,
                    max_block_size: MaxDomainBlockSize::get(),
                    max_block_weight: MaxDomainBlockWeight::get(),
                    bundle_slot_probability: (1, 1),
                    target_bundles_per_block: 10,
                    operator_allow_list: genesis_domain.operator_allow_list.clone(),
                    signing_key: genesis_domain.operator_signing_key.clone(),
                    nomination_tax: Percent::from_percent(5),
                    minimum_nominator_stake: 100 * SSC,
                    initial_balances: genesis_domain.initial_balances,
                }
            })
            .collect()
    } else {
        vec![]
    };

    Ok(RuntimeGenesisConfig {
        system: SystemConfig::default(),
        balances: BalancesConfig { balances },
        transaction_payment: Default::default(),
        sudo: SudoConfig {
            // Assign network admin rights.
            key: Some(sudo_account.clone()),
        },
        subspace: SubspaceConfig {
            enable_rewards_at,
            allow_authoring_by,
            pot_slot_iterations,
            phantom: PhantomData,
        },
        rewards: rewards_config,
        council: CouncilConfig::default(),
        democracy: DemocracyConfig::default(),
        runtime_configs: RuntimeConfigsConfig {
            enable_domains,
            enable_dynamic_cost_of_storage,
            enable_balance_transfers,
            enable_non_root_calls,
            confirmation_depth_k,
            council_democracy_config_params,
        },
        domains: DomainsConfig {
            permissioned_action_allowed_by: enable_domains
                .then_some(genesis_domain_params.permissioned_action_allowed_by),
            genesis_domains,
        },
        history_seeding: HistorySeedingConfig {
            history_seeder: Some(history_seeder_account),
        },
    })
}

// TODO: Workaround for https://github.com/paritytech/polkadot-sdk/issues/4001
fn patch_domain_runtime_version(mut genesis_config: serde_json::Value) -> serde_json::Value {
    let Some(genesis_domains) = genesis_config
        .get_mut("domains")
        .and_then(|domains| domains.get_mut("genesisDomains"))
        .and_then(|genesis_domains| genesis_domains.as_array_mut())
    else {
        return genesis_config;
    };

    for genesis_domain in genesis_domains {
        let Some(runtime_version) = genesis_domain.get_mut("runtime_version") else {
            continue;
        };

        if let Some(spec_name) = runtime_version.get_mut("specName") {
            if let Some(spec_name_bytes) = spec_name
                .as_str()
                .map(|spec_name| spec_name.as_bytes().to_vec())
            {
                *spec_name = serde_json::to_value(spec_name_bytes)
                    .expect("Bytes serialization doesn't fail; qed");
            }
        }

        if let Some(impl_name) = runtime_version.get_mut("implName") {
            if let Some(impl_name_bytes) = impl_name
                .as_str()
                .map(|impl_name| impl_name.as_bytes().to_vec())
            {
                *impl_name = serde_json::to_value(impl_name_bytes)
                    .expect("Bytes serialization doesn't fail; qed");
            }
        }
    }

    genesis_config
}
