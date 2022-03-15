#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use pallet_grandpa::{
	fg_primitives, AuthorityId as GrandpaId, AuthorityList as GrandpaAuthorityList,
};
use scale_info::{prelude::{format, string::String}, TypeInfo};
use sp_api::impl_runtime_apis;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::{crypto::KeyTypeId, OpaqueMetadata};
use sp_runtime::{
	create_runtime_str, generic, impl_opaque_keys,
	traits::{self, AccountIdLookup, BlakeTwo256, Block as BlockT, IdentifyAccount, Hash as HashT, NumberFor, Verify},
	transaction_validity::{TransactionSource, TransactionValidity},
	ApplyExtrinsicResult, MultiSignature,
};
use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

// A few exports that help ease life for downstream crates.
pub use frame_support::{
	construct_runtime, parameter_types, debug, print,
	traits::{Currency, KeyOwnerProofSystem, Randomness, StorageInfo},
	weights::{
		constants::{BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight, WEIGHT_PER_SECOND},
		IdentityFee, Weight,
	},
	StorageValue,
};
pub use pallet_balances::Call as BalancesCall;
pub use pallet_timestamp::Call as TimestampCall;
use pallet_transaction_payment::CurrencyAdapter;
#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;
pub use sp_runtime::{Perbill, Permill};

/// Import the template pallet.
pub use pallet_blogchain;

/// An index to a block.
pub type BlockNumber = u32;

/// A fixed size array of bytes (until we implement the real thing)
const PUBLIC_KEY_SIZE: usize = 32;
pub type PublicKey = [u8; PUBLIC_KEY_SIZE];

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance of an account.
pub type Balance = u128;

/// Index of a transaction in the chain.
pub type Index = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;


// Swap these two lines about to have the custom implementation of a Header
// the generic Header
pub type HeaderType = HookHeader;
//pub type HeaderType = generic::Header<BlockNumber, BlakeTwo256>;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
	use super::*;

	pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

	/// Opaque block header type.
	pub type Header = HeaderType;
    /// Opaque block type.
	pub type Block = generic::Block<Header, UncheckedExtrinsic>;
	/// Opaque block identifier type.
	pub type BlockId = generic::BlockId<Block>;

	impl_opaque_keys! {
		pub struct SessionKeys {
			pub aura: Aura,
			pub grandpa: Grandpa,
		}
	}
}

// To learn more about runtime versioning and what each of the following value means:
//   https://docs.substrate.io/v3/runtime/upgrades#runtime-versioning
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: create_runtime_str!("node-blogchain"),
	impl_name: create_runtime_str!("node-blogchain"),
	authoring_version: 1,
	// The version of the runtime specification. A full node will not attempt to use its native
	//   runtime in substitute for the on-chain Wasm runtime unless all of `spec_name`,
	//   `spec_version`, and `authoring_version` are the same between Wasm and native.
	// This value is set to 100 to notify Polkadot-JS App (https://polkadot.js.org/apps) to use
	//   the compatible custom types.
	spec_version: 100,
	impl_version: 1,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 1,
};

/// This determines the average expected block time that we are targeting.
/// Blocks will be produced at a minimum duration defined by `SLOT_DURATION`.
/// `SLOT_DURATION` is picked up by `pallet_timestamp` which is in turn picked
/// up by `pallet_aura` to implement `fn slot_duration()`.
///
/// Change this to adjust the block time.
pub const MILLISECS_PER_BLOCK: u64 = 6000;

// NOTE: Currently it is not possible to change the slot duration after the chain has started.
//       Attempting to do so will brick block production.
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;

// Time is measured by number of blocks.
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
	NativeVersion { runtime_version: VERSION, can_author_with: Default::default() }
}

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

parameter_types! {
	pub const Version: RuntimeVersion = VERSION;
	pub const BlockHashCount: BlockNumber = 2400;
	/// We allow for 2 seconds of compute with a 6 second average block time.
	pub BlockWeights: frame_system::limits::BlockWeights = frame_system::limits::BlockWeights
		::with_sensible_defaults(2 * WEIGHT_PER_SECOND, NORMAL_DISPATCH_RATIO);
	pub BlockLength: frame_system::limits::BlockLength = frame_system::limits::BlockLength
		::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
	pub const SS58Prefix: u8 = 42;
    pub const BlogPostMinBytes: u32 = 64;
    pub const BlogPostMaxBytes: u32 = 4096;
    pub const BlogPostCommentMinBytes: u32 = 64;
    pub const BlogPostCommentMaxBytes: u32 = 1024;
}

use frame_support::codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

// Configure FRAME pallets to include in runtime.
#[derive(Encode, Decode, PartialEq, Eq, Clone, sp_core::RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "std", serde(deny_unknown_fields))]
pub struct HookHeader {
    header: generic::Header<BlockNumber, BlakeTwo256>,
    public_key: PublicKey,
}

#[cfg(feature = "std")]
impl parity_util_mem::MallocSizeOf for HookHeader {
	fn size_of(&self, ops: &mut parity_util_mem::MallocSizeOfOps) -> usize {
        let size = self.header.size_of(ops) + PUBLIC_KEY_SIZE;
        print(format!("########## sizeof called: {}", size).as_str());
        size
	}
}

impl HookHeader {
    /*fn new_with_key(header: HookHeader, public_key: PublicKey) -> Self {
        Self {
            public_key,
            header: header.header
        }
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }*/

    fn number(&self) -> BlockNumber {
        self.header.number
    }

    // Returns the hash of the header.
    fn hash(&self) -> <HookHeader as traits::Header>::Hash {
        let hash = BlakeTwo256::hash_of(self);
        print(format!("##### Hash: {}", hash).as_str());
        hash
    }

    fn parent_hash(&self) -> <HookHeader as traits::Header>::Hash {
        self.header.parent_hash
    }
}

impl traits::Header for HookHeader
{
    type Number = BlockNumber;
    type Hash = <BlakeTwo256 as HashT>::Output;
    type Hashing = BlakeTwo256;

    fn new(
        number: Self::Number,
        extrinsics_root: Self::Hash,
        state_root: Self::Hash,
        parent_hash: Self::Hash,
        digest: generic::Digest,
    ) -> Self {
        let header = generic::Header::new(
            number,
            extrinsics_root,
            state_root,
            parent_hash,
            digest,
        );
        Self { header, public_key: [5; PUBLIC_KEY_SIZE] }
    }
    fn number(&self) -> &Self::Number {
        &self.header.number
    }

    fn set_number(&mut self, num: Self::Number) {
        self.header.number = num
    }
    fn extrinsics_root(&self) -> &Self::Hash {
        &self.header.extrinsics_root
    }

    fn set_extrinsics_root(&mut self, root: Self::Hash) {
        self.header.extrinsics_root = root
    }
    fn state_root(&self) -> &Self::Hash {
        &self.header.state_root
    }

    fn set_state_root(&mut self, root: Self::Hash) {
        self.header.state_root = root
    }
    fn parent_hash(&self) -> &Self::Hash {
        &self.header.parent_hash
    }

    fn set_parent_hash(&mut self, hash: Self::Hash) {
        self.header.parent_hash = hash
    }

    fn digest(&self) -> &generic::Digest {
        &self.header.digest
    }

    fn digest_mut(&mut self) -> &mut generic::Digest {
        &mut self.header.digest
    }
}

#[cfg(all(test, feature = "std"))]
pub mod tests {
    use super::*;
	use crate::traits::BlakeTwo256;
    #[test]
    fn test_encoding() {
        let header = crate::generic::Header::<u32, BlakeTwo256> {
            parent_hash: BlakeTwo256::hash(b"1"),
            number: 2,
            state_root: BlakeTwo256::hash(b"3"),
            extrinsics_root: BlakeTwo256::hash(b"4"),
            digest: crate::generic::Digest {
                logs: vec![crate::generic::DigestItem::Other(b"6".to_vec())],
            },
        };
        let hook_header = HookHeader {
            header,
            public_key: [5;32],
        };

        let header_encoded = hook_header.encode();
        assert_eq!(
            header_encoded,
            vec![
                146, 205, 245, 120, 196, 112, 133, 165, 153, 34, 86, 240, 220, 249, 125, 11, 25,
                241, 241, 201, 222, 77, 95, 227, 12, 58, 206, 97, 145, 182, 229, 219, 8, 88, 19,
                72, 51, 123, 15, 62, 20, 134, 32, 23, 61, 170, 165, 249, 77, 0, 216, 129, 112, 93,
                203, 240, 170, 131, 239, 218, 186, 97, 210, 237, 225, 235, 134, 73, 33, 73, 151,
                87, 78, 32, 196, 100, 56, 138, 23, 36, 32, 210, 84, 3, 104, 43, 187, 184, 12, 73,
                104, 49, 200, 204, 31, 143, 13, 4, 0, 4, 54,
                // 32x 5's at the end
                5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5
            ],
        );
        assert_ne!(
            header_encoded,
            vec![146, 205, 245, 120, 196, 112, 133, 165, 153, 34, 86, 240, 220, 249, 125, 11, 25,
                241, 241, 201, 222, 77, 95, 227, 12, 58, 206, 97, 145, 182, 229, 219, 8, 88, 19,
                72, 51, 123, 15, 62, 20, 134, 32, 23, 61, 170, 165, 249, 77, 0, 216, 129, 112, 93,
                203, 240, 170, 131, 239, 218, 186, 97, 210, 237, 225, 235, 134, 73, 33, 73, 151,
                87, 78, 32, 196, 100, 56, 138, 23, 36, 32, 210, 84, 3, 104, 43, 187, 184, 12, 73,
                104, 49, 200, 204, 31, 143, 13, 4, 0, 4, 54,
                // just changed the '1'................v
                5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 1, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5
            ],
        );

        assert_eq!(hook_header, HookHeader::decode(&mut &header_encoded[..]).unwrap());
    }
}

impl frame_system::Config for Runtime {
	/// The basic call filter to use in dispatchable.
	type BaseCallFilter = frame_support::traits::Everything;
	/// Block & extrinsics weights: base values and limits.
	type BlockWeights = BlockWeights;
	/// The maximum length of a block (in bytes).
	type BlockLength = BlockLength;
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;
	/// The aggregated dispatch type that is available for extrinsics.
	type Call = Call;
	/// The lookup mechanism to get account ID from whatever is passed in dispatchers.
	type Lookup = AccountIdLookup<AccountId, ()>;
	/// The index type for storing how many extrinsics an account has signed.
	type Index = Index;
	/// The index type for blocks.
	type BlockNumber = BlockNumber;
	/// The type for hashing blocks and tries.
	type Hash = Hash;
	/// The hashing algorithm used.
	type Hashing = BlakeTwo256;
	/// The header type.
	type Header = HeaderType;
    /// The ubiquitous event type.
	type Event = Event;
	/// The ubiquitous origin type.
	type Origin = Origin;
	/// Maximum number of block number to block hash mappings to keep (oldest pruned first).
	type BlockHashCount = BlockHashCount;
	/// The weight of database operations that the runtime can invoke.
	type DbWeight = RocksDbWeight;
	/// Version of the runtime.
	type Version = Version;
	/// Converts a module to the index of the module in `construct_runtime!`.
	///
	/// This type is being generated by `construct_runtime!`.
	type PalletInfo = PalletInfo;
	/// What to do if a new account is created.
	type OnNewAccount = ();
	/// What to do if an account is fully reaped from the system.
	type OnKilledAccount = ();
	/// The data to be stored in an account.
	type AccountData = pallet_balances::AccountData<Balance>;
	/// Weight information for the extrinsics of this pallet.
	type SystemWeightInfo = ();
	/// This is used as an identifier of the chain. 42 is the generic substrate prefix.
	type SS58Prefix = SS58Prefix;
	/// The set code logic, just the default since we're not a parachain.
	type OnSetCode = ();
}

impl pallet_randomness_collective_flip::Config for Runtime {}

parameter_types! {
	pub const MaxAuthorities: u32 = 32;
}

impl pallet_aura::Config for Runtime {
	type AuthorityId = AuraId;
	type DisabledValidators = ();
	type MaxAuthorities = MaxAuthorities;
}

impl pallet_grandpa::Config for Runtime {
	type Event = Event;
	type Call = Call;

	type KeyOwnerProofSystem = ();

	type KeyOwnerProof =
		<Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(KeyTypeId, GrandpaId)>>::Proof;

	type KeyOwnerIdentification = <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(
		KeyTypeId,
		GrandpaId,
	)>>::IdentificationTuple;

	type HandleEquivocation = ();

	type WeightInfo = ();
	type MaxAuthorities = MaxAuthorities;
}

parameter_types! {
	pub const MinimumPeriod: u64 = SLOT_DURATION / 2;
}

impl pallet_timestamp::Config for Runtime {
	/// A timestamp: milliseconds since the unix epoch.
	type Moment = u64;
	type OnTimestampSet = Aura;
	type MinimumPeriod = MinimumPeriod;
	type WeightInfo = ();
}

parameter_types! {
	pub const ExistentialDeposit: u128 = 500;
	pub const MaxLocks: u32 = 50;
}

impl pallet_balances::Config for Runtime {
	type MaxLocks = MaxLocks;
	type MaxReserves = ();
	type ReserveIdentifier = [u8; 8];
	/// The type for recording an account's balance.
	type Balance = Balance;
	/// The ubiquitous event type.
	type Event = Event;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
	pub const TransactionByteFee: Balance = 1;
	pub OperationalFeeMultiplier: u8 = 5;
}

impl pallet_transaction_payment::Config for Runtime {
	type OnChargeTransaction = CurrencyAdapter<Balances, ()>;
	type TransactionByteFee = TransactionByteFee;
	type OperationalFeeMultiplier = OperationalFeeMultiplier;
	type WeightToFee = IdentityFee<Balance>;
	type FeeMultiplierUpdate = ();
}

impl pallet_sudo::Config for Runtime {
	type Event = Event;
	type Call = Call;
}

/// Configure the pallet-blogchain in pallets/blogchain.
impl pallet_blogchain::Config for Runtime {
	type Event = Event;
    type Currency = Balances;

    type BlogPostMinBytes = BlogPostMinBytes;
    type BlogPostMaxBytes = BlogPostMaxBytes;
    type BlogPostCommentMinBytes = BlogPostCommentMinBytes;
    type BlogPostCommentMaxBytes = BlogPostCommentMaxBytes;
}

// Create the runtime by composing the FRAME pallets that were previously configured.
construct_runtime!(
	pub enum Runtime where
		Block = Block,
        NodeBlock = opaque::Block,
		UncheckedExtrinsic = UncheckedExtrinsic
	{
		System: frame_system,
		RandomnessCollectiveFlip: pallet_randomness_collective_flip,
		Timestamp: pallet_timestamp,
		Aura: pallet_aura,
		Grandpa: pallet_grandpa,
		Balances: pallet_balances,
		TransactionPayment: pallet_transaction_payment,
		Sudo: pallet_sudo,
		// Include the custom logic from the pallet-template in the runtime.
		Blogchain: pallet_blogchain,
	}
);

/// The address format for describing accounts.
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;
/// Block header type as expected by this runtime.
pub type Header = HeaderType;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);
/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic = generic::UncheckedExtrinsic<Address, Call, Signature, SignedExtra>;
/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPallets,
>;

const EPOCH: u32 = 7;

fn get_epoch_and_slot(block_number: u32) -> (u32, u32) {
    (block_number / EPOCH, block_number % EPOCH)
}

fn is_last_block_of_epoch(block_number: u32) -> bool {
    let (_, slot) = get_epoch_and_slot(block_number);
    slot == EPOCH - 1
}

fn generate_public_key(block_number: u32) -> (String, PublicKey) {
    let (epoch, slot) = get_epoch_and_slot(block_number);
    let key_str = format!("epoch: {} : slot: {}", epoch, slot);
    let mut key_bytes = key_str.as_bytes().to_vec();
    key_bytes.resize(PUBLIC_KEY_SIZE,0);
    // don't judge me... it's temporary ;o)
    let key: PublicKey = key_bytes.try_into().expect("not enough bytes");
    (key_str, key)
}

impl_runtime_apis! {
	impl sp_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: Block) {
            print("########### Execute block");
            debug(&block);
            //debug(&block.header.public_key());
			Executive::execute_block(block);
		}

		fn initialize_block(header: &<Block as BlockT>::Header) {
            let (key_str, _key_bytes) = generate_public_key(header.number());
            //let header_with_key = HookHeader::new_with_key(header.clone(), key_bytes);
            print(format!("########### Initialise block: {} Hash: {} Parent Hash: {}", key_str, header.hash(), header.parent_hash()).as_str());
            //debug(&header_with_key);
            if is_last_block_of_epoch(header.number()) {
                print("########### Last block of epoch");
            };
            //debug(header);
			Executive::initialize_block(&header)
		}
	}

	impl sp_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
            print("########### Metadata");
			OpaqueMetadata::new(Runtime::metadata().into())
		}
	}

	impl sp_block_builder::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
			print("########### Apply Extrinsic");
			Executive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> <Block as BlockT>::Header {
            let header = Executive::finalize_block();
            print(format!("########### Finalise block: hash: {}", header.hash()).as_str());
			header
		}

		fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
			data.create_extrinsics()
		}

		fn check_inherents(
			block: Block,
			data: sp_inherents::InherentData,
		) -> sp_inherents::CheckInherentsResult {
            print("########## Check Inherents");
			data.check_extrinsics(&block)
		}
	}

	impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(
			source: TransactionSource,
			tx: <Block as BlockT>::Extrinsic,
			block_hash: <Block as BlockT>::Hash,
		) -> TransactionValidity {
			Executive::validate_transaction(source, tx, block_hash)
		}
	}

	impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(header: &<Block as BlockT>::Header) {
			Executive::offchain_worker(header)
		}
	}

	impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
		fn slot_duration() -> sp_consensus_aura::SlotDuration {
			sp_consensus_aura::SlotDuration::from_millis(Aura::slot_duration())
		}

		fn authorities() -> Vec<AuraId> {
			Aura::authorities().into_inner()
		}
	}

	impl sp_session::SessionKeys<Block> for Runtime {
		fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
			opaque::SessionKeys::generate(seed)
		}

		fn decode_session_keys(
			encoded: Vec<u8>,
		) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
			opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
		}
	}

	impl fg_primitives::GrandpaApi<Block> for Runtime {
		fn grandpa_authorities() -> GrandpaAuthorityList {
			Grandpa::grandpa_authorities()
		}

		fn current_set_id() -> fg_primitives::SetId {
			Grandpa::current_set_id()
		}

		fn submit_report_equivocation_unsigned_extrinsic(
			_equivocation_proof: fg_primitives::EquivocationProof<
				<Block as BlockT>::Hash,
				NumberFor<Block>,
			>,
			_key_owner_proof: fg_primitives::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			None
		}

		fn generate_key_ownership_proof(
			_set_id: fg_primitives::SetId,
			_authority_id: GrandpaId,
		) -> Option<fg_primitives::OpaqueKeyOwnershipProof> {
			// NOTE: this is the only implementation possible since we've
			// defined our key owner proof type as a bottom type (i.e. a type
			// with no values).
			None
		}
	}

	impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Index> for Runtime {
		fn account_nonce(account: AccountId) -> Index {
			System::account_nonce(account)
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
		fn query_info(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32,
		) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
			TransactionPayment::query_info(uxt, len)
		}
		fn query_fee_details(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32,
		) -> pallet_transaction_payment::FeeDetails<Balance> {
			TransactionPayment::query_fee_details(uxt, len)
		}
	}

	#[cfg(feature = "runtime-benchmarks")]
	impl frame_benchmarking::Benchmark<Block> for Runtime {
		fn benchmark_metadata(extra: bool) -> (
			Vec<frame_benchmarking::BenchmarkList>,
			Vec<frame_support::traits::StorageInfo>,
		) {
			use frame_benchmarking::{list_benchmark, baseline, Benchmarking, BenchmarkList};
			use frame_support::traits::StorageInfoTrait;
			use frame_system_benchmarking::Pallet as SystemBench;
			use baseline::Pallet as BaselineBench;

			let mut list = Vec::<BenchmarkList>::new();

			list_benchmark!(list, extra, frame_benchmarking, BaselineBench::<Runtime>);
			list_benchmark!(list, extra, frame_system, SystemBench::<Runtime>);
			list_benchmark!(list, extra, pallet_balances, Balances);
			list_benchmark!(list, extra, pallet_timestamp, Timestamp);
			list_benchmark!(list, extra, pallet_template, TemplateModule);

			let storage_info = AllPalletsWithSystem::storage_info();

			return (list, storage_info)
		}

		fn dispatch_benchmark(
			config: frame_benchmarking::BenchmarkConfig
		) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
			use frame_benchmarking::{baseline, Benchmarking, BenchmarkBatch, add_benchmark, TrackedStorageKey};

			use frame_system_benchmarking::Pallet as SystemBench;
			use baseline::Pallet as BaselineBench;

			impl frame_system_benchmarking::Config for Runtime {}
			impl baseline::Config for Runtime {}

			let whitelist: Vec<TrackedStorageKey> = vec![
				// Block Number
				hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef702a5c1b19ab7a04f536c519aca4983ac").to_vec().into(),
				// Total Issuance
				hex_literal::hex!("c2261276cc9d1f8598ea4b6a74b15c2f57c875e4cff74148e4628f264b974c80").to_vec().into(),
				// Execution Phase
				hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef7ff553b5a9862a516939d82b3d3d8661a").to_vec().into(),
				// Event Count
				hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef70a98fdbe9ce6c55837576c60c7af3850").to_vec().into(),
				// System Events
				hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7").to_vec().into(),
			];

			let mut batches = Vec::<BenchmarkBatch>::new();
			let params = (&config, &whitelist);

			add_benchmark!(params, batches, frame_benchmarking, BaselineBench::<Runtime>);
			add_benchmark!(params, batches, frame_system, SystemBench::<Runtime>);
			add_benchmark!(params, batches, pallet_balances, Balances);
			add_benchmark!(params, batches, pallet_timestamp, Timestamp);
			add_benchmark!(params, batches, pallet_blogchain, TemplateModule);

			Ok(batches)
		}
	}
}
