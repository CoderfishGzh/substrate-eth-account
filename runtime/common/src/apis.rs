#[macro_export]
macro_rules! impl_runtime_apis_plus_common {
    {$($custom:tt)*} => {
        impl_runtime_apis! {
            $($custom)*

            impl sp_api::Core<Block> for Runtime {
				fn version() -> RuntimeVersion {
					VERSION
				}

				fn execute_block(block: Block) {
					Executive::execute_block(block)
				}

				fn initialize_block(header: &<Block as BlockT>::Header) {
					Executive::initialize_block(header)
				}
			}

            impl sp_api::Metadata<Block> for Runtime {
				fn metadata() -> OpaqueMetadata {
					OpaqueMetadata::new(Runtime::metadata().into())
				}
			}

            impl sp_block_builder::BlockBuilder<Block> for Runtime {
				fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
					Executive::apply_extrinsic(extrinsic)
				}

				fn finalize_block() -> <Block as BlockT>::Header {
					Executive::finalize_block()
				}

				fn inherent_extrinsics(
					data: sp_inherents::InherentData,
				) -> Vec<<Block as BlockT>::Extrinsic> {
					data.create_extrinsics()
				}

				fn check_inherents(
					block: Block,
					data: sp_inherents::InherentData,
				) -> sp_inherents::CheckInherentsResult {
					data.check_extrinsics(&block)
				}
			}

            impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
				fn offchain_worker(header: &<Block as BlockT>::Header) {
					Executive::offchain_worker(header)
				}
			}

            impl sp_session::SessionKeys<Block> for Runtime {
				fn decode_session_keys(
					encoded: Vec<u8>,
				) -> Option<Vec<(Vec<u8>, sp_core::crypto::KeyTypeId)>> {
					opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
				}

				fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
					opaque::SessionKeys::generate(seed)
				}
			}

            impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Index> for Runtime {
				fn account_nonce(account: AccountId) -> Index {
					System::account_nonce(account)
				}
			}

            impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance>
			for Runtime {
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

            impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
                fn validate_transaction(
                    source: TransactionSource,
                    tx: <Block as BlockT>::Extrinsic,
                    block_hash: <Block as BlockT>::Hash,
                ) -> TransactionValidity {
                    Executive::validate_transaction(source, tx, block_hash)
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

            impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentCallApi<Block, Balance, RuntimeCall> for Runtime {
		        fn query_call_info(
			        call: RuntimeCall,
			        len: u32,
		        ) -> pallet_transaction_payment::RuntimeDispatchInfo<Balance> {
			        TransactionPayment::query_call_info(call, len)
		        }
		        fn query_call_fee_details(
			        call: RuntimeCall,
			        len: u32,
		        ) -> pallet_transaction_payment::FeeDetails<Balance> {
			        TransactionPayment::query_call_fee_details(call, len)
		        }
	        }
        }

    }
}
