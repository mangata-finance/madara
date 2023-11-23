use blockifier::abi::abi_utils::get_storage_var_address;
use frame_support::{assert_err, assert_ok};
use mp_felt::Felt252Wrapper;
use mp_transactions::compute_hash::ComputeTransactionHash;
use mp_transactions::{InvokeTransaction, InvokeTransactionV1};
use pretty_assertions::assert_eq;
use sp_runtime::traits::ValidateUnsigned;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidityError, ValidTransaction,
};
use starknet_api::api_core::{ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Event as StarknetEvent, EventContent, EventData, EventKey, Fee, TransactionHash};
use starknet_core::utils::get_selector_from_name;
use starknet_crypto::FieldElement;

use super::constants::{BLOCKIFIER_ACCOUNT_ADDRESS, MULTIPLE_EVENT_EMITTING_CONTRACT_ADDRESS, TEST_CONTRACT_ADDRESS, MADARA_RUNTIME_ORIGIN_CONTRACT_ADDRESS, CONTRACT_TEST_CONTRACT_ADDRESS};
use super::mock::default_mock::*;
use super::mock::*;
use super::utils::sign_message_hash;
use crate::message::Message;
use crate::tests::{
    get_invoke_argent_dummy, get_invoke_braavos_dummy, get_invoke_dummy, get_invoke_emit_event_dummy,
    get_invoke_nonce_dummy, get_invoke_openzeppelin_dummy, get_storage_read_write_dummy, set_nonce, fees_disabled::get_balance_default_mock,
    utils::{build_transfer_invoke_transaction},
};
use crate::{Call, Config, Error, Event, StorageView, MadaraExecutorCalls, MadaraExecutorCallsResults, MadaraExecutorCall, MadaraExecutorCallResult};
use crate::types::BuildTransferInvokeTransaction;

#[test]
fn madara_runtime_origin_test() {
    new_test_ext::<MockRuntime>().execute_with(|| {
        basic_test_setup(2);
		let _ = env_logger::try_init();

        
        let madara_runtime_origin_contract_address = Felt252Wrapper::from_hex_be(MADARA_RUNTIME_ORIGIN_CONTRACT_ADDRESS).unwrap();
        let contract_test_contract_address = Felt252Wrapper::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).unwrap();


        let internal_selector = Felt252Wrapper::from(get_selector_from_name("echo_u8a").unwrap());
        println!("{:?}", internal_selector);

        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );

        let transaction = InvokeTransactionV1 {
            sender_address: madara_runtime_origin_contract_address.into(),
            calldata: vec![
                Felt252Wrapper::ONE,
                contract_test_contract_address, // Token address
                internal_selector,
                Felt252Wrapper::THREE, // Calldata len
                Felt252Wrapper::TWO,
                Felt252Wrapper::from_hex_be("0x08").unwrap(),
                Felt252Wrapper::from_hex_be("0x09").unwrap()
            ],
            nonce: Felt252Wrapper::ZERO,
            max_fee: u128::MAX,
            signature: vec![],
        };

        assert_ok!(Starknet::madara_executor_invoke(RuntimeOrigin::root(), transaction.into()));
        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );

    });
}

#[test]
fn madara_runtime_origin_with_madara_executor_invoke_on_privileged_entrypoint_works() {
    new_test_ext::<MockRuntime>().execute_with(|| {
        basic_test_setup(2);
		let _ = env_logger::try_init();

        
        let madara_runtime_origin_contract_address = Felt252Wrapper::from_hex_be(MADARA_RUNTIME_ORIGIN_CONTRACT_ADDRESS).unwrap();
        let contract_test_contract_address = Felt252Wrapper::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).unwrap();


        let internal_selector = Felt252Wrapper::from(get_selector_from_name("privileged_write_u8").unwrap());
        println!("{:?}", internal_selector);

        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );

        let transaction = InvokeTransactionV1 {
            sender_address: madara_runtime_origin_contract_address.into(),
            calldata: vec![
                Felt252Wrapper::ONE,
                contract_test_contract_address, // Token address
                internal_selector,
                Felt252Wrapper::ONE, // Calldata len
                Felt252Wrapper::from_hex_be("0x01").unwrap()
            ],
            nonce: Felt252Wrapper::ZERO,
            max_fee: u128::MAX,
            signature: vec![],
        };

        assert_ok!(Starknet::madara_executor_invoke(RuntimeOrigin::root(), transaction.into()));
        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x01").unwrap())
        );

    });
}

#[test]
fn other_account_with_invoke_on_privileged_entrypoint_does_not_work() {
    new_test_ext::<MockRuntime>().execute_with(|| {
        basic_test_setup(2);
		let _ = env_logger::try_init();

        let sender_account = get_account_address(None, AccountType::V0(AccountTypeV0Inner::NoValidate));
        let contract_test_contract_address = Felt252Wrapper::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).unwrap();


        let internal_selector = Felt252Wrapper::from(get_selector_from_name("privileged_write_u8").unwrap());
        println!("{:?}", sender_account);
        println!("{:?}", internal_selector);

        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );
        let transaction = InvokeTransactionV1 {
            sender_address: sender_account.into(),
            calldata: vec![
                contract_test_contract_address, // Token address
                internal_selector,
                Felt252Wrapper::ONE, // Calldata len
                Felt252Wrapper::from_hex_be("0x01").unwrap()
            ],
            nonce: Felt252Wrapper::ZERO,
            max_fee: u128::MAX,
            signature: vec![],
        };

        let none_origin = RuntimeOrigin::none();

        assert_ok!(Starknet::invoke(none_origin, transaction.into()));
        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );
    });
}

#[test]
fn other_account_entrancy_attempt_into_madara_runtime_origin_account_prevented() {
    new_test_ext::<MockRuntime>().execute_with(|| {
        basic_test_setup(2);
		let _ = env_logger::try_init();

        
        let madara_runtime_origin_contract_address = Felt252Wrapper::from_hex_be(MADARA_RUNTIME_ORIGIN_CONTRACT_ADDRESS).unwrap();
        let sender_account = get_account_address(None, AccountType::V0(AccountTypeV0Inner::NoValidate));
        let contract_test_contract_address = Felt252Wrapper::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).unwrap();


        let internal_selector = Felt252Wrapper::from(get_selector_from_name("__execute__").unwrap());
        let contract_test_internal_selector = Felt252Wrapper::from(get_selector_from_name("privileged_write_u8").unwrap());

        println!("{:?}", internal_selector);
        println!("{:?}", contract_test_internal_selector);
        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );
        let transaction = InvokeTransactionV1 {
            sender_address: sender_account.into(),
            calldata: vec![
                madara_runtime_origin_contract_address, // Token address
                internal_selector,
                Felt252Wrapper::from_hex_be("0x05").unwrap(),
                Felt252Wrapper::from_hex_be("0x01").unwrap(),
                contract_test_contract_address,
                contract_test_internal_selector,
                Felt252Wrapper::ONE, // Calldata len
                Felt252Wrapper::from_hex_be("0x01").unwrap()
            ],
            nonce: Felt252Wrapper::ZERO,
            max_fee: u128::MAX,
            signature: vec![],
        };

        let none_origin = RuntimeOrigin::none();

        assert_ok!(Starknet::invoke(none_origin, transaction.into()));
        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );
    });
}

#[test]
fn other_account_with_madara_executor_invoke_does_not_work() {
    new_test_ext::<MockRuntime>().execute_with(|| {
        basic_test_setup(2);
		let _ = env_logger::try_init();

        
        let contract_test_contract_address = Felt252Wrapper::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).unwrap();
        let sender_account = get_account_address(None, AccountType::V0(AccountTypeV0Inner::NoValidate));

        let internal_selector = Felt252Wrapper::from(get_selector_from_name("privileged_write_u8").unwrap());
        println!("{:?}", internal_selector);

        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );

        let transaction = InvokeTransactionV1 {
            sender_address: sender_account.into(),
            calldata: vec![
                contract_test_contract_address, // Token address
                internal_selector,
                Felt252Wrapper::ONE, // Calldata len
                Felt252Wrapper::from_hex_be("0x01").unwrap()
            ],
            nonce: Felt252Wrapper::ZERO,
            max_fee: u128::MAX,
            signature: vec![],
        };

        assert_err!(Starknet::madara_executor_invoke(RuntimeOrigin::root(), transaction.into()), Error::<MockRuntime>::MadaraRuntimeOriginSenderAddressOnly);
        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );

    });
}

#[test]
fn madara_runtime_origin_with_invoke_does_not_work() {
    new_test_ext::<MockRuntime>().execute_with(|| {
        basic_test_setup(2);
		let _ = env_logger::try_init();

        let madara_runtime_origin_contract_address = Felt252Wrapper::from_hex_be(MADARA_RUNTIME_ORIGIN_CONTRACT_ADDRESS).unwrap();
        let contract_test_contract_address = Felt252Wrapper::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).unwrap();


        let internal_selector = Felt252Wrapper::from(get_selector_from_name("privileged_write_u8").unwrap());

        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );
        let transaction = InvokeTransactionV1 {
            sender_address: madara_runtime_origin_contract_address.into(),
            calldata: vec![
                Felt252Wrapper::ONE,
                contract_test_contract_address, // Token address
                internal_selector,
                Felt252Wrapper::ONE, // Calldata len
                Felt252Wrapper::from_hex_be("0x01").unwrap()
            ],
            nonce: Felt252Wrapper::ZERO,
            max_fee: u128::MAX,
            signature: vec![],
        };

        let none_origin = RuntimeOrigin::none();

        assert_err!(Starknet::invoke(none_origin, transaction.into()), Error::<MockRuntime>::MadaraRuntimeOriginIsPrivileged);
        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );
    });
}


#[test]
fn madara_runtime_origin_with_madara_executor_invoke_does_not_charge_fee() {
    new_test_ext::<MockRuntime>().execute_with(|| {
        basic_test_setup(2);
		let _ = env_logger::try_init();

        
        let madara_runtime_origin_contract_address = Felt252Wrapper::from_hex_be(MADARA_RUNTIME_ORIGIN_CONTRACT_ADDRESS).unwrap();
        let contract_test_contract_address = Felt252Wrapper::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).unwrap();


        let internal_selector = Felt252Wrapper::from(get_selector_from_name("privileged_write_u8").unwrap());
        println!("{:?}", internal_selector);

        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );

        let (initial_balance_low, initial_balance_high) = get_balance_default_mock(madara_runtime_origin_contract_address.into());
        assert_eq!(
            (initial_balance_low, initial_balance_high),
            (Felt252Wrapper::from_hex_be("0x00").unwrap(), Felt252Wrapper::from_hex_be("0x00").unwrap())
        );

        let transaction = InvokeTransactionV1 {
            sender_address: madara_runtime_origin_contract_address.into(),
            calldata: vec![
                Felt252Wrapper::ONE,
                contract_test_contract_address, // Token address
                internal_selector,
                Felt252Wrapper::ONE, // Calldata len
                Felt252Wrapper::from_hex_be("0x01").unwrap()
            ],
            nonce: Felt252Wrapper::ZERO,
            max_fee: u128::MAX,
            signature: vec![],
        };

        assert_ok!(Starknet::madara_executor_invoke(RuntimeOrigin::root(), transaction.into()));
        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x01").unwrap())
        );

        let sender_account = get_account_address(None, AccountType::V0(AccountTypeV0Inner::NoValidate));
        let transfer_transaction = build_transfer_invoke_transaction(BuildTransferInvokeTransaction {
            sender_address: sender_account.into(),
            token_address: Starknet::fee_token_address().into(),
            recipient: madara_runtime_origin_contract_address.into(),
            amount_low: Felt252Wrapper::from(15_000_000u128),
            amount_high: Felt252Wrapper::ZERO,
            nonce: Felt252Wrapper::ZERO,
        });

        assert_ok!(Starknet::invoke(RuntimeOrigin::none(), transfer_transaction));
        
        let (after_transfer_balance_low, after_transfer_balance_high) = get_balance_default_mock(madara_runtime_origin_contract_address.into());
        assert_eq!(
            (after_transfer_balance_low, after_transfer_balance_high),
            (Felt252Wrapper::from_hex_be("0xe4e1c0").unwrap(), Felt252Wrapper::from_hex_be("0x00").unwrap())
        );

 
        let transaction = InvokeTransactionV1 {
            sender_address: madara_runtime_origin_contract_address.into(),
            calldata: vec![
                Felt252Wrapper::ONE,
                contract_test_contract_address, // Token address
                internal_selector,
                Felt252Wrapper::ONE, // Calldata len
                Felt252Wrapper::from_hex_be("0x02").unwrap()
            ],
            nonce: Felt252Wrapper::ZERO,
            max_fee: u128::MAX,
            signature: vec![],
        };

        assert_ok!(Starknet::madara_executor_invoke(RuntimeOrigin::root(), transaction.into()));
        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x02").unwrap())
        );

        let (after_txn_balance_low, after_txn_balance_high) = get_balance_default_mock(madara_runtime_origin_contract_address.into());
        assert_eq!(
            (after_txn_balance_low, after_txn_balance_high),
            (after_transfer_balance_low, after_transfer_balance_high)
        );

    });
}

#[test]
fn madara_runtime_origin_with_madara_executor_invoke_does_not_validate_or_update_nonce() {
    new_test_ext::<MockRuntime>().execute_with(|| {
        basic_test_setup(2);
		let _ = env_logger::try_init();

        
        let madara_runtime_origin_contract_address = Felt252Wrapper::from_hex_be(MADARA_RUNTIME_ORIGIN_CONTRACT_ADDRESS).unwrap();
        let contract_test_contract_address = Felt252Wrapper::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).unwrap();


        let internal_selector = Felt252Wrapper::from(get_selector_from_name("privileged_write_u8").unwrap());
        println!("{:?}", internal_selector);

        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );

        assert_eq!(
            Starknet::nonce(Into::<ContractAddress>::into(madara_runtime_origin_contract_address)).0,
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );

        let transaction = InvokeTransactionV1 {
            sender_address: madara_runtime_origin_contract_address.into(),
            calldata: vec![
                Felt252Wrapper::ONE,
                contract_test_contract_address, // Token address
                internal_selector,
                Felt252Wrapper::ONE, // Calldata len
                Felt252Wrapper::from_hex_be("0x01").unwrap()
            ],
            nonce: Felt252Wrapper::from_hex_be("0x10").unwrap(),
            max_fee: u128::MAX,
            signature: vec![],
        };

        assert_ok!(Starknet::madara_executor_invoke(RuntimeOrigin::root(), transaction.into()));
        assert_eq!(
            Starknet::get_storage_at(contract_test_contract_address.into(), get_storage_var_address("u8_storage", &[]).unwrap()).unwrap(),
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x01").unwrap())
        );
        assert_eq!(
            Starknet::nonce(Into::<ContractAddress>::into(madara_runtime_origin_contract_address)).0,
            StarkFelt::from(Felt252Wrapper::from_hex_be("0x00").unwrap())
        );

    });
}

#[test]
fn madara_executor_invoke_curated_call_works_with_single_call() {
    new_test_ext::<MockRuntime>().execute_with(|| {
        basic_test_setup(2);
		let _ = env_logger::try_init();

        let calls_res = Starknet::madara_executor_invoke_curated_call_inner(
            MadaraExecutorCalls(
                vec![MadaraExecutorCall::EchoU8(7_u8)]
            )
        ).expect("operation is sucessful");
        assert_eq!(calls_res, MadaraExecutorCallsResults(vec![MadaraExecutorCallResult::EchoU8Result(7_u8)]));

    });
}

#[test]
fn madara_executor_invoke_curated_call_works_with_multiple_calls() {
    new_test_ext::<MockRuntime>().execute_with(|| {
        basic_test_setup(2);
		let _ = env_logger::try_init();

        let calls_res = Starknet::madara_executor_invoke_curated_call_inner(
            MadaraExecutorCalls(
                vec![
                    MadaraExecutorCall::EchoU8(7_u8),
                    MadaraExecutorCall::EchoU8(0_u8),
                    MadaraExecutorCall::EchoU8a(vec![1_u8, 2_u8, 3_u8, 8_u8, 11_u8]),
                    MadaraExecutorCall::EchoU8a(vec![]),
                    MadaraExecutorCall::EchoU8aU8a(vec![157_u8, 2_u8, 3_u8, 8_u8, 110_u8], vec![181_u8, 123_u8]),
                    MadaraExecutorCall::EchoU8aU8a(vec![157_u8, 2_u8, 3_u8, 8_u8, 110_u8], vec![]),
                    MadaraExecutorCall::EchoU8aU8a(vec![], vec![181_u8, 123_u8]),
                    MadaraExecutorCall::EchoU8aU8a(vec![], vec![]),
                    MadaraExecutorCall::EchoU8U128(4_u8, 19_u128),
                    MadaraExecutorCall::EchoTupleU8U128((41_u8, 191_u128)),
                    MadaraExecutorCall::EchoOptionU8U128(Some((6_u8, 13_u128))),
                    MadaraExecutorCall::EchoOptionU8U128(None)
                ]
            )
        ).expect("operation is sucessful");
        assert_eq!(calls_res, MadaraExecutorCallsResults(
            vec![
                MadaraExecutorCallResult::EchoU8Result(7_u8),
                MadaraExecutorCallResult::EchoU8Result(0_u8),
                MadaraExecutorCallResult::EchoU8aResult(vec![1_u8, 2_u8, 3_u8, 8_u8, 11_u8]),
                MadaraExecutorCallResult::EchoU8aResult(vec![]),
                MadaraExecutorCallResult::EchoU8aU8aResult(vec![157_u8, 2_u8, 3_u8, 8_u8, 110_u8], vec![181_u8, 123_u8]),
                MadaraExecutorCallResult::EchoU8aU8aResult(vec![157_u8, 2_u8, 3_u8, 8_u8, 110_u8], vec![]),
                MadaraExecutorCallResult::EchoU8aU8aResult(vec![], vec![181_u8, 123_u8]),
                MadaraExecutorCallResult::EchoU8aU8aResult(vec![], vec![]),
                MadaraExecutorCallResult::EchoU8U128Result(4_u8, 19_u128),
                MadaraExecutorCallResult::EchoTupleU8U128Result((41_u8, 191_u128)),
                MadaraExecutorCallResult::EchoOptionU8U128Result(Some((6_u8, 13_u128))),
                MadaraExecutorCallResult::EchoOptionU8U128Result(None)
            ]
        ));

    });
}

// #[test]
// fn madara_executor_invoke_curated_call_works_test() {
//     new_test_ext::<MockRuntime>().execute_with(|| {
//         basic_test_setup(2);
// 		let _ = env_logger::try_init();

//         let calls_res = Starknet::madara_executor_invoke_curated_call_inner(
//             MadaraExecutorCalls(
//                 vec![
//                     MadaraExecutorCall::EchoU8a(vec![8_u8, 9_u8]),
//                     // MadaraExecutorCall::EchoU8(7_u8),
//                     // MadaraExecutorCall::EchoU8a(vec![1_u8, 2_u8, 3_u8, 8_u8, 11_u8]),
//                     // MadaraExecutorCall::EchoU8U128(4_u8, 19_u128),
//                     // MadaraExecutorCall::EchoOptionU8U128(Some((6_u8, 13_u128))),
//                     // MadaraExecutorCall::EchoOptionU8U128(None)
//                 ]
//             )
//         ).expect("operation is sucessful");
//         assert_eq!(calls_res, MadaraExecutorCallsResults(
//             vec![
//                 MadaraExecutorCallResult::EchoU8aResult(vec![8_u8, 9_u8]),
//                 // MadaraExecutorCallResult::EchoU8Result(7_u8),
//                 // MadaraExecutorCallResult::EchoU8aResult(vec![1_u8, 2_u8, 3_u8, 8_u8, 11_u8]),
//                 // MadaraExecutorCallResult::EchoU8U128Result(4_u8, 19_u128),
//                 // MadaraExecutorCallResult::EchoOptionU8U128Result(Some((6_u8, 13_u128))),
//                 // MadaraExecutorCallResult::EchoOptionU8U128Result(None)
//             ]
//         ));

//     });
// }
