extern crate starknet_rpc_test;

use std::vec;

use assert_matches::assert_matches;
use rstest::rstest;
use starknet_accounts::{Account, Call};
use starknet_core::types::{BlockId, StarknetError, BlockTag, MaybePendingTransactionReceipt, TransactionFinalityStatus, ExecutionResult, TransactionReceipt};
use starknet_ff::FieldElement;
use starknet_providers::{MaybeUnknownErrorCode, Provider, ProviderError, StarknetErrorWithMessage};
use starknet_rpc_test::constants::{ARGENT_CONTRACT_ADDRESS, FEE_TOKEN_ADDRESS, SIGNER_PRIVATE, CONTRACT_TEST_CONTRACT_ADDRESS, MADARA_RUNTIME_ORIGIN_CONTRACT_ADDRESS,};
use starknet_rpc_test::fixtures::{madara, ThreadSafeMadaraClient};
use starknet_rpc_test::utils::{TransactionReceiptResult, get_transaction_receipt_poll, build_single_owner_account, read_erc20_balance, AccountActions, U256, assert_eq_msg_to_l1};
use starknet_rpc_test::{TransactionResult, SendTransactionError, Transaction};
use starknet_core::utils::get_selector_from_name;

#[rstest]
#[tokio::test]
async fn runtime_denies_invoke_with_sender_as_madara_runtime_origin(madara: &ThreadSafeMadaraClient) -> Result<(), anyhow::Error> {
    let rpc = madara.get_starknet_client().await;

    let funding_account = build_single_owner_account(&rpc, SIGNER_PRIVATE, MADARA_RUNTIME_ORIGIN_CONTRACT_ADDRESS, false);

    assert_eq!(
        rpc
        .get_storage_at(
            FieldElement::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).expect("Invalid Contract Address"),
            FieldElement::from(get_selector_from_name("u8_storage").unwrap()),
            BlockId::Tag(BlockTag::Latest),
        )
        .await.expect("get_storage_at unwraps"),
        FieldElement::ZERO//from_hex_be("0x00").expect("Valid expected value")
    );

    let mut madara_write_lock = madara.write().await;

    let mut txs = madara_write_lock
        .create_block_with_txs(vec![Transaction::Execution(funding_account.invoke_call(
            vec![
                Call{
                    to: FieldElement::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).expect("Invalid Contract Address"),
                    selector: FieldElement::from(get_selector_from_name("privileged_write_u8").unwrap()),
                    calldata:
                    vec![
                        // FieldElement::ONE, // Calldata len
                        FieldElement::from_hex_be("0x01").unwrap()
                    ]
                }
            ],
            None
        ))])
        .await?;
    
        assert_eq!(txs.len(), 1);
        let rpc_response = match txs.remove(0).unwrap() {
            TransactionResult::Execution(rpc_response) => rpc_response,
            _ => panic!("expected execution result"),
        };
    
        let invoke_tx_receipt = get_transaction_receipt_poll(&rpc, rpc_response.transaction_hash).await;
        assert!(
            invoke_tx_receipt.is_none(),
            "Invoke should fail"
        );

    assert_eq!(
        rpc
        .get_storage_at(
            FieldElement::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).expect("Invalid Contract Address"),
            FieldElement::from(get_selector_from_name("u8_storage").unwrap()),
            BlockId::Tag(BlockTag::Latest),
        )
        .await.expect("get_storage_at unwraps"),
        FieldElement::ZERO
    );

    Ok(())
}

#[rstest]
#[tokio::test]
async fn other_account_cannot_access_privileged_contract_entrypoint(madara: &ThreadSafeMadaraClient) -> Result<(), anyhow::Error> {
    let rpc = madara.get_starknet_client().await;

    let funding_account = build_single_owner_account(&rpc, SIGNER_PRIVATE, ARGENT_CONTRACT_ADDRESS, true);

    assert_eq!(
        rpc
        .get_storage_at(
            FieldElement::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).expect("Invalid Contract Address"),
            FieldElement::from(get_selector_from_name("u8_storage").unwrap()),
            BlockId::Tag(BlockTag::Latest),
        )
        .await.expect("get_storage_at unwraps"),
        FieldElement::ZERO
    );

    let mut madara_write_lock = madara.write().await;

    let mut txs = madara_write_lock
        .create_block_with_txs(vec![Transaction::Execution(funding_account.invoke_call(
            vec![
                Call{
                    to: FieldElement::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).expect("Invalid Contract Address"),
                    selector: FieldElement::from(get_selector_from_name("privileged_write_u8").unwrap()),
                    calldata:
                    vec![
                        // FieldElement::ONE, // Calldata len
                        FieldElement::from_hex_be("0x01").unwrap()
                    ]
                }
            ],
            None
        ))])
        .await?;
    
        assert_eq!(txs.len(), 1);
        let rpc_response = match txs.remove(0).unwrap() {
            TransactionResult::Execution(rpc_response) => rpc_response,
            _ => panic!("expected execution result"),
        };
    
        let invoke_tx_receipt = get_transaction_receipt_poll(&rpc, rpc_response.transaction_hash).await.expect("Invoke should not fail");
        
        match invoke_tx_receipt {
            Ok(MaybePendingTransactionReceipt::Receipt(TransactionReceipt::Invoke(receipt))) => {
                assert_eq!(receipt.transaction_hash, rpc_response.transaction_hash);
                // assert_eq!(receipt.actual_fee, expected_fee); TODO: Fix in RPC
                assert_eq!(receipt.finality_status, TransactionFinalityStatus::AcceptedOnL2);
                assert_eq_msg_to_l1(receipt.messages_sent, vec![]);
                assert_matches!(receipt.execution_result, ExecutionResult::Reverted { .. });
            }
            _ => panic!("expected invoke transaction receipt"),
        };

    assert_eq!(
        rpc
        .get_storage_at(
            FieldElement::from_hex_be(CONTRACT_TEST_CONTRACT_ADDRESS).expect("Invalid Contract Address"),
            FieldElement::from(get_selector_from_name("u8_storage").unwrap()),
            BlockId::Tag(BlockTag::Latest),
        )
        .await.expect("get_storage_at unwraps"),
        FieldElement::ZERO
    );

    Ok(())
}
