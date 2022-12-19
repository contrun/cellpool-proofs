use crate::signature::Signature;

use crate::random_oracle::blake2s::RO;
use crate::random_oracle::RandomOracle;

use super::account::{AccountId, AccountPublicKey, AccountSecretKey};
use super::ledger::{self, Amount};
use super::signature::{
    schnorr::{self, Schnorr},
    SignatureScheme,
};
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_std::rand::Rng;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

/// Transaction transferring some amount from one account to another.
#[derive(Copy, Clone, Debug)]
pub struct Transaction {
    /// The account information of the sender.
    pub sender: AccountId,
    /// The account information of the recipient.
    pub recipient: AccountId,
    /// The amount being transferred from the sender to the receiver.
    pub amount: Amount,
    /// The fee being collected by the miner.
    pub fee: Amount,
}

impl Transaction {
    /// Convert the transaction information to bytes.
    pub fn to_bytes_le(&self) -> Vec<u8> {
        ark_ff::to_bytes![
            self.sender.to_bytes_le(),
            self.recipient.to_bytes_le(),
            self.amount.to_bytes_le(),
            self.fee.to_bytes_le()
        ]
        .unwrap()
    }

    pub fn new(sender: AccountId, recipient: AccountId, amount: Amount) -> Self {
        Self {
            sender,
            recipient,
            amount,
            fee: ledger::Amount(0),
        }
    }
}

pub fn get_transactions_hash(transactions: &[Transaction]) -> [u8; 32] {
    let mut hash_input = Vec::new();
    for transaction in transactions {
        hash_input.extend_from_slice(&transaction.to_bytes_le());
    }
    RO::evaluate(&(), &hash_input).unwrap()
}

/// Transaction transferring some amount from one account to another.
#[derive(Clone, Debug)]
pub struct SignedTransaction {
    transaction: Transaction,
    /// The spend authorization is a signature over the sender, the recipient,
    /// and the amount.
    pub signature: Signature,
}

impl From<SignedTransaction> for Transaction {
    fn from(signed_transaction: SignedTransaction) -> Transaction {
        (&signed_transaction).into()
    }
}

impl From<&SignedTransaction> for Transaction {
    fn from(signed_transaction: &SignedTransaction) -> Transaction {
        signed_transaction.transaction
    }
}

impl SignedTransaction {
    pub fn sender(&self) -> AccountId {
        self.transaction.sender
    }

    pub fn recipient(&self) -> AccountId {
        self.transaction.recipient
    }

    pub fn amount(&self) -> Amount {
        self.transaction.amount
    }

    pub fn fee(&self) -> Amount {
        self.transaction.fee
    }

    /// Verify just the signature in the transaction.
    fn verify_signature(
        &self,
        pp: &schnorr::Parameters<EdwardsProjective>,
        pub_key: &AccountPublicKey,
    ) -> bool {
        // The authorized message consists of
        // (SenderAccId || SenderPubKey || RecipientAccId || RecipientPubKey || Amount)
        let message = self.transaction.to_bytes_le();
        Schnorr::verify(pp, pub_key, &message, &self.signature).unwrap()
    }

    /// Check that the transaction is valid for the given ledger state. This checks
    /// the following conditions:
    /// 1. Verify that the signature is valid with respect to the public key
    /// corresponding to `self.sender`.
    /// 2. Verify that the sender's account has sufficient balance to finance
    /// the transaction.
    /// 3. Verify that the recipient's account exists.
    pub fn validate(&self, parameters: &ledger::Parameters, state: &ledger::State) -> bool {
        // Lookup public key corresponding to sender ID
        if let Some(sender_acc_info) = state.id_to_account_info.get(&self.sender()) {
            let mut result = true;
            // Check that the account_info exists in the Merkle tree.
            result &= {
                let path = state
                    .account_merkle_tree
                    .generate_proof(self.sender().0 as usize)
                    .expect("path should exist");
                path.verify(
                    &parameters.leaf_crh_params,
                    &parameters.two_to_one_crh_params,
                    &state.account_merkle_tree.root(),
                    &sender_acc_info.to_bytes_le(),
                )
                .unwrap()
            };
            // Verify the signature against the sender pubkey.
            result &= self.verify_signature(&parameters.sig_params, &sender_acc_info.public_key);
            // assert!(result, "signature verification failed");
            // Verify the amount is available in the sender account.
            result &= self.amount() <= sender_acc_info.balance;
            // Verify that recipient account exists.
            result &= state.id_to_account_info.get(&self.recipient()).is_some();
            result
        } else {
            false
        }
    }

    /// Create a (possibly invalid) transaction.
    pub fn create<R: Rng>(
        parameters: &ledger::Parameters,
        sender: AccountId,
        recipient: AccountId,
        amount: Amount,
        sender_sk: &AccountSecretKey,
        rng: &mut R,
    ) -> Self {
        // The authorized message consists of (SenderAccId || RecipientAccId || Amount)
        let transaction = Transaction::new(sender, recipient, amount);
        let message = transaction.to_bytes_le();
        let signature = Schnorr::sign(&parameters.sig_params, sender_sk, &message, rng).unwrap();
        Self {
            transaction,
            signature,
        }
    }
}

// Ideas to make exercises more interesting/complex:
// 1. Add fees
// 2. Add recipient confirmation requirement if tx amount is too large.
// 3. Add authority confirmation if tx amount is too large.
// 4. Create account if it doesn't exist.
// 5. Add idea for compressing state transitions with repeated senders and recipients.
