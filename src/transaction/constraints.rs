use super::Transaction;

use crate::account::{AccountInformationVar, AccountPublicKeyVar};
use crate::ledger::{self, AccPathVar, AccRootVar, AmountVar};

use crate::signature::constraints::SigVerifyGadget;
use crate::signature::schnorr::constraints::{
    ParametersVar as SchnorrParamsVar, SchnorrSignatureVerifyGadget,
};
use crate::signature::SignatureVar;
use crate::ConstraintF;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use std::borrow::Borrow;

/// Transaction transferring some amount from one account to another.
pub struct TransactionVar {
    /// The account information of the sender.
    pub sender: AccountPublicKeyVar,
    /// The account information of the recipient.
    pub recipient: AccountPublicKeyVar,
    /// The amount being transferred from the sender to the receiver.
    pub amount: AmountVar,
    /// The fee being collected by the miner.
    pub fee: AmountVar,
}

impl TransactionVar {
    /// Convert the transaction information to bytes.
    pub fn to_bytes_le(&self) -> Vec<UInt8<ConstraintF>> {
        let mut message = self
            .sender
            .to_bytes()
            .expect("Must serialize AccountPublicKeyVar");
        message.extend(
            self.recipient
                .to_bytes()
                .expect("Must serialize AccountPublicKeyVar"),
        );
        message.extend(self.amount.to_bytes_le());
        message.extend(self.fee.to_bytes_le());
        message
    }

    /// Verify just the signature in the transaction.
    #[tracing::instrument(target = "r1cs", skip(self, pp, pub_key))]
    fn verify_signature(
        &self,
        pp: &SchnorrParamsVar<EdwardsProjective, EdwardsVar>,
        pub_key: &AccountPublicKeyVar,
        signature: &SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        let message = self.to_bytes_le();
        SchnorrSignatureVerifyGadget::verify(pp, pub_key, &message, signature)
    }

    /// Check that the transaction is valid for the given ledger state. This checks
    /// the following conditions:
    /// 1. Verify that the signature is valid with respect to the public key
    /// corresponding to `self.sender`.
    /// 2. Verify that the sender's account has sufficient balance to finance
    /// the transaction.
    /// 3. Verify that the recipient's account exists.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(
        target = "r1cs",
        skip(
            self,
            parameters,
            pre_sender_acc_info,
            pre_sender_path,
            post_sender_path,
            pre_recipient_acc_info,
            pre_recipient_path,
            post_recipient_path,
            pre_root,
            post_root
        )
    )]
    pub fn validate(
        &self,
        parameters: &ledger::ParametersVar,
        signature: &SignatureVar,
        pre_sender_acc_info: &AccountInformationVar,
        pre_sender_path: &AccPathVar,
        post_sender_path: &AccPathVar,
        pre_recipient_acc_info: &AccountInformationVar,
        pre_recipient_path: &AccPathVar,
        post_recipient_path: &AccPathVar,
        pre_root: &AccRootVar,
        post_root: &AccRootVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        // Verify the signature against the sender pubkey.
        let sig_verifies = self.verify_signature(
            &parameters.sig_params,
            &pre_sender_acc_info.public_key,
            signature,
        )?;

        // Compute the new sender balance.
        let mut post_sender_acc_info = pre_sender_acc_info.clone();
        post_sender_acc_info.balance = pre_sender_acc_info.balance.checked_sub(&self.amount)?;

        let mut post_recipient_acc_info = pre_recipient_acc_info.clone();
        post_recipient_acc_info.balance =
            pre_recipient_acc_info.balance.checked_add(&self.amount)?;

        // Check that the pre-tx sender account information is correct with
        // respect to `pre_tx_root`, and that the post-tx sender account
        // information is correct with respect to `post_tx_root`.
        let sender_exists = pre_sender_path.verify_membership(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            pre_root,
            &pre_sender_acc_info,
        )?;
        let sender_updated_correctly = post_sender_path.verify_membership(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            post_root,
            &post_sender_acc_info,
        )?;

        // Check that the pre-tx recipient account information is correct with
        // respect to `pre_tx_root`, and that the post-tx recipient account
        // information is correct with respect to `post_tx_root`.
        let recipient_exists = pre_recipient_path.verify_membership(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            pre_root,
            &pre_recipient_acc_info,
        )?;
        let recipient_updated_correctly = post_recipient_path.verify_membership(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            post_root,
            &post_recipient_acc_info,
        )?;

        sender_exists
            .and(&sender_updated_correctly)?
            .and(&recipient_exists)?
            .and(&recipient_updated_correctly)?
            .and(&sig_verifies)
    }
}

impl AllocVar<Transaction, ConstraintF> for TransactionVar {
    #[tracing::instrument(target = "r1cs", skip(cs, f, mode))]
    fn new_variable<T: Borrow<Transaction>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        f().and_then(|tx| {
            let tx: &Transaction = tx.borrow();
            let sender = AccountPublicKeyVar::new_variable(cs.clone(), || Ok(&tx.sender), mode)?;
            let recipient =
                AccountPublicKeyVar::new_variable(cs.clone(), || Ok(&tx.recipient), mode)?;
            let amount = AmountVar::new_variable(cs.clone(), || Ok(&tx.amount), mode)?;
            let fee = AmountVar::new_variable(cs.clone(), || Ok(&tx.fee), mode)?;
            Ok(Self {
                sender,
                recipient,
                amount,
                fee,
            })
        })
    }
}
