use crate::account::AccountInformationVar;
use crate::ledger::*;
use crate::random_oracle::blake2s::constraints::ROGadget;
use crate::random_oracle::blake2s::RO;
use crate::random_oracle::constraints::RandomOracleGadget;
use crate::signature::{Signature, SignatureVar};
use crate::transaction::{get_transactions_hash, Transaction, TransactionVar};
use crate::ConstraintF;
use crate::{
    account::AccountInformation,
    ledger::{AccPath, AccRoot, Parameters, State},
    transaction::SignedTransaction,
};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

pub struct Rollup<const NUM_TX: usize> {
    /// The ledger parameters.
    pub ledger_params: Parameters,
    /// The Merkle tree root before applying this batch of transactions.
    pub initial_root: Option<AccRoot>,
    /// The Merkle tree root after applying this batch of transactions.
    pub final_root: Option<AccRoot>,
    /// The current batch of transactions.
    pub transactions: Option<Vec<Transaction>>,
    /// The current batch of transactions.
    pub signatures: Option<Vec<Signature>>,
    /// The sender's account information and corresponding authentication path,
    /// *before* applying the transactions.
    pub sender_pre_tx_info_and_paths: Option<Vec<(AccountInformation, AccPath)>>,
    /// The authentication path corresponding to the sender's account information
    /// *after* applying the transactions.
    pub sender_post_paths: Option<Vec<AccPath>>,
    /// The recipient's account information and corresponding authentication path,
    /// *before* applying the transactions.
    pub recv_pre_tx_info_and_paths: Option<Vec<(AccountInformation, AccPath)>>,
    /// The authentication path corresponding to the recipient's account information
    /// *after* applying the transactions.
    pub recv_post_paths: Option<Vec<AccPath>>,
    /// List of state roots, so that the i-th root is the state root after applying
    /// the i-th transaction. This means that `post_tx_roots[NUM_TX - 1] == final_root`.
    pub post_tx_roots: Option<Vec<AccRoot>>,
}

impl<const NUM_TX: usize> Rollup<NUM_TX> {
    pub fn new_empty(ledger_params: Parameters) -> Self {
        Self {
            ledger_params,
            initial_root: None,
            final_root: None,
            transactions: None,
            signatures: None,
            sender_pre_tx_info_and_paths: None,
            sender_post_paths: None,
            recv_pre_tx_info_and_paths: None,
            recv_post_paths: None,
            post_tx_roots: None,
        }
    }

    pub fn must_get_public_inputs(&self) -> Vec<ConstraintF> {
        use ark_ff::ToConstraintField;
        let transaction_fields: Vec<ConstraintF> =
            get_transactions_hash(self.transactions.as_ref().unwrap())
                .to_field_elements()
                .unwrap();
        let mut result = Vec::with_capacity(transaction_fields.len() + 2);
        result.push(self.initial_root.unwrap());
        result.push(self.final_root.unwrap());
        result.extend(transaction_fields);
        result
    }

    pub fn only_initial_and_final_roots(
        ledger_params: Parameters,
        initial_root: AccRoot,
        final_root: AccRoot,
    ) -> Self {
        Self {
            ledger_params,
            initial_root: Some(initial_root),
            final_root: Some(final_root),
            transactions: None,
            signatures: None,
            sender_pre_tx_info_and_paths: None,
            sender_post_paths: None,
            recv_pre_tx_info_and_paths: None,
            recv_post_paths: None,
            post_tx_roots: None,
        }
    }

    pub fn with_state_and_transactions(
        ledger_params: Parameters,
        transactions: &[SignedTransaction],
        state: &mut State,
        validate_transactions: bool,
        _create_non_existent_accounts: bool,
    ) -> Option<Self> {
        assert_eq!(transactions.len(), NUM_TX);
        let initial_root = Some(state.root());
        let mut sender_pre_tx_info_and_paths = Vec::with_capacity(NUM_TX);
        let mut recipient_pre_tx_info_and_paths = Vec::with_capacity(NUM_TX);
        let mut sender_post_paths = Vec::with_capacity(NUM_TX);
        let mut recipient_post_paths = Vec::with_capacity(NUM_TX);
        let mut post_tx_roots = Vec::with_capacity(NUM_TX);
        for tx in transactions {
            if !tx.validate(&ledger_params, &*state) && validate_transactions {
                return None;
            }
        }
        for tx in transactions {
            let sender_id = tx.sender();
            let recipient_id = tx.recipient();
            let sender_pre_acc_info = state.get_account_information_from_pk(&sender_id)?;
            let sender_pre_path = state
                .account_merkle_tree
                .generate_proof(sender_pre_acc_info.id.0 as usize)
                .unwrap();
            let recipient_pre_acc_info = state.get_account_information_from_pk(&recipient_id)?;
            let recipient_pre_path = state
                .account_merkle_tree
                .generate_proof(recipient_pre_acc_info.id.0 as usize)
                .unwrap();

            if validate_transactions {
                state.apply_transaction(&ledger_params, tx)?;
            } else {
                let _ = state.apply_transaction(&ledger_params, tx);
            }
            let post_tx_root = state.root();
            let sender_post_path = state
                .account_merkle_tree
                .generate_proof(sender_pre_acc_info.id.0 as usize)
                .unwrap();
            let recipient_post_path = state
                .account_merkle_tree
                .generate_proof(recipient_pre_acc_info.id.0 as usize)
                .unwrap();
            sender_pre_tx_info_and_paths.push((sender_pre_acc_info, sender_pre_path));
            recipient_pre_tx_info_and_paths.push((recipient_pre_acc_info, recipient_pre_path));
            sender_post_paths.push(sender_post_path);
            recipient_post_paths.push(recipient_post_path);
            post_tx_roots.push(post_tx_root);
        }

        Some(Self {
            ledger_params,
            initial_root,
            final_root: Some(state.root()),
            transactions: Some(transactions.iter().map(Into::into).collect()),
            signatures: Some(transactions.iter().map(|s| s.signature.clone()).collect()),
            sender_pre_tx_info_and_paths: Some(sender_pre_tx_info_and_paths),
            recv_pre_tx_info_and_paths: Some(recipient_pre_tx_info_and_paths),
            sender_post_paths: Some(sender_post_paths),
            recv_post_paths: Some(recipient_post_paths),
            post_tx_roots: Some(post_tx_roots),
        })
    }
}

impl<const NUM_TX: usize> ConstraintSynthesizer<ConstraintF> for Rollup<NUM_TX> {
    #[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Declare the parameters as constants.
        let ledger_params = ParametersVar::new_constant(
            ark_relations::ns!(cs, "Ledger parameters"),
            &self.ledger_params,
        )?;
        // Declare the initial root as a public input.
        let initial_root = AccRootVar::new_input(ark_relations::ns!(cs, "Initial root"), || {
            self.initial_root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Declare the final root as a public input.
        let final_root = AccRootVar::new_input(ark_relations::ns!(cs, "Final root"), || {
            self.final_root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce the transacations hash from input is legal
        let transaction_list = self
            .transactions
            .as_ref()
            .ok_or(SynthesisError::AssignmentMissing)?;

        let transactions_hash = get_transactions_hash(transaction_list);
        // Declare the transactions hash as a public input.
        let transactions_hash =
            ark_crypto_primitives::prf::blake2s::constraints::OutputVar::new_input(
                ark_relations::ns!(cs, "Transactions hash"),
                || Ok(&transactions_hash),
            )?;

        let mut hash_input = vec![];
        for transaction in transaction_list {
            for byte in transaction.to_bytes_le() {
                hash_input.push(UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap());
            }
        }

        let hash_parameters =
            <ROGadget as RandomOracleGadget<RO, ConstraintF>>::ParametersVar::new_witness(
                ark_relations::ns!(cs, "RandomOracle Parameters"),
                || Ok(&()),
            )
            .unwrap();
        let hash_result = <ROGadget as RandomOracleGadget<RO, ConstraintF>>::evaluate(
            &hash_parameters,
            &hash_input,
        )
        .unwrap();

        transactions_hash.enforce_equal(&hash_result)?;

        let mut prev_root = initial_root;

        for i in 0..NUM_TX {
            let tx = self.transactions.as_ref().and_then(|t| t.get(i));
            let signature = self.signatures.as_ref().and_then(|t| t.get(i));

            let sender_acc_info = self.sender_pre_tx_info_and_paths.as_ref().map(|t| t[i].0);
            let sender_pre_path = self.sender_pre_tx_info_and_paths.as_ref().map(|t| &t[i].1);

            let recipient_acc_info = self.recv_pre_tx_info_and_paths.as_ref().map(|t| t[i].0);
            let recipient_pre_path = self.recv_pre_tx_info_and_paths.as_ref().map(|t| &t[i].1);

            let sender_post_path = self.sender_post_paths.as_ref().map(|t| &t[i]);
            let recipient_post_path = self.recv_post_paths.as_ref().map(|t| &t[i]);

            let post_tx_root = self.post_tx_roots.as_ref().map(|t| t[i]);

            // Let's declare all these things!

            let tx = TransactionVar::new_witness(ark_relations::ns!(cs, "Transaction"), || {
                tx.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let signature = SignatureVar::new_witness(ark_relations::ns!(cs, "Signature"), || {
                signature.ok_or(SynthesisError::AssignmentMissing)
            })?;
            // Declare the sender's initial account balance...
            let sender_acc_info = AccountInformationVar::new_witness(
                ark_relations::ns!(cs, "Sender Account Info"),
                || sender_acc_info.ok_or(SynthesisError::AssignmentMissing),
            )?;
            // ..., corresponding authentication path, ...
            let sender_pre_path =
                AccPathVar::new_witness(ark_relations::ns!(cs, "Sender Pre-Path"), || {
                    sender_pre_path.ok_or(SynthesisError::AssignmentMissing)
                })?;
            // ... and authentication path after the update.
            let sender_post_path =
                AccPathVar::new_witness(ark_relations::ns!(cs, "Sender Post-Path"), || {
                    sender_post_path.ok_or(SynthesisError::AssignmentMissing)
                })?;

            // Declare the recipient's initial account balance...
            let recipient_acc_info = AccountInformationVar::new_witness(
                ark_relations::ns!(cs, "Recipient Account Info"),
                || recipient_acc_info.ok_or(SynthesisError::AssignmentMissing),
            )?;
            // ..., corresponding authentication path, ...
            let recipient_pre_path =
                AccPathVar::new_witness(ark_relations::ns!(cs, "Recipient Pre-Path"), || {
                    recipient_pre_path.ok_or(SynthesisError::AssignmentMissing)
                })?;

            // ... and authentication path after the update.
            let recipient_post_path =
                AccPathVar::new_witness(ark_relations::ns!(cs, "Recipient Post-Path"), || {
                    recipient_post_path.ok_or(SynthesisError::AssignmentMissing)
                })?;

            // ... and after the transaction.
            let post_tx_root =
                AccRootVar::new_witness(ark_relations::ns!(cs, "Post-tx Root"), || {
                    post_tx_root.ok_or(SynthesisError::AssignmentMissing)
                })?;

            // Validate that the transaction signature and amount is correct.
            tx.validate(
                &ledger_params,
                &signature,
                &sender_acc_info,
                &sender_pre_path,
                &sender_post_path,
                &recipient_acc_info,
                &recipient_pre_path,
                &recipient_post_path,
                &prev_root,
                &post_tx_root,
            )?
            .enforce_equal(&Boolean::TRUE)?;

            // Set the root for the next transaction.
            prev_root = post_tx_root;
        }
        // Check that the final root is consistent with the root computed after
        // applying all state transitions
        final_root.enforce_equal(&prev_root)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    
    use crate::ledger::{Amount, Parameters, State};
    use crate::transaction::SignedTransaction;
    use ark_relations::r1cs::{
        ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, TracingMode::OnlyConstraints,
    };
    use tracing_subscriber::layer::SubscriberExt;

    fn test_cs<const NUM_TX: usize>(rollup: Rollup<NUM_TX>) -> bool {
        let mut layer = ConstraintLayer::default();
        layer.mode = OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        let cs = ConstraintSystem::new_ref();
        rollup.generate_constraints(cs.clone()).unwrap();
        let result = cs.is_satisfied().unwrap();
        if !result {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        result
    }

    #[test]
    fn single_tx_validity_test() {
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new(32, &pp);
        // Let's make an account for Alice.
        let (alice_id, alice_pk, alice_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();
        // Let's give her some initial balance to start with.
        state
            .update_balance_by_id(&alice_id, Amount(20))
            .expect("Alice's account should exist");
        // Let's make an account for Bob.
        let (_bob_id, bob_pk, bob_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();

        // Alice wants to transfer 5 units to Bob.
        let mut temp_state = state.clone();
        let tx1 = SignedTransaction::create(&pp, alice_pk, bob_pk, Amount(5), &alice_sk, &mut rng);
        assert!(tx1.validate(&pp, &temp_state));
        let rollup = Rollup::<1>::with_state_and_transactions(
            pp.clone(),
            &[tx1],
            &mut temp_state,
            true,
            true,
        )
        .unwrap();
        assert!(test_cs(rollup));

        let mut temp_state = state.clone();
        let bad_tx = SignedTransaction::create(&pp, alice_pk, bob_pk, Amount(5), &bob_sk, &mut rng);
        assert!(!bad_tx.validate(&pp, &temp_state));
        assert!(matches!(temp_state.apply_transaction(&pp, &bad_tx), None));
        let rollup = Rollup::<1>::with_state_and_transactions(
            pp.clone(),
            &[bad_tx.clone()],
            &mut temp_state,
            false,
            true,
        )
        .unwrap();
        assert!(!test_cs(rollup));
    }

    #[test]
    fn end_to_end() {
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new(32, &pp);
        // Let's make an account for Alice.
        let (alice_id, alice_pk, alice_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();
        // Let's give her some initial balance to start with.
        state
            .update_balance_by_id(&alice_id, Amount(20))
            .expect("Alice's account should exist");
        // Let's make an account for Bob.
        let (bob_id, bob_pk, bob_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();

        // Alice wants to transfer 5 units to Bob.
        let mut temp_state = state.clone();
        let tx1 = SignedTransaction::create(&pp, alice_pk, bob_pk, Amount(5), &alice_sk, &mut rng);
        assert!(tx1.validate(&pp, &temp_state));
        let rollup = Rollup::<1>::with_state_and_transactions(
            pp.clone(),
            &[tx1.clone()],
            &mut temp_state,
            true,
            true,
        )
        .unwrap();
        assert!(test_cs(rollup));

        let mut temp_state = state.clone();
        let rollup = Rollup::<2>::with_state_and_transactions(
            pp.clone(),
            &[tx1.clone(), tx1],
            &mut temp_state,
            true,
            true,
        )
        .unwrap();
        assert!(test_cs(rollup));
        assert_eq!(
            temp_state
                .id_to_account_info
                .get(&alice_id)
                .unwrap()
                .balance,
            Amount(10)
        );
        assert_eq!(
            temp_state.id_to_account_info.get(&bob_id).unwrap().balance,
            Amount(10)
        );

        // Let's try creating invalid transactions:
        // First, let's try a transaction where the amount is larger than Alice's balance.
        let mut temp_state = state.clone();
        let bad_tx =
            SignedTransaction::create(&pp, alice_pk, bob_pk, Amount(21), &alice_sk, &mut rng);
        assert!(!bad_tx.validate(&pp, &temp_state));
        assert!(matches!(temp_state.apply_transaction(&pp, &bad_tx), None));
        let rollup = Rollup::<1>::with_state_and_transactions(
            pp.clone(),
            &[bad_tx.clone()],
            &mut temp_state,
            false,
            true,
        )
        .unwrap();
        assert!(!test_cs(rollup));

        // Next, let's try a transaction where the signature is incorrect:
        let mut temp_state = state.clone();
        let bad_tx = SignedTransaction::create(&pp, alice_pk, bob_pk, Amount(5), &bob_sk, &mut rng);
        assert!(!bad_tx.validate(&pp, &temp_state));
        assert!(matches!(temp_state.apply_transaction(&pp, &bad_tx), None));
        let rollup = Rollup::<1>::with_state_and_transactions(
            pp.clone(),
            &[bad_tx.clone()],
            &mut temp_state,
            false,
            true,
        )
        .unwrap();
        assert!(!test_cs(rollup));

        // Finally, let's try a transaction to an non-existant account:
        let bad_tx = SignedTransaction::create(
            &pp,
            alice_pk,
            crate::account::non_existent_account(),
            Amount(5),
            &alice_sk,
            &mut rng,
        );
        assert!(!bad_tx.validate(&pp, &state));
        assert!(matches!(temp_state.apply_transaction(&pp, &bad_tx), None));
    }

    // Builds a circuit with two txs, using different pubkeys & amounts every time.
    // It returns this circuit
    fn build_two_tx_circuit() -> Rollup<2> {
        use ark_std::rand::Rng;
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new(32, &pp);
        // Let's make an account for Alice.
        let (alice_id, alice_pk, alice_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();
        // Let's give her some initial balance to start with.
        state
            .update_balance_by_id(&alice_id, Amount(1000))
            .expect("Alice's account should exist");
        // Let's make an account for Bob.
        let (_bob_id, bob_pk, _bob_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();

        let amount_to_send = rng.gen_range(0..200);

        // Alice wants to transfer amount_to_send units to Bob, and does this twice
        let mut temp_state = state.clone();
        let tx1 = SignedTransaction::create(
            &pp,
            alice_pk,
            bob_pk,
            Amount(amount_to_send),
            &alice_sk,
            &mut rng,
        );

        Rollup::<2>::with_state_and_transactions(
            pp.clone(),
            &[tx1.clone(), tx1],
            &mut temp_state,
            true,
            true,
        )
        .unwrap()
    }

    #[test]
    fn snark_verification() {
        use ark_bls12_381::Bls12_381;
        use ark_groth16::Groth16;
        use ark_snark::SNARK;
        // Use a circuit just to generate the circuit
        let circuit_defining_cs = build_two_tx_circuit();

        let mut rng = ark_std::test_rng();
        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(circuit_defining_cs, &mut rng).unwrap();

        // Use the same circuit but with different inputs to verify against
        // This test checks that the SNARK passes on the provided input
        let circuit_to_verify_against = build_two_tx_circuit();
        let public_input = circuit_to_verify_against.must_get_public_inputs();

        let proof = Groth16::prove(&pk, circuit_to_verify_against, &mut rng).unwrap();
        let valid_proof = Groth16::verify(&vk, &public_input, &proof).unwrap();
        assert!(valid_proof);

        // Use the same circuit but with different inputs to verify against
        // This test checks that the SNARK fails on the wrong input
        let circuit_to_verify_against = build_two_tx_circuit();
        // Error introduced, used the final root twice!
        let mut public_input = circuit_to_verify_against.must_get_public_inputs();
        public_input[0] = public_input[1];

        let proof = Groth16::prove(&pk, circuit_to_verify_against, &mut rng).unwrap();
        let valid_proof = Groth16::verify(&vk, &public_input, &proof).unwrap();
        assert!(!valid_proof);
    }
}
