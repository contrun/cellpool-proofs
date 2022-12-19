use crate::ledger::{AccRoot, Parameters, State};
use crate::rollup::Rollup;
use crate::transaction::{get_transactions_hash, SignedTransaction, Transaction};
use crate::ConstraintF;
use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_groth16::Proof;
use ark_snark::SNARK;

pub fn rollup_and_prove(
    state: &mut State,
    transactions: &[SignedTransaction],
) -> Option<Proof<Bls12_381>> {
    let rollup = state.rollup_transactions(transactions, true, true)?;

    let mut rng = ark_std::test_rng();
    let pk = get_proving_key(&state.parameters);

    // Use the same circuit but with different inputs to verify against
    // This test checks that the SNARK passes on the provided input
    let proof = Groth16::prove(&pk, rollup, &mut rng).unwrap();
    Some(proof)
}

pub fn get_public_inputs(
    initial_root: AccRoot,
    final_root: AccRoot,
    transactions: &[Transaction],
) -> Vec<ConstraintF> {
    use ark_ff::ToConstraintField;
    let transaction_fields: Vec<ConstraintF> = get_transactions_hash(transactions)
        .to_field_elements()
        .unwrap();
    let mut result = Vec::with_capacity(transaction_fields.len() + 2);
    result.push(initial_root);
    result.push(final_root);
    result.extend(transaction_fields);
    result
}

pub fn verify(
    params: &Parameters,
    proof: &Proof<Bls12_381>,
    initial_root: AccRoot,
    final_root: AccRoot,
    transactions: &[Transaction],
) -> Result<bool, <Groth16<Bls12_381> as SNARK<ConstraintF>>::Error> {
    let public_inputs = get_public_inputs(initial_root, final_root, transactions);
    let vk = get_verifying_key(params);
    Groth16::verify(&vk, &public_inputs, proof)
}

fn get_verifying_key(
    params: &Parameters,
) -> <Groth16<Bls12_381> as SNARK<ConstraintF>>::VerifyingKey {
    let mut rng = ark_std::test_rng();
    let (_pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        Rollup::new_with_params(params.clone()),
        &mut rng,
    )
    .unwrap();
    vk
}

fn get_proving_key(params: &Parameters) -> <Groth16<Bls12_381> as SNARK<ConstraintF>>::ProvingKey {
    let mut rng = ark_std::test_rng();
    let (pk, _vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        Rollup::new_with_params(params.clone()),
        &mut rng,
    )
    .unwrap();
    pk
}

#[cfg(test)]
mod test {
    use crate::ledger::Amount;

    use super::*;

    fn build_n_transactions(
        n: usize,
        surplus: u64,
    ) -> (State, Vec<Transaction>, Vec<SignedTransaction>) {
        use ark_std::rand::Rng;
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new(32, &pp);
        // Let's make an account for Alice.
        let (alice_id, alice_pk, alice_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();
        // Let's make an account for Bob.
        let (_bob_id, bob_pk, _bob_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();

        let mut alice_balance = 0;
        let mut txs = Vec::with_capacity(n);
        let mut signed_txs = Vec::with_capacity(n);
        for _ in 0..n {
            let amount = rng.gen_range(10..20);
            alice_balance = alice_balance + amount;
            let signed_tx = SignedTransaction::create(
                &pp,
                alice_pk,
                bob_pk,
                Amount(amount),
                &alice_sk,
                &mut rng,
            );
            txs.push(Transaction::from(&signed_tx));
            signed_txs.push(signed_tx);
        }

        alice_balance = alice_balance + surplus;
        state
            .update_balance_by_id(&alice_id, Amount(alice_balance))
            .expect("Alice's account should exist");

        (state, txs, signed_txs)
    }

    #[test]
    fn prove_and_verify() {
        // Use a circuit just to generate the circuit
        let (mut state, txs, signed_txs) = build_n_transactions(2, 100);

        let initial_root = state.root();
        let proof = rollup_and_prove(&mut state, &signed_txs).expect("Must create proof");

        let final_root = state.root();
        let is_valid_proof = verify(&state.parameters, &proof, initial_root, final_root, &txs)
            .expect("Must verify proof");
        assert!(is_valid_proof);
    }
}
