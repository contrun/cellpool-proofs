use crate::ledger::{AccRoot, State};

use crate::transaction::{get_transactions_hash, SignedTransaction, Transaction};
use crate::ConstraintF;
use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_serialize::*;
use ark_snark::SNARK;

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof {
    proof: ark_groth16::Proof<Bls12_381>,
    vk: <Groth16<Bls12_381> as SNARK<ConstraintF>>::VerifyingKey,
}

pub fn rollup_and_prove(state: &mut State, transactions: &[SignedTransaction]) -> Option<Proof> {
    let rollup = state.rollup_transactions(transactions, true, true)?;

    let mut rng = ark_std::test_rng();
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(rollup.clone(), &mut rng).unwrap();

    let proof = Groth16::prove(&pk, rollup, &mut rng).unwrap();
    Some(Proof { proof, vk })
}

pub fn verify(
    proof: &Proof,
    initial_root: AccRoot,
    final_root: AccRoot,
    transactions: &[Transaction],
) -> Result<bool, <Groth16<Bls12_381> as SNARK<ConstraintF>>::Error> {
    let public_inputs = get_public_inputs(initial_root, final_root, transactions);
    Groth16::verify(&proof.vk, &public_inputs, &proof.proof)
}

pub(crate) fn get_public_inputs(
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

#[cfg(test)]
mod test {

    use super::*;
    use crate::ledger::{Amount, Parameters, State};

    fn build_n_transactions(
        n: usize,
        is_legal_transaction: bool,
    ) -> (State, Vec<Transaction>, Vec<SignedTransaction>) {
        use ark_std::rand::Rng;
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new_with_parameters(32, &pp);
        // Let's make an account for Alice.
        let (alice_id, alice_pk, alice_sk) = state.sample_keys_and_register(&mut rng).unwrap();
        // Let's make an account for Bob.
        let (_bob_id, bob_pk, _bob_sk) = state.sample_keys_and_register(&mut rng).unwrap();

        let mut alice_balance = 0;
        let mut txs = Vec::with_capacity(n);
        let mut signed_txs = Vec::with_capacity(n);
        for _ in 0..n {
            let amount = rng.gen_range(10..20);
            alice_balance += amount;
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

        if is_legal_transaction {
            alice_balance += rng.gen_range(10..20);
        } else {
            alice_balance -= rng.gen_range(1..5);
        }
        state
            .update_balance_by_id(&alice_id, Amount(alice_balance))
            .expect("Alice's account should exist");

        (state, txs, signed_txs)
    }

    #[test]
    fn prove_and_verify_normal_transactions() {
        let (mut state, txs, signed_txs) = build_n_transactions(10, true);

        let initial_root = state.root();
        let proof = rollup_and_prove(&mut state, &signed_txs).expect("Must create proof");

        let final_root = state.root();
        let is_valid_proof =
            verify(&proof, initial_root, final_root, &txs).expect("Must verify proof");
        assert!(is_valid_proof);
    }

    #[test]
    fn prove_generation_on_illegal_transactions() {
        let (mut state, _txs, signed_txs) = build_n_transactions(5, false);

        let proof = rollup_and_prove(&mut state, &signed_txs);
        assert!(proof.is_none());
    }
}
