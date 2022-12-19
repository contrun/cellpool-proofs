use super::ledger::*;
use super::signature::schnorr;

use ark_ed_on_bls12_381::EdwardsProjective;
use ark_serialize::CanonicalSerialize;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

/// Account public key used to verify transaction signatures.
pub type AccountPublicKey = schnorr::PublicKey<EdwardsProjective>;
/// Account secret key used to create transaction signatures.
pub type AccountSecretKey = schnorr::SecretKey<EdwardsProjective>;

pub fn get_public_key_bytes(pk: &AccountPublicKey) -> Vec<u8> {
    let mut bytes = Vec::new();
    pk.serialize_uncompressed(&mut bytes)
        .expect("Must serialize public key");
    bytes
}

/// A special account for minting and burning assets.
/// Assets transferring from this account is regardded as minted,
/// while assets transferring to this account is regarded as burend.
pub fn sentinel_account() -> AccountPublicKey {
    use ark_ec::AffineCurve;
    AccountPublicKey::prime_subgroup_generator()
}

#[cfg(test)]
pub fn non_existent_account() -> AccountPublicKey {
    use ark_ec::AffineCurve;
    AccountPublicKey::prime_subgroup_generator().mul(42).into()
}

/// Account identifier. This prototype supports only 256 accounts at a time.
#[derive(Hash, Eq, PartialEq, Copy, Clone, Ord, PartialOrd, Debug)]
pub struct AccountId(pub WrappedAccountId);
type WrappedAccountId = u16;

impl AccountId {
    /// Convert the account identifier to bytes.
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

impl AccountId {
    /// Increment the identifier in place.
    pub(crate) fn checked_increment(&mut self) -> Option<()> {
        self.0.checked_add(1).map(|result| self.0 = result)
    }
}

/// Information about the account, such as the balance and the associated public key.
#[derive(Hash, Eq, PartialEq, Copy, Clone)]
pub struct AccountInformation {
    /// The account public key.
    pub id: AccountId,
    /// The account public key.
    pub public_key: AccountPublicKey,
    /// The balance associated with this this account.
    pub balance: Amount,
}

impl AccountInformation {
    /// Convert the account information to bytes.
    pub fn to_bytes_le(&self) -> Vec<u8> {
        ark_ff::to_bytes![self.public_key, self.balance.to_bytes_le()].unwrap()
    }
}
