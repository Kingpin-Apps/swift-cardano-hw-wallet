// Offline oracle for the swift-cardano-hw-wallet Keystone validation. Runs the **actual Keystone
// device** Cardano signing code (`app_cardano::transaction::sign_tx_hash`, which uses `keystore`'s
// BIP32-Ed25519 derive+sign) over a transaction body hash + witness path, and prints the resulting
// CardanoTxWitnessSet CBOR as hex — the exact bytes the device puts in its CardanoSignature UR.
//
//   cargo run --example keystone_oracle -- <bodyHashHex> [entropyHex] [account]
//
// Defaults: entropy = 16 zero bytes ("abandon … about" mnemonic), account 0, path m/1852'/1815'/0'/0/0.
use app_cardano::transaction::{calc_icarus_master_key, sign_tx_hash};
use ur_registry::crypto_key_path::{CryptoKeyPath, PathComponent};

fn comp(index: u32, hardened: bool) -> PathComponent {
    PathComponent::new(Some(index), hardened).unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let body_hash = args.get(1).cloned().expect("usage: keystone_oracle <bodyHashHex> [entropyHex] [account]");
    let entropy_hex = args.get(2).cloned().unwrap_or_else(|| "00000000000000000000000000000000".to_string());
    let account: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);

    let entropy = hex::decode(&entropy_hex).expect("bad entropy hex");
    let master_key = calc_icarus_master_key(&entropy, b"").expect("icarus master key");

    // m/1852'/1815'/account'/0/0
    let path = CryptoKeyPath::new(
        vec![comp(1852, true), comp(1815, true), comp(account, true), comp(0, false), comp(0, false)],
        Some([0u8; 4]),
        None,
    );

    let witness_set = sign_tx_hash(&body_hash, &vec![path], master_key).expect("sign_tx_hash");
    println!("{}", hex::encode(witness_set));
}
