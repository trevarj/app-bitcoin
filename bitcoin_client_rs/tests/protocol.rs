use std::str::FromStr;

use bitcoin::{
    bip32::DerivationPath,
    hashes::{sha256, Hash},
};
use ledger_bitcoin_client::{
    apdu::ClientCommandCode,
    command,
    interpreter::ClientCommandInterpreter,
    merkle::MerkleTree,
    protocol::{CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG, CCMD_YIELD_MUSIG_PUBNONCE_TAG},
    wallet::{Version, WalletPolicy, WalletPubKey},
};

const KEY: &str = "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U";
const MERKLE_LEAF_PREFIX: u8 = 0;
const SHA256_HASH_TYPE: u8 = 0;

// Expected wire values are independent of the production APDU constants.
const EXPECTED_BITCOIN_CLA: u8 = 0xe1;
const EXPECTED_PROTOCOL_VERSION: u8 = 0x01;
const EXPECTED_REGISTER_WALLET_INS: u8 = 0x02;
const EXPECTED_GET_WALLET_ADDRESS_INS: u8 = 0x03;
const EXPECTED_SIGN_PSBT_INS: u8 = 0x04;
const EXPECTED_SIGN_MESSAGE_INS: u8 = 0x10;

fn wallet(version: Version) -> WalletPolicy {
    WalletPolicy::new(
        "".into(),
        version,
        "tr(@0/**)".into(),
        [WalletPubKey::from_str(KEY).unwrap()],
    )
}

fn hash(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

#[test]
fn public_command_builders() {
    assert_eq!(
        command::get_version().encode(),
        hex::decode("b001000000").unwrap()
    );
    assert_eq!(
        command::get_master_fingerprint().encode(),
        hex::decode("e105000100").unwrap()
    );
    let path = DerivationPath::from_str("m/44'/1/0").unwrap();
    assert_eq!(
        command::get_extended_pubkey(&path, true).encode(),
        hex::decode("e10000010e01038000002c0000000100000000").unwrap()
    );
    assert_eq!(
        command::continue_interrupted(vec![1, 2]).encode(),
        vec![0xf8, 1, 0, 1, 2, 1, 2]
    );
    let wallet = wallet(Version::V2);
    let mut registration = vec![wallet.serialize().len() as u8];
    registration.extend(wallet.serialize());
    let cmd = command::register_wallet(&wallet);
    assert_eq!(
        (cmd.cla, cmd.ins, cmd.p1, cmd.p2),
        (
            EXPECTED_BITCOIN_CLA,
            EXPECTED_REGISTER_WALLET_INS,
            0,
            EXPECTED_PROTOCOL_VERSION
        )
    );
    assert_eq!(cmd.data, registration);
    let mut address = vec![1];
    address.extend(wallet.id());
    address.extend([7; 32]);
    address.extend([1, 0, 0, 0, 9]);
    let cmd = command::get_wallet_address(&wallet, Some(&[7; 32]), true, 9, true);
    assert_eq!(cmd.ins, EXPECTED_GET_WALLET_ADDRESS_INS);
    assert_eq!(cmd.data, address);
    let mut psbt = vec![8, 1];
    psbt.extend([2; 32]);
    psbt.push(3);
    psbt.extend([4; 32]);
    psbt.extend(wallet.id());
    psbt.extend([0; 32]);
    let cmd = command::sign_psbt(&[8], 1, &[2; 32], 3, &[4; 32], &wallet, None);
    assert_eq!(cmd.ins, EXPECTED_SIGN_PSBT_INS);
    assert_eq!(cmd.data, psbt);
    let cmd = command::sign_message(5, &[6; 32], &path);
    assert_eq!(cmd.ins, EXPECTED_SIGN_MESSAGE_INS);
    let mut message = hex::decode("038000002c000000010000000005").unwrap();
    message.extend([6; 32]);
    assert_eq!(cmd.data, message);
}

#[test]
fn wallet_versions_and_repeated_templates() {
    let key_leaf = hash(&[&[MERKLE_LEAF_PREFIX][..], KEY.as_bytes()].concat());
    for version in [Version::V1, Version::V2] {
        let wallet = wallet(version);
        let mut expected = vec![version as u8, 0, 9];
        if version == Version::V1 {
            expected.extend(b"tr(@0/**)");
        } else {
            expected.extend(hash(b"tr(@0/**)"));
        }
        expected.push(1);
        expected.extend(key_leaf);
        assert_eq!(wallet.serialize(), expected);
        assert_eq!(wallet.id(), hash(&expected));
    }
    assert_eq!(
        hex::encode(wallet(Version::V2).id()),
        "627535418bc03eeee2b62b3a0254dc0624881f8bc6fc20c4d3b2c1c4fc929893"
    );
    let mut repeated = wallet(Version::V2);
    repeated.descriptor_template = "tr(@0/**,pk(@0/<2;3>/*))".into();
    assert_eq!(repeated.keys.len(), 1);
    assert_eq!(
        repeated.get_descriptor(false).unwrap(),
        format!("tr({KEY}/0/*,pk({KEY}/2/*))")
    );
    assert_eq!(
        repeated.get_descriptor(true).unwrap(),
        format!("tr({KEY}/1/*,pk({KEY}/3/*))")
    );
}

#[test]
fn public_merkle_and_interpreter() {
    let leaf = hash(b"\0hello");
    let tree = MerkleTree::new(vec![leaf]);
    assert_eq!(tree.size(), 1);
    assert_eq!(tree.root_hash(), &leaf);
    assert_eq!(tree.get_leaf(0), Some(&leaf));
    assert_eq!(tree.get_leaf_proof(0), Some(vec![]));
    assert_eq!(tree.get_leaf_proof(1), None);
    let mut interpreter = ClientCommandInterpreter::new();
    assert_eq!(interpreter.add_known_list(&[b"hello"]), leaf);
    let mut request = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
    request.extend(leaf);
    assert_eq!(interpreter.execute(request).unwrap(), b"\x06\x06\0hello");
    assert_eq!(
        interpreter
            .execute(vec![ClientCommandCode::Yield as u8, 1, 2])
            .unwrap(),
        Vec::<u8>::new()
    );
    assert_eq!(interpreter.yielded(), vec![vec![1, 2]]);
}

#[test]
fn missing_leaves_and_unknown_roots_are_distinct() {
    use ledger_bitcoin_client::interpreter::InterpreterError;
    let mut interpreter = ClientCommandInterpreter::new();
    let root = interpreter.add_known_list(&[b"hello"]);
    let mut index = vec![ClientCommandCode::GetMerkleLeafIndex as u8];
    index.extend(root);
    index.extend([9; 32]);
    assert_eq!(interpreter.execute(index.clone()).unwrap(), [0, 0]);
    index[33..].copy_from_slice(&root);
    assert_eq!(interpreter.execute(index.clone()).unwrap(), [1, 0]);
    index[1..33].fill(8);
    assert!(matches!(
        interpreter.execute(index),
        Err(InterpreterError::UnknownMerkleRoot)
    ));
    let mut proof = vec![ClientCommandCode::GetMerkleLeafProof as u8];
    proof.extend([8; 32]);
    proof.extend([1, 0]);
    assert!(matches!(
        interpreter.execute(proof),
        Err(InterpreterError::UnknownMerkleRoot)
    ));
    let mut preimage = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
    preimage.extend([9; 32]);
    assert!(matches!(
        interpreter.execute(preimage),
        Err(InterpreterError::UnknownHash)
    ));
}

#[test]
fn preimage_and_proof_fragmentation_and_queue_transitions() {
    use ledger_bitcoin_client::interpreter::InterpreterError;
    let mut interpreter = ClientCommandInterpreter::new();
    let preimage = vec![0x55; 600];
    interpreter.add_known_preimage(preimage.clone());
    let mut request = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
    request.extend(hash(&preimage));
    let first = interpreter.execute(request).unwrap();
    assert_eq!(&first[..4], &[0xfd, 0x58, 2, 251]);
    let mut reconstructed = first[4..].to_vec();
    assert!(matches!(
        interpreter.execute(vec![ClientCommandCode::GetMerkleLeafProof as u8]),
        Err(InterpreterError::UnexpectedQueue)
    ));
    for expected_count in [253, 96] {
        let next = interpreter
            .execute(vec![ClientCommandCode::GetMoreElements as u8])
            .unwrap();
        assert_eq!(&next[..2], &[expected_count, 1]);
        reconstructed.extend(&next[2..]);
    }
    assert_eq!(reconstructed, preimage);
    assert!(matches!(
        interpreter.execute(vec![ClientCommandCode::GetMoreElements as u8]),
        Err(InterpreterError::UnexpectedQueue)
    ));

    let elements: Vec<Vec<u8>> = (0u16..256).map(|i| i.to_le_bytes().to_vec()).collect();
    let leaves: Vec<_> = elements
        .iter()
        .map(|e| hash(&[&[MERKLE_LEAF_PREFIX][..], e].concat()))
        .collect();
    let tree = MerkleTree::new(leaves);
    let root = interpreter.add_known_list(&elements);
    let mut request = vec![ClientCommandCode::GetMerkleLeafProof as u8];
    request.extend(root);
    request.extend([0xfd, 0, 1, 0]);
    let first = interpreter.execute(request.clone()).unwrap();
    assert_eq!(&first[..32], tree.get_leaf(0).unwrap());
    assert_eq!(&first[32..34], &[8, 6]);
    assert!(matches!(
        interpreter.execute(request.clone()),
        Err(InterpreterError::UnexpectedQueue)
    ));
    let rest = interpreter
        .execute(vec![ClientCommandCode::GetMoreElements as u8])
        .unwrap();
    assert_eq!(&rest[..2], &[2, 32]);
    let mut proof = first[34..].to_vec();
    proof.extend(&rest[2..]);
    assert_eq!(proof, tree.get_leaf_proof(0).unwrap().concat());
    assert!(matches!(
        interpreter.execute(vec![ClientCommandCode::GetMoreElements as u8]),
        Err(InterpreterError::UnexpectedQueue)
    ));
    request.pop();
    request.push(1);
    assert!(interpreter.execute(request).is_ok());
    assert!(matches!(
        interpreter.execute(vec![]),
        Err(InterpreterError::EmptyInput)
    ));
    assert!(matches!(
        interpreter.execute(vec![0xff]),
        Err(InterpreterError::UnknownCommand(0xff))
    ));
    assert!(matches!(
        interpreter.execute(vec![ClientCommandCode::GetPreimage as u8]),
        Err(InterpreterError::UnsupportedRequest(code)) if code == ClientCommandCode::GetPreimage as u8
    ));
}

fn compact_size(value: u64) -> Vec<u8> {
    bitcoin::consensus::serialize(&bitcoin::VarInt(value))
}

const PUBKEY: &str = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
const RESERVED_YIELD_TAG_START: u64 = 0x8000_0000;
const MAX_UNTAGGED_INPUT_INDEX: u64 = 0x7fff_ffff;
const MUSIG_PUBNONCE_LEN: usize = 66;
const MUSIG_PARTIAL_SIGNATURE_LEN: usize = 32;

fn musig_yield(tag: u64, index: u64, tapleaf: bool) -> Vec<u8> {
    let mut payload = compact_size(tag);
    payload.extend(compact_size(index));
    let value_len = if tag == CCMD_YIELD_MUSIG_PUBNONCE_TAG {
        MUSIG_PUBNONCE_LEN
    } else {
        MUSIG_PARTIAL_SIGNATURE_LEN
    };
    payload.extend(vec![0xaa; value_len]);
    payload.extend(hex::decode(PUBKEY).unwrap());
    payload.extend(hex::decode(PUBKEY).unwrap());
    if tapleaf {
        payload.extend([1; 32]);
    }
    payload
}

#[test]
fn yielded_indices_and_malformed_payloads() {
    use ledger_bitcoin_client::{
        protocol::{parse_sign_psbt_yielded, SignPsbtYieldedObject},
        PartialSignatureError,
    };
    // Reserved and unknown tags still carry a u32 input index, even with a 64-bit tag.
    for tag in [
        CCMD_YIELD_MUSIG_PUBNONCE_TAG,
        CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG,
        RESERVED_YIELD_TAG_START,
        u64::MAX,
    ] {
        for index in [u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
            let payload = if matches!(
                tag,
                CCMD_YIELD_MUSIG_PUBNONCE_TAG | CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG
            ) {
                musig_yield(tag, index, false)
            } else {
                [compact_size(tag), compact_size(index)].concat()
            };
            let parsed = parse_sign_psbt_yielded(&payload);
            if index == u32::MAX as u64 {
                assert_eq!(parsed.ok().expect("valid u32 index").0, u32::MAX as usize);
            } else {
                assert!(matches!(parsed, Err(PartialSignatureError::InvalidLength)));
            }
        }
    }
    let mut regular = compact_size(MAX_UNTAGGED_INPUT_INDEX);
    regular.push(32);
    regular.extend(&hex::decode(PUBKEY).unwrap()[1..]);
    regular.extend([0xaa; 64]);
    assert_eq!(
        parse_sign_psbt_yielded(&regular).ok().unwrap().0,
        MAX_UNTAGGED_INPUT_INDEX as usize
    );
    for malformed in [
        vec![],
        vec![0xfd],
        vec![0xfd, 1, 0],
        vec![0xfe, 0, 1, 0, 0],
        vec![0xff, 0, 0, 0, 0, 0, 0, 0, 0],
    ] {
        assert!(matches!(
            parse_sign_psbt_yielded(&malformed),
            Err(PartialSignatureError::InvalidLength)
        ));
    }
    for tag in [
        CCMD_YIELD_MUSIG_PUBNONCE_TAG,
        CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG,
    ] {
        for tapleaf in [false, true] {
            let valid = musig_yield(tag, 2, tapleaf);
            assert_eq!(parse_sign_psbt_yielded(&valid).ok().unwrap().0, 2);
            assert!(parse_sign_psbt_yielded(&valid[..valid.len() - 1]).is_err());
            let mut bad_key = valid;
            let tag_and_index_len = compact_size(tag).len() + compact_size(2).len();
            let value_len = if tag == CCMD_YIELD_MUSIG_PUBNONCE_TAG {
                MUSIG_PUBNONCE_LEN
            } else {
                MUSIG_PARTIAL_SIGNATURE_LEN
            };
            let offset = tag_and_index_len + value_len;
            bad_key[offset] = 0xff;
            assert!(parse_sign_psbt_yielded(&bad_key).is_err());
        }
    }
    let mut unknown = compact_size(RESERVED_YIELD_TAG_START);
    unknown.extend([3, 7, 8]);
    assert!(
        matches!(parse_sign_psbt_yielded(&unknown), Ok((3, SignPsbtYieldedObject::Unknown(bytes))) if bytes == [7, 8])
    );
    for malformed in [vec![0], vec![0, 64, 1], vec![0, 32], vec![0, 33, 0, 0]] {
        assert!(parse_sign_psbt_yielded(&malformed).is_err());
    }
    let mut bad_schnorr = regular;
    bad_schnorr.pop();
    assert!(parse_sign_psbt_yielded(&bad_schnorr).is_err());
}
