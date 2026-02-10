"""Integration tests: end-to-end flows."""

from satoshi_kit.hd.bip32 import Xpriv
from satoshi_kit.hd.bip39 import Mnemonic
from satoshi_kit.keys.address import (
    pubkey_to_bech32_address,
    pubkey_to_ethereum_address,
    pubkey_to_p2pkh_address,
    pubkey_to_p2sh_p2wpkh_address,
)
from satoshi_kit.keys.ec import ECKey
from satoshi_kit.keys.keyinfo import keyinfo
from satoshi_kit.keys.wif import secret_to_wif, wif_to_secret
from satoshi_kit.network import BITCOIN, BITCOIN_TESTNET3


def test_mnemonic_to_address_roundtrip():
    """Full flow: generate mnemonic → seed → xpriv → derive → address."""
    m = Mnemonic()
    mnemonic = m.generate(128)
    assert m.check(mnemonic)

    seed = Mnemonic.to_seed(mnemonic)
    assert len(seed) == 64

    xpriv = Xpriv.from_seed(seed)
    child = xpriv.derive_path("m/44'/0'/0'/0/0")

    ki = keyinfo(child.key.hex(), network=BITCOIN, force_compressed=True)
    assert ki.addr.startswith("1")
    assert ki.wif is not None


def test_known_mnemonic_full_derivation():
    """Deterministic test: known mnemonic → known xpriv → derivation."""
    xpriv = Xpriv.from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "TREZOR",
    )
    assert xpriv.to_base58() == "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"

    child = xpriv.derive_path("m/44'/0'/0'/0/0")
    ki = keyinfo(child.key.hex(), network=BITCOIN, force_compressed=True)
    assert ki.addr.startswith("1")
    assert len(ki.public_key) == 33


def test_private_key_1_all_formats():
    """Test key 1 across all address formats."""
    ec = ECKey.from_secret_exponent(1)
    pub_u = ec.public_key(compressed=False)
    pub_c = ec.public_key(compressed=True)

    # P2PKH uncompressed
    assert pubkey_to_p2pkh_address(pub_u, BITCOIN) == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"

    # P2PKH compressed
    p2pkh_c = pubkey_to_p2pkh_address(pub_c, BITCOIN)
    assert p2pkh_c == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

    # P2SH-P2WPKH
    p2sh = pubkey_to_p2sh_p2wpkh_address(pub_c, BITCOIN)
    assert p2sh.startswith("3")

    # Bech32
    bech = pubkey_to_bech32_address(pub_c, BITCOIN)
    assert bech.startswith("bc1")

    # WIF roundtrip
    secret = ec.secret_bytes()
    wif = secret_to_wif(secret, compressed=False, network=BITCOIN)
    assert wif == "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"
    recovered, comp = wif_to_secret(wif)
    assert recovered == secret
    assert not comp


def test_wif_to_keyinfo():
    """WIF → keyinfo → addr matches."""
    ki = keyinfo("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", network=BITCOIN, force_compressed=False)
    assert ki.addr == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
    assert ki.secret == b"\x00" * 31 + b"\x01"
    assert not ki.compressed


def test_hex_to_keyinfo():
    """Hex key → keyinfo."""
    ki = keyinfo("1", network=BITCOIN, force_compressed=False)
    assert ki.addr == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"


def test_ethereum_address():
    """Ethereum address derivation from known key."""
    ec = ECKey.from_secret_exponent(1)
    pub = ec.public_key(compressed=False)
    eth_addr = pubkey_to_ethereum_address(pub)
    assert eth_addr.startswith("0x")
    assert len(eth_addr) == 42
    # Verify EIP-55 checksum is applied
    lower = eth_addr[2:].lower()
    from satoshi_kit.keys.address import eip55_checksum
    assert eip55_checksum(lower) == eth_addr


def test_testnet_addresses():
    """Testnet address derivation."""
    ec = ECKey.from_secret_exponent(1)
    pub = ec.public_key(compressed=True)
    addr = pubkey_to_p2pkh_address(pub, BITCOIN_TESTNET3)
    assert addr.startswith("m") or addr.startswith("n")
    bech = pubkey_to_bech32_address(pub, BITCOIN_TESTNET3)
    assert bech.startswith("tb1")
