"""Tests for hd/bip32.py — using test vectors from BIP-32 spec and the original pywallet."""

from satoshi_kit.hd.bip32 import Xpriv


def test_bip32_vector1():
    """BIP-32 Test Vector 1: seed 000102030405060708090a0b0c0d0e0f."""
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    master = Xpriv.from_seed(seed)
    child = master.derive_path("m/0'/1/2'/2/1000000000")
    assert child.to_xpub() == "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"


def test_bip32_vector2():
    """BIP-32 Test Vector 2."""
    seed = bytes.fromhex(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
    )
    master = Xpriv.from_seed(seed)
    child = master.derive_path("m/0/2147483647'/1/2147483646'/2")
    assert child.to_xpub() == "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"


def test_bip32_vector3():
    """BIP-32 Test Vector 3."""
    seed = bytes.fromhex(
        "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
    )
    master = Xpriv.from_seed(seed)
    child = master.derive_path("m/0'")
    assert child.to_xpub() == "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"


def test_bip32_multi_path():
    """Test from original pywallet: multi-path derivation."""
    xpriv = Xpriv.from_base58(
        "xprv9s21ZrQH143K2gCVXRarFj5npbgjtJ7MuNb15AoRYJ92ZMA1hcnoqpxJKfcsiMHP6cNmDKHCTphsC6uzzyzr2MwjXbDxg6U9ivvEupavYUb"
    )
    keys = xpriv.derive_path_multi("m/7-8'/3/99'/38-39")

    expected = [
        "5ca736abd3b19632d11366c4dd79c227236500879980c6a1fc4e7c1e33933350",
        "8c793bce5319bf04349b5e4d21d091a98c1a1ad632bffc0425a5f4802c999a76",
        "692f2ddb1d5c7213d194643984642df6e9a5c8cd14a1a6b4054571955fcab05f",
        "8739db9026ceb50d7774ef145bd27e899228700f1096072fe9d26f8387378314",
    ]
    assert len(keys) == 4
    for k, expected_hex in zip(keys, expected, strict=True):
        assert k.key == bytes.fromhex(expected_hex)


def test_bip32_from_mnemonic():
    """BIP-39 → BIP-32 integration: test vector from original pywallet."""
    xpriv = Xpriv.from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "TREZOR",
    )
    assert xpriv.to_base58() == "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"


def test_bip32_from_mnemonic_2():
    """Second BIP-39 test vector from original pywallet."""
    xpriv = Xpriv.from_mnemonic(
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        "TREZOR",
    )
    assert xpriv.to_base58() == "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"


def test_xpriv_base58_roundtrip():
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    master = Xpriv.from_seed(seed)
    encoded = master.to_base58()
    decoded = Xpriv.from_base58(encoded)
    assert decoded.key == master.key
    assert decoded.chain_code == master.chain_code
    assert decoded.depth == master.depth
