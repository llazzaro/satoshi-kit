"""Tests for network.py."""

from satoshi_kit.network import BITCOIN, BITCOIN_TESTNET3, ETHEREUM, find_network


def test_bitcoin_constants():
    assert BITCOIN.name == "Bitcoin"
    assert BITCOIN.p2pkh_prefix == 0
    assert BITCOIN.wif_prefix == 0x80
    assert BITCOIN.segwit_hrp == "bc"


def test_testnet_constants():
    assert BITCOIN_TESTNET3.p2pkh_prefix == 0x6F
    assert BITCOIN_TESTNET3.segwit_hrp == "tb"


def test_ethereum_constants():
    assert ETHEREUM.name == "Ethereum"
    assert ETHEREUM.segwit_hrp is None


def test_find_network():
    assert find_network("Bitcoin") == BITCOIN
    assert find_network("bitcoin") == BITCOIN
    assert find_network("Bitcoin-Testnet3") == BITCOIN_TESTNET3
    assert find_network("Ethereum") == ETHEREUM
    assert find_network("nonexistent") is None
