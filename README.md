# satoshi-kit

A Python library for Bitcoin key management, HD wallet derivation, and wallet.dat operations.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Type Checked: mypy](https://img.shields.io/badge/type%20checked-mypy--strict-blue.svg)](https://mypy-lang.org/)

**satoshi-kit** is a modern Python toolkit for Bitcoin private key generation, BIP-32 hierarchical deterministic (HD) wallet derivation, BIP-39 mnemonic seed phrases, Bitcoin address generation (P2PKH, P2SH-P2WPKH, bech32 SegWit), WIF encoding, and reading/writing Bitcoin Core `wallet.dat` files.

## Features

- **Bitcoin private key generation** -- secp256k1 elliptic curve keys via the `ecdsa` library
- **BIP-39 mnemonic phrases** -- generate and validate 12/24-word seed phrases, derive seeds with optional passphrase
- **BIP-32 HD key derivation** -- derive child keys from extended private keys (xpriv) using standard derivation paths like `m/44'/0'/0'/0/0`
- **Bitcoin address generation** -- P2PKH (`1...`), P2SH-P2WPKH (`3...`), bech32 P2WPKH (`bc1...`)
- **Ethereum address support** -- EIP-55 checksummed addresses from secp256k1 public keys
- **WIF encoding/decoding** -- Wallet Import Format for private key import/export
- **wallet.dat read/write** -- parse and modify Bitcoin Core wallet files (BerkeleyDB)
- **Encrypted wallet support** -- decrypt wallet.dat master keys and private keys with passphrase
- **CLI tool** -- command-line interface built with Click for all operations
- **Fully typed** -- passes `mypy --strict`, uses dataclasses throughout

## Installation

```bash
pip install satoshi-kit
```

For Bitcoin Core `wallet.dat` operations (requires Berkeley DB headers):

```bash
pip install satoshi-kit[wallet]
```

### Using uv

```bash
uv sync              # core only
uv sync --extra wallet  # with wallet.dat support
```

### macOS (Homebrew)

The `wallet` extra depends on `bsddb3`, which needs Berkeley DB headers. Install them first:

```bash
brew install berkeley-db@5
export BERKELEYDB_DIR="$(brew --prefix berkeley-db@5)"
pip install satoshi-kit[wallet]
```

## Command-Line Interface

satoshi-kit includes a CLI built with [Click](https://click.palletsprojects.com/).

### Wallet Operations

```bash
# Dump wallet contents
satoshi-kit dump --wallet /path/to/wallet/dir --format all

# Dump encrypted wallet
satoshi-kit dump --wallet /path/to/wallet/dir --passphrase "my passphrase"

# Import a private key
satoshi-kit import --wallet /path/to/wallet/dir --key 5HueCGU8r... --label "my key"
```

### Key Information

```bash
satoshi-kit info --key 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
```

### Generate a Random Key

```bash
satoshi-kit random-key
satoshi-kit random-key --network testnet3
```

### BIP-39 Mnemonic Operations

```bash
# Generate a 12-word mnemonic
satoshi-kit bip39-generate

# Generate a 24-word mnemonic
satoshi-kit bip39-generate --strength 256

# Validate a mnemonic
satoshi-kit bip39-validate abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

### BIP-32 HD Key Derivation

```bash
satoshi-kit bip32 --xpriv xprv9s21ZrQH143K... --path "m/44'/0'/0'/0/*" --format addr
satoshi-kit bip32 --xpriv xprv9s21ZrQH143K... --path "m/44'/0'/0'/0/0" --format wif
```

## Quick Start (Python API)

### Generate a Bitcoin Private Key

```python
from satoshi_kit.keys.ec import ECKey
from satoshi_kit.keys.wif import secret_to_wif
from satoshi_kit.keys.address import pubkey_to_p2pkh_address
from satoshi_kit.network import BITCOIN

key = ECKey.generate()
address = pubkey_to_p2pkh_address(key.public_key(), BITCOIN)
wif = secret_to_wif(key.secret_bytes(), compressed=True, network=BITCOIN)
print(f"Address: {address}")
print(f"WIF:     {wif}")
```

### Get Key Info from WIF or Hex

```python
from satoshi_kit.keys.keyinfo import keyinfo

ki = keyinfo("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
print(ki.addr)          # 1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S
print(ki.wif)           # 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
print(ki.secret.hex())  # 0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d
```

### BIP-39 Mnemonic Seed Phrase

```python
from satoshi_kit.hd.bip39 import Mnemonic

m = Mnemonic()
words = m.generate()       # 12-word mnemonic
seed = m.to_seed(words)    # 64-byte seed

# Validate an existing mnemonic
assert m.check("abandon " * 11 + "about")
```

### BIP-32 HD Wallet Derivation

```python
from satoshi_kit.hd.bip32 import Xpriv
from satoshi_kit.hd.bip39 import Mnemonic

m = Mnemonic()
seed = m.to_seed("abandon " * 11 + "about", passphrase="TREZOR")

master = Xpriv.from_seed(seed)
child = master.derive_path("m/44'/0'/0'/0/0")
print(child.key.hex())
```

### Bitcoin Address Types

```python
from satoshi_kit.keys.ec import ECKey
from satoshi_kit.keys.address import (
    pubkey_to_p2pkh_address,
    pubkey_to_p2sh_p2wpkh_address,
    pubkey_to_bech32_address,
)
from satoshi_kit.network import BITCOIN

key = ECKey.from_secret_exponent(1)
pub = key.public_key(compressed=True)

pubkey_to_p2pkh_address(pub, BITCOIN)        # 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
pubkey_to_p2sh_p2wpkh_address(pub, BITCOIN)  # 3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
pubkey_to_bech32_address(pub, BITCOIN)        # bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
```

## Supported Networks

| Network | P2PKH | P2SH | SegWit (bech32) | WIF prefix |
|---|---|---|---|---|
| Bitcoin mainnet | `1...` | `3...` | `bc1...` | `5` / `K` / `L` |
| Bitcoin testnet | `m` / `n` | `2...` | `tb1...` | `9` / `c` |
| Ethereum | `0x...` (EIP-55) | -- | -- | -- |

## Package Structure

```
src/satoshi_kit/
  crypto/          # SHA-256, RIPEMD-160, Keccak-256, Base58, bech32, AES-256-CBC
  keys/            # secp256k1 EC keys, WIF, P2PKH/P2SH/bech32 addresses
  hd/              # BIP-32 HD derivation, BIP-39 mnemonics
  wallet/          # wallet.dat parsing, encryption, BerkeleyDB I/O
  network.py       # Bitcoin, testnet, Ethereum network definitions
  cli/             # Click-based command-line interface
```

## Development

```bash
git clone https://github.com/example/satoshi-kit.git
cd satoshi-kit
pip install -e ".[dev]"

pytest                       # 74 tests
ruff check src/ tests/       # linting
mypy --strict src/satoshi_kit/  # type checking
```

## Background

- Requires Python 3.10+
- Replaces hand-rolled cryptography with `cryptography`, `ecdsa`, and `pycryptodome`
- Eliminates all global mutable state
- Uses typed dataclasses and passes `mypy --strict`
- Focuses on core operations (key management, HD wallets, wallet.dat) -- drops web UI, balance checking, block explorer scraping, and disk recovery

## License

MIT
