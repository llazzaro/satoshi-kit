"""Command-line interface for satoshi-kit."""

from __future__ import annotations

import json
import sys

import click

from satoshi_kit import __version__


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="satoshi-kit")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Bitcoin key management toolkit."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.option("--key", required=True, help="WIF or hex private key.")
@click.option("--network", default=None, help="Network name (bitcoin, testnet3, ethereum).")
def info(key: str, network: str | None) -> None:
    """Display key information."""
    from satoshi_kit.crypto.hashing import hash_160
    from satoshi_kit.keys.address import pubkey_to_bech32_address, pubkey_to_p2sh_p2wpkh_address
    from satoshi_kit.keys.keyinfo import keyinfo
    from satoshi_kit.network import BITCOIN, find_network

    net = None
    if network:
        net = find_network(network)
        if net is None:
            click.echo(f"Unknown network: {network}", err=True)
            sys.exit(1)

    ki = keyinfo(key, network=net)
    display_net = net or BITCOIN

    click.echo(f"Network:             {display_net.name}")
    click.echo(f"Compressed:          {ki.compressed}")
    click.echo(f"P2PKH Address:       {ki.addr}")
    if ki.compressed:
        click.echo(f"P2SH-P2WPKH Address: {pubkey_to_p2sh_p2wpkh_address(ki.public_key, display_net)}")
        if display_net.segwit_hrp:
            click.echo(f"P2WPKH Address:      {pubkey_to_bech32_address(ki.public_key, display_net)}")
    if ki.wif:
        click.echo(f"Privkey:             {ki.wif}")
    click.echo(f"Hexprivkey:          {ki.secret.hex()}")
    click.echo(f"Hash160:             {hash_160(ki.public_key).hex()}")
    click.echo(f"Pubkey:              {ki.public_key.hex()}")


@cli.command()
@click.option("--wallet", required=True, help="Wallet directory path.")
@click.option("--wallet-file", default=None, help="Wallet filename (default: wallet.dat).")
@click.option("--passphrase", default=None, help="Wallet passphrase.")
@click.option("--format", "fmt", default="all", type=click.Choice(["all", "addr", "keys"]), help="Output format.")
@click.option("--network", default=None, help="Network name.")
def dump(wallet: str, wallet_file: str | None, passphrase: str | None, fmt: str, network: str | None) -> None:
    """Dump wallet contents as JSON."""
    from satoshi_kit.network import BITCOIN, find_network
    from satoshi_kit.wallet.bdb import create_env
    from satoshi_kit.wallet.reader import read_wallet

    net = BITCOIN
    if network:
        net = find_network(network) or BITCOIN

    db_env = create_env(wallet)
    wf = wallet_file or "wallet.dat"
    wallet_data = read_wallet(db_env, wf, passphrase=passphrase, network=net)

    output: dict[str, object] = {}
    if fmt in ("all", "keys"):
        output["keys"] = [
            {
                "addr": k.addr,
                "compressed": k.compressed,
                "wif": k.wif,
                "hex_secret": k.hex_secret,
                "label": k.label,
                "reserve": k.reserve,
            }
            for k in wallet_data.keys
        ]
    if fmt in ("all", "addr"):
        output["addresses"] = [k.addr for k in wallet_data.keys]
    if fmt == "all":
        output["version"] = wallet_data.version
        output["crypted"] = wallet_data.crypted

    click.echo(json.dumps(output, indent=2))


@cli.command("import")
@click.option("--wallet", required=True, help="Wallet directory path.")
@click.option("--wallet-file", default=None, help="Wallet filename (default: wallet.dat).")
@click.option("--key", required=True, help="WIF or hex private key.")
@click.option("--label", default="", help="Address book label.")
@click.option("--reserve", is_flag=True, help="Import as reserve key.")
@click.option("--passphrase", default=None, help="Wallet passphrase.")
@click.option("--network", default=None, help="Network name.")
def import_key(
    wallet: str,
    wallet_file: str | None,
    key: str,
    label: str,
    reserve: bool,
    passphrase: str | None,
    network: str | None,
) -> None:
    """Import a private key into a wallet."""
    from satoshi_kit.network import BITCOIN, find_network
    from satoshi_kit.wallet.bdb import create_env, open_wallet
    from satoshi_kit.wallet.reader import read_wallet
    from satoshi_kit.wallet.writer import import_private_key

    net = BITCOIN
    if network:
        net = find_network(network) or BITCOIN

    db_env = create_env(wallet)
    wf = wallet_file or "wallet.dat"

    wallet_data = read_wallet(db_env, wf, network=net)
    db = open_wallet(db_env, wf, writable=True)

    addr = import_private_key(
        db,
        key,
        label=label,
        reserve=reserve,
        network=net,
        master_key_info=wallet_data.master_key,
        passphrase=passphrase,
    )
    db.close()
    click.echo(f"Imported key for address: {addr}")


@cli.command()
@click.option("--xpriv", required=True, help="Base58-encoded xpriv.")
@click.option("--path", required=True, help="Derivation path (e.g. m/44'/0'/0'/0/0).")
@click.option("--format", "fmt", default="addr", type=click.Choice(["addr", "privkey", "wif"]), help="Output format.")
@click.option("--network", default=None, help="Network name.")
def bip32(xpriv: str, path: str, fmt: str, network: str | None) -> None:
    """BIP-32 key derivation."""
    from satoshi_kit.hd.bip32 import Xpriv
    from satoshi_kit.keys.keyinfo import keyinfo
    from satoshi_kit.network import find_network

    net = None
    if network:
        net = find_network(network)

    xp = Xpriv.from_base58(xpriv)

    for child in xp.derive_path_multi(path):
        ki = keyinfo(child.key.hex(), network=net, force_compressed=True)
        if fmt == "privkey":
            click.echo(f"{child.full_path}: {ki.secret.hex()}")
        elif fmt == "wif":
            click.echo(f"{child.full_path}: {ki.wif}")
        else:
            click.echo(f"{child.full_path}: {ki.addr}")


@cli.command("bip39-generate")
@click.option("--strength", type=int, default=128, help="Entropy bits (default: 128).")
def bip39_generate(strength: int) -> None:
    """Generate a BIP-39 mnemonic."""
    from satoshi_kit.hd.bip39 import Mnemonic

    m = Mnemonic()
    click.echo(m.generate(strength=strength))


@cli.command("bip39-validate")
@click.argument("mnemonic", nargs=-1, required=True)
def bip39_validate(mnemonic: tuple[str, ...]) -> None:
    """Validate a BIP-39 mnemonic.

    Pass the mnemonic words as arguments:

      satoshi-kit bip39-validate abandon abandon ... about
    """
    from satoshi_kit.hd.bip39 import Mnemonic

    m = Mnemonic()
    phrase = " ".join(mnemonic)
    if m.check(phrase):
        click.echo("Valid mnemonic")
    else:
        click.echo("Invalid mnemonic", err=True)
        sys.exit(1)


@cli.command("random-key")
@click.option("--network", default=None, help="Network name.")
def random_key(network: str | None) -> None:
    """Generate a random private key."""
    from satoshi_kit.keys.ec import ECKey
    from satoshi_kit.keys.keyinfo import keyinfo
    from satoshi_kit.network import find_network

    net = None
    if network:
        net = find_network(network)

    ec = ECKey.generate()
    ki = keyinfo(ec.secret_bytes().hex(), network=net)
    click.echo(f"Address: {ki.addr}")
    if ki.wif:
        click.echo(f"WIF:     {ki.wif}")
    click.echo(f"Hex:     {ki.secret.hex()}")


def main(argv: list[str] | None = None) -> None:
    """Entry point that accepts argv for testing compatibility."""
    cli(args=argv, standalone_mode=True)
