"""Tests for cli/main.py."""

from click.testing import CliRunner

from satoshi_kit.cli.main import cli


def test_cli_info():
    runner = CliRunner()
    result = runner.invoke(cli, ["info", "--key", "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"])
    assert result.exit_code == 0
    assert "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm" in result.output


def test_cli_info_compressed():
    runner = CliRunner()
    result = runner.invoke(cli, ["info", "--key", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"])
    assert result.exit_code == 0
    assert "P2SH-P2WPKH Address:" in result.output
    assert "P2WPKH Address:" in result.output


def test_cli_bip39_generate():
    runner = CliRunner()
    result = runner.invoke(cli, ["bip39-generate"])
    assert result.exit_code == 0
    words = result.output.strip().split(" ")
    assert len(words) == 12


def test_cli_bip39_generate_256():
    runner = CliRunner()
    result = runner.invoke(cli, ["bip39-generate", "--strength", "256"])
    assert result.exit_code == 0
    words = result.output.strip().split(" ")
    assert len(words) == 24


def test_cli_bip39_validate():
    runner = CliRunner()
    words = ["abandon"] * 11 + ["about"]
    result = runner.invoke(cli, ["bip39-validate"] + words)
    assert result.exit_code == 0
    assert "Valid" in result.output


def test_cli_random_key():
    runner = CliRunner()
    result = runner.invoke(cli, ["random-key"])
    assert result.exit_code == 0
    assert "Address:" in result.output


def test_cli_bip32_derive():
    runner = CliRunner()
    result = runner.invoke(cli, [
        "bip32",
        "--xpriv", "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF",
        "--path", "m/0'/0",
        "--format", "addr",
    ])
    assert result.exit_code == 0
    assert "m/0'/0:" in result.output


def test_cli_no_args():
    runner = CliRunner()
    result = runner.invoke(cli, [])
    assert result.exit_code == 0  # click shows help with exit 0 for groups
    assert "Usage:" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "satoshi-kit" in result.output
