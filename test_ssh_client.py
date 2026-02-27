import argparse
import socket
import sys
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from ssh_client import (InteractiveShell, SecureSSHClient, SSHConfig,
                        SSHParser, main)


@pytest.fixture
def mock_args():
    return argparse.Namespace(
        destination="testuser@192.168.1.1",
        user=None,
        port=2222,
        keyfile=None,
        insecure=False
    )


def test_ssh_config_dataclass():
    config = SSHConfig(host="localhost", port=22, user="admin", password="password")
    assert config.host == "localhost"
    assert config.port == 22
    assert config.user == "admin"
    assert config.password == "password"
    assert config.pkey is None


@patch("ssh_client.getpass.getpass", return_value="secret")
def test_parser_build_config_with_password(mock_getpass, mock_args):
    config = SSHParser.build_config(mock_args)
    assert config is not None
    assert config.host == "192.168.1.1"
    assert config.user == "testuser"
    assert config.port == 2222
    assert config.password == "secret"
    mock_getpass.assert_called_once()


@patch("ssh_client.getpass.getuser", return_value="default_machine_user")
@patch("ssh_client.getpass.getpass", return_value="secret")
@patch("ssh_client.input", side_effect=["10.0.0.1", ""])
def test_parser_build_config_interactive(mock_input, mock_getpass, mock_getuser):
    args = argparse.Namespace(destination=None, user=None, port=22, keyfile=None, insecure=False)
    config = SSHParser.build_config(args)
    assert config is not None
    assert config.host == "10.0.0.1"
    # Should fallback to the system default user
    assert config.user == "default_machine_user"
    assert config.password == "secret"


@patch("ssh_client.paramiko.RSAKey.from_private_key_file")
@patch("os.path.exists", return_value=True)
def test_parser_build_config_with_key(mock_exists, mock_rsa, mock_args):
    mock_args.keyfile = "~/.ssh/id_rsa"
    mock_args.destination = "host.com"
    mock_args.user = "admin"
    
    mock_key = MagicMock()
    mock_rsa.return_value = mock_key

    config = SSHParser.build_config(mock_args)
    
    assert config is not None
    assert config.host == "host.com"
    assert config.user == "admin"
    assert config.pkey == mock_key
    assert config.password is None


@patch("ssh_client.paramiko.SSHClient")
def test_secure_ssh_client_success(mock_client_class):
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    
    config = SSHConfig(host="server", port=22, user="root", password="pw")
    secure_client = SecureSSHClient(config)
    
    result = secure_client.connect()
    assert result is True
    mock_client.connect.assert_called_once()


@patch("ssh_client.paramiko.SSHClient")
def test_secure_ssh_client_auth_failure(mock_client_class):
    mock_client = MagicMock()
    mock_client.connect.side_effect = paramiko.AuthenticationException("Auth failed")
    mock_client_class.return_value = mock_client

    config = SSHConfig(host="server", port=22, user="root", password="wrong")
    secure_client = SecureSSHClient(config)
    
    result = secure_client.connect()
    assert result is False


@patch("ssh_client.paramiko.SSHClient")
def test_secure_ssh_client_kex_fallback(mock_client_class):
    mock_client = MagicMock()
    # First call fails with KEX issue, second call succeeds
    mock_client.connect.side_effect = [
        paramiko.SSHException("Incompatible ssh peer (no acceptable kex algorithm)"),
        None
    ]
    mock_client_class.return_value = mock_client

    config = SSHConfig(host="server", port=22, user="root", password="pw")
    secure_client = SecureSSHClient(config)
    
    result = secure_client.connect()
    assert result is True
    assert mock_client.connect.call_count == 2
    # Verify legacy KEX arguments were passed in the second call
    call_args = mock_client.connect.call_args_list[1][1]
    assert "kex_algorithms" in call_args
    assert any(kex in call_args["kex_algorithms"] for kex in SecureSSHClient.LEGACY_KEX)


@patch("ssh_client.paramiko.SSHClient")
@patch("ssh_client.paramiko.AutoAddPolicy")
def test_secure_ssh_client_insecure(mock_auto_add, mock_client_class):
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    
    config = SSHConfig(host="server", port=22, user="root", password="pw")
    secure_client = SecureSSHClient(config, insecure=True)
    
    mock_client.set_missing_host_key_policy.assert_called_once()
    assert mock_auto_add.called


@patch("ssh_client.select.select")
def test_interactive_shell(mock_select):
    mock_chan = MagicMock()
    mock_stdin = MagicMock()
    mock_stdout = MagicMock()

    # Simulate chan ready, then stdin ready, then exit
    mock_select.side_effect = [
        ([mock_chan], [], []),
        ([mock_stdin], [], []),
        ([], [], [])
    ]
    
    mock_chan.recv.return_value = b"Hello from server\n"
    # End of stream when recv returns empty bytes
    mock_chan.recv.side_effect = [b"Hello from server\n", b""] 
    
    mock_stdin.readline.return_value = "ls -l\n"

    InteractiveShell.run(mock_chan, stdin=mock_stdin, stdout=mock_stdout)
    
    # Check stdout behavior
    mock_stdout.write.assert_called_with("Hello from server\n")
    mock_stdout.flush.assert_called()


@patch("sys.exit")
@patch("ssh_client.SSHParser.parse_args")
@patch("ssh_client.SSHParser.build_config")
@patch("ssh_client.SecureSSHClient")
@patch("ssh_client.InteractiveShell.run")
def test_main_execution_flow(mock_run, mock_secure_client_class, mock_build, mock_parse, mock_exit):
    mock_config = MagicMock()
    mock_config.host = "test"
    mock_config.port = 22
    mock_config.user = "root"
    mock_build.return_value = mock_config

    mock_client = MagicMock()
    mock_client.connect.return_value = True
    mock_client.get_channel.return_value = MagicMock()
    mock_secure_client_class.return_value = mock_client

    main()
    
    mock_client.connect.assert_called_once()
    mock_client.get_channel.assert_called_once()
    mock_run.assert_called_once()
    mock_client.close.assert_called_once()
