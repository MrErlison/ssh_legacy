#!/usr/bin/env python3

import argparse
import getpass
import logging
import os
import select
import socket
import sys
from dataclasses import dataclass
from typing import Optional

import paramiko

# Configure logging to prevent sensitive information leak, but allow debugging if needed.
logger = logging.getLogger("ssh_client")
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

@dataclass
class SSHConfig:
    host: str
    port: int
    user: str
    password: Optional[str] = None
    pkey: Optional[paramiko.PKey] = None


class SSHParser:
    """Responsible for parsing CLI arguments and collecting missing credentials."""

    @staticmethod
    def parse_args() -> argparse.Namespace:
        parser = argparse.ArgumentParser(description="Cliente SSH interativo")
        parser.add_argument("destination", nargs="?", help="user@host ou host")
        parser.add_argument("-l", dest="user", help="Usuário")
        parser.add_argument("-p", dest="port", type=int, default=22, help="Porta SSH (padrão 22)")
        parser.add_argument("-i", dest="keyfile", help="Chave privada")
        parser.add_argument(
            "--insecure",
            action="store_true",
            help="Permite conexões insegura (e.x., AutoAddPolicy para hosts desconhecidos)"
        )
        return parser.parse_args()

    @classmethod
    def build_config(cls, args: argparse.Namespace) -> Optional[SSHConfig]:
        host: Optional[str] = None
        username: Optional[str] = None

        if args.destination:
            if "@" in args.destination:
                username, host = args.destination.split("@", 1)
            else:
                host = args.destination

        if args.user:
            username = args.user

        if not host:
            try:
                host = input("Host: ").strip()
            except EOFError:
                return None
            if not host:
                logger.error("Informe o host.")
                return None

        default_user = getpass.getuser()
        if not username and default_user:
            username = default_user
        elif not username and not default_user:
            username = input("Usuário: ").strip()

        pkey = None
        password = None

        if args.keyfile:
            keyfile = os.path.expanduser(args.keyfile)
            if not os.path.exists(keyfile):
                logger.error(f"Chave {keyfile} não encontrada.")
                return None

            try:
                pkey = paramiko.RSAKey.from_private_key_file(keyfile)
            except paramiko.PasswordRequiredException:
                try:
                    key_pass = getpass.getpass("Senha da chave privada: ")
                    pkey = paramiko.RSAKey.from_private_key_file(keyfile, password=key_pass)
                    # Clear passphrase variable to reduce in-memory lifetime
                    del key_pass
                except Exception as e:
                    logger.error(f"Failed to decrypt private key: {e}")
                    return None
            except Exception as e:
                logger.error(f"Failed to load private key: {e}")
                return None
        else:
            try:
                password = getpass.getpass("Senha: ")
            except EOFError:
                logger.error("Entrada da senha cancelada.")
                return None

        return SSHConfig(
            host=host,
            port=args.port,
            user=username,
            password=password,
            pkey=pkey
        )


class SecureSSHClient:
    """Manages the SSH connection, handling security policies and legacy fallbacks."""

    # Algoritmos legados (usar apenas como último recurso)
    LEGACY_KEX = [
        'diffie-hellman-group14-sha1',
        'diffie-hellman-group-exchange-sha1',
        'diffie-hellman-group1-sha1',
    ]

    def __init__(self, config: SSHConfig, insecure: bool = False):
        self.config = config
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()

        # Trade-off: AutoAddPolicy is vulnerable to MITM.
        # RejectPolicy is secure but may block legimitimate new hosts without ssh-keyscan.
        # Implemented an --insecure flag to explicitly allow unknown hosts.
        if insecure:
            logger.warning("Using AutoAddPolicy (insecure). MITM attacks are possible.")
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

    def connect(self) -> bool:
        """Attempts connection, with a fallback for legacy KEX algorithms if needed."""
        try:
            self._do_connect()
            return True
        except paramiko.SSHException as e:
            # Detect KEX negotiation failure to attempt legacy fallback
            if "Incompatible ssh peer" in str(e) or "kex" in str(e).lower():
                logger.warning(f"Connection failed due to algorithm mismatch. Retrying with legacy KEX... ({e})")
                try:
                    self._do_connect(use_legacy_kex=True)
                    logger.warning("Connected using legacy KEX algorithms. This is less secure.")
                    return True
                except Exception as fallback_e:
                    logger.error(f"Legacy KEX fallback also failed: {fallback_e}")
                    return False
            else:
                logger.error(f"SSH Error: {e}")
                return False
        except paramiko.AuthenticationException:
            logger.error("Authentication failed or rejected.")
            return False
        except socket.error as e:
            logger.error(f"Network error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return False

    def _do_connect(self, use_legacy_kex: bool = False):
        kwargs = {
            "hostname": self.config.host,
            "port": self.config.port,
            "username": self.config.user,
            "password": self.config.password,
            "pkey": self.config.pkey,
            "look_for_keys": False,
            "allow_agent": False,
            "timeout": 10,
            "disabled_algorithms": {'keys': []}
        }

        if use_legacy_kex:
            # Overriding specific connection parameters rather than global paramiko settings
            kwargs["disabled_algorithms"] = dict()
            current_kex = list(paramiko.Transport._preferred_kex)
            # Prepend legacy KEX instead of overwriting entirely to attempt both
            kwargs["kex_algorithms"] = self.LEGACY_KEX + [k for k in current_kex if k not in self.LEGACY_KEX]

        self.client.connect(**kwargs)

    def close(self):
        self.client.close()

    def get_channel(self) -> Optional[paramiko.Channel]:
        try:
            return self.client.invoke_shell()
        except paramiko.SSHException as e:
            logger.error(f"Failed to invoke shell: {e}")
            return None


class InteractiveShell:
    """Handles the IO loop between local stdin/stdout and remote SSH channel."""

    @staticmethod
    def run(chan: paramiko.Channel, stdin=sys.stdin, stdout=sys.stdout):
        try:
            while True:
                r, _, _ = select.select([chan, stdin], [], [])

                if chan in r:
                    try:
                        data = chan.recv(1024)
                        if not data:
                            break
                        stdout.write(data.decode('utf-8', errors='replace'))
                        stdout.flush()
                    except socket.timeout:
                        pass
                    except Exception as e:
                        logger.error(f"Error reading from channel: {e}")
                        break

                if stdin in r:
                    line = stdin.readline()
                    if not line:
                        break
                    chan.send(line)
        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            pass
        except Exception as e:
            logger.error(f"Interactive loop error: {e}")


def main():
    args = SSHParser.parse_args()
    config = SSHParser.build_config(args)

    if not config:
        sys.exit(1)

    ssh_client = SecureSSHClient(config, insecure=args.insecure)

    if not ssh_client.connect():
        sys.exit(1)

    print(f"\nConectado a {config.host}:{config.port} como {config.user}! Digite comandos (Ctrl+C para sair):\n")

    try:
        chan = ssh_client.get_channel()
        if chan:
            InteractiveShell.run(chan)
    finally:
        ssh_client.close()
        print("\nConexão encerrada.")

if __name__ == "__main__":
    main()
