#!/usr/bin/env python3

# Copyright (c) 2024 Julian Müller (ChaoticByte)
# License: MIT

import asyncio

from argparse import ArgumentParser
from pathlib import Path
from sys import stdout
from sys import stderr

import asyncssh
import yaml


config_host = ""
config_port = 8022
connected_clients = []
config_clients = {
    # username: asyncssh.SSHAuthorizedKeys
}


class SSHServer(asyncssh.SSHServer):
    def host_based_auth_supported(self): return False
    def kbdint_auth_supported(self): return False
    def password_auth_supported(self): return False
    def public_key_auth_supported(self): return True
    def begin_auth(self, username: str) -> bool: return True # we wanna handle auth

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        try:
            return config_clients[username].validate(key, "", "") is not None # checks client key
        except:
            return False


def broadcast(msg: str, use_stderr: bool = False):
    # Broadcast a message to all connected clients
    assert type(msg) == str
    msg = msg.strip("\r\n")
    if use_stderr:
        msg += "\r\n" # we need CRLF for stderr apparently
        for c in connected_clients:
            c.stderr.write(msg)
    else:
        msg += "\n"
        for c in connected_clients:
            c.stdout.write(msg)

async def handle_connection(process: asyncssh.SSHServerProcess):
    connected_clients.append(process)
    username = process.get_extra_info("username")
    try:
        # hello there
        connected_msg = f"[connected] {username}\n"
        stderr.write(connected_msg)
        broadcast(connected_msg, True)
        if process.command is not None:
            # client has provided a command as a ssh commandline argument
            line = process.command.strip("\r\n")
            msg = f"{username}: {line}\n"
            stdout.write(msg)
            broadcast(msg)
        else:
            # client wants an interactive session
            while True:
                try:
                    async for line in process.stdin:
                        if line == "": raise asyncssh.BreakReceived(0)
                        line = line.strip('\r\n')
                        msg = f"{username}: {line}\n"
                        stdout.write(msg)
                        broadcast(msg)
                except asyncssh.TerminalSizeChanged:
                    continue # we don't want to exit when the client changes its terminal size lol
                finally:     # but otherwise, we do want to
                    break    # exit this loop.
    except asyncssh.BreakReceived:
        pass # we don't want to write an error message on this exception
    except Exception as e:
        stderr.write(f"An error occured: {type(e).__name__} {e}\n")
        stderr.flush()
    finally:
        # exit process, remove client from list, inform other clients
        disconnected_msg = f"[disconnected] {username}\n"
        process.exit(0)
        connected_clients.remove(process)
        stderr.write(disconnected_msg)
        broadcast(disconnected_msg, True)


if __name__ == "__main__":
    # commandline arguments
    argp = ArgumentParser()
    argp.add_argument("config", type=Path, help="The path to the config file")
    argp.add_argument("pkey", type=Path, help="The path to the ssh private key")
    args = argp.parse_args()
    # read config
    config = yaml.safe_load(args.config.read_text())
    config_host = str(config["host"])
    config_port = int(config["port"])
    config_private_key = asyncssh.import_private_key(args.pkey.read_text())
    for c in config["clients"]:
        config_clients[str(c)] = asyncssh.import_authorized_keys(str(config["clients"][c]))
    # read private key
    server_public_key = config_private_key.export_public_key("openssh").decode().strip("\n\r")
    stderr.write(f"Server public key is \"{server_public_key}\"\n")
    stderr.flush()
    # start server
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        asyncssh.create_server(
            SSHServer,
            config_host,
            config_port,
            server_host_keys=[config_private_key],
            process_factory=handle_connection
        ))
    loop.run_forever()
