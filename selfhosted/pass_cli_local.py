#!/usr/bin/env python3
"""Local-only Proton-like CLI adapter for passd v3.

This executable intentionally does not touch Proton production services or alter
Proton entitlement behavior. It speaks newline-delimited JSON to a local passd
Unix socket. Machine API keys authenticate agents; HITL-approved access leases
supply all resource authority.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import socket
import sys
from pathlib import Path


class RpcError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message); self.code = code


def default_data_dir() -> Path:
    value = os.environ.get("PASSD_DATA_DIR")
    return Path(value).expanduser() if value else Path.home() / ".local" / "share" / "passd"


def socket_path(data_dir: Path) -> Path:
    value = os.environ.get("PASSD_SOCKET")
    return Path(value).expanduser() if value else data_dir / "passd.sock"


def master_password() -> str:
    if os.environ.get("PASSD_MASTER_PASSWORD_FILE"):
        return Path(os.environ["PASSD_MASTER_PASSWORD_FILE"]).expanduser().read_text().strip()
    if os.environ.get("PASSD_MASTER_PASSWORD"):
        return os.environ["PASSD_MASTER_PASSWORD"]
    return getpass.getpass("Master password: ")


def agent_token(value: str | None) -> str | None:
    return value or os.environ.get("PASSD_AGENT_TOKEN")


def reason(value: str | None) -> str | None:
    return value or os.environ.get("PASSD_AGENT_REASON")


def parse_ttl(value: str) -> int:
    value = value.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if not value: raise ValueError("empty expiration")
    if value[-1] in units: return int(value[:-1]) * units[value[-1]]
    return int(value)


def kv_pairs(values: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for value in values:
        if "=" not in value: raise ValueError(f"expected NAME=VALUE, got: {value}")
        key, val = value.split("=", 1)
        if not key: raise ValueError("name must not be empty")
        out[key] = val
    return out


class RpcClient:
    def __init__(self, path: Path): self.path = Path(path)

    def call(self, op: str, params: dict | None = None, *, admin_password: str | None = None, agent_token: str | None = None, reason: str | None = None):
        request = {"op": op, "params": params or {}}
        if admin_password is not None: request["admin_password"] = admin_password
        if agent_token is not None: request["agent_token"] = agent_token
        if reason is not None: request["reason"] = reason
        payload = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(self.path)); sock.sendall(payload)
            buf = bytearray()
            while b"\n" not in buf:
                part = sock.recv(65536)
                if not part: break
                buf.extend(part)
        finally:
            sock.close()
        if not buf: raise RpcError("transport_error", "passd closed the socket without a response")
        response = json.loads(bytes(buf).split(b"\n", 1)[0].decode())
        if not response.get("ok"):
            error = response.get("error") or {}
            raise RpcError(error.get("code", "rpc_error"), error.get("message", "unknown RPC error"))
        return response.get("result")


def emit(value, *, raw: bool = False):
    if raw and isinstance(value, (str, int, float)): print(value)
    else: print(json.dumps(value, ensure_ascii=False, indent=2))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pass-cli-local", description="Local Proton-like adapter for passd's HITL capability broker")
    p.add_argument("--data-dir", type=Path, default=default_data_dir())
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")

    v = sub.add_parser("vault"); vs = v.add_subparsers(dest="vault_command", required=True)
    vl = vs.add_parser("list"); vl.add_argument("--agent-token")
    vc = vs.add_parser("create"); vc.add_argument("name"); vc.add_argument("--description", default="")

    i = sub.add_parser("item"); ins = i.add_subparsers(dest="item_command", required=True)
    il = ins.add_parser("list"); il.add_argument("vault"); il.add_argument("--agent-token")
    iv = ins.add_parser("view"); iv.add_argument("uri"); iv.add_argument("--agent-token"); iv.add_argument("--reason"); iv.add_argument("--raw", action="store_true")
    ip = ins.add_parser("put-login")
    ip.add_argument("--vault", required=True); ip.add_argument("--title", required=True)
    ip.add_argument("--username"); ip.add_argument("--email"); ip.add_argument("--password"); ip.add_argument("--password-file", type=Path)
    ip.add_argument("--url", action="append", default=[]); ip.add_argument("--field", action="append", default=[], metavar="NAME=VALUE"); ip.add_argument("--note", default="")

    a = sub.add_parser("agent"); ags = a.add_subparsers(dest="agent_command", required=True)
    ac = ags.add_parser("create"); ac.add_argument("name")
    ac.add_argument("--scope", action="append", choices=["access.request", "metadata.read", "secret.use", "secret.reveal", "capability.request", "capability.invoke"], default=[])
    ac.add_argument("--allow-host", action="append", default=[]); ac.add_argument("--expiration", default="1d")
    ags.add_parser("list")
    aro = ags.add_parser("rotate"); aro.add_argument("agent")
    ar = ags.add_parser("revoke"); ar.add_argument("agent")
    am = ags.add_parser("monitor"); am.add_argument("agent", nargs="?"); am.add_argument("--limit", type=int, default=100)

    cp = sub.add_parser("capability", help="typed agent capabilities; backing vault selectors stay hidden")
    cps = cp.add_subparsers(dest="capability_command", required=True)
    cl = cps.add_parser("list"); cl.add_argument("--agent-token")
    cg = cps.add_parser("get"); cg.add_argument("capability_id")
    put = cps.add_parser("put-http"); put.add_argument("capability_id"); put.add_argument("--description", default="")
    put.add_argument("--backing-uri", required=True); put.add_argument("--scheme", choices=["http", "https"], default="https")
    put.add_argument("--host", required=True); put.add_argument("--port", type=int); put.add_argument("--method", action="append", default=[])
    put.add_argument("--path-prefix", required=True); put.add_argument("--inject-header", default="Authorization"); put.add_argument("--inject-prefix", default="Bearer ")
    put.add_argument("--static-header", action="append", default=[], metavar="NAME=VALUE"); put.add_argument("--timeout", type=float, default=20.0)
    cr = cps.add_parser("request"); cr.add_argument("capability_id"); cr.add_argument("--method", default="POST"); cr.add_argument("--path", required=True)
    cr.add_argument("--expiration", default="5m"); cr.add_argument("--uses", type=int, default=1); cr.add_argument("--agent-token"); cr.add_argument("--reason")
    ci = cps.add_parser("invoke"); ci.add_argument("capability_id"); ci.add_argument("--method", default="POST"); ci.add_argument("--path", required=True)
    ci.add_argument("--body"); ci.add_argument("--body-file", type=Path); ci.add_argument("--agent-token"); ci.add_argument("--reason")

    access = sub.add_parser("access"); axs = access.add_subparsers(dest="access_command", required=True)
    rq = axs.add_parser("request"); rq.add_argument("uri"); rq.add_argument("--capability", choices=["secret.use", "secret.reveal"], default="secret.use")
    rq.add_argument("--host"); rq.add_argument("--expiration", default="5m"); rq.add_argument("--uses", type=int, default=1); rq.add_argument("--agent-token"); rq.add_argument("--reason")
    st = axs.add_parser("status"); st.add_argument("request", nargs="?"); st.add_argument("--agent-token")
    pe = axs.add_parser("pending"); pe.add_argument("--limit", type=int, default=100)
    ap = axs.add_parser("approve"); ap.add_argument("request"); ap.add_argument("--expiration"); ap.add_argument("--uses", type=int); ap.add_argument("--note")
    de = axs.add_parser("deny"); de.add_argument("request"); de.add_argument("--note")
    rv = axs.add_parser("revoke"); rv.add_argument("request")

    r = sub.add_parser("resolve"); r.add_argument("uri"); r.add_argument("--agent-token"); r.add_argument("--reason"); r.add_argument("--raw", action="store_true")

    b = sub.add_parser("broker-http"); b.add_argument("uri"); b.add_argument("url")
    b.add_argument("--method", default="GET"); b.add_argument("--header", default="Authorization"); b.add_argument("--prefix", default="Bearer "); b.add_argument("--body")
    b.add_argument("--header-extra", action="append", default=[], metavar="NAME=VALUE"); b.add_argument("--agent-token"); b.add_argument("--reason"); b.add_argument("--timeout", type=float, default=20.0)
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    client = RpcClient(socket_path(args.data_dir.expanduser()))
    try:
        if args.command == "doctor":
            emit({"socket": str(client.path), "daemon": client.call("health")}); return 0

        if args.command == "vault":
            if args.vault_command == "list":
                token = agent_token(args.agent_token)
                emit(client.call("vault.list", agent_token=token) if token else client.call("vault.list", admin_password=master_password()))
            else:
                emit(client.call("vault.create", {"name": args.name, "description": args.description}, admin_password=master_password()))
            return 0

        if args.command == "item":
            if args.item_command == "list":
                token = agent_token(args.agent_token); kwargs = {"agent_token": token} if token else {"admin_password": master_password()}
                emit(client.call("item.list", {"vault": args.vault}, **kwargs)); return 0
            if args.item_command == "view":
                token = agent_token(args.agent_token); kwargs = {"agent_token": token, "reason": reason(args.reason)} if token else {"admin_password": master_password()}
                emit(client.call("secret.resolve", {"uri": args.uri}, **kwargs), raw=args.raw); return 0
            fields = kv_pairs(args.field)
            if args.username is not None: fields["username"] = args.username
            if args.email is not None: fields["email"] = args.email
            secret = args.password_file.read_text().strip() if args.password_file else args.password
            if secret is None: secret = getpass.getpass("Secret password/API key: ")
            fields["password"] = secret
            emit(client.call("item.put", {"vault": args.vault, "title": args.title, "type": "login", "fields": fields, "urls": args.url, "note": args.note}, admin_password=master_password()))
            return 0

        if args.command == "agent":
            admin = master_password()
            if args.agent_command == "create":
                emit(client.call("agent.create", {"name": args.name, "scopes": args.scope or ["capability.request", "capability.invoke"], "allowed_hosts": args.allow_host, "ttl_seconds": parse_ttl(args.expiration)}, admin_password=admin))
            elif args.agent_command == "list": emit(client.call("agent.list", admin_password=admin))
            elif args.agent_command == "rotate": emit(client.call("agent.rotate", {"agent": args.agent}, admin_password=admin))
            elif args.agent_command == "revoke": emit(client.call("agent.revoke", {"agent": args.agent}, admin_password=admin))
            else: emit(client.call("audit.list", {"agent": args.agent, "limit": args.limit}, admin_password=admin))
            return 0

        if args.command == "capability":
            if args.capability_command == "list":
                token = agent_token(args.agent_token)
                emit(client.call("capability.list", agent_token=token) if token else client.call("capability.list", admin_password=master_password()))
            elif args.capability_command == "get":
                emit(client.call("capability.get", {"id": args.capability_id}, admin_password=master_password()))
            elif args.capability_command == "put-http":
                params = {
                    "id": args.capability_id, "description": args.description, "kind": "http_secret",
                    "backing_uri": args.backing_uri, "scheme": args.scheme, "host": args.host,
                    "methods": args.method or ["POST"], "path_prefix": args.path_prefix,
                    "inject_header": args.inject_header, "inject_prefix": args.inject_prefix,
                    "static_headers": kv_pairs(args.static_header), "timeout_seconds": args.timeout,
                }
                if args.port is not None: params["port"] = args.port
                emit(client.call("capability.put", params, admin_password=master_password()))
            elif args.capability_command == "request":
                emit(client.call(
                    "capability.request",
                    {"capability_id": args.capability_id, "method": args.method, "path": args.path, "ttl_seconds": parse_ttl(args.expiration), "max_uses": args.uses},
                    agent_token=agent_token(args.agent_token), reason=reason(args.reason),
                ))
            else:
                body = args.body_file.read_text() if args.body_file else args.body
                emit(client.call(
                    "capability.invoke",
                    {"capability_id": args.capability_id, "method": args.method, "path": args.path, "body": body},
                    agent_token=agent_token(args.agent_token), reason=reason(args.reason),
                ))
            return 0

        if args.command == "access":
            if args.access_command == "request":
                emit(client.call("access.request", {"uri": args.uri, "capability": args.capability, "target_host": args.host, "ttl_seconds": parse_ttl(args.expiration), "max_uses": args.uses}, agent_token=agent_token(args.agent_token), reason=reason(args.reason)))
            elif args.access_command == "status":
                emit(client.call("access.status", {"request": args.request} if args.request else {}, agent_token=agent_token(args.agent_token)))
            elif args.access_command == "pending": emit(client.call("access.pending", {"limit": args.limit}, admin_password=master_password()))
            elif args.access_command == "approve":
                params = {"request": args.request, "note": args.note}
                if args.expiration: params["ttl_seconds"] = parse_ttl(args.expiration)
                if args.uses is not None: params["max_uses"] = args.uses
                emit(client.call("access.approve", params, admin_password=master_password()))
            elif args.access_command == "deny": emit(client.call("access.deny", {"request": args.request, "note": args.note}, admin_password=master_password()))
            else: emit(client.call("access.revoke", {"request": args.request}, admin_password=master_password()))
            return 0

        if args.command == "resolve":
            token = agent_token(args.agent_token); kwargs = {"agent_token": token, "reason": reason(args.reason)} if token else {"admin_password": master_password()}
            emit(client.call("secret.resolve", {"uri": args.uri}, **kwargs), raw=args.raw); return 0

        if args.command == "broker-http":
            token = agent_token(args.agent_token); kwargs = {"agent_token": token, "reason": reason(args.reason)} if token else {"admin_password": master_password()}
            emit(client.call("broker.http", {"uri": args.uri, "url": args.url, "method": args.method, "header": args.header, "prefix": args.prefix, "body": args.body, "headers": kv_pairs(args.header_extra), "timeout": args.timeout}, **kwargs)); return 0
        return 2
    except (RpcError, ValueError, OSError, json.JSONDecodeError) as exc:
        code = getattr(exc, "code", "error")
        print(f"pass-cli-local: {code}: {exc}", file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())
