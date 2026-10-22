"""REA pyGhidra bridge: serves the Java bridge's newline-delimited JSON protocol.

One authenticated client connects to a private Unix socket; every request carries the
session token and is answered with exactly one response line.
"""
import os
import signal
import socket
import sys

from operations import FUNCTION_HANDLERS, INVENTORY_HANDLERS
from rea_addresses import AddressCodec
from rea_descriptor import parse_descriptor
from rea_extensions import ExtensionHost
from rea_handshake import session_info
from rea_protocol import (
    INVALID_REQUEST_ID,
    RequestFailure,
    decode_request,
    encode_response,
    failure_payload,
    require_keys,
    token_matches,
)
from rea_session import Session, exception_label
from rea_startup import (
    analyze_program,
    import_target,
    open_decompiler,
    start_ghidra,
    verify_imported_target,
)

HANDLERS = {**INVENTORY_HANDLERS, **FUNCTION_HANDLERS}
INVALID_REQUEST_MESSAGE = "Bridge request is invalid"


def _capabilities():
    return ["ping", "shutdown", *HANDLERS]


def _dispatch(session, descriptor, provider_version, request):
    if request.method == "ping":
        require_keys(request.params, set())
        return session_info(session, descriptor, provider_version, _capabilities())
    handler = HANDLERS.get(request.method)
    if handler is None:
        raise RequestFailure("method_unavailable", "Bridge method is unavailable")
    return handler(session, request.params)


def _answer(session, descriptor, provider_version, request):
    try:
        result = _dispatch(session, descriptor, provider_version, request)
        return encode_response(request.id, result=result)
    except RequestFailure as failure:
        error = failure_payload(failure.code, failure.message)
    except Exception as exception:
        error = failure_payload("bridge_exception", exception_label(exception))
    return encode_response(request.id, error=error)


def _serve_client(connection, session, descriptor, provider_version):
    """Answer requests until shutdown, EOF, or an unparseable frame."""
    reader = connection.makefile("rb")
    while True:
        line = reader.readline()
        if not line:
            return
        try:
            request = decode_request(line)
        except ValueError:
            connection.sendall(
                encode_response(INVALID_REQUEST_ID, error=failure_payload("invalid_request", INVALID_REQUEST_MESSAGE))
            )
            return
        if not token_matches(request.token, descriptor.token):
            # The peer is already connected; refuse the request without ending the session.
            connection.sendall(
                encode_response(
                    request.id,
                    error=failure_payload("invalid_request", INVALID_REQUEST_MESSAGE),
                )
            )
            continue
        if request.method == "shutdown":
            try:
                require_keys(request.params, set())
            except RequestFailure as failure:
                error = failure_payload(failure.code, failure.message)
                connection.sendall(encode_response(request.id, error=error))
                continue
            connection.sendall(
                encode_response(
                    request.id, result={"shutdown": True, "project_ephemeral": True}
                )
            )
            return
        connection.sendall(_answer(session, descriptor, provider_version, request))


def _bind(endpoint_path):
    if os.path.lexists(endpoint_path):
        os.remove(endpoint_path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous = os.umask(0o177)
    try:
        listener.bind(endpoint_path)
    finally:
        os.umask(previous)
    os.chmod(endpoint_path, 0o600)
    listener.listen(1)
    return listener


def _serve(session, descriptor, provider_version):
    listener = _bind(descriptor.endpoint_path)
    try:
        connection, _ = listener.accept()
        with connection:
            _serve_client(connection, session, descriptor, provider_version)
    finally:
        listener.close()
        if os.path.lexists(descriptor.endpoint_path):
            os.remove(descriptor.endpoint_path)


def _terminate(_signal, _frame):
    sys.exit(143)


def _consume_descriptor(descriptor_path):
    # The token is a bearer secret: once read, the file has no further purpose.
    os.remove(descriptor_path)


def run_bridge(descriptor_dict, descriptor_path, target_path):
    descriptor = parse_descriptor(descriptor_dict)
    runtime_root = os.path.dirname(os.path.abspath(descriptor_path))
    _consume_descriptor(descriptor_path)
    signal.signal(signal.SIGTERM, _terminate)
    provider_version = start_ghidra(descriptor.provider_version)
    from ghidra.util.task import TaskMonitor

    workspace = import_target(runtime_root, target_path, descriptor)
    extensions = ExtensionHost()
    decompiler = None
    try:
        program = workspace.program
        verify_imported_target(program, descriptor)
        analyze_program(program, TaskMonitor.DUMMY, descriptor)
        extensions.analyze(descriptor.analysis_extensions, program, TaskMonitor.DUMMY)
        decompiler = open_decompiler(program)
        session = Session(
            program=program,
            monitor=TaskMonitor.DUMMY,
            target_sha256=descriptor.target_sha256,
            profile_digest=descriptor.profile_digest,
            addresses=AddressCodec(program),
            extensions=extensions,
            decompiler=decompiler,
        )
        _serve(session, descriptor, provider_version)
    finally:
        try:
            if decompiler is not None:
                decompiler.dispose()
        finally:
            try:
                extensions.close()
            finally:
                workspace.close()
