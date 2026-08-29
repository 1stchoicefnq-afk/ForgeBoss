from __future__ import annotations

import os,socket
from .boundary import unix_peer_context,windows_pipe_peer_context
from .protocol import AuthorityError,MAX_REQUEST_BYTES


def serve_unix_once(listener:socket.socket,service)->bytes:
    if os.name=='nt':raise AuthorityError('IPC_PLATFORM_INVALID')
    conn,_=listener.accept()
    try:
        ctx=unix_peer_context(conn);chunks=[];total=0
        while True:
            part=conn.recv(min(65536,MAX_REQUEST_BYTES+1-total))
            if not part:break
            total+=len(part)
            if total>MAX_REQUEST_BYTES:raise AuthorityError('REQUEST_SIZE_INVALID')
            chunks.append(part)
        result=service.handle_json(b''.join(chunks),peer_context=ctx);conn.sendall(result);return result
    finally:conn.close()

def handle_windows_pipe_message(pipe_handle:int,raw:bytes,service)->bytes:
    if os.name!='nt':raise AuthorityError('IPC_PLATFORM_INVALID')
    if not isinstance(raw,bytes) or not raw or len(raw)>MAX_REQUEST_BYTES:raise AuthorityError('REQUEST_SIZE_INVALID')
    return service.handle_json(raw,peer_context=windows_pipe_peer_context(pipe_handle))
