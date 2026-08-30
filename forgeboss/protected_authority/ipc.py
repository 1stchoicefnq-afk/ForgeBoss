from __future__ import annotations

import os,socket,time
from .boundary import unix_peer_context,windows_pipe_peer_context
from .protocol import AuthorityError,MAX_REQUEST_BYTES


def serve_unix_once(listener:socket.socket,service,*,accept_timeout:float|None=None,preauth_timeout:float|None=None,stop_event=None,on_connection=None)->bytes:
    if os.name=='nt':raise AuthorityError('IPC_PLATFORM_INVALID')
    if accept_timeout is not None:
        if not isinstance(accept_timeout,(int,float)) or not 0.01<=float(accept_timeout)<=5.0:raise AuthorityError('IPC_TIMEOUT_INVALID')
        listener.settimeout(float(accept_timeout))
    try:
        conn,_=listener.accept()
    except socket.timeout as e:
        raise AuthorityError('IPC_ACCEPT_TIMEOUT') from e
    except OSError as e:
        if stop_event is not None and stop_event.is_set():raise AuthorityError('IPC_STOPPED') from e
        raise AuthorityError('IPC_ACCEPT_FAILED') from e
    if on_connection is not None:on_connection(conn,True)
    try:
        ctx=unix_peer_context(conn);chunks=[];total=0
        deadline=None
        if preauth_timeout is not None:
            if not isinstance(preauth_timeout,(int,float)) or not 0.05<=float(preauth_timeout)<=30.0:raise AuthorityError('IPC_TIMEOUT_INVALID')
            deadline=time.monotonic()+float(preauth_timeout)
        while True:
            if stop_event is not None and stop_event.is_set():raise AuthorityError('IPC_STOPPED')
            if deadline is not None:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise AuthorityError('IPC_PREAUTH_TIMEOUT')
                conn.settimeout(min(remaining,0.25))
            try:part=conn.recv(min(65536,MAX_REQUEST_BYTES+1-total))
            except socket.timeout:
                if deadline is not None and time.monotonic()>=deadline:raise AuthorityError('IPC_PREAUTH_TIMEOUT')
                continue
            except OSError as e:
                if stop_event is not None and stop_event.is_set():raise AuthorityError('IPC_STOPPED') from e
                raise AuthorityError('IPC_READ_FAILED') from e
            if not part:break
            total+=len(part)
            if total>MAX_REQUEST_BYTES:raise AuthorityError('REQUEST_SIZE_INVALID')
            chunks.append(part)
        if not total:raise AuthorityError('REQUEST_SIZE_INVALID')
        result=service.handle_json(b''.join(chunks),peer_context=ctx);conn.sendall(result);return result
    finally:
        if on_connection is not None:on_connection(conn,False)
        try:conn.close()
        except OSError:pass

def handle_windows_pipe_message(pipe_handle:int,raw:bytes,service)->bytes:
    if os.name!='nt':raise AuthorityError('IPC_PLATFORM_INVALID')
    if not isinstance(raw,bytes) or not raw or len(raw)>MAX_REQUEST_BYTES:raise AuthorityError('REQUEST_SIZE_INVALID')
    return service.handle_json(raw,peer_context=windows_pipe_peer_context(pipe_handle))
