"""Proxy de auditoría: registra cada petición saliente que le llega
(CONNECT host:port o GET http://...) y la deniega con 403. Nada sale a la
red. Uso: python -I audit_proxy.py <puerto> <archivo_log>

El log es la evidencia de la auditoría: lo que escribe el programa auditado
se guarda escapado (solo ASCII visible), para que no pueda borrar ni
inventar líneas con CR, escapes de terminal o controles C1."""

import os
import socketserver
import sys
import threading
import time

_LOG_LOCK = threading.Lock()


def _escaped(raw: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b < 0x7F else f"\\x{b:02x}" for b in raw)


class Handler(socketserver.StreamRequestHandler):
    timeout = 10  # un cliente que no envía nada no retiene el hilo

    def handle(self) -> None:
        try:
            line = self.rfile.readline(4096).rstrip(b"\r\n")
        except OSError:
            return
        with _LOG_LOCK, open(LOG, "a", encoding="ascii") as log:
            log.write(f"{time.strftime('%H:%M:%S')} {_escaped(line)}\n")
        self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    # En Windows, SO_REUSEADDR deja que otro socket (de otra cuenta) se una
    # al mismo puerto y reciba peticiones sin registrarlas.
    allow_reuse_address = os.name != "nt"


if __name__ == "__main__":
    PORT, LOG = int(sys.argv[1]), sys.argv[2]
    with Server(("127.0.0.1", PORT), Handler) as server:
        server.serve_forever()
