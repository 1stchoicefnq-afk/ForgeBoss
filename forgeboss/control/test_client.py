from __future__ import annotations
import io
import json
import unittest
from unittest.mock import patch
from forgeboss.control.client import Client


class _Socket:
    def __init__(self, response_factory):
        self.response_factory = response_factory
        self.reader = None

    def makefile(self, mode):
        parent = self
        class File:
            def write(self, data):
                request = json.loads(data.decode())
                response = parent.response_factory(request)
                parent.reader = io.BytesIO((json.dumps(response) + "\n").encode())
            def flush(self):
                pass
            def readline(self, limit=-1):
                return parent.reader.readline(limit)
            def close(self):
                pass
        return File()

    def close(self):
        pass


class ClientCorrelationTests(unittest.TestCase):
    def make_client(self, response_factory):
        sock = _Socket(response_factory)
        with patch("forgeboss.control.client.socket.create_connection", return_value=sock), patch(
            "forgeboss.control.client.secret_file", return_value=(None, b"s" * 32)
        ):
            client = Client()
        return client

    def test_connect_and_call_require_exact_response_identity(self):
        client = self.make_client(lambda req: {"type": "res", "id": req["id"], "ok": True, "payload": {}})
        self.assertEqual(client.call("health"), {})

    def test_mismatched_response_id_fails_closed(self):
        client = self.make_client(lambda req: {"type": "res", "id": req["id"], "ok": True, "payload": {}})
        client.f = _Socket(lambda req: {"type": "res", "id": "wrong", "ok": True, "payload": {}}).makefile("rwb")
        with self.assertRaisesRegex(RuntimeError, "correlation"):
            client.call("health")

    def test_non_object_payload_rejected(self):
        client = self.make_client(lambda req: {"type": "res", "id": req["id"], "ok": True, "payload": {}})
        client.f = _Socket(lambda req: {"type": "res", "id": req["id"], "ok": True, "payload": []}).makefile("rwb")
        with self.assertRaisesRegex(RuntimeError, "payload"):
            client.call("health")


if __name__ == "__main__":
    unittest.main()
