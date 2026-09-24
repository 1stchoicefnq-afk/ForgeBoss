from __future__ import annotations

import os
import unittest
from unittest import mock

from forgeboss.control.windows_service_sid import (
    ServiceSidConfigError,
    _close_service_handles,
    configure_and_verify_service_sid,
    configure_unrestricted_service_sid,
    query_service_sid_type,
    resolve_service_sid,
    verify_unrestricted_service_sid,
)


class FakeHandle:
    pass


class FakeServiceApi:
    SC_MANAGER_CONNECT = 1
    SERVICE_CHANGE_CONFIG = 2
    SERVICE_QUERY_CONFIG = 4
    SERVICE_CONFIG_SERVICE_SID_INFO = 5
    SERVICE_SID_TYPE_UNRESTRICTED = 6

    def __init__(self):
        self.scm = FakeHandle()
        self.service = FakeHandle()
        self.closed = []
        self.changed = []
        self.sid_type = self.SERVICE_SID_TYPE_UNRESTRICTED

    def OpenSCManager(self, machine, database, access):
        if access != self.SC_MANAGER_CONNECT:
            raise AssertionError("wrong SCM access")
        return self.scm

    def OpenService(self, scm, name, access):
        if scm is not self.scm:
            raise AssertionError("wrong SCM handle")
        if name != "ForgeBossControl":
            raise AssertionError("wrong service name")
        return self.service

    def ChangeServiceConfig2(self, service, level, value):
        self.changed.append((service, level, value))

    def QueryServiceConfig2(self, service, level):
        return self.sid_type

    def CloseServiceHandle(self, handle):
        self.closed.append(handle)


class ServiceSidConfigUnitTests(unittest.TestCase):
    def test_close_handles_closes_service_then_scm(self):
        api = FakeServiceApi()
        _close_service_handles(api, api.scm, api.service)
        self.assertEqual(api.closed, [api.service, api.scm])

    @unittest.skipIf(os.name == "nt", "non-Windows fail-closed test")
    def test_public_windows_functions_fail_closed_off_windows(self):
        for func in (
            configure_unrestricted_service_sid,
            query_service_sid_type,
            resolve_service_sid,
            verify_unrestricted_service_sid,
            configure_and_verify_service_sid,
        ):
            with self.subTest(func=func.__name__):
                with self.assertRaisesRegex(
                    ServiceSidConfigError,
                    "unavailable on this platform",
                ):
                    func()


if __name__ == "__main__":
    unittest.main()
