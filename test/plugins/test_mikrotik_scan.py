import os
import sys
import types
from unittest.mock import MagicMock, patch


_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_SERVER = os.path.join(_ROOT, "server")
_PLUGIN_DIR = os.path.join(_ROOT, "front", "plugins", "mikrotik_scan")

for _path in [_ROOT, _SERVER, _PLUGIN_DIR]:
    if _path not in sys.path:
        sys.path.insert(0, _path)


if "librouteros" not in sys.modules:
    _librouteros = types.ModuleType("librouteros")
    _librouteros.connect = MagicMock()
    sys.modules["librouteros"] = _librouteros

if "librouteros.exceptions" not in sys.modules:
    _librouteros_exceptions = types.ModuleType("librouteros.exceptions")

    class _TrapError(Exception):
        pass

    _librouteros_exceptions.TrapError = _TrapError
    sys.modules["librouteros.exceptions"] = _librouteros_exceptions


with patch("helper.get_setting_value", return_value="UTC"), \
     patch("logger.Logger"):
    import mikrotik  # noqa: E402


class TestMikrotikScan:
    def setup_method(self):
        mikrotik.MT_HOST = "192.168.1.1"
        mikrotik.MT_PORT = 8728
        mikrotik.MT_USER = "user"
        mikrotik.MT_PASS = "pass"

    def test_skips_non_bound_and_missing_mac_without_aborting(self):
        leases = [
            {
                ".id": "*1",
                "address": "192.168.1.10",
                "mac-address": "AA:BB:CC:DD:EE:01",
                "host-name": "host-a",
                "comment": "",
                "last-seen": "10s",
                "status": "bound",
            },
            {
                ".id": "*2",
                "address": "192.168.1.11",
                "status": "waiting",
            },
            {
                ".id": "*3",
                "address": "192.168.1.12",
                "status": "bound",
            },
            {
                ".id": "*4",
                "address": "192.168.1.13",
                "mac-address": "AA:BB:CC:DD:EE:04",
                "host-name": "",
                "comment": "reserved-entry",
                "last-seen": "1m",
                "status": "bound",
            },
        ]

        api = MagicMock(return_value=iter(leases))
        plugin_objects = MagicMock()

        with patch.object(mikrotik, "connect", return_value=api):
            result = mikrotik.get_entries(plugin_objects)

        assert result is plugin_objects
        assert plugin_objects.add_object.call_count == 2
        first_call = plugin_objects.add_object.call_args_list[0]
        second_call = plugin_objects.add_object.call_args_list[1]
        assert first_call.kwargs["primaryId"] == "aa:bb:cc:dd:ee:01"
        assert second_call.kwargs["primaryId"] == "aa:bb:cc:dd:ee:04"

    def test_skips_invalid_mac_but_processes_next_valid_lease(self):
        leases = [
            {
                ".id": "*1",
                "address": "192.168.1.20",
                "mac-address": "not-a-mac",
                "host-name": "bad-mac",
                "comment": "",
                "last-seen": "2m",
                "status": "bound",
            },
            {
                ".id": "*2",
                "address": "192.168.1.21",
                "mac-address": "AA:BB:CC:DD:EE:21",
                "host-name": "good-mac",
                "comment": "",
                "last-seen": "1m",
                "status": "bound",
            },
        ]

        api = MagicMock(return_value=iter(leases))
        plugin_objects = MagicMock()

        with patch.object(mikrotik, "connect", return_value=api):
            mikrotik.get_entries(plugin_objects)

        plugin_objects.add_object.assert_called_once()
        assert plugin_objects.add_object.call_args.kwargs["primaryId"] == "aa:bb:cc:dd:ee:21"
