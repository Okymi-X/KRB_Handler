import io
import json
import stat
import struct
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import KRB_Handler as krb


def sample_profile():
    profile = krb.new_profile("lab", "Authorized lab")
    krb.merge_target(
        profile,
        {
            "realm": "CORP.LOCAL",
            "domain": "corp.local",
            "fqdn": "dc01.corp.local",
            "ip": "10.10.10.10",
            "netbios_domain": "CORP",
            "forest": "corp.local",
        },
    )
    return profile


class ValidationTests(unittest.TestCase):
    def test_profile_name_rejects_path_and_control_characters(self):
        for value in ("../lab", ".hidden", "a/b", "bad\nname", "", "a" * 65):
            with self.subTest(value=value):
                self.assertFalse(krb.valid_name(value))
        self.assertTrue(krb.valid_name("corp-lab_01.prod"))

    def test_domain_and_endpoint_validation(self):
        self.assertTrue(krb.valid_dns_name("dc01.corp.local"))
        self.assertTrue(krb.valid_endpoint("2001:db8::10"))
        self.assertFalse(krb.valid_dns_name("dc01.corp.local\nadmin_server = evil"))
        self.assertFalse(krb.valid_endpoint("host name"))

    def test_profile_rejects_config_injection(self):
        profile = sample_profile()
        profile["realms"]["CORP.LOCAL"]["kdc"][0] = "dc01.corp.local\ninclude /tmp/evil"
        with self.assertRaises(ValueError):
            krb.validate_profile(profile)

    def test_profile_rejects_realm_without_kdc(self):
        profile = sample_profile()
        profile["realms"]["CORP.LOCAL"]["kdc"] = []
        with self.assertRaises(ValueError):
            krb.validate_profile(profile)

    def test_profile_is_normalized_before_rendering(self):
        profile = sample_profile()
        rendered = krb.render_krb5(profile)
        hosts = krb.render_hosts_block(profile)
        self.assertIn("default_realm = CORP.LOCAL", rendered)
        self.assertIn("kdc = dc01.corp.local", rendered)
        self.assertIn("10.10.10.10\tdc01.corp.local", hosts)

    def test_default_realm_is_used_as_clock_source(self):
        profile = sample_profile()
        krb.merge_target(
            profile,
            {
                "realm": "CHILD.CORP.LOCAL",
                "domain": "child.corp.local",
                "fqdn": "dc01.child.corp.local",
                "ip": "10.10.10.20",
            },
        )
        self.assertEqual(krb.profile_clock_host(profile), "10.10.10.20")


class ParserTests(unittest.TestCase):
    def test_malformed_ber_is_ignored(self):
        malformed = b"\x30\x84\xff"
        self.assertEqual(krb._parse_rootdse(malformed), {})

    def test_oversized_smb_frame_is_rejected(self):
        class FakeSocket:
            def __init__(self):
                self.parts = [struct.pack(">I", krb.MAX_SMB_FRAME + 1)]

            def recv(self, _size):
                return self.parts.pop(0) if self.parts else b""

        self.assertEqual(krb._smb_recv(FakeSocket()), b"")

    def test_ntp_response_is_validated_and_parsed(self):
        packet = bytearray(48)
        packet[0] = 0x24  # NTP version 4, server mode
        packet[1] = 2
        struct.pack_into("!II", packet, 40, 1_700_000_000 + 2_208_988_800, 0)
        self.assertEqual(krb._parse_ntp_time(packet, now=1_700_000_000), 1_700_000_000)
        packet[0] = 0x23  # client mode is not a valid server response
        self.assertIsNone(krb._parse_ntp_time(packet, now=1_700_000_000))


class StorageTests(unittest.TestCase):
    def test_profile_write_is_atomic_private_and_round_trips(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            with mock.patch.multiple(
                krb,
                BASE=base,
                PROF_DIR=base / "profiles",
                ACTIVE_F=base / "active",
            ):
                krb.PROF_DIR.mkdir()
                krb.save_profile(sample_profile())
                krb.set_active("lab")
                self.assertEqual(krb.load_profile("lab")["default_realm"], "CORP.LOCAL")
                self.assertEqual(krb.active_profile(), "lab")
                mode = stat.S_IMODE((krb.PROF_DIR / "lab.json").stat().st_mode)
                self.assertEqual(mode, 0o600)
                self.assertEqual(json.loads((krb.PROF_DIR / "lab.json").read_text())["name"], "lab")

    def test_system_write_is_atomic_and_public_readable(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "krb5.conf"
            krb.write_system_text(target, "[libdefaults]\n", mode=0o644)
            self.assertEqual(target.read_text(encoding="utf-8"), "[libdefaults]\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_state_file_is_private(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "state.json"
            with (
                mock.patch.object(krb, "STATE_F", target),
                mock.patch.object(krb, "ensure_system_storage"),
            ):
                krb.write_state({"ntp_was_on": True})
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_invalid_profile_is_reported_instead_of_treated_as_missing(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            profiles = base / "profiles"
            profiles.mkdir()
            (profiles / "lab.json").write_text("{not json}\n", encoding="utf-8")
            with (
                mock.patch.multiple(
                    krb,
                    BASE=base,
                    PROF_DIR=profiles,
                    ACTIVE_F=base / "active",
                ),
                self.assertRaisesRegex(ValueError, "profile 'lab' is invalid"),
            ):
                krb.load_profile("lab")

    def test_hosts_block_is_removed_without_touching_surrounding_content(self):
        content = (
            "127.0.0.1 localhost\n"
            "# >>> KRB_Handler: lab\n"
            "10.0.0.1 dc.lab.local\n"
            "# <<< KRB_Handler\n"
            "192.0.2.1 keep.example\n"
        )
        self.assertEqual(
            krb.remove_hosts_block(content),
            "127.0.0.1 localhost\n192.0.2.1 keep.example\n",
        )

    def test_malformed_hosts_markers_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "malformed KRB_Handler marker block"):
            krb.remove_hosts_block("127.0.0.1 localhost\n# >>> KRB_Handler: lab\n")

    def test_auto_elevation_does_not_preserve_full_environment(self):
        with (
            mock.patch.object(krb.sys, "argv", ["krb-handler", "hosts", "10.0.0.1", "dc.lab.local"]),
            mock.patch.object(krb.os, "geteuid", return_value=1000),
            mock.patch.object(krb.shutil, "which", return_value="/usr/bin/sudo"),
            mock.patch.object(krb.os, "execv", side_effect=SystemExit) as execv,
            self.assertRaises(SystemExit),
        ):
            krb.main()
        argv = execv.call_args.args[1]
        self.assertNotIn("-E", argv)
        self.assertEqual(argv[:2], ["/usr/bin/sudo", "--"])


class CommandLineTests(unittest.TestCase):
    def test_parser_accepts_equals_syntax(self):
        pos, opts = krb.parse_args(
            ["10.0.0.1", "--realm=CORP.LOCAL", "--dry-run"],
            krb.SET_BOOL_FLAGS,
            krb.SET_VALUE_FLAGS,
        )
        self.assertEqual(pos, ["10.0.0.1"])
        self.assertEqual(opts, {"realm": "CORP.LOCAL", "dry-run": True})

    def test_parser_rejects_options_not_supported_by_command(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            krb.parse_args(["--weak"], krb.USE_BOOL_FLAGS)

    def test_command_help_never_elevates_or_initializes_state(self):
        with (
            mock.patch.object(krb.sys, "argv", ["krb-handler", "set", "--help"]),
            mock.patch.object(krb.os, "geteuid", return_value=1000),
            mock.patch.object(krb.os, "execv") as execv,
            mock.patch.object(krb, "init_paths") as init_paths,
            redirect_stdout(io.StringIO()) as output,
        ):
            krb.main()
        self.assertIn("usage: krb-handler set", output.getvalue())
        execv.assert_not_called()
        init_paths.assert_not_called()

    def test_dry_run_does_not_elevate(self):
        handler = mock.Mock()
        with (
            mock.patch.object(krb.sys, "argv", ["krb-handler", "set", "target", "--dry-run"]),
            mock.patch.object(krb.os, "geteuid", return_value=1000),
            mock.patch.object(krb.os, "execv") as execv,
            mock.patch.object(krb, "init_paths") as init_paths,
            mock.patch.dict(krb.COMMANDS, {"set": handler}),
        ):
            krb.main()
        execv.assert_not_called()
        init_paths.assert_called_once_with(create=False)
        handler.assert_called_once_with(["target", "--dry-run"])

    def test_apply_profile_dry_run_performs_no_writes(self):
        profile = sample_profile()
        with (
            mock.patch.object(krb, "write_krb5") as write_krb5,
            mock.patch.object(krb, "write_hosts") as write_hosts,
            mock.patch.object(krb, "save_profile") as save_profile,
            mock.patch.object(krb, "set_active") as set_active,
            mock.patch.object(krb, "sync_clock") as sync_clock,
            redirect_stdout(io.StringIO()) as output,
        ):
            changed = krb.apply_profile(
                profile,
                {"dry-run": True},
                "dc01.corp.local",
                time.time() + 300,
            )
        self.assertFalse(changed)
        self.assertIn("/etc/krb5.conf (preview)", output.getvalue())
        for operation in (write_krb5, write_hosts, save_profile, set_active, sync_clock):
            operation.assert_not_called()


class ClockTests(unittest.TestCase):
    def test_invalid_clock_value_is_never_applied(self):
        with (
            mock.patch.object(krb.subprocess, "run") as run,
            redirect_stderr(io.StringIO()),
        ):
            self.assertFalse(krb.sync_clock(0, "dc01.corp.local"))
        run.assert_not_called()

    def test_failed_clock_change_reenables_ntp(self):
        state_writes = []
        with (
            mock.patch.object(krb.time, "time", return_value=1_700_000_000),
            mock.patch.object(krb, "ntp_enabled", return_value=True),
            mock.patch.object(krb, "set_ntp", side_effect=[True, True]) as set_ntp,
            mock.patch.object(krb, "read_state", return_value={}),
            mock.patch.object(krb, "write_state", side_effect=lambda value: state_writes.append(dict(value))),
            mock.patch.object(
                krb.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=1, stderr="permission denied"),
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            self.assertFalse(krb.sync_clock(1_700_000_300, "dc01.corp.local"))
        self.assertEqual(set_ntp.call_args_list, [mock.call(False), mock.call(True)])
        self.assertEqual(state_writes, [{"ntp_was_on": True}, {}])


if __name__ == "__main__":
    unittest.main()
