import json
import stat
import struct
import tempfile
import unittest
from pathlib import Path
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

    def test_auto_elevation_does_not_preserve_full_environment(self):
        with (
            mock.patch.object(krb.sys, "argv", ["krb-handler", "hosts", "10.0.0.1", "dc.lab.local"]),
            mock.patch.object(krb.os, "geteuid", return_value=1000),
            mock.patch.object(krb.shutil, "which", return_value="/usr/bin/sudo"),
            mock.patch.object(krb.os, "execv", side_effect=SystemExit) as execv,
        ):
            with self.assertRaises(SystemExit):
                krb.main()
        argv = execv.call_args.args[1]
        self.assertNotIn("-E", argv)
        self.assertEqual(argv[:2], ["/usr/bin/sudo", "--"])


if __name__ == "__main__":
    unittest.main()
