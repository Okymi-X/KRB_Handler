<p align="center">
  <img src="caramelo.jpeg" alt="Caramelo Storm" width="160">
</p>

<h1 align="center">KRB_Handler</h1>

<p align="center">
  <strong>Prepare a Linux host for Kerberos authentication against Active Directory.</strong><br>
  Discover the realm, domain controller hostname, host mappings, and clock skew,
  then manage the required system configuration as a reusable profile.
</p>

<p align="center">
  Created by <strong>Rafael Raugi (Avocado)</strong> of <strong>Caramelo Storm</strong><br>
  <a href="https://www.linkedin.com/in/rafael-raugi/">LinkedIn</a> ·
  <a href="https://www.youtube.com/@avocado-shell">YouTube</a>
</p>

## Why this exists

Kerberos tools often fail for environmental reasons rather than bad credentials:
the realm has no KDC mapping, the domain controller is addressed by IP instead of
its service-principal hostname, DNS cannot resolve the DC, or the local clock is too
far from the KDC.

KRB_Handler handles that setup in one command:

```bash
krb-handler set 10.10.11.42
```

It can update `/etc/krb5.conf`, maintain a clearly delimited block in `/etc/hosts`,
and align the local clock with the KDC. The discovered environment is saved as a
profile, making it easy to switch between authorized labs or client environments.

KRB_Handler is configuration tooling. It does not request credentials, obtain
tickets, execute Impacket, exploit a target, or authenticate to Active Directory.

## Features

- Credential-free discovery through an anonymous SMB2/NTLM challenge.
- LDAP rootDSE, NTP, and reverse-DNS fallbacks when SMB data is incomplete.
- Reusable profiles for separate environments and multi-realm forests.
- Longest-suffix realm mapping for parent and child domains.
- Automatic, root-owned backups of files managed by the tool.
- Atomic writes and strict validation before profile data reaches system files.
- Automatic privilege elevation only for operations that change system state.
- `--dry-run` previews generated configuration without requiring root.
- `NO_COLOR` support and clean output when redirected to a file or pipe.
- Python standard library only; no runtime dependencies.

## Installation

Python 3.10 or newer and Linux are required. Install the command in an isolated
environment with [pipx](https://pipx.pypa.io/):

```bash
git clone https://github.com/Okymi-X/KRB_Handler.git
cd KRB_Handler
pipx install .
pipx ensurepath
krb-handler --version
```

To reinstall after updating the checkout:

```bash
git pull --ff-only
pipx reinstall krb-handler
```

The script can also be run directly:

```bash
python3 KRB_Handler.py --help
```

## Quick start

Preview the changes first:

```bash
krb-handler set 10.10.11.42 --dry-run
```

Create and apply a profile:

```bash
krb-handler set 10.10.11.42 --profile htb --desc "Authorized HTB lab"
```

Inspect the resulting state:

```bash
krb-handler status
krb-handler check
krb-handler show htb
```

Restore the original system configuration when finished:

```bash
krb-handler restore
```

## Commands

| Command | Purpose |
|---|---|
| `set <target>` | Discover a target, create or update a profile, and apply it |
| `add <target>` | Add another realm or trusted domain to a profile |
| `use <profile>` | Apply a saved profile |
| `list` | List profiles and identify the active one |
| `show [profile]` | Print the generated Kerberos and hosts configuration |
| `status` | Show active realm, managed hosts, NTP state, and KDC skew |
| `check [target]` | Check DNS, ports, realm identity, and clock skew |
| `clock [target]` | Synchronize the clock with a KDC |
| `hosts <ip> <fqdn> [alias ...]` | Add a managed host entry |
| `rename <old> <new>` | Rename a profile |
| `del <profile>` | Delete a profile without changing system files |
| `restore` | Restore original files and automatic NTP state |

Use `krb-handler help <command>` or `krb-handler <command> --help` for focused help.

### Discovery and apply options

| Option | Purpose |
|---|---|
| `--realm CORP.LOCAL` | Override realm discovery |
| `--dc dc01.corp.local` | Override domain controller hostname discovery |
| `--profile NAME` | Select the profile name |
| `--desc TEXT` | Set a profile description |
| `--no-clock` | Do not adjust the system clock |
| `--no-hosts` | Do not update `/etc/hosts` |
| `--faketime` | Create a wrapper using `faketime` instead of changing the clock |
| `--weak` | Enable legacy RC4 compatibility for old lab domains |
| `--dry-run` | Preview generated configuration without changing state |

Options accept both `--name value` and `--name=value` forms.

## How discovery works

The primary probe opens TCP port 445 and performs an SMB2 negotiation followed by
an anonymous NTLMSSP negotiation. It stops at the challenge and does not
authenticate. The responses can provide:

- the server clock from SMB2 `SystemTime`;
- the DNS domain and forest;
- the domain controller FQDN;
- NetBIOS domain and computer names.

When SMB is unavailable or incomplete, KRB_Handler tries anonymous LDAP rootDSE on
TCP 389, NTP on UDP 123, and reverse DNS. Discovery can always be overridden with
`--realm` and `--dc`:

```bash
krb-handler set 10.10.11.42 \
  --realm CORP.LOCAL \
  --dc dc01.corp.local
```

## Multi-realm profiles

A profile can contain a forest root, child domains, and trusted realms:

```bash
krb-handler set 192.168.56.10 --profile lab
krb-handler add 192.168.56.11
krb-handler add 192.168.56.12
```

Each realm receives its own KDC definition. Host mappings use the longest matching
DNS suffix so that a child-domain host is not accidentally sent to its parent KDC.

## Files and state

User-owned profile data is stored under:

```text
~/.krb-profiles/
├── active
├── faketime.sh
└── profiles/
    └── <name>.json
```

Privileged state and original backups are root-owned:

```text
/var/lib/krb-handler/
├── state.json
└── backup/
    ├── krb5.conf.orig
    └── hosts.orig
```

Only the block between `# >>> KRB_Handler` and `# <<< KRB_Handler` is managed in
`/etc/hosts`. Malformed or duplicate marker blocks are rejected instead of being
rewritten. Original backups are created once and are not replaced on later runs.

## Clock handling

Kerberos normally rejects authentication when clock skew exceeds the configured
limit. Before setting the clock, KRB_Handler records whether automatic NTP was
enabled and disables it so that the adjustment is not immediately reverted.
`restore` re-enables NTP only when KRB_Handler disabled it.

If a clock adjustment fails after NTP was disabled, the tool attempts to re-enable
NTP immediately. Use `--faketime` when changing the host clock is undesirable; this
requires the optional `faketime` executable.

## Troubleshooting

### Discovery fails

Confirm that the target is reachable and try explicit values:

```bash
krb-handler check 10.10.11.42
krb-handler set 10.10.11.42 --realm CORP.LOCAL --dc dc01.corp.local
```

### `Server not found in Kerberos database`

Use the DC FQDN expected by its service principal, not its IP address. Inspect the
generated host mapping with `krb-handler show`.

### `Clock skew too great`

Check the measured offset, then synchronize or use a wrapper:

```bash
krb-handler status
krb-handler clock
krb-handler clock --faketime
```

### Legacy encryption errors

Use `--weak` only for an old, authorized lab that requires RC4. It weakens the
generated Kerberos client policy and should not be the default.

## Development

Run the test suite and syntax check with the standard library:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile KRB_Handler.py
```

## Authorized use

This tool changes system authentication configuration and the local clock. Use it
only on systems you own or in environments covered by explicit written
authorization. Review `--dry-run` output before applying an unfamiliar profile.

## License

[MIT](LICENSE). The additional notice in the license describes the intended
authorized-security use of the project.
