# Development

## Test / lab

Two layers, both under [`test/`](../test/) with their own [README](../test/README.md): a
dependency-free **unit suite** over the logic that decides security (every case is a
refusal - the part an end-to-end run never reaches), and **eight end-to-end suites**
against a Vagrant OPNsense VM with Authentik and Keycloak in Docker, driving real browser
ceremonies and a real OpenVPN client.

```sh
php test/unit/run.php                                       # ~590 assertions, no setup
cd test && vagrant up && (cd idp && ./up.sh)                # bring the lab up
SSO_GUI_URL=https://192.168.60.10 test/e2e/run-all.sh       # ~175 checks, either IdP
```

## Translations

OPNsense has a single gettext domain (`OPNsense`, bound to `/usr/local/share/locale`) and
its catalogues live in [opnsense/lang](https://github.com/opnsense/lang), built from the
core and plugin sources - so a plugin ships no catalogue of its own, it ships translatable
strings. What that needs from this repository is that every user-facing string goes through
`gettext()` (PHP) or `lang._()` (Volt), which is what [`lang/os-sso.pot`](../lang/os-sso.pot)
makes checkable:

```sh
sh tools/extract-strings.sh    # rewrites lang/os-sso.pot (needs gettext-tools)
```

Anything user-facing that is missing from the template is a string somebody forgot to
wrap. Model and form XML (field labels and help) is translated by the WebGUI renderer at
display time and cannot be extracted by `xgettext` - core has the same gap.
