# Ansible: relays on fixed hosts

Role `ferrum_relay` installs the pinned `ferrum` binary (the download must
match `ferrum_sha256`), the relay unit, and the mesh key and relay token as
systemd credentials. Use it for relays that aren't in an autoscaled pool:
anycast PoPs ([../anycast/](../anycast/)) or a standalone relay. Pool
instances configure themselves through cloud-init
([../autoscaling/](../autoscaling/)).

```sh
cp inventory.example.ini inventory.ini        # edit hosts and settings
ansible-vault create group_vars/ferrum_relays/vault.yml
#   ferrum_relay_mesh_key: "<head -c 32 /dev/urandom | base64>"
#   ferrum_relay_token: "<only if the coordinator uses OIDC>"
ansible-playbook -i inventory.ini relay.yml --ask-vault-pass
```

Settings and their defaults are in
[`roles/ferrum_relay/defaults/main.yml`](roles/ferrum_relay/defaults/main.yml).
A change restarts the relay, which drains first (up to
`ferrum_relay_drain_grace` seconds).

Checked in CI (the Deploy templates workflow): `--syntax-check`, and the unit
rendered with and without the optional settings passes `systemd-analyze
verify`. Not run against real hosts here.
