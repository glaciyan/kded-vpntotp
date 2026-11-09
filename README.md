# kded-vpntotp

A kded6 module (KDE background service) that acts as a NetworkManager secret agent.
When a VPN connection asks for its password, it answers with
`<stored password><current 6-digit TOTP code>`, so connecting from the Plasma
network applet, autoconnect, and reconnects need no typing.

## Secrets

Stored in the network wallet (`kdewallet`), folder **VPN TOTP**, one pair per connection:

| Entry | Value |
|---|---|
| `<connection-uuid>;password` | static password |
| `<connection-uuid>;totp` | base32 TOTP secret (SHA1 / 6 digits / 30 s) |

Get the UUID with `nmcli -g connection.uuid connection show "<name>"`.
Edit the entries in KWalletManager.

Connections without both entries are ignored and fall through to Plasma's normal
password dialog. So does a retry after a rejected password, so a wrong secret
can't cause a reconnect loop.

The connection's password must be set to "ask every time" (`password-flags=2`).

## Build and install (Arch)

```
cd packaging/arch && makepkg -f
sudo pacman -U kded-vpntotp-*.pkg.tar.zst
qdbus6 org.kde.kded6 /kded loadModule vpntotp   # or log out and back in
```

It's listed in System Settings → Background Services as "VPN TOTP Autofill".
Log category: `kded.vpntotp` (`journalctl --user -b | grep -i totp`).
