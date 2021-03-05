# an2linuxserver-rs

Sync Android notifications to a Linux (and more!) desktop, inspired by https://github.com/rootkiwi/an2linuxserver

This is re-implementation of the server part of AN2Linux.

The Android app can be found here: https://github.com/rootkiwi/an2linuxclient

## Features and TODOs

- [x] Display notifications with [notify-rust](https://github.com/hoodie/notify-rust)
  - [x] Linux support with [zbus](https://gitlab.freedesktop.org/dbus/zbus)
  - [ ] Mac support (Need testing)
  - [ ] Windows support (Need testing)
- [x] TLS server
- [ ] Bluetooth server
- [ ] Message filtering
- [ ] User-friendly error and warning messages
- [ ] Unit and integration tests

## Usage

### Generating Certificate

You have to generate certificate and private key with `openssl`, without DES.

```sh
$ mkdir -p ~/.config/an2linux_rs/ 
$ cd ~/.config/an2linux_rs/
$ openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout rsakey.pem -out certificate.pem -days 365
```

### Pairing with Android device

Run the server in pairing mode with:

```sh
$ cargo run -- pair
```

And pair with Android device using [an2linuxclient app](https://github.com/rootkiwi/an2linuxclient).

### Running the notification server

```sh
$ cargo run
```

## License

_an2linuxserver-rs_ is distributed under the terms of [GNU General Public License 3](https://www.gnu.org/licenses/gpl-3.0.html).

_an2linuxserver-rs_ is re-implementation of [rootkiwi/an2linuxserver](https://github.com/rootkiwi/an2linuxserver).

See [LICENSE](LICENSE) for more details.
