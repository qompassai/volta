# Volta
![Repository Views](https://komarev.com/ghpvc/?username=qompassai-volta)
Volta is a verifying OpenPGP key server.

## Quick Start

Building Volta requires a working stable Rust toolchain.
The easiest way to get the toolchain is to download [rustup](https://rustup.rs).

Additionally, some external dependencies are required.
Get them (on Debian or Ubuntu) with

```bash
sudo apt install gnutls-bin nettle-dev gcc llvm-dev libclang-dev build-essential pkg-config gettext
```

After Rust and the other dependencies are installed, copy the config file, then simply compile and run:

```bash
cd volta
cp Rocket.toml.dist Rocket.toml
cargo run
```

This will spawn a web server listening on port 8080.

For deployment, a release build should be used (`cargo build --release`). This
will be statically built, and can be copied anywhere. You will also need to
adjust `Rocket.toml` accordingly. Volta uses `sendmail` for mailing, so you
also need a working local mailer setup.

## Reverse Proxy

Volta is designed to defer lookups to reverse proxy server like Nginx.
Lookups via `/vks/v1/by-finingerprint`, `/vks/v1/by-keyid`, and
`/vks/v1/by-email` can be handled by a robust and performant HTTP server.
A sample configuration for nginx is part of the repository (`nginx.conf`,
`volta-routes.conf`).
Note that we make use of
[ngx_http_lua_module](https://github.com/openresty/lua-nginx-module) to
perform some request rewrites.

