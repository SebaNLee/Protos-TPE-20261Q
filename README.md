# ChungusMonitor - Protos-TPE-20261Q

SOCKS5 proxy server in C (c11) following RFC 1928. Built-in custom protocol for monitoring and managing the server.

Repo named after the monitor protocol because it is cooler. The proxy is the real work, just doesn't have a cool name anyways. 

## Run the project

### WSL

Install build tools and test library:

```bash
sudo apt-get install -y make check pkg-config
```

Build:

```bash
make all
```

Run the proxy (SOCKS5 on :1080, monitor on :8080):

```bash
./bin/server -u user:pass -a admin:pass
```

Run TUI in another terminal:

```bash
./bin/client
```

For stress testing, see `doc/stress_test.md`:

```bash
make stress
./bin/stress_client -u user:pass -d 127.0.0.1:9999 -n 500 -M connections
```

### Docker usage (macOS)

```bash
# Init build
docker compose build
docker compose up -d
docker compose exec dev bash

# Inside the container, same stuff
make all
./bin/server -u user:user -a admin:admin
./bin/client

# When done
docker compose down
```


## Monitor Client (TUI)

Cursor-based (not the AI) TUI, just execute the binary:

```
# connect to 127.0.0.1:8080
./bin/client

# or custom monitor port
./bin/client -p 9090
```

> Login: username + password

> Navigation: `↑` `↓` to move, `Enter` to select, `q` to go back / quit


| Menu                | Description                                        |
|---------------------|----------------------------------------------------|
| `Stats`             | Proxy metrics (bytes in/out, session count)        |
| `Active connections`| Live SOCKS sessions (src IP → dst IP)              |
| `Registered users`  | All configured users                               |
| `Configuration`     | Tune `timeout`, `max_connections`, `io_buffer_size`|
| `Add user`          | Create a new user                                  |
| `Delete user`       | Remove an existing user                            |
| `Change password`   | Update a user   password                           |
| `Access log`        | Connection history (user, host, duration, status)  |
| `Quit`              | Disconnect and exit                                |

> Note: All server responses finish with a `.\n` which marks the end of the REPL message (you don't see this on the client tho)

## Binaries reference

### `bin/server` — SOCKS5 proxy + monitor server

```
Usage: ./bin/server [-p socks_port] [-m monitor_port] -u <user>:<pass> -a <admin>:<pass>
    -p  SOCKS5 port (default 1080)
    -m  Monitor port (default 8080)
    -u  Add SOCKS user:password pair (required, repeatable)
    -a  Add admin user:password pair (required, repeatable)
```

> Note: Admin users have access to the monitor TUI

### `bin/client` — Monitor TUI (ChungusMonitor)

```
Usage: ./bin/client [-p port]
    -p  Monitor port (default 8080)
```

## Repo layout

| The thing         | Lives in                                    |
|-------------------|---------------------------------------------|
| Source code       | `src/server/`, `src/client/`, `src/shared/` |
| Build system      | `makefile` + `makefile.inc`                 |
| Docs              | `doc/`                                      |
| Scripts           | `scripts/`                                  |

### Generated content:

| Location   | Contents             |
|------------|----------------------|
| `bin/`     | Executables          |
| `obj/`     | Object files         |
| `build/`   | Test binaries        |

## Devs

### pre-commit

There is a pre-commit hook that uses Clang when committing for code formatting. Should be installed with:

```
pre-commit install
```

### socks5 usage example

```
curl --socks5 admin:admin@localhost:1080 http://google.com
```

PD: este readme fue escrito a mano ;)
