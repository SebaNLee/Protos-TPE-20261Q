# Protos-TPE-20261Q

TODO

## Run the project

### WSL

Install `make` and Check test library:

```bash
sudo apt-get install -y make check pkg-config
```

From the repo root:

```bash
make clean test check
```

`make check` builds every test under `build/` and runs them. To run one test:

```bash
./build/selector_test
```

When `src/server/` and `src/client/` exist:

```bash
make all
./bin/server    
./bin/client    
```

### Docker usage (macOS)

Setup:

```bash
# Build image
docker compose build

# Start dev container in bg and expose ports
docker compose up -d

# Start dev container
docker compose exec dev bash
```

Inside the container:

```bash
# Build and run all tests
make clean test check

# Run a single test
./build/<test>

# Run server (check port mapping on docker-compose.yaml)
./bin/server -u user:user -a admin:admin

# Run client
./bin/client
```

When done:

```bash
docker compose down
```

## Makefile targets


| Target       | Description                                                                    |
| ------------ | ------------------------------------------------------------------------------ |
| `make all`   | Build `bin/server` and `bin/client` (when `src/server/` / `src/client/` exist) |
| `make test`  | Build tests into `build/`                                                      |
| `make check` | Build and run all tests                                                        |
| `make clean` | Remove `obj/`, `bin/`, `build/`                                                |


## Monitor REPL (monitor and manage client)

Auth:

```
+OK ChugusMonitor v1.0
AUTH admin admin
```

Available commands (post-auth):

| Command | Description |
|---------|-------------|
| `STATS` | proxy metrics |
| `CONNECTIONS` | active SOCKS sessions |
| `USERS` | saved users |
| `CONFIG <param> <value>` | runtime configs (`timeout`, `max_connections`, `io_buffer_size`) |
| `ACCESS_LOG [username]` | connection logs |
| `ADD_USER <user> <pass> [admin]` | create new user |
| `DEL_USER <user>` | delete user |
| `SET_PASSWORD <user> <newpass>` | change user password |
| `HELP [command]` | show help |
| `QUIT` | close connection |

> Note: All server responses finish with a `.\n` which marks the end of the REPL message.

> Note: HELP is available before auth too.

## Devs

### pre-commit

There is a pre-commit hook that uses Clang when committing for code formatting. Should be installed with:

```
pre-commit install
```

### socks5 usage example (current impl)

`
curl --socks5 admin:admin@localhost:1080 http://google.com
`