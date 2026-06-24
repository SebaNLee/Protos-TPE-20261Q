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

### macOS

Using docker. 

Image build:

```bash
docker compose build
```

Build and run tests:

```bash
docker compose run --rm dev make clean test check
```

Run a single test:

```bash
docker compose run --rm dev ./build/selector_test
```

## Makefile targets


| Target       | Description                                                                    |
| ------------ | ------------------------------------------------------------------------------ |
| `make all`   | Build `bin/server` and `bin/client` (when `src/server/` / `src/client/` exist) |
| `make test`  | Build tests into `build/`                                                      |
| `make check` | Build and run all tests                                                        |
| `make clean` | Remove `obj/`, `bin/`, `build/`                                                |


## Devs

### pre-commit

There is a pre-commit hook that uses Clang when committing for code formatting. Should be installed with:

```
pre-commit install
```
