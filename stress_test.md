# Pruebas de estrés — RNF3

## Herramientas

| Binario                       | Rol                                             |
| ----------------------------- | ----------------------------------------------- |
| `bin/server`                  | Proxy SOCKS5 bajo prueba                        |
| `bin/stress_client`           | Generador de carga (handshake + auth + CONNECT) |
| `bin/echo_backend`            | Destino TCP de eco detrás del proxy             |
| `scripts/run_stress_tests.sh` | Batería de conexiones + throughput              |

```bash
make stress
```

## Arquitectura

```
stress_client → bin/server (:1080) → echo_backend (:9999)
```

El proxy es lo que se mide. `echo_backend` simula un servidor de destino predecible (loopback).

## Entorno

- Docker: `docker compose run --rm dev`
- Credenciales: `socksuser:sockspass`, admin `admin:admin`
- Default `max_connections`: **1024**
- Máximo configurable: **2^14 = 16384** (`STORE_SESSIONS_CAP_MAX`), limitado por el selector (2 FDs por sesión en relay; la jump table admite fd &lt; 65536)

## Resultados

### ¿Cuál es la máxima cantidad de conexiones simultáneas?

| Escenario                                      |         N |    Éxitos | Fallos |      Tiempo |
| ---------------------------------------------- | --------: | --------: | -----: | ----------: |
| Default (`max_connections=1024`), barrido      |       500 |       500 |      0 |       8.4 s |
| `CONFIG max_connections 16384`, prueba al tope | **16384** | **16384** |  **0** | **266.6 s** |

**Conclusión:** el servidor cumple el requisito (≥ 500) y soportó **16.384 conexiones SOCKS simultáneas** (handshake + auth + CONNECT + túnel idle 1 s) con el cap configurado al máximo arquitectónico.

### ¿Cómo se degrada el throughput?

Modo `throughput`, 64 KiB por cliente (ping-pong 4 KiB para evitar deadlock en el túnel):

|   N | Agregado (MiB/s) | Por cliente (MiB/s) |
| --: | ---------------: | ------------------: |
|   1 |              3.0 |                 3.0 |
|  10 |             26.5 |                 2.6 |
| 100 |             94.8 |                0.95 |
| 500 |            117.5 |                0.24 |

El throughput agregado se estabiliza ~100–118 MiB/s; por cliente cae casi en proporción a N (servidor single-threaded con `epoll`).

## Reproducir el máximo (16.384)

```bash
docker compose run --rm dev bash -c '
  ulimit -n 65535 2>/dev/null || true
  make stress server -j4
  ./bin/echo_backend -p 9999 &
  ./bin/server -p 1080 -m 8080 -u socksuser:sockspass -a admin:admin &
  sleep 1
  exec 3<>/dev/tcp/127.0.0.1/8080
  while read -r l <&3; do [[ "$l" == "." ]] && break; done
  echo "AUTH admin admin" >&3
  while read -r l <&3; do [[ "$l" == "." ]] && break; done
  echo "CONFIG max_connections 16384" >&3
  while read -r l <&3; do echo "$l"; [[ "$l" == "." ]] && break; done
  exec 3<&-; exec 3>&-
  ./bin/stress_client -u socksuser:sockspass -d 127.0.0.1:9999 \
    -M connections -n 16384 -k 1
'
```

Éxito: `successes=16384 failures=0`.

## Batería completa (conexiones + throughput)

```bash
docker compose run --rm dev bash scripts/run_stress_tests.sh
```

## Limitaciones

- Loopback dentro del contenedor; destino es un eco simple.
- Pruebas de conexión usan túneles idle; con tráfico el máximo podría ser menor.
- Hace falta `ulimit -n` alto para pruebas &gt; 1024.
