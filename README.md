# cask

Almacén content-addressable de solo-append en C, sin dependencias más allá
de libc. Formato binario propio con checksums CRC32 + SHA-256, deduplicación
por contenido y recuperación automática ante truncamiento o corrupción.

```
  [SUPER] -> [ OBJ1 | size | sha256 | crc32 | payload ]+ 
```

## Qué hace

- **`cask init <store>`** crea un almacén nuevo (`CASKCASK` v1).
- **`cask put <store> <file...>`** añade archivos deduplicados por su hash
  SHA-256; si el contenido ya existe, no se vuelve a escribir.
- **`cask get <store> <hash>`** extrae un objeto por su clave.
- **`cask has <store> <hash>`** comprueba existencia.
- **`cask verify <store>`** recorre todos los registros validando estructura,
  CRC32 y SHA-256 de cada payload.
- **`cask recover <store>`** recorta el archivo a la última escritura íntegra
  y reescribe el superbloque (recuperación ante truncamiento/corrupción).
- **`cask dump`** / **`cask info`** listan objetos o el estado del almacén.

## Arquitectura

- `src/crc32.{h,c}` — checksum polinómico estándar (0xEDB88320).
- `src/sha256.{h,c}` — hash SHA-256 FIPS 180-4, implementación a mano.
- `src/store.{h,c}` — formato binario y operaciones del almacén.
- `src/main.c` — interfaz de línea de comandos.
- `tests/run_tests.c` — suite de pruebas sin dependencias (`make test`).

## Formato (v1)

Superbloque (64 bytes al inicio):

| off | campo |
|-----|-------|
| 0   | magic `CASKCASK` (8B) |
| 8   | version u16 `1` |
| 10  | flags u16 |
| 12  | count u64 (objetos confirmados) |
| 20  | tail u64 (offsets donde se escribe el próximo append) |
| 28  | reservado (32B) |
| 60  | crc32 u32 del superbloque (cover de [0,60)) |

Registro de objeto (cabecera 52B + payload):

| off | campo |
|-----|-------|
| 0   | magic `OBJ1` u32 |
| 4   | flags u16 |
| 6   | reservado u16 |
| 8   | size u64 |
| 16  | key[32] = SHA-256(payload) |
| 48  | crc32 u32 del payload |
| 52  | payload |

Confirmación en dos fases: el payload se escribe y se hace `fsync` antes de
actualizar `count`/`tail` en el superbloque (también con `fsync`). Si hay un
corte a mitad de escritura, al reabrir el almacén se recorta a `tail` y el
apéndice parcial queda descartado; ante truncamiento físico o corrupción,
`cask recover` vuelve a la última escritura íntegra.

## Requisitos

- compilador C11 (gcc/clang), POSIX (`fsync`, `ftruncate`).

## Uso

```
$ make
$ ./cask init demo.cask
$ ./cask put demo.cask hola.txt mundo.txt
added   e3b0...
skipped e3b0...   (contenido ya presente)
$ ./cask has demo.cask <hash>
yes
$ ./cask get demo.cask <hash> -o salida.txt
$ ./cask verify demo.cask
ok: 2 objects, all checksums valid
$ ./cask info demo.cask
```

## Testing

```
$ make test
$ ./tests/run_tests tiny:/tmp/cask-test.cask    # (opcional size del blob)
```

Vectores conocidos comprobados: `crc32("123456789")==0xCBF43926`,
`sha256("abc")==ba7816bf...`, más roundtrip, dedup, corrupción y
truncamiento simulados.

## Limitaciones

- Sin borrado ni GC: el formato es solo-reserva definitiva por diseño
  (append-only). El `count` cuenta objetos únicos; la dedup no usa
  refcounts. Las búsquedas `has/get` son O(n) lineales.
- La integridad CRC32 detecta corrupción accidental, no males adversarios.
  El SHA-256 actúa como segunda comprobación y clave del objeto.

## Licencia

MIT — ver `LICENSE`.