# Ascon coursework: benchmarks and rejection tests

Host and Arduino measurements of Ascon-AEAD128 and Ascon-Hash256 (from
[ascon-c](https://github.com/ascon/ascon-c), pinned commit
`446347f21b209f3921c65ece70027c366cbe1693`, bundled as `ascon-c.zip`), with
AES-128-GCM and ChaCha20-Poly1305 from OpenSSL as comparators.

## What's here

| File | What it does |
|---|---|
| `benchmark_harness_aead.c` | Times Ascon-AEAD128 encrypt/decrypt at 1 B to 16 KiB, 7 trials, min and median ns/byte |
| `benchmark_harness_hash.c` | Same for Ascon-Hash256 |
| `benchmark_harness_competitor_aead.c` | Same message sizes for AES-128-GCM and ChaCha20-Poly1305 via OpenSSL EVP |
| `aead_negative_tests.c` | Checks that tampered ciphertext, tag, AD, nonce and key are all rejected |
| `run_arduino_avr_tests.py` | Builds, uploads and collects results on the Mega 2560 (AVR) |
| `run_arduino_dwt_tests.py` | Same for Cortex-M boards (Nano 33 BLE, UNO R4) using the DWT cycle counter |
| `host_results.csv`, `arduino_results.csv` | Every result CSV merged into one file, one row per source line |
| `ascon_csvs_all.zip` | The individual result CSVs |
| `build_version_commands.txt` | Tool versions and the exact build commands used |

## Running the host benchmarks

Needs clang (or gcc) and OpenSSL 3.

```sh
make run              # builds against ascon-c opt64, writes results/*.csv
make run IMPL=ref     # or any other ascon-c implementation folder
```
