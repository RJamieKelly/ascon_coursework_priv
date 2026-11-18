from __future__ import annotations

import csv
import os
import re
import select
import shutil
import subprocess
import termios
import time
from pathlib import Path


ROOT = Path(os.environ.get("ASCON_AVR_ROOT", str(Path(__file__).resolve().parent)))
ASCON = Path(os.environ.get("ASCON_AVR_ASCON_DIR", str(ROOT / "ascon-c")))
RUN = Path(os.environ.get("ASCON_AVR_RUN_DIR", str(ROOT / "arduino_mega2560_avr_board_run_20260503")))
PORT = os.environ.get("ASCON_AVR_PORT", "/dev/cu.usbmodem2101")
FQBN = os.environ.get("ASCON_AVR_FQBN", "arduino:avr:mega")
BOARD_LABEL = os.environ.get("ASCON_AVR_BOARD_LABEL", "Arduino Mega 2560 R3")
CORE_NOTE = os.environ.get("ASCON_AVR_CORE_NOTE", "Arduino AVR core")
CPU_HZ = int(os.environ.get("ASCON_AVR_CPU_HZ", "16000000"))
MESSAGE_LENGTHS = [
    int(item.strip())
    for item in os.environ.get("ASCON_AVR_LENGTHS", "16,64,256,1024").split(",")
    if item.strip()
]
MAX_LEN = max(MESSAGE_LENGTHS)
SIZE_TOOL = Path(
    os.environ.get(
        "ASCON_AVR_SIZE_TOOL",
        str(Path.home()) + "/Library/Arduino15/packages/arduino/tools/"
        "avr-gcc/7.3.0-atmel3.6.1-arduino7/bin/avr-size",
    )
)

AEAD_VARIANTS = ["ref", "avr", "avr_lowsize"]
HASH_VARIANTS = ["ref", "avr", "avr_lowsize"]


AEAD_TEMPLATE = r'''/*
  AVR Arduino board test harness for Ascon-AEAD128.
  Serial output contains CSV blocks for KAT, rejection tests, and timing.
*/

#include <Arduino.h>
#include <math.h>
#include <string.h>

extern "C" {
#include "api.h"
#include "crypto_aead.h"
}

#define IMPLEMENTATION_NAME "__IMPL__"
#define NUM_LENGTHS __NUM_LENGTHS__
#define NUM_TRIALS 7
#define MAX_LEN __MAX_LEN__UL
#define TARGET_BYTES 4096UL
#define CPU_HZ __CPU_HZ__UL

static const unsigned long lengths[NUM_LENGTHS] = {__LENGTHS__};

static uint8_t ad[64];
static uint8_t msg[MAX_LEN];
static uint8_t ct[MAX_LEN + CRYPTO_ABYTES];
static uint8_t ct2[MAX_LEN + CRYPTO_ABYTES];
static uint8_t dec[MAX_LEN];
static uint8_t nonce[CRYPTO_NPUBBYTES];
static uint8_t key[CRYPTO_KEYBYTES];

static const uint8_t kat_key[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const uint8_t kat_nonce[16] = {
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

static const uint8_t kat_empty_ct[16] = {
  0x4F, 0x9C, 0x27, 0x82, 0x11, 0xBE, 0xC9, 0x31,
  0x6B, 0xF6, 0x8F, 0x46, 0xEE, 0x8B, 0x2E, 0xC6
};

static void print_csv_double(double v, unsigned digits) {
  Serial.print(v, digits);
}

static void init_inputs(void) {
  for (size_t i = 0; i < sizeof(ad); ++i) ad[i] = (uint8_t)(i & 0xffu);
  for (size_t i = 0; i < sizeof(msg); ++i) msg[i] = (uint8_t)((i * 7u) & 0xffu);
  for (size_t i = 0; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(0xa0u + i);
  for (size_t i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)(0x50u + i);
}

static void set_nonce_counter(unsigned long i) {
  for (size_t j = 0; j < sizeof(nonce); ++j) nonce[j] = (uint8_t)(0xa0u + j);
  for (size_t j = 0; j < sizeof(nonce) && i; ++j) {
    nonce[j] ^= (uint8_t)(i & 0xffu);
    i >>= 8;
  }
}

static void sort_doubles(double *values, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    for (size_t j = i + 1; j < n; ++j) {
      if (values[j] < values[i]) {
        double tmp = values[i];
        values[i] = values[j];
        values[j] = tmp;
      }
    }
  }
}

static bool run_empty_aead_kat(void) {
  unsigned long long clen = 0;
  unsigned long long dlen = 0;
  uint8_t empty[1] = {0};
  if (CRYPTO_KEYBYTES != 16 || CRYPTO_NPUBBYTES != 16 || CRYPTO_ABYTES != 16) return false;
  if (crypto_aead_encrypt(ct, &clen, empty, 0, empty, 0, NULL, kat_nonce, kat_key) != 0) return false;
  if (clen != 16 || memcmp(ct, kat_empty_ct, 16) != 0) return false;
  if (crypto_aead_decrypt(dec, &dlen, NULL, ct, clen, empty, 0, kat_nonce, kat_key) != 0) return false;
  return dlen == 0;
}

static int make_ciphertext64(unsigned long long *clen) {
  return crypto_aead_encrypt(ct, clen, msg, 64, ad, 64, NULL, nonce, key);
}

static bool decrypt_current(unsigned long long clen) {
  unsigned long long dlen = 0;
  int rc = crypto_aead_decrypt(dec, &dlen, NULL, ct, clen, ad, 64, nonce, key);
  return rc == 0 && dlen == 64 && memcmp(dec, msg, 64) == 0;
}

static void print_case(const char *name, bool passed, const char *expected) {
  Serial.print(name);
  Serial.print(',');
  Serial.print(passed ? "pass" : "fail");
  Serial.print(',');
  Serial.println(expected);
}

static void run_negative_tests(void) {
  unsigned long long clen = 0;
  unsigned long long clen2 = 0;
  init_inputs();

  Serial.println("BEGIN_NEGATIVE_CSV");
  Serial.println("case,result,expected");

  if (make_ciphertext64(&clen) != 0) {
    print_case("valid_decrypt", false, "valid ciphertext decrypts");
    Serial.println("END_NEGATIVE_CSV");
    return;
  }

  print_case("valid_decrypt", decrypt_current(clen), "valid ciphertext decrypts");
  ct[0] ^= 0x01u;
  print_case("tampered_ciphertext_rejected", !decrypt_current(clen), "modified ciphertext must be rejected");
  ct[0] ^= 0x01u;
  ct[clen - 1] ^= 0x01u;
  print_case("tampered_tag_rejected", !decrypt_current(clen), "modified tag must be rejected");
  ct[clen - 1] ^= 0x01u;
  ad[0] ^= 0x01u;
  print_case("wrong_associated_data_rejected", !decrypt_current(clen), "wrong associated data must be rejected");
  ad[0] ^= 0x01u;
  nonce[0] ^= 0x01u;
  print_case("wrong_nonce_rejected", !decrypt_current(clen), "wrong nonce must be rejected");
  nonce[0] ^= 0x01u;
  key[0] ^= 0x01u;
  print_case("wrong_key_rejected", !decrypt_current(clen), "wrong key must be rejected");
  key[0] ^= 0x01u;
  int reuse_rc = crypto_aead_encrypt(ct2, &clen2, msg, 64, ad, 64, NULL, nonce, key);
  print_case("nonce_reuse_second_encrypt_succeeds", reuse_rc == 0, "API allows second encryption; caller must enforce nonce uniqueness");

  Serial.println("END_NEGATIVE_CSV");
}

static double time_encrypt_us_per_op(unsigned long mlen, unsigned long reps) {
  unsigned long long clen = 0;
  uint32_t start = micros();
  for (unsigned long i = 0; i < reps; ++i) {
    set_nonce_counter(i);
    if (crypto_aead_encrypt(ct, &clen, msg, mlen, ad, (mlen < 64 ? mlen : 64), NULL, nonce, key) != 0) return -1.0;
  }
  uint32_t stop = micros();
  return (double)(uint32_t)(stop - start) / (double)reps;
}

static double time_decrypt_us_per_op(unsigned long mlen, unsigned long reps) {
  unsigned long long clen = 0;
  unsigned long long dlen = 0;
  set_nonce_counter(0);
  if (crypto_aead_encrypt(ct, &clen, msg, mlen, ad, (mlen < 64 ? mlen : 64), NULL, nonce, key) != 0) return -1.0;
  uint32_t start = micros();
  for (unsigned long i = 0; i < reps; ++i) {
    if (crypto_aead_decrypt(dec, &dlen, NULL, ct, clen, ad, (mlen < 64 ? mlen : 64), nonce, key) != 0) return -1.0;
  }
  uint32_t stop = micros();
  if (dlen != mlen || memcmp(dec, msg, mlen) != 0) return -1.0;
  return (double)(uint32_t)(stop - start) / (double)reps;
}

static void print_timing_row(const char *operation, unsigned long mlen, unsigned long reps, double *values) {
  sort_doubles(values, NUM_TRIALS);
  double min_us = values[0];
  double med_us = values[NUM_TRIALS / 2];
  double max_us = values[NUM_TRIALS - 1];
  double cycles_per_op_est = med_us * (double)(CPU_HZ / 1000000UL);
  double cycles_per_byte_est = cycles_per_op_est / (double)mlen;
  double mbps = (double)mlen / med_us;

  Serial.print("Ascon-AEAD128,"); Serial.print(IMPLEMENTATION_NAME); Serial.print(',');
  Serial.print(operation); Serial.print(',');
  Serial.print(mlen); Serial.print(','); Serial.print(NUM_TRIALS); Serial.print(','); Serial.print(reps); Serial.print(',');
  print_csv_double(min_us, 3); Serial.print(',');
  print_csv_double(med_us, 3); Serial.print(',');
  print_csv_double(max_us, 3); Serial.print(',');
  print_csv_double(cycles_per_op_est, 1); Serial.print(',');
  print_csv_double(cycles_per_byte_est, 3); Serial.print(',');
  print_csv_double(mbps, 3); Serial.println();
}

static void run_timing(void) {
  double enc_trials[NUM_TRIALS];
  double dec_trials[NUM_TRIALS];
  init_inputs();
  Serial.println("BEGIN_TIMER_CSV");
  Serial.println("clock_hz,method,trials,notes");
  Serial.print(CPU_HZ); Serial.print(",micros_block_timing,"); Serial.print(NUM_TRIALS);
  Serial.println(",AVR board elapsed-time timing; cycles are derived estimates");
  Serial.println("END_TIMER_CSV");

  Serial.println("BEGIN_TIMING_CSV");
  Serial.println("primitive,implementation,operation,message_len,trials,reps,min_us_per_op,median_us_per_op,max_us_per_op,median_cycles_per_op_est,median_cycles_per_byte_est,median_MBps");

  for (size_t i = 0; i < NUM_LENGTHS; ++i) {
    unsigned long mlen = lengths[i];
    unsigned long reps = TARGET_BYTES / mlen;
    if (reps < 4) reps = 4;
    (void)time_encrypt_us_per_op(mlen, reps / 4 > 1 ? reps / 4 : 1);
    (void)time_decrypt_us_per_op(mlen, reps / 4 > 1 ? reps / 4 : 1);
    for (size_t trial = 0; trial < NUM_TRIALS; ++trial) {
      enc_trials[trial] = time_encrypt_us_per_op(mlen, reps);
      dec_trials[trial] = time_decrypt_us_per_op(mlen, reps);
    }
    print_timing_row("encrypt", mlen, reps, enc_trials);
    print_timing_row("decrypt", mlen, reps, dec_trials);
  }
  Serial.println("END_TIMING_CSV");
}

void setup(void) {
  Serial.begin(115200);
  while (!Serial) { delay(10); }
  delay(500);
  init_inputs();
  Serial.println("BEGIN_KAT_CSV");
  Serial.println("primitive,implementation,status,notes");
  Serial.print("Ascon-AEAD128,");
  Serial.print(IMPLEMENTATION_NAME);
  Serial.print(',');
  Serial.print(run_empty_aead_kat() ? "pass" : "fail");
  Serial.println(",empty PT/AD KAT Count 1 plus decrypt check");
  Serial.println("END_KAT_CSV");
  run_negative_tests();
  run_timing();
}

void loop(void) {
  delay(1000);
}
'''


HASH_TEMPLATE = r'''/*
  AVR Arduino board test harness for Ascon-Hash256.
  Serial output contains CSV blocks for KAT and timing.
*/

#include <Arduino.h>
#include <math.h>
#include <string.h>

extern "C" {
#include "api.h"
#include "crypto_hash.h"
}

#define IMPLEMENTATION_NAME "__IMPL__"
#define NUM_LENGTHS __NUM_LENGTHS__
#define NUM_TRIALS 7
#define MAX_LEN __MAX_LEN__UL
#define TARGET_BYTES 4096UL
#define CPU_HZ __CPU_HZ__UL

static const unsigned long lengths[NUM_LENGTHS] = {__LENGTHS__};
static uint8_t msg[MAX_LEN];
static uint8_t out[CRYPTO_BYTES];

static const uint8_t kat_empty_md[32] = {
  0x0B, 0x3B, 0xE5, 0x85, 0x0F, 0x2F, 0x6B, 0x98,
  0xCA, 0xF2, 0x9F, 0x8F, 0xDE, 0xA8, 0x9B, 0x64,
  0xA1, 0xFA, 0x70, 0xAA, 0x24, 0x9B, 0x8F, 0x83,
  0x9B, 0xD5, 0x3B, 0xAA, 0x30, 0x4D, 0x92, 0xB2
};

static void print_csv_double(double v, unsigned digits) {
  Serial.print(v, digits);
}

static void init_inputs(void) {
  for (size_t i = 0; i < sizeof(msg); ++i) msg[i] = (uint8_t)((i * 11u) & 0xffu);
}

static void sort_doubles(double *values, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    for (size_t j = i + 1; j < n; ++j) {
      if (values[j] < values[i]) {
        double tmp = values[i];
        values[i] = values[j];
        values[j] = tmp;
      }
    }
  }
}

static bool run_empty_hash_kat(void) {
  uint8_t empty[1] = {0};
  if (CRYPTO_BYTES != 32) return false;
  if (crypto_hash(out, empty, 0) != 0) return false;
  return memcmp(out, kat_empty_md, 32) == 0;
}

static double time_hash_us_per_op(unsigned long mlen, unsigned long reps) {
  uint32_t start = micros();
  for (unsigned long i = 0; i < reps; ++i) {
    if (crypto_hash(out, msg, mlen) != 0) return -1.0;
  }
  uint32_t stop = micros();
  return (double)(uint32_t)(stop - start) / (double)reps;
}

static void print_timing_row(unsigned long mlen, unsigned long reps, double *values) {
  sort_doubles(values, NUM_TRIALS);
  double min_us = values[0];
  double med_us = values[NUM_TRIALS / 2];
  double max_us = values[NUM_TRIALS - 1];
  double cycles_per_op_est = med_us * (double)(CPU_HZ / 1000000UL);
  double cycles_per_byte_est = cycles_per_op_est / (double)mlen;
  double mbps = (double)mlen / med_us;

  Serial.print("Ascon-Hash256,"); Serial.print(IMPLEMENTATION_NAME); Serial.print(",hash,");
  Serial.print(mlen); Serial.print(','); Serial.print(NUM_TRIALS); Serial.print(','); Serial.print(reps); Serial.print(',');
  print_csv_double(min_us, 3); Serial.print(',');
  print_csv_double(med_us, 3); Serial.print(',');
  print_csv_double(max_us, 3); Serial.print(',');
  print_csv_double(cycles_per_op_est, 1); Serial.print(',');
  print_csv_double(cycles_per_byte_est, 3); Serial.print(',');
  print_csv_double(mbps, 3); Serial.println();
}

static void run_timing(void) {
  double trials[NUM_TRIALS];
  init_inputs();
  Serial.println("BEGIN_TIMER_CSV");
  Serial.println("clock_hz,method,trials,notes");
  Serial.print(CPU_HZ); Serial.print(",micros_block_timing,"); Serial.print(NUM_TRIALS);
  Serial.println(",AVR board elapsed-time timing; cycles are derived estimates");
  Serial.println("END_TIMER_CSV");
  Serial.println("BEGIN_TIMING_CSV");
  Serial.println("primitive,implementation,operation,message_len,trials,reps,min_us_per_op,median_us_per_op,max_us_per_op,median_cycles_per_op_est,median_cycles_per_byte_est,median_MBps");
  for (size_t i = 0; i < NUM_LENGTHS; ++i) {
    unsigned long mlen = lengths[i];
    unsigned long reps = TARGET_BYTES / mlen;
    if (reps < 4) reps = 4;
    (void)time_hash_us_per_op(mlen, reps / 4 > 1 ? reps / 4 : 1);
    for (size_t trial = 0; trial < NUM_TRIALS; ++trial) trials[trial] = time_hash_us_per_op(mlen, reps);
    print_timing_row(mlen, reps, trials);
  }
  Serial.println("END_TIMING_CSV");
}

void setup(void) {
  Serial.begin(115200);
  while (!Serial) { delay(10); }
  delay(500);
  init_inputs();
  Serial.println("BEGIN_KAT_CSV");
  Serial.println("primitive,implementation,status,notes");
  Serial.print("Ascon-Hash256,");
  Serial.print(IMPLEMENTATION_NAME);
  Serial.print(',');
  Serial.print(run_empty_hash_kat() ? "pass" : "fail");
  Serial.println(",empty-message KAT Count 1");
  Serial.println("END_KAT_CSV");
  run_timing();
}

void loop(void) {
  delay(1000);
}
'''


def run_command(args: list[str], cwd: Path | None = None, timeout: int = 120) -> tuple[int, str]:
    proc = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout


def copy_variant(src: Path, dst: Path, primitive: str, impl: str) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for child in src.iterdir():
        if child.is_file():
            shutil.copy2(child, dst / child.name)
    lengths_literal = ", ".join(str(length) for length in MESSAGE_LENGTHS)
    if primitive == "aead":
        shutil.copy2(ASCON / "tests" / "crypto_aead.h", dst / "crypto_aead.h")
        ino = AEAD_TEMPLATE.replace("__IMPL__", impl)
    else:
        shutil.copy2(ASCON / "tests" / "crypto_hash.h", dst / "crypto_hash.h")
        ino = HASH_TEMPLATE.replace("__IMPL__", impl)
    ino = ino.replace("__NUM_LENGTHS__", str(len(MESSAGE_LENGTHS)))
    ino = ino.replace("__MAX_LEN__", str(MAX_LEN))
    ino = ino.replace("__LENGTHS__", lengths_literal)
    ino = ino.replace("__CPU_HZ__", str(CPU_HZ))
    (dst / f"{dst.name}.ino").write_text(ino, encoding="utf-8")


def parse_compile_size(text: str) -> tuple[int | None, int | None]:
    flash = None
    ram = None
    for line in text.splitlines():
        m = re.search(r"Sketch uses ([0-9]+) bytes", line)
        if m:
            flash = int(m.group(1))
        m = re.search(r"Global variables use ([0-9]+) bytes", line)
        if m:
            ram = int(m.group(1))
    return flash, ram


def object_size(build_path: Path) -> tuple[int, int, int, int, str]:
    objects = []
    for obj in sorted(build_path.rglob("*.o")):
        rel_s = str(obj.relative_to(build_path))
        if "/core/" in rel_s or "/libraries/" in rel_s or rel_s.endswith(".ino.cpp.o"):
            continue
        if rel_s.startswith("sketch/"):
            objects.append(obj)
    if not objects:
        return 0, 0, 0, 0, "no isolated sketch objects found"
    total_text = total_data = total_bss = 0
    names = []
    for obj in objects:
        rc, out = run_command([str(SIZE_TOOL), str(obj)], timeout=30)
        if rc != 0:
            continue
        lines = [line.split() for line in out.splitlines() if line.strip()]
        if len(lines) >= 2 and len(lines[1]) >= 3:
            total_text += int(lines[1][0])
            total_data += int(lines[1][1])
            total_bss += int(lines[1][2])
            names.append(obj.name)
    return total_text, total_data, total_bss, total_text + total_data + total_bss, ";".join(names)


def monitor_serial(log_path: Path, timeout_s: int = 240) -> str:
    fd = os.open(PORT, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    attrs = termios.tcgetattr(fd)
    attrs[4] = termios.B115200
    attrs[5] = termios.B115200
    attrs[2] |= termios.CLOCAL | termios.CREAD
    attrs[3] &= ~(termios.ICANON | termios.ECHO | termios.ECHOE | termios.ISIG)
    attrs[0] &= ~(termios.IXON | termios.IXOFF | termios.IXANY)
    attrs[1] &= ~termios.OPOST
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    chunks: list[bytes] = []
    start = time.time()
    try:
        while time.time() - start < timeout_s:
            readable, _, _ = select.select([fd], [], [], 0.25)
            if readable:
                try:
                    chunk = os.read(fd, 4096)
                except BlockingIOError:
                    chunk = b""
                if chunk:
                    chunks.append(chunk)
                text_so_far = b"".join(chunks).decode("utf-8", "replace")
                if "END_TIMING_CSV" in text_so_far:
                    time.sleep(0.5)
                    break
    finally:
        os.close(fd)
    text = b"".join(chunks).decode("utf-8", "replace")
    log_path.write_text(text, encoding="utf-8")
    return text


def extract_block(text: str, name: str) -> list[list[str]]:
    start = f"BEGIN_{name}_CSV"
    end = f"END_{name}_CSV"
    in_block = False
    rows: list[list[str]] = []
    for raw in text.replace("\r", "").splitlines():
        line = raw.strip()
        if start in line:
            in_block = True
            if line != start:
                line = line.split(start, 1)[1].strip()
                if not line:
                    continue
            else:
                continue
        if end in line:
            if line != end and in_block:
                line = line.split(end, 1)[0].strip()
                if line:
                    rows.append(next(csv.reader([line])))
            break
        if in_block and line:
            rows.append(next(csv.reader([line])))
    if len(rows) <= 1:
        return []
    return rows[1:]

def write_csv(path: Path, header: list[str], rows: list[list[object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def main() -> None:
    if RUN.exists():
        shutil.rmtree(RUN)
    RUN.mkdir(parents=True)
    builds = RUN / "builds"
    builds.mkdir()
    evidence = RUN / "filled_evidence"
    evidence.mkdir()

    sketches: list[tuple[str, str, Path]] = []
    for impl in AEAD_VARIANTS:
        dst = RUN / f"avr_aead_{impl}"
        copy_variant(ASCON / "crypto_aead" / "asconaead128" / impl, dst, "aead", impl)
        sketches.append(("aead", impl, dst))
    for impl in HASH_VARIANTS:
        dst = RUN / f"avr_hash_{impl}"
        copy_variant(ASCON / "crypto_hash" / "asconhash256" / impl, dst, "hash", impl)
        sketches.append(("hash", impl, dst))

    compile_rows: list[list[object]] = []
    object_rows: list[list[object]] = []
    kat_rows: list[list[object]] = []
    negative_rows: list[list[object]] = []
    timing_rows: list[list[object]] = []
    timer_rows: list[list[object]] = []

    for primitive, impl, sketch in sketches:
        label = f"{primitive}_{impl}"
        build_path = builds / label
        print(f"== compile {label}", flush=True)
        rc, compile_out = run_command(
            [
                "arduino-cli",
                "compile",
                "--fqbn",
                FQBN,
                "--build-path",
                str(build_path),
                "--clean",
                str(sketch),
            ],
            timeout=180,
        )
        (RUN / f"compile_{label}.log").write_text(compile_out, encoding="utf-8")
        if rc != 0:
            raise RuntimeError(f"compile failed for {label}\n{compile_out}")
        flash, ram = parse_compile_size(compile_out)
        compile_rows.append([primitive, impl, flash, ram, "arduino-cli compile whole-sketch output"])
        text, data, bss, total, names = object_size(build_path)
        object_rows.append([primitive, impl, text, data, bss, total, names])

        print(f"== upload {label}", flush=True)
        rc, upload_out = run_command(
            [
                "arduino-cli",
                "upload",
                "-p",
                PORT,
                "--fqbn",
                FQBN,
                "--build-path",
                str(build_path),
                str(sketch),
            ],
            timeout=180,
        )
        (RUN / f"upload_{label}.log").write_text(upload_out, encoding="utf-8")
        if rc != 0:
            raise RuntimeError(f"upload failed for {label}\n{upload_out}")
        time.sleep(2)

        print(f"== monitor {label}", flush=True)
        serial_text = monitor_serial(RUN / f"serial_{label}.log", timeout_s=240)
        if "END_TIMING_CSV" not in serial_text:
            raise RuntimeError(f"serial capture incomplete for {label}")

        for row in extract_block(serial_text, "KAT"):
            kat_rows.append(row)
        for row in extract_block(serial_text, "NEGATIVE"):
            negative_rows.append([primitive, impl] + row)
        for row in extract_block(serial_text, "TIMER"):
            timer_rows.append([primitive, impl] + row)
        for row in extract_block(serial_text, "TIMING"):
            timing_rows.append(row)

    write_csv(
        evidence / "mega2560_compile_size_avr.csv",
        ["primitive", "implementation", "sketch_flash_bytes", "sketch_ram_bytes", "notes"],
        compile_rows,
    )
    write_csv(
        evidence / "mega2560_avr_object_size.csv",
        ["primitive", "implementation", "text_bytes", "data_bytes", "bss_bytes", "total_bytes", "objects_summed"],
        object_rows,
    )
    write_csv(evidence / "mega2560_kat_status_avr.csv", ["primitive", "implementation", "status", "notes"], kat_rows)
    write_csv(
        evidence / "mega2560_negative_tests_avr.csv",
        ["primitive", "implementation", "case", "result", "expected"],
        negative_rows,
    )
    write_csv(
        evidence / "mega2560_timer_info_avr.csv",
        ["primitive", "implementation", "clock_hz", "method", "trials", "notes"],
        timer_rows,
    )
    write_csv(
        evidence / "mega2560_timing_avr.csv",
        [
            "primitive",
            "implementation",
            "operation",
            "message_len",
            "trials",
            "reps",
            "min_us_per_op",
            "median_us_per_op",
            "max_us_per_op",
            "median_cycles_per_op_est",
            "median_cycles_per_byte_est",
            "median_MBps",
        ],
        timing_rows,
    )
    (evidence / "mega2560_board_info_avr.txt").write_text(
        f"Board: {BOARD_LABEL} detected by arduino-cli\n"
        f"FQBN: {FQBN}\nPort: {PORT}\n"
        f"Timing method: block-level micros() timing at nominal {CPU_HZ} Hz; serial output outside timed regions.\n"
        "Scope: AVR elapsed-time timing; cycle counts are derived estimates, not DWT hardware counts.\n"
        f"Payload lengths: {','.join(str(v) for v in MESSAGE_LENGTHS)} bytes.\n",
        encoding="utf-8",
    )
    print(f"wrote {evidence}", flush=True)


if __name__ == "__main__":
    main()
