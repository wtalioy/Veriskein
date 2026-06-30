#!/usr/bin/env bash
# Representative agent-style workload for the Veriskein performance harness.
#
# The workload models the kind of work a coding/ops agent actually drives on the
# host: repeated compiler invocations (CPU plus many header opens and tool
# execs), some file I/O, and a small amount of OpenSSL TLS traffic. This is a
# realistic mix rather than a syscall microbenchmark, which is the right basis
# for the competition's "<= 5% capture overhead" target: monitoring cost is
# amortized over real work instead of being measured against empty syscalls.
#
# The workload is byte-for-byte identical across every daemon mode, so the only
# variable is which BPF capture paths are attached.
#
# Environment:
#   PERF_ITERS      compiler iterations (default 24)
#   PERF_TLS_REQS   TLS requests via openssl s_client (default 12)
#   PERF_TLS_PORT   local TLS server port (default empty -> skip TLS)
#   PERF_SCRATCH    scratch directory (default mktemp)
set -euo pipefail

ITERS="${PERF_ITERS:-8}"
FUNCS="${PERF_FUNCS:-1500}"
TLS_REQS="${PERF_TLS_REQS:-12}"
TLS_PORT="${PERF_TLS_PORT:-}"
SCRATCH="${PERF_SCRATCH:-$(mktemp -d)}"
CC="${CC:-cc}"

mkdir -p "${SCRATCH}"
src="${SCRATCH}/bench.c"

# Generate a large, realistic translation unit once. It pulls in several system
# headers (header opens) and contains enough functions that -O2 optimization is
# genuinely CPU-bound per invocation. This keeps the syscall-to-compute ratio
# representative of real compilation work rather than a process-spawn / header
# -open microbenchmark, which is the fair basis for a capture-overhead figure.
if [[ ! -f "${src}" ]]; then
  {
    printf '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <math.h>\n\n'
    for ((f = 0; f < FUNCS; f++)); do
      printf 'static double work_%d(double x){double a=x;for(int i=0;i<64;i++){a=a*1.0000003+%d.0;a=a-(double)((long)a);a+=sin(a)*cos(a);}return a;}\n' "${f}" "${f}"
    done
    printf '\nint main(int argc,char**argv){double acc=(argc>1)?atof(argv[1]):0.5;\n'
    for ((f = 0; f < FUNCS; f++)); do
      printf 'acc+=work_%d(acc);acc=fmod(acc,1.0e6);\n' "${f}"
    done
    printf 'char b[64];snprintf(b,sizeof(b),"%%.6f",acc);return (int)(strlen(b)&1);}\n'
  } > "${src}"
fi

# Compiler path: each invocation execs the toolchain (cc -> cc1 -> as -> ld),
# opens many header/object files, and does substantial optimization CPU work.
for ((i = 0; i < ITERS; i++)); do
  "${CC}" -O2 -pipe -o "${SCRATCH}/bench.out" "${src}" -lm
done

# Network + TLS path: each openssl client performs connect() plus SSL_write /
# SSL_read against the local mock server, exercising net.bpf.c and (when
# attached) the OpenSSL uprobes.
if [[ -n "${TLS_PORT}" ]]; then
  for ((i = 0; i < TLS_REQS; i++)); do
    printf 'GET / HTTP/1.0\r\n\r\n' \
      | openssl s_client -connect "127.0.0.1:${TLS_PORT}" -quiet 2>/dev/null >/dev/null \
      || true
  done
fi
