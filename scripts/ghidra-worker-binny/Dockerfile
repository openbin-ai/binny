# BINNY's worker image: openbin/ghidra-worker:7 + two fixes that matter for
# raw firmware (plus a runtime-tunable JVM heap, superseding ghidra-worker-bigmem).
#
#   1. main.py learns an `image_base` form field → passes BinaryLoader's
#      -loader-baseAddr, so a raw kernel linked at e.g. 0x80000000 (MIPS KSEG0)
#      is mapped at its real address. Without it every absolute pointer lands
#      outside the program and Ghidra creates NO string/data xrefs — the
#      decompiler shows bare constants like (byte *)0x804ccc58 and string→code
#      navigation is impossible.
#   2. extract.py emits, per string, its address and the functions that
#      reference it (`string_refs`), so a string→code pivot works even when the
#      decompiler doesn't inline the literal.
#
# Build:
#   docker build -t openbin/ghidra-worker:7-binny scripts/ghidra-worker-binny
# Use (binny picks it up):
#   OPENBIN_GHIDRA_IMAGE=openbin/ghidra-worker:7-binny ./run.sh
#
# HEAP sizing — made RUNTIME-TUNABLE instead of a baked constant so the one
# published image is safe for everyone. The default stays 2G (same as stock
# ghidra-worker:7 — fine on small Docker VMs and for ordinary binaries), but an
# explicit `-e MAXMEM=...` on `docker run` overrides it. binny raises it to 4G
# ONLY for a raw image loaded at its real base, where the decompiler resolves
# thousands of pointers and a 2G heap OOMs (exit 137) — so a user analyzing a
# normal file on a modest laptop is never forced into a bigger heap. launch.sh
# already applies -Xmx${MAXMEM}, and main.py runs analyzeHeadless with the
# container env inherited, so the override flows straight through.
#   normal binary            -> 2G  (image default)
#   raw firmware (ImageBase) -> 4G  (binny sets MAXMEM; needs an ~8 GB VM)
#   bigger/faster, fewer stubs -> -e MAXMEM=6G on a 12 GB VM
FROM openbin/ghidra-worker:7

RUN sed -i 's/^MAXMEM=2G/MAXMEM=${MAXMEM:-2G}/' /opt/ghidra/support/analyzeHeadless \
 && grep '^MAXMEM=' /opt/ghidra/support/analyzeHeadless

COPY main.py /app/app/main.py
COPY extract.py /app/scripts/extract.py

# Fail the build early if either patch didn't land. main.py is Python 3 (f-strings,
# __future__), so ast-parse it with CPython. extract.py is Jython 2, so compile it
# with the bundled Jython interpreter (CPython 3 can't parse its `except E, e`).
RUN python3 -c "import ast; ast.parse(open('/app/app/main.py').read())" \
 && grep -q 'loader-baseAddr' /app/app/main.py \
 && grep -q 'string_refs' /app/scripts/extract.py \
 && java -jar /opt/ghidra/Ghidra/Features/Jython/lib/jython-standalone-2.7.3.jar \
      -c "import py_compile; py_compile.compile('/app/scripts/extract.py', doraise=True)"
