# Derived ghidra-worker with a larger Ghidra JVM heap.
#
# The stock openbin/ghidra-worker:7 launches analyzeHeadless with MAXMEM=2G.
# A large stripped firmware kernel (multi-MB vendor-driver, 10k+ functions)
# builds a result.json whose in-heap representation blows past 2G, so extract.py
# dies on a java.lang.OutOfMemoryError BEFORE it can write the file — surfacing
# as the worker's "exited 0 but no result.json". Raising the heap fixes it.
#
# Build:
#   docker build -t openbin/ghidra-worker:7-bigmem scripts/ghidra-worker-bigmem
# Use (point binny at it) + give Docker Desktop >= 8 GB RAM:
#   OPENBIN_GHIDRA_IMAGE=openbin/ghidra-worker:7-bigmem ./run.sh
#
# MAXMEM must be <= the RAM you give the Docker VM. 6G heap -> 8 GB VM.
ARG HEAP=6G
FROM openbin/ghidra-worker:7
ARG HEAP
RUN sed -i "s/^MAXMEM=2G/MAXMEM=${HEAP}/" /opt/ghidra/support/analyzeHeadless \
 && grep '^MAXMEM=' /opt/ghidra/support/analyzeHeadless
