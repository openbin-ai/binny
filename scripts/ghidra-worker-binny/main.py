"""FastAPI wrapper around Ghidra's analyzeHeadless.

Single endpoint: POST /analyze takes a binary upload and an arch label, runs
Ghidra in headless mode with the bundled extract.py post-script, and returns
the resulting JSON.

Synchronous on purpose — the OpenAPK core wraps this call in its own @Async
executor so it never blocks a Spring request thread. Keeping the worker
synchronous means we don't have to ship a separate job store here.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("ghidra-worker")

GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "/opt/ghidra")
ANALYZE_HEADLESS = Path(GHIDRA_HOME) / "support" / "analyzeHeadless"
SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"
# Hard cap on the whole subprocess (analyzeHeadless + post-script). Bumped
# above analyzeHeadless's own per-file analysis timeout (see ANALYSIS_TIMEOUT_SEC)
# so a long-but-not-stuck analysis completes instead of getting killed.
ANALYZE_TIMEOUT_SEC = int(os.environ.get("GHIDRA_ANALYZE_TIMEOUT", "1500"))
# Per-file ceiling Ghidra applies inside analyzeHeadless itself. With aggressive
# function-start search enabled (see scripts/preflight.py), large stripped libs
# can take 15+ minutes. Should always be lower than ANALYZE_TIMEOUT_SEC.
ANALYSIS_TIMEOUT_SEC = int(os.environ.get("GHIDRA_PER_FILE_TIMEOUT", "1200"))
# Slice reserved out of ANALYZE_TIMEOUT_SEC for extract.py's post-decompile
# work (strings/imports/data-symbols) + JSON serialization + the HTTP response.
# We hand extract.py a wall-clock deadline of (now + ANALYZE_TIMEOUT_SEC - this)
# so it STOPS decompiling and emits a partial result BEFORE subprocess.run's own
# hard timeout would kill everything. Without this, a binary whose auto-analysis
# eats most of the budget produced a 504 with nothing salvaged.
EXTRACT_TAIL_MARGIN_SEC = int(os.environ.get("GHIDRA_EXTRACT_TAIL_MARGIN", "150"))

app = FastAPI(title="ghidra-worker", version="0.1.0")


@app.get("/health")
def health() -> dict:
    """Liveness + sanity-check that analyzeHeadless is wired up."""
    ok = ANALYZE_HEADLESS.is_file() and os.access(ANALYZE_HEADLESS, os.X_OK)
    return {
        "status": "ok" if ok else "degraded",
        "ghidra_home": str(GHIDRA_HOME),
        "analyze_headless_present": ok,
    }


# A Ghidra language ID: family:endianness:size:variant (e.g. ARM:LE:32:v7).
# Validated so a caller-supplied value can't smuggle arbitrary argv tokens.
_PROCESSOR_RE = re.compile(r"^[A-Za-z0-9_.+-]+:[LB]E:[0-9]+:[A-Za-z0-9_.+-]+$")


@app.post("/analyze")
async def analyze(
    binary: UploadFile = File(..., description="A single native library (.so / .dll / .dylib)"),
    arch: str = Form("unknown", description="Caller-supplied arch label; round-tripped in metadata"),
    processor: str = Form(
        "",
        description="Ghidra language ID to FORCE (-processor), e.g. ARM:LE:32:v7. "
        "Empty/'auto' = let Ghidra autodetect. Required for raw firmware whose "
        "arch Ghidra can't autodetect.",
    ),
    loader: str = Form(
        "",
        description="'binary' forces Ghidra's raw BinaryLoader for headerless "
        "images (requires processor). Empty = loader autodetect.",
    ),
    image_base: str = Form(
        "",
        description="Load/link base address for a raw image, hex (e.g. "
        "0x80000000 for a MIPS KSEG0 kernel). Passed to BinaryLoader as "
        "-loader-baseAddr so absolute pointers in the code resolve to the "
        "mapped image — without it every pointer lands outside the program "
        "and Ghidra creates no string/data xrefs. Only used with loader=binary.",
    ),
) -> JSONResponse:
    if not ANALYZE_HEADLESS.is_file():
        raise HTTPException(status_code=503, detail=f"analyzeHeadless not found at {ANALYZE_HEADLESS}")

    processor = (processor or "").strip()
    if processor.lower() in ("", "auto", "unknown"):
        processor = ""
    elif not _PROCESSOR_RE.match(processor):
        raise HTTPException(
            status_code=400,
            detail=f"invalid processor {processor!r} — expected a Ghidra language ID like ARM:LE:32:v7",
        )
    loader = (loader or "").strip().lower()
    if loader not in ("", "binary"):
        raise HTTPException(status_code=400, detail="loader must be empty or 'binary'")
    if loader == "binary" and not processor:
        raise HTTPException(
            status_code=400,
            detail="loader=binary (raw image) requires a processor — Ghidra has no headers to autodetect from",
        )

    # Load/link base for raw images. Validated to a bare hex/decimal integer so
    # it can't smuggle extra argv tokens, then normalized to 0x-prefixed hex
    # (the form BinaryLoader's -loader-baseAddr expects).
    image_base = (image_base or "").strip()
    if image_base.lower() in ("", "0", "0x0", "auto"):
        image_base = ""
    else:
        try:
            _base_int = int(image_base, 16) if image_base.lower().startswith("0x") else int(image_base, 0)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"invalid image_base {image_base!r} — expected a hex address like 0x80000000",
            )
        if _base_int < 0 or _base_int >= (1 << 64):
            raise HTTPException(status_code=400, detail="image_base out of range")
        image_base = "0x%x" % _base_int
        if loader != "binary":
            # A base address is meaningless to a header-aware loader (ELF/PE
            # carry their own); only BinaryLoader honors -loader-baseAddr.
            image_base = ""

    job_id = uuid.uuid4().hex[:8]
    tmp_root = Path(tempfile.mkdtemp(prefix=f"ghidra-{job_id}-"))
    try:
        # Stash the binary on disk so Ghidra can mmap it.
        in_name = _safe_filename(binary.filename, fallback=f"binary-{job_id}")
        bin_path = tmp_root / in_name
        size = 0
        with bin_path.open("wb") as out:
            while True:
                chunk = await binary.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
                size += len(chunk)
        log.info("job=%s saved binary name=%s size=%d arch=%s", job_id, in_name, size, arch)

        out_path = tmp_root / "result.json"
        ghidra_proj = tmp_root / "ghidra-proj"
        ghidra_proj.mkdir(exist_ok=True)
        proj_name = f"p_{job_id}"
        ghidra_log = tmp_root / "ghidra.log"

        cmd = [
            str(ANALYZE_HEADLESS),
            str(ghidra_proj), proj_name,
            "-import", str(bin_path),
            "-scriptPath", str(SCRIPT_DIR),
            # Pre-script tunes analyzer options BEFORE auto-analysis runs.
            # Post-script extracts the result AFTER auto-analysis finishes.
            "-preScript", "preflight.py",
            "-postScript", "extract.py", str(out_path),
            "-analysisTimeoutPerFile", str(ANALYSIS_TIMEOUT_SEC),
            "-deleteProject",
            "-overwrite",
            "-log", str(ghidra_log),
        ]
        # Forced language for firmware/raw images Ghidra can't autodetect.
        # -processor alone still lets a real ELF/PE loader run; -loader
        # BinaryLoader is the headerless-image case (validated above to
        # always come with a processor).
        if processor:
            cmd += ["-processor", processor]
        if loader == "binary":
            cmd += ["-loader", "BinaryLoader"]
            if image_base:
                cmd += ["-loader-baseAddr", image_base]
        log.info("job=%s running: %s", job_id, " ".join(cmd))

        # Hand extract.py an absolute wall-clock deadline for its decompile
        # phase. It reads GHIDRA_EXTRACT_DEADLINE_EPOCH and, once too little
        # budget remains to safely decompile one more function, stubs the rest
        # and writes result.json — so a big binary yields a PARTIAL result
        # instead of hitting subprocess.run's hard timeout with nothing.
        child_env = dict(os.environ)
        child_env["GHIDRA_EXTRACT_DEADLINE_EPOCH"] = repr(time.time() + ANALYZE_TIMEOUT_SEC - EXTRACT_TAIL_MARGIN_SEC)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=ANALYZE_TIMEOUT_SEC,
                env=child_env,
            )
        except subprocess.TimeoutExpired:
            # Hard wall hit. extract.py's own deadline (EXTRACT_TAIL_MARGIN_SEC
            # before this) should normally have written a partial result first;
            # if it did, serve that instead of losing the whole run. This covers
            # the case where auto-analysis alone ate most of the budget.
            if out_path.exists():
                log.warning("job=%s subprocess timed out but a (partial) result.json exists — serving it", job_id)
            else:
                raise HTTPException(status_code=504, detail=f"ghidra analysis timed out after {ANALYZE_TIMEOUT_SEC}s")
            proc = None

        # analyzeHeadless's exit code reflects analysis success — NOT post-script
        # success. A non-zero exit means the binary was rejected (unsupported
        # format, malformed, etc.); the script may not have run at all. proc is
        # None only on the salvaged-timeout path above, where result.json exists.
        if proc is not None and proc.returncode != 0:
            detail = _build_error_detail(
                "ghidra analyzeHeadless exited %d" % proc.returncode,
                proc, ghidra_log,
            )
            log.error("job=%s %s", job_id, detail)
            raise HTTPException(status_code=500, detail=detail)

        # No result.json after exit 0 ⇒ the post-script (extract.py) crashed
        # silently. Surface stdout/stderr/ghidra.log so we can actually debug.
        if not out_path.exists():
            detail = _build_error_detail(
                "ghidra exited 0 but extract.py produced no result.json "
                "(post-script likely crashed)",
                proc, ghidra_log,
            )
            log.error("job=%s %s", job_id, detail)
            raise HTTPException(status_code=500, detail=detail)

        with out_path.open("r", encoding="utf-8") as f:
            result = json.load(f)

        # extract.py writes {"error": "..."} when it caught an exception itself.
        # Treat that as a 500 too — it's still useful info for the caller.
        if isinstance(result, dict) and result.get("error"):
            script_error = result.get("error")
            detail = _build_error_detail(
                "extract.py reported an error: %s" % script_error,
                proc, ghidra_log,
            )
            log.error("job=%s %s", job_id, detail)
            raise HTTPException(status_code=500, detail=detail)

        # Stamp arch + size in metadata so the caller doesn't need to track it separately.
        meta = result.setdefault("metadata", {})
        meta["arch"] = arch
        meta["bytes"] = size
        meta["filename"] = in_name
        if processor:
            # Record that the language was forced (and what to), so consumers
            # can tell a forced-arch analysis from an autodetected one.
            meta["forced_processor"] = processor
        if image_base:
            meta["image_base"] = image_base

        log.info(
            "job=%s done functions=%d strings=%d imports=%d",
            job_id,
            len(result.get("functions", [])),
            len(result.get("strings", [])),
            len(result.get("imports", [])),
        )
        return JSONResponse(result)

    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def _safe_filename(name: str | None, fallback: str) -> str:
    if not name:
        return fallback
    # Strip path components and anything weird Ghidra might choke on.
    base = os.path.basename(name).replace("\x00", "")
    base = "".join(c for c in base if c.isprintable())
    return base or fallback


def _build_error_detail(headline: str, proc: subprocess.CompletedProcess, ghidra_log: Path) -> str:
    """Assemble a debuggable error blob from the analyzeHeadless run.

    Includes the headline + last 2KB of stderr/stdout + last 2KB of ghidra.log.
    Long enough to capture a Jython traceback, short enough to fit in an
    HTTP response without choking the caller.
    """
    parts = [headline]
    stderr_tail = (proc.stderr or "").strip() if proc is not None else ""
    if stderr_tail:
        parts.append("--- stderr (last 2KB) ---\n" + stderr_tail[-2048:])
    stdout_tail = (proc.stdout or "").strip() if proc is not None else ""
    if stdout_tail:
        parts.append("--- stdout (last 2KB) ---\n" + stdout_tail[-2048:])
    if ghidra_log.exists():
        try:
            log_text = ghidra_log.read_text(errors="replace").strip()
            if log_text:
                parts.append("--- ghidra.log (last 2KB) ---\n" + log_text[-2048:])
        except OSError:
            pass
    return "\n\n".join(parts)
