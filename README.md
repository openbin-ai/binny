<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/binny-on-dark.png">
    <img src="docs/binny-on-light.png" width="160" alt="BINNY, the OpenBin mascot: a smiling file with bits rising off it">
  </picture>
</p>

<h1 align="center">BINNY</h1>

<p align="center">An open source agent harness for reverse engineering. Plug in any model, point it at a binary, and it works through the code with real tools and hands you a report to review.</p>

BINNY is the harness, not the model. It brings the tools (decompiled functions, strings, imports, data, a sealed sandbox, local Ghidra and JADX), the playbooks, the triage, investigate, draft loop, the budgets, the checkpoints and the report format. The model is whatever you plug in: Claude, GPT, DeepSeek, Qwen, Kimi, Gemini, Bedrock, or a local model through Ollama or LM Studio. BINNY opens one of your [OpenBin](https://openbin.ai) or [OpenAPK](https://openapk.ai) projects, or decompiles a file on your disk, and runs that loop against the decompiled code. Every step is a tool call you can watch: it lists functions, reads decompilations, pulls strings, imports and data, runs scripts in a sealed sandbox, and records findings as it goes. The draft lands on the project report for you to check before anything is published.

It runs on your own model key, or on a local model. Nothing about your sample goes to us unless you put it in a project.

## Install

macOS and Linux:

```sh
curl -fsSL https://openbin.ai/install-binny.sh | sh
```

Windows (PowerShell):

```powershell
irm https://openbin.ai/install-binny.ps1 | iex
```

Then:

```sh
openbin login   # once; BINNY reuses the openbin CLI's sign-in
binny           # pick a project, set a key, go
```

Prebuilt binaries for every platform are on the [releases page](https://github.com/openbin-ai/binny/releases). Docker is needed only for `/decompile` (local Ghidra or JADX) and the sandbox tools.

## What it does

**Investigate.** `/investigate` starts the full loop. Triage classifies the sample against the STIX 2.1 malware vocabulary, picks the matching playbooks, then investigates function by function until the budget or the evidence runs out, and writes the draft. `/mode malware` and `/mode vuln` switch the lens between a malware analysis report and a vulnerability research report.

**Three ways to run it.** `/autonomy autonomous` runs to a finished draft with no stops. `supervised` pauses at phase boundaries and whenever BINNY is unsure, and asks you. `collaborative` adds a short interview before the write-up: audience, depth, framing.

**Ask.** `/ask` skips the pipeline. Pick up a project at its current state and question it: verify a claim in an existing report, inspect one function, or build a defensive proof of concept such as a config decryptor. An existing report is treated as claims to check, not facts.

**Tools, not vibes.** Read tools work on the project's analysis: metadata, function list, decompiled function, strings, imports, exports, data symbols, raw data reads. Android projects get their own set: the parsed manifest (permissions, exported components, intent filters), code search, find definition / find usages, and file listing and reads; the native-only tools are not offered there. `/sample <path>` attaches the raw binary and unlocks extraction. The sandbox `run` tool executes scripts in a Docker container with no network, a read-only root, a read-only sample mount, dropped capabilities and CPU, memory and pid limits. `/work` is a persistent workspace that survives between sessions.

**Local decompile.** `/decompile <path> [processor]` runs Ghidra on your machine and keeps the result on disk. Nothing is uploaded. Raw firmware takes a Ghidra processor ID such as `ARM:LE:32:v7`. Point it at an `.apk` or `.xapk` and it runs JADX instead, with the same worker image as `openbin apk` (the image cache is shared with the openbin CLI); every Android tool then reads the decompiled tree from disk. `/upload` turns that local APK into an OpenAPK project without decompiling again. Multi-sample projects (dropper plus payloads, firmware revisions) are handled with `/samples` and `/switch`.

**Resume.** Sessions auto-save after every step. Reopen a project marked resumable and BINNY continues where it stopped.

**Report.** `/draft` shows the draft, `/findings` the recorded findings, IOCs, classification and coverage. `/save` pushes the draft to the project report as a draft for you to review.

## Models

Bring your own key. Anthropic, OpenAI, DeepSeek, Qwen, Kimi, Gemini (OpenAI-compatible) and Bedrock are preconfigured. `/key` stores a key locally, `/model` switches, `/models` lists what is configured. `/endpoint <url>` points a provider at another host, for example a gateway that fronts the Claude Messages API on your own domain. Config lives in `~/.config/binny/config.json`.

### Local models

Ollama and LM Studio are preconfigured and need no key. Start the server, pick `ollama` or `lmstudio` in setup (or `/model ollama`), and BINNY lists the models you have pulled. llama.cpp (`llama-server`) and vLLM work the same way: `/endpoint ollama http://localhost:8080/v1`.

Two things matter for a local model:

- It must support tool calling. qwen3, gpt-oss, llama3.1 and newer, mistral-nemo and devstral do; most small instruct models do not.
- The context window must be big enough. Ollama defaults to 4k, which is too small for decompiled code; run it with `OLLAMA_CONTEXT_LENGTH=32768` or set `num_ctx` in a Modelfile. BINNY compacts history earlier for local providers (`contextTokens` in config.json) so the tool list stays in the window.

## Commands

Type `/` in the prompt for the palette, or `/help` for the full list.

| Command | What it does |
| --- | --- |
| `/investigate` | start the analysis loop |
| `/ask` | Q&A mode on the current project |
| `/autonomy <mode>` | autonomous, supervised or collaborative |
| `/mode malware\|vuln` | analysis lens |
| `/sample <path>` | attach the raw binary |
| `/decompile <path> [proc]` | local decompile, kept on disk (Ghidra for binaries, JADX for APKs) |
| `/upload` | create an OpenAPK project from the attached local APK |
| `/samples`, `/switch` | multi-sample projects |
| `/workspace [path]` | persistent sandbox workspace |
| `/draft`, `/findings`, `/save` | the report |
| `/model`, `/key`, `/endpoint`, `/models` | providers |
| `/budget [n]` | per-project token budget |
| `/status`, `/settings`, `/project` | session |

## Build from source

Go 1.22 or newer for a release build; the module itself compiles on Go 1.18.

```sh
go build -o binny .
go test ./...
```

Releases are cut by tagging `v*` (see `.github/workflows/release.yml`) or
with `scripts/release-local.sh <tag>`. The workflow cross-compiles for Linux,
macOS and Windows. Binaries are published to the public
`openbin-ai/binny-releases` repo for the installers; this repo stays private.

## Contributing

Pull requests are welcome. Contributors must sign the [Contributor License Agreement](CLA.md) once; it lets the project stay AGPL while OpenBin can offer the same code under a commercial licence to teams that cannot use AGPL. The CLA Assistant bot will prompt you on your first pull request.

## License

BINNY is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE). The platform BINNY talks to is [openbin-ai/platform](https://github.com/openbin-ai/platform), under the same licence.
