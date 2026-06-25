# LLM provider profiles

A **profile** is a sourceable env file that selects the LLM backend for a whole
pipeline run **without editing any project YAML**. `run_project.sh --profile <name>`
sources `profiles/<name>.env`, so the same three projects (glibc, tcpdump, openssl)
can be benchmarked across different AI families by swapping one flag.

## Environment-variable contract

Every setting below overrides the matching `config.yaml` `llm:` value when set.
Profiles set the non-secret ones; secrets are sourced separately (see below).

| Variable | Applies to | Example | Overrides |
|----------|-----------|---------|-----------|
| `LLM_PROVIDER` | both | `openai` / `ollama` | `llm.provider` |
| `LLM_MODELS_BY_ATTEMPT` | both | `m1,m2,m3,m4` | the 4-model ramp (see below) |
| `LLM_OPENAI_MODEL` | openai | `gpt-4.1` | `llm.openai_model` (single-model fallback) |
| `LLM_OPENAI_BASE_URL` | openai | `https://host/v1` | OpenAI SDK `base_url` |
| `LLM_ENDPOINT` | ollama | `http://10.3.1.226:80/api/chat` | `llm.endpoint` |
| `LLM_MODEL` | ollama | `qwen2.5-coder:7b` | `llm.models[0]` (single-model fallback) |
| `LLM_NUM_CTX` | ollama | `32768` | `llm.num_ctx` |
| `LLM_TEMPERATURE` | both | `0.2` | `llm.temperature` |
| `LLM_MAX_TOKENS` | openai | `16384` | `llm.max_tokens` |
| `LLM_TIMEOUT` | both | `600` | `llm.timeout` |
| `OPENAI_API_KEY` | openai | *(secret)* | from `API-openai-key` |
| `OLLAMA_USERNAME` | ollama | `talmeida` | basic-auth user (from `API-ollama-proxy`) |
| `OLLAMA_PASSWORD` | ollama | *(secret)* | basic-auth pass (from `API-ollama-proxy`) |

### The 4-model ramp (`LLM_MODELS_BY_ATTEMPT`)

Each profile names **4 models** as a comma list. They map to the 4 feedback
attempts (`max_retries: 3` ⇒ 1 initial + 3 retries) and escalate on each retry —
identically for OpenAI and Ollama. The **attempt-1** model is also what Phase 0
(PoC repair) and Phase 1 (negative filter) use, so the *whole run stays on one
family*. Order = attempt 1 → 4.

## Secrets — never in YAML or in profile files

Secrets live in single-line, gitignored files next to `API-openai-key`:

- `API-openai-key`  — OpenAI key (already present).
- `API-ollama-proxy` — proxy basic-auth, one line `username:password`.

Create the proxy secret once (run from `pipeline/`):

```bash
printf 'talmeida:<password>\n' > API-ollama-proxy
chmod 600 API-ollama-proxy
echo 'API-ollama-proxy' >> .gitignore   # if not already covered by an API-* rule
```

`run_project.sh` reads `API-ollama-proxy` and exports `OLLAMA_USERNAME` /
`OLLAMA_PASSWORD` for the run.

## Shipped profiles (each = 4 models, same family unless noted)

| Profile | Provider | Ramp (attempt 1 → 4) | Token tier |
|---------|----------|----------------------|------------|
| `openai-fast` *(default)* | openai | gpt-4.1-nano, gpt-4.1-mini, gpt-5-mini, gpt-5.4-mini | 10M (cheap breadth) |
| `openai-mix` | openai | gpt-4.1-mini, gpt-5-mini, gpt-5.4-mini, gpt-5.4 | 10M → 1M on retry |
| `openai-high` | openai | gpt-5, gpt-5.1, gpt-5.2, gpt-5.4 *(flagship ladder)* | 1M (budget-bound) |
| `openai-codex` | openai | codex-mini-latest, gpt-5.1-codex-mini, gpt-5-codex, gpt-5.1-codex | 10M → 1M; see caveat |
| `ollama-proxy-qwen-coder` | ollama | qwen2.5-coder:1.5b → :7b → :14b → qwen3-coder:30b | Qwen family, size ladder |
| `ollama-proxy-deepseek` | ollama | deepseek-coder:1.3b → :6.7b → -v2:16b → :33b | DeepSeek family, size ladder |
| `ollama-proxy-devstral` | ollama | codestral:22b ↔ devstral:24b (cycled ×2) | Mistral family, head-to-head |
| `ollama-proxy-frontier-coder` | ollama | qwen2.5-coder:14b → deepseek-coder-v2:16b → devstral:24b → qwen3-coder:30b | cross-family frontier |

All Ollama models above are present on the proxy (pulled where needed).

> **Token tiers (OpenAI):** flagships (gpt-5.4/5.2/5.1/5, gpt-4.1, gpt-4o, o1, o3)
> share **1M tokens/day**; minis/nanos/codex-mini share **10M/day**. `fast`/`mix`
> lean on the 10M tier for breadth; `high` is bound by the 1M budget.
> `openai-codex`: the full `gpt-5*-codex` models may need OpenAI's Responses API
> (the pipeline uses chat.completions) — test on one CVE first.

## Ollama context window (important)

Ollama's default context is ~2k tokens; the pipeline overrides it per request with
`LLM_NUM_CTX` (32768) on **all three** LLM phases (Phase 0 repair defaults to the
tiny server value and relies on this var, so always keep it set). Whole-function
patch prompts can be ~5–15k tokens, so 32k is the right floor.

Prefer models whose *native* context ≥ 32k. Safe: qwen2.5(-coder) (32k),
qwen3-coder (256k), deepseek-coder-v2 (128k), devstral / devstral-32k (128k),
codestral (32k). **16k-native:** `codellama` and DeepSeek-Coder **v1** (the
`ollama-proxy-deepseek` 1.3b/6.7b/33b rungs) — Ollama RoPE-extends these to 32k,
which can degrade quality on the longest prompts (a real model-context limit,
flagged in that profile). The 30B+ rungs are also VRAM-heavy at 32k and may
partially offload to CPU on a small GPU (the pipeline logs a warning).

## Benchmarking other families

Copy a proxy profile and change the four models in `LLM_MODELS_BY_ATTEMPT` (keep
endpoint / num_ctx / the CVE set fixed so the model is the only variable). To pull
a model onto the proxy:

```bash
U=talmeida; P=$(cut -d: -f2- ../API-ollama-proxy)
curl -u "$U:$P" http://10.3.1.226:80/api/pull -d '{"model":"codestral:22b"}'
```

Each run already gets an isolated output dir (`projects/<project>__<profile>/`).
