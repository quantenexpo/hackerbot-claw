Here is a polished, consistent, repository‑ready **README.md** based entirely on your provided text, with file names and paths aligned to the structure of  
**[https://github.com/quantenexpo/hackerbot-claw](https://github.com/quantenexpo/hackerbot-claw)**.

No copyrighted content is included, and everything is original wording.

You can paste this directly into `README.md` at the root of the repository.

---

# KICS Query Customization Example

## Disclaimer
This repository is provided for **educational purposes**.  
It demonstrates one possible approach to customizing **Checkmarx KICS** queries.  
While Anthropic Claude (Sonnet 4.6) was used to generate the queries, other AI systems can be used as well.

---

# Background

This repository contains **seven vulnerable GitHub Actions workflows** that were exploited by the *hackerbot‑claw* threat actor to compromise seven different repositories.  
The full incident analysis is available here:

**[https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation#what-happened](https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation#what-happened)**

To detect these vulnerabilities using **KICS**, two custom queries were created:

1. **Custom_run_block_injection**  
   An extension of the existing KICS query `run_block_injection`.

2. **UntrustedCheckoutCritical**  
   A new query that does not exist in standard KICS.

Both queries were created following the official KICS tutorial:  
**[https://docs.kics.io/latest/creating-queries/](https://docs.kics.io/latest/creating-queries/)**

The query logic was generated using Claude, based on the **positive** (vulnerable) and **negative** (fixed) workflow variants stored in:

```
.github/workflows/
```

---

# Workflows Used

### For `UntrustedCheckoutCritical`
The following workflows exhibit the vulnerability and were used as **positive** examples:

- `amber-auto-review`
- `apidiff`
- `pr-quality-checks`
- `pr-auto-commit`
- `update-versions`

Their fixed versions were used as **negative** examples, except:

- `50-format-request`
- `apidiff`

These two have no fixed versions because the “fix” consisted of retiring the workflow entirely.

### For `Custom_run_block_injection`
The workflow:

- `sync-copywriter-changes`

was used because the original KICS `run_block_injection` query did **not** detect the vulnerability it contains.

---

# Project Setup for Query Generation

Two Claude projects were created—one for each custom query.  
Each project included:

- The **positive** and **negative** workflow payloads (generated via KICS CLI)
- The **KICS GitHub repository** for reference:  
  [https://github.com/Checkmarx/kics](https://github.com/Checkmarx/kics)

Payloads were generated using KICS CLI commands such as:

```bash
docker run -t \
  -v "<your_working_directory>":/test \
  checkmarx/kics scan \
  -p /test/sync-copywriter-changes_positive.yml \
  -o "/test/results" \
  --output-name "sync-copywriter-changes_positive_ex.json" \
  -d "/test/sync-copywriter-changes_positive_payload_output.json" \
  -i 20f14e1a-a899-4e79-9f09-b6a84cd4649b
```

The `-i` flag forces KICS to run only the `run_block_injection` query.

---

# 1. Extending the `run_block_injection` Query

### Files involved
The base query used for customization is located in this repository:

```
playground/run_block_injection/run_block_injection_4_AI.rego
```

This version contains all required helper functions inline, so no imports are needed.

### Claude Prompt Used
A prompt similar to the following was used:

> `run_block_injection_4_AI.rego` is a KICS query.  
> `sync-copywriter-changes_positive_payload_output.json` should trigger the policy on `steps.pr_info.outputs.pr_head_ref`, but currently does not.  
> Modify the query so it triggers on that field in `run` steps.  
> It should detect **one issue** in the positive payload (line 25) and **no issues** in the negative payload.

### Metadata
If you want to use `Custom_run_block_injection` as a **separate** query (not replacing the built‑in one), you must also create a `metadata.json`.

You may:

- Generate it using an AI prompt such as:  
  *“For the attached `Custom_run_block_injection.rego`, create a metadata.json file using the standard KICS template.”*
- Or simply use the `metadata.json` provided in this repository, which is identical to the standard KICS metadata except for the query ID.

---

# 2. Creating the `UntrustedCheckoutCritical` Query

### Purpose
This query detects critical checkouts of untrusted code.  
It is inspired by GitHub’s CodeQL rule:

```
Security/CWE-829/UntrustedCheckoutCritical.ql
```

### Files referenced
- CodeQL source:  
  `https://github.com/actions/ql/src/Security/CWE-829/UntrustedCheckoutCritical.ql` [(github.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fgithub.com%2Factions%2Fql%2Fsrc%2FSecurity%2FCWE-829%2FUntrustedCheckoutCritical.ql")
- Additional routines:  
  [https://github.com/actions/ql](https://github.com/actions/ql)
- KICS libraries:  
  `https://github.com/kics/assets/libraries` [(github.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fgithub.com%2Fkics%2Fassets%2Flibraries")

### Claude Prompt Used
A prompt similar to the following was used:

> Generate an OPA (Rego) query for KICS named `UntrustedCheckoutCritical`, based on the CodeQL rule above.  
> Use helper routines from `kics/assets/libraries`.  
> The query must include a `build_search_line_step`.  
> It must detect issues in all `*positive*.json` payloads and none in `*negative*.json`.  
> The description must be under 500 characters.

Claude produced:

- The Rego query  
- The metadata file  

Both work as-is.  
Optionally, the query can be refactored to use `import` statements for shared routines.

---

# Repository Structure

```
.github/
  workflows/
    <positive and negative workflow examples>
    kics-scan.yml

playground/
  run_block_injection/
    run_block_injection_4_AI.rego

queries/
  Custom_run_block_injection/
    Custom_run_block_injection.rego
    metadata.json

  UntrustedCheckoutCritical/
    UntrustedCheckoutCritical.rego
    metadata.json
```

---

# Summary

This repository demonstrates:

- How to extend an existing KICS query (`run_block_injection`)
- How to create a new KICS query (`UntrustedCheckoutCritical`)
- How to use LLMs to assist in generating and refining Rego policies
- How to validate queries using positive/negative workflow payloads
- How to reproduce the process using the KICS CLI and official KICS libraries

These examples can serve as a template for building additional custom KICS queries for GitHub Actions security analysis.

---

If you want, I can also generate:

- A CONTRIBUTING.md  
- A diagram showing the query‑generation workflow  
- A section explaining how to run the KICS scan locally
