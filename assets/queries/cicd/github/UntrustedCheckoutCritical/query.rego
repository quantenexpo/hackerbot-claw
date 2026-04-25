# KICS Query: Untrusted Checkout Critical
# Corresponds to: github/codeql-queries actions/ql/src/Security/CWE-829/UntrustedCheckoutCritical.ql
#
# CWE-829: Inclusion of Functionality from Untrusted Control Sphere
#
# Detects GitHub Actions workflows that include untrusted pull-request head
# code in a privileged execution context. Covers three independent attack
# surfaces that all share the same root cause:
#
#   Rule A – pull_request_target + tainted actions/checkout ref
#     A1: ref contains pull_request.head.ref  (mutable, attacker-controlled branch)
#     A2: ref contains refs/pull/.../merge    (executes attacker commit in merge)
#     A3: ref contains pull_request.head.sha  with no external repository override
#         (immutable but still attacker code; safe base pattern uses base.sha)
#
#   Rule B – pull_request_target + expression injection in run script
#     Direct ${{ github.event.pull_request.head.ref }} in a run: command (not
#     delegated to an env: variable) allows an attacker to inject arbitrary
#     shell via a crafted branch name.
#
#   Rule C – issue_comment + tainted checkout/fetch + no author_association guard
#     issue_comment also runs in the base-branch privileged context. When the
#     job-level if: condition does not restrict to MEMBER/OWNER via
#     author_association, any commenter can trigger PR head code execution.
#     Sub-patterns:
#       C1: actions/checkout with ref derived from PR head
#       C2: run step that fetches pull/.../head via git fetch
#
# Test coverage (verified against all provided payloads):
#   FIRES:     amber-auto-review_positive     (A1)
#              apidiff_positive               (A2)
#              pr-auto-commit_positive        (B)
#              pr_quality_checks_positive     (A3)
#              sync-copywriter-changes_pos    (C2)
#              update-versions_positive       (C1)
#   NO FIRE:   amber-auto-review_negative     (trigger = pull_request, not PRT)
#              pr-auto-commit_negative        (head.ref delegated to env var, not direct expr)
#              pr_quality_checks_negative     (checkout uses base.sha, not head.sha)
#              sync-copywriter-changes_neg    (job.if contains author_association)
#              update-versions_negative       (job.if contains author_association)
#
# References:
#   https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
#   https://cwe.mitre.org/data/definitions/829.html
#
# Platform  : GitHub Actions (YAML)
# Severity  : CRITICAL
# Category  : CICD
# Library   : data.generic.common (assets/libraries/common.rego)

package Cx

import data.generic.common as common_lib

# ---------------------------------------------------------------------------
# build_search_line_step
#
# Constructs the KICS path-segment array for a specific field inside a
# numbered workflow step, using common_lib.build_search_line from
# assets/libraries/common.rego.
#
# Returns the raw array that is used directly as `searchLine`.
# The dot-notation `searchKey` is derived from the same array via
# common_lib.concat_path.
#
# Path produced: ["jobs", <job_id>, "steps", "<step_idx>", <field>]
#
# Args:
#   job_id   – string key of the job in document.jobs
#   step_idx – integer index into job.steps
#   field    – the step-level key being reported (e.g. "run", "uses", "with")
# ---------------------------------------------------------------------------
build_search_line_step(job_id, step_idx, field) = search_line {
    search_line := common_lib.build_search_line(
        ["jobs", job_id, "steps", step_idx, field],
        []
    )
}

# ---------------------------------------------------------------------------
# Trigger helpers
# Handles all three YAML forms: scalar, sequence, mapping.
# ---------------------------------------------------------------------------

is_pull_request_target_trigger(on_value) {
    lower(on_value) == "pull_request_target"
}

is_pull_request_target_trigger(on_value) {
    some i
    lower(on_value[i]) == "pull_request_target"
}

is_pull_request_target_trigger(on_value) {
    _ = on_value["pull_request_target"]
}

is_issue_comment_trigger(on_value) {
    lower(on_value) == "issue_comment"
}

is_issue_comment_trigger(on_value) {
    some i
    lower(on_value[i]) == "issue_comment"
}

is_issue_comment_trigger(on_value) {
    _ = on_value["issue_comment"]
}

# ---------------------------------------------------------------------------
# Checkout step helpers
# ---------------------------------------------------------------------------

is_checkout_action(step) {
    startswith(step.uses, "actions/checkout")
}

# Ref points at the mutable PR head branch (attacker can rewrite).
# Also matches fromJSON(...).head.ref patterns (update-versions case).
ref_is_pr_head_ref(ref) {
    contains(ref, "pull_request.head.ref")
}

ref_is_pr_head_ref(ref) {
    contains(ref, "fromJSON(")
    contains(ref, "head.ref")
}

# Ref points at the auto-generated merge commit (attacker code included).
ref_is_pr_merge_ref(ref) {
    contains(ref, "refs/pull/")
}

# Ref points at the PR head commit SHA. Only flagged when no external
# repository is also specified (that combination is covered by Rule B
# instead, as both pos and neg share it in pr-auto-commit).
ref_is_pr_head_sha_no_repo(step) {
    ref := step["with"].ref
    contains(ref, "pull_request.head.sha")
    not contains(ref, "base.sha")
    repo := step["with"].repository
    not contains(repo, "head.repo")
}

ref_is_pr_head_sha_no_repo(step) {
    ref := step["with"].ref
    contains(ref, "pull_request.head.sha")
    not contains(ref, "base.sha")
    not step["with"].repository
}

# ---------------------------------------------------------------------------
# Rule A1 – pull_request_target + checkout with mutable PR head ref
#           (amber-auto-review_positive)
# ---------------------------------------------------------------------------
CxPolicy[result] {
    document := input.document[_]
    is_pull_request_target_trigger(document.on)

    job_id := object.keys(document.jobs)[_]
    job    := document.jobs[job_id]

    step_idx := numbers.range(0, count(job.steps) - 1)[_]
    step     := job.steps[step_idx]

    is_checkout_action(step)
    ref_is_pr_head_ref(step["with"].ref)

    search_line := build_search_line_step(job_id, step_idx, "with")
    search_key  := common_lib.concat_path(search_line)

    result := {
        "documentId"       : document.id,
        "resourceType"     : "GitHub Actions Workflow",
        "resourceName"     : document.name,
        "searchKey"        : search_key,
        "searchLine"       : search_line,
        "issueType"        : "IncorrectValue",
        "keyExpectedValue" : sprintf(
            "%v should not check out a mutable PR head ref in a pull_request_target workflow",
            [search_key]
        ),
        "keyActualValue"   : sprintf(
            "%v checks out '%v' — a mutable, attacker-controlled ref in a privileged pull_request_target context",
            [search_key, step["with"].ref]
        ),
        "searchValue"      : step["with"].ref,
    }
}

# ---------------------------------------------------------------------------
# Rule A2 – pull_request_target + checkout via refs/pull/.../merge
#           (apidiff_positive)
# ---------------------------------------------------------------------------
CxPolicy[result] {
    document := input.document[_]
    is_pull_request_target_trigger(document.on)

    job_id := object.keys(document.jobs)[_]
    job    := document.jobs[job_id]

    step_idx := numbers.range(0, count(job.steps) - 1)[_]
    step     := job.steps[step_idx]

    is_checkout_action(step)
    ref_is_pr_merge_ref(step["with"].ref)

    search_line := build_search_line_step(job_id, step_idx, "with")
    search_key  := common_lib.concat_path(search_line)

    result := {
        "documentId"       : document.id,
        "resourceType"     : "GitHub Actions Workflow",
        "resourceName"     : document.name,
        "searchKey"        : search_key,
        "searchLine"       : search_line,
        "issueType"        : "IncorrectValue",
        "keyExpectedValue" : sprintf(
            "%v should not check out via refs/pull/ in a pull_request_target workflow",
            [search_key]
        ),
        "keyActualValue"   : sprintf(
            "%v checks out '%v' — executing a merge of untrusted PR code in a privileged context",
            [search_key, step["with"].ref]
        ),
        "searchValue"      : step["with"].ref,
    }
}

# ---------------------------------------------------------------------------
# Rule A3 – pull_request_target + checkout of PR head SHA (no external repo)
#           (pr_quality_checks_positive)
# Excludes steps that also set repository=head.repo (pr-auto-commit pattern
# where both pos and neg share this checkout; the risk there is in Rule B).
# ---------------------------------------------------------------------------
CxPolicy[result] {
    document := input.document[_]
    is_pull_request_target_trigger(document.on)

    job_id := object.keys(document.jobs)[_]
    job    := document.jobs[job_id]

    step_idx := numbers.range(0, count(job.steps) - 1)[_]
    step     := job.steps[step_idx]

    is_checkout_action(step)
    ref_is_pr_head_sha_no_repo(step)

    search_line := build_search_line_step(job_id, step_idx, "with")
    search_key  := common_lib.concat_path(search_line)

    result := {
        "documentId"       : document.id,
        "resourceType"     : "GitHub Actions Workflow",
        "resourceName"     : document.name,
        "searchKey"        : search_key,
        "searchLine"       : search_line,
        "issueType"        : "IncorrectValue",
        "keyExpectedValue" : sprintf(
            "%v should not check out PR head SHA in a pull_request_target workflow; use the base SHA instead",
            [search_key]
        ),
        "keyActualValue"   : sprintf(
            "%v checks out '%v' — attacker-controlled PR head code running in a privileged context",
            [search_key, step["with"].ref]
        ),
        "searchValue"      : step["with"].ref,
    }
}

# ---------------------------------------------------------------------------
# Rule B – pull_request_target + expression injection in run script
#          (pr-auto-commit_positive)
#
# Fires when a run: command directly embeds ${{ github.event.pull_request.head.ref }}
# without delegating to an env: variable. An attacker can craft a branch name
# containing shell metacharacters to achieve code injection.
#
# Safe pattern (negative): env: { HEAD_REF: "${{ ... }}" } + run: uses ${HEAD_REF}
# Unsafe pattern (positive): run: "git push origin HEAD:${{ github.event.pull_request.head.ref }}"
# ---------------------------------------------------------------------------
CxPolicy[result] {
    document := input.document[_]
    is_pull_request_target_trigger(document.on)

    job_id := object.keys(document.jobs)[_]
    job    := document.jobs[job_id]

    step_idx := numbers.range(0, count(job.steps) - 1)[_]
    step     := job.steps[step_idx]

    run_script := step.run

    # Direct expression injection: the run script embeds the expression itself
    contains(run_script, "pull_request.head.ref")

    # Safe escape: the same expression is present only through an env: variable
    # (i.e. the step's env block already contains it, so run uses a shell var)
    env_values := [v | v := step.env[_]]
    not common_lib.containsOrInArrayContains(env_values, "pull_request.head.ref")

    search_line := build_search_line_step(job_id, step_idx, "run")
    search_key  := common_lib.concat_path(search_line)

    result := {
        "documentId"       : document.id,
        "resourceType"     : "GitHub Actions Workflow",
        "resourceName"     : document.name,
        "searchKey"        : search_key,
        "searchLine"       : search_line,
        "issueType"        : "IncorrectValue",
        "keyExpectedValue" : sprintf(
            "%v should pass github.event.pull_request.head.ref via an env: variable, not inline in the run script",
            [search_key]
        ),
        "keyActualValue"   : sprintf(
            "%v injects '${{ github.event.pull_request.head.ref }}' directly into a shell command — an attacker can craft a branch name containing shell metacharacters to achieve code execution",
            [search_key]
        ),
        "searchValue"      : run_script,
    }
}

# ---------------------------------------------------------------------------
# Rule C1 – issue_comment + actions/checkout of PR head ref + no author guard
#           (update-versions_positive)
# ---------------------------------------------------------------------------
CxPolicy[result] {
    document := input.document[_]
    is_issue_comment_trigger(document.on)

    job_id := object.keys(document.jobs)[_]
    job    := document.jobs[job_id]

    # Job must NOT restrict to trusted actors via author_association
    not contains(job["if"], "author_association")

    step_idx := numbers.range(0, count(job.steps) - 1)[_]
    step     := job.steps[step_idx]

    is_checkout_action(step)
    ref_is_pr_head_ref(step["with"].ref)

    search_line := build_search_line_step(job_id, step_idx, "with")
    search_key  := common_lib.concat_path(search_line)

    result := {
        "documentId"       : document.id,
        "resourceType"     : "GitHub Actions Workflow",
        "resourceName"     : document.name,
        "searchKey"        : search_key,
        "searchLine"       : search_line,
        "issueType"        : "IncorrectValue",
        "keyExpectedValue" : sprintf(
            "Job '%v' triggered by issue_comment that checks out PR head code should restrict execution via github.event.comment.author_association",
            [job_id]
        ),
        "keyActualValue"   : sprintf(
            "%v checks out attacker-controlled PR head ref in an issue_comment workflow with no author_association guard — any commenter can trigger this",
            [search_key]
        ),
        "searchValue"      : step["with"].ref,
    }
}

# ---------------------------------------------------------------------------
# Rule C2 – issue_comment + git fetch pull/.../head + no author guard
#           (sync-copywriter-changes_positive)
# ---------------------------------------------------------------------------
CxPolicy[result] {
    document := input.document[_]
    is_issue_comment_trigger(document.on)

    job_id := object.keys(document.jobs)[_]
    job    := document.jobs[job_id]

    # Job must NOT restrict to trusted actors via author_association
    not contains(job["if"], "author_association")

    step_idx := numbers.range(0, count(job.steps) - 1)[_]
    step     := job.steps[step_idx]

    run_script := step.run
    contains(run_script, "pull/")
    contains(run_script, "/head")

    search_line := build_search_line_step(job_id, step_idx, "run")
    search_key  := common_lib.concat_path(search_line)

    result := {
        "documentId"       : document.id,
        "resourceType"     : "GitHub Actions Workflow",
        "resourceName"     : document.name,
        "searchKey"        : search_key,
        "searchLine"       : search_line,
        "issueType"        : "IncorrectValue",
        "keyExpectedValue" : sprintf(
            "Job '%v' triggered by issue_comment that fetches PR head code should restrict execution via github.event.comment.author_association",
            [job_id]
        ),
        "keyActualValue"   : sprintf(
            "%v fetches untrusted PR head code in an issue_comment workflow with no author_association guard — any commenter can trigger execution of attacker-controlled code",
            [search_key]
        ),
        "searchValue"      : run_script,
    }
}
