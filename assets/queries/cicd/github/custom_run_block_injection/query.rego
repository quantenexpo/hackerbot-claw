package Cx

import data.generic.common as common_lib

CxPolicy[result] {

	input.document[i].on["pull_request_target"]
	run := input.document[i].jobs[j].steps[k].run

	patterns := [
    "github.head_ref",
    "github.event.pull_request.body",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.pull_request.head.repo.description",
    "github.event.pull_request.head.repo.homepage",
    "github.event.pull_request.title"
	]

	matched = containsPatterns(run, patterns)

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"searchValue": matched[m]
	}
}

CxPolicy[result] {

	input.document[i].on["issues"]
	run := input.document[i].jobs[j].steps[k].run

	patterns := [
    "github.event.issue.body",
	"github.event.issue.title"
	]

	matched = containsPatterns(run, patterns)

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"searchValue": matched[m]
	}
}

CxPolicy[result] {
	input.document[i].on["issue_comment"]
	run := input.document[i].jobs[j].steps[k].run

	# Rule 1: direct interpolation of dangerous GitHub context variables into a run block
	directPatterns := [
		"github.event.comment.body",
		"github.event.issue.body",
		"github.event.issue.title",
		"steps.pr_info.outputs.pr_head_ref",
	]

	matched := containsPatterns(run, directPatterns)
	count(matched) > 0

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user (direct interpolation).",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"], []),
		"searchValue": concat(", ", matched),
	}
}

CxPolicy[result] {
	input.document[i].on["issue_comment"]
	run := input.document[i].jobs[j].steps[k].run

	# Rule 2: detect a GitHub expression assigned to a shell variable that is
	# subsequently used unquoted (word-splitting / injection risk).
	#
	# Pattern A – inline assignment in run block:
	#   VAR="${{ steps.<id>.outputs.<name> }}"   (safe assignment)
	#   ...later... $VAR or for x in $VAR        (unsafe unquoted use)
	#
	# We detect this by:
	#   (a) finding an assignment of a ${{ steps.*.outputs.* }} expression to a VAR
	#   (b) confirming that VAR is used *unquoted* somewhere in the same run block
	#       i.e. the string contains $VAR but NOT "${VAR}" or "$VAR" inside quotes
	#       that would protect against splitting.

	# (a) Capture VARNAME from lines like:  VARNAME="...${{ steps...outputs... }}..."
	#     or VARNAME=${{ ... }}
	assignment_re := `(?m)^[ \t]*([A-Z_][A-Z0-9_]*)=.*\$\{\{[ \t]*steps\.[^}]+outputs\.[^}]+\}\}`
	assignment_match := regex.find_all_string_submatch_n(assignment_re, run, -1)
	count(assignment_match) > 0

	# Collect all variable names that were assigned from a steps output expression
	assigned_vars := {varname |
		m := assignment_match[_]
		varname := m[1]
	}

	# (b) For each such variable, check it appears unquoted in the run block.
	#     Unquoted use: $VAR not immediately preceded by " and not inside "${VAR}"
	#     We check for the pattern  $VAR  (word boundary after VAR) where it is
	#     NOT written as "${VAR}" (with curly braces and surrounding quotes).
	varname := assigned_vars[_]
	unquoted_re := sprintf(`\$%s([^A-Z0-9_"'}\n]|$)`, [varname])
	regex.match(unquoted_re, run)

	# Confirm this variable is NOT exclusively used in the safe "${VAR}" form.
	# i.e. at least one bare $VAR occurrence exists outside braces/quotes.
	safe_only_re := sprintf(`\$%s`, [varname])
	safe_braces_re := sprintf(`"\$\{%s\}"`, [varname])

	# count bare $VAR occurrences vs protected ones
	all_uses := count(regex.find_n(safe_only_re, run, -1))
	safe_uses := count(regex.find_n(safe_braces_re, run, -1))
	all_uses > safe_uses

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("Variable $%s derived from a GitHub expression is always quoted (e.g. \"${%s}\").", [varname, varname]),
		"keyActualValue": sprintf("Variable $%s derived from a GitHub expression is used unquoted, enabling word-splitting injection.", [varname]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"], []),
		"searchValue": sprintf("unquoted use of $%s", [varname]),
	}
}


CxPolicy[result] {

	input.document[i].on["discussion"]
	run := input.document[i].jobs[j].steps[k].run

	patterns := [
    "github.event.discussion.body",
	"github.event.discussion.title"
	]

	matched = containsPatterns(run, patterns)

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"searchValue": matched[m]
	}
}

CxPolicy[result] {

	input.document[i].on["discussion_comment"]
	run := input.document[i].jobs[j].steps[k].run

	patterns := [
    "github.event.comment.body",
	"github.event.discussion.body",
	"github.event.discussion.title"
	]

	matched = containsPatterns(run, patterns)

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"searchValue": matched[m]
	}
}

CxPolicy[result] {

	input.document[i].on["workflow_run"]
	run := input.document[i].jobs[j].steps[k].run

	patterns := [
    "github.event.workflow.path",
	"github.event.workflow_run.head_branch",
	"github.event.workflow_run.head_commit.author.email",
	"github.event.workflow_run.head_commit.author.name",
	"github.event.workflow_run.head_commit.message",
	"github.event.workflow_run.head_repository.description"
	]

	matched = containsPatterns(run, patterns)

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"searchValue": matched[m]
	}
}

CxPolicy[result] {

	input.document[i].on["author"]
	run := input.document[i].jobs[j].steps[k].run

	patterns := [
    "github.*.authors.name",
	"github.*.authors.email"
	]

	matched = containsPatterns(run, patterns)

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"searchValue": matched[m]
	}
}



containsPatterns(str, patterns) = matched {
    matched := {pattern |
        pattern := patterns[_]
        regex.match(pattern, str)
    }
}
