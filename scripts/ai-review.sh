#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

merge_file_lists() {
	local line
	mapfile -t files < <(
		{
			printf '%s\n' "${files[@]}"
			git ls-files --others --exclude-standard
		} | awk 'NF && !seen[$0]++'
	)
}

diff_mode="staged"
if git diff --cached --quiet --ignore-submodules HEAD --; then
	if git diff --quiet --ignore-submodules --; then
		mapfile -t files < <(git ls-files --others --exclude-standard)
		if [[ ${#files[@]} -eq 0 ]]; then
			echo "ai-review: no staged, unstaged, or untracked changes"
			exit 0
		fi
		diff_mode="untracked"
	else
		diff_mode="working tree"
		mapfile -t files < <(git diff --name-only --diff-filter=ACMR)
	fi
else
	mapfile -t files < <(git diff --cached --name-only --diff-filter=ACMR)
fi

merge_file_lists

if [[ ${#files[@]} -eq 0 ]]; then
	echo "ai-review: no added, copied, modified, renamed, or untracked files"
	exit 0
fi

if git ls-files --others --exclude-standard | grep -q .; then
	case "$diff_mode" in
		staged|working\ tree)
			diff_mode="${diff_mode} + untracked"
			;;
	esac
fi

has_agent=0
has_backend=0
has_dataplane=0
has_response=0
has_web=0
has_specs=0
has_product=0
has_generated=0
has_generated_source=0

need_go_test=0
need_make_test=0
need_go_generate=0
need_web_build=0

need_modules_spec=0
need_rules_spec=0
need_events_spec=0
need_responses_spec=0
need_stats_spec=0

warnings=()
failures=()

for file in "${files[@]}"; do
	case "$file" in
		docs/ai-workflow.md|docs/ai-review-checklist.md)
			failures+=("$file is not allowed. Keep AI workflow rules in AGENTS.md, skills/, or .agent/.")
			;;
	esac

	if [[ "$file" == "internal/dataplane/sidersp_bpfel.go" ]]; then
		has_generated=1
		need_go_generate=1
		continue
	fi

	case "$file" in
		AGENTS.md|skills/*|.agent/*|Makefile|scripts/ai-review.sh)
			has_agent=1
			;;
		specs/*)
			has_specs=1
			;;
		web/*)
			has_web=1
			has_product=1
			need_web_build=1
			need_rules_spec=1
			need_stats_spec=1
			;;
		bpf/*)
			has_backend=1
			has_dataplane=1
			has_product=1
			has_generated_source=1
			need_go_test=1
			need_make_test=1
			need_go_generate=1
			need_modules_spec=1
			need_rules_spec=1
			need_events_spec=1
			need_stats_spec=1
			;;
		internal/dataplane/*)
			has_backend=1
			has_dataplane=1
			has_product=1
			has_generated_source=1
			need_go_test=1
			need_make_test=1
			need_go_generate=1
			need_modules_spec=1
			need_rules_spec=1
			need_events_spec=1
			need_stats_spec=1
			;;
		internal/response/*)
			has_backend=1
			has_response=1
			has_product=1
			need_go_test=1
			need_modules_spec=1
			need_rules_spec=1
			need_responses_spec=1
			;;
		cmd/*|internal/*|configs/*|deploy/*)
			has_backend=1
			has_product=1
			need_go_test=1
			;;
	esac
done

if [[ $has_generated -eq 1 && $has_generated_source -eq 0 ]]; then
	failures+=("internal/dataplane/sidersp_bpfel.go changed without source changes. Regenerate it from bpf/ or internal/dataplane/ inputs.")
fi

if [[ $has_product -eq 1 && $has_specs -eq 0 ]]; then
	warnings+=("Product-facing files changed without spec edits. Confirm no contract changed, or update the matching spec.")
fi

echo "ai-review: $diff_mode changes"
printf '  - %s\n' "${files[@]}"

echo
echo "areas:"
if [[ $has_agent -eq 1 ]]; then
	echo "  - agent workflow"
fi
if [[ $has_backend -eq 1 ]]; then
	echo "  - backend"
fi
if [[ $has_dataplane -eq 1 ]]; then
	echo "  - dataplane"
fi
if [[ $has_response -eq 1 ]]; then
	echo "  - response"
fi
if [[ $has_web -eq 1 ]]; then
	echo "  - web"
fi

echo
echo "specs to inspect:"
if [[ $need_modules_spec -eq 1 ]]; then
	echo "  - specs/MODULES.md"
fi
if [[ $need_rules_spec -eq 1 ]]; then
	echo "  - specs/RULES.md"
fi
if [[ $need_events_spec -eq 1 ]]; then
	echo "  - specs/EVENTS.md"
fi
if [[ $need_responses_spec -eq 1 ]]; then
	echo "  - specs/RESPONSES.md"
fi
if [[ $need_stats_spec -eq 1 ]]; then
	echo "  - specs/STATS.md"
fi
if [[ $need_modules_spec -eq 0 && $need_rules_spec -eq 0 && $need_events_spec -eq 0 && $need_responses_spec -eq 0 && $need_stats_spec -eq 0 ]]; then
	echo "  - matching files in specs/ when behavior changes"
fi

echo
echo "verify commands:"
if [[ $need_go_test -eq 1 ]]; then
	echo "  - go test ./..."
fi
if [[ $need_make_test -eq 1 ]]; then
	echo "  - make test"
fi
if [[ $need_go_generate -eq 1 ]]; then
	echo "  - go generate ./internal/dataplane"
fi
if [[ $need_web_build -eq 1 ]]; then
	echo "  - npm --prefix web run build"
fi
if [[ $need_go_test -eq 0 && $need_make_test -eq 0 && $need_go_generate -eq 0 && $need_web_build -eq 0 ]]; then
	echo "  - diff review is usually enough for agent-only changes"
fi

echo
echo "templates:"
echo "  - .agent/templates/plan.md"
echo "  - .agent/templates/review.md"

if [[ ${#warnings[@]} -gt 0 ]]; then
	echo
	echo "warnings:"
	printf '  - %s\n' "${warnings[@]}"
fi

if [[ ${#failures[@]} -gt 0 ]]; then
	echo
	echo "failures:"
	printf '  - %s\n' "${failures[@]}"
	exit 1
fi
