import json
import os


def load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


# 1. Compare Bandit
before_bandit = load_json("resultados/scan-before/bandit-results.json", {"results": []})
after_bandit = load_json("resultados/scan-after/bandit-results.json", {"results": []})


def get_bandit_issues(data):
    return set(
        f"{r.get('test_id')} in {r.get('filename')}" for r in data.get("results", [])
    )


before_b = get_bandit_issues(before_bandit)
after_b = get_bandit_issues(after_bandit)

# 2. Compare Semgrep
before_semgrep = load_json(
    "resultados/scan-before/semgrep-results.json", {"results": []}
)
after_semgrep = load_json("resultados/scan-after/semgrep-results.json", {"results": []})


def get_semgrep_issues(data):
    return set(
        f"{r.get('check_id')} in {r.get('path')}" for r in data.get("results", [])
    )


before_s = get_semgrep_issues(before_semgrep)
after_s = get_semgrep_issues(after_semgrep)

# Resolved issues are ones that were in BEFORE but not in AFTER
fixed_b = before_b - after_b
fixed_s = before_s - after_s

report_lines = ["# Mitigation Validation Report\n"]

if fixed_b or fixed_s:
    report_lines.append("### Successfully Mitigated Vulnerabilities:\n")
    report_lines.append(
        "The following findings were detected in the baseline scan but are no longer present, indicating the fixes were successful:\n"
    )
    for issue in fixed_b:
        report_lines.append(f"- **Bandit**: `{issue}`")
    for issue in fixed_s:
        report_lines.append(f"- **Semgrep**: `{issue}`")
else:
    report_lines.append(
        "No previously detected vulnerabilities appear to be resolved in the new scan.\n"
    )

# Write out to a markdown file
report_path = "resultados/scan-after/mitigation-explanation.md"
with open(report_path, "w") as f:
    f.write("\n".join(report_lines))

# Also append to the GitHub Step Summary for visibility
with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
    f.write("\n".join(report_lines))

print("Comparison report generated successfully.")
