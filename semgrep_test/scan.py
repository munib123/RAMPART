import subprocess
import json

result = subprocess.run(
    [
        "semgrep",
        "scan",
        "--config",
        "auto",
        "--json",
        "test_code",
    ],
    capture_output=True,
    text=True,
    encoding="utf-8", 
    errors = "replace",
)

if result.returncode == 0 or result.stdout:
    data = json.loads(result.stdout)

    print(f"Found {len(data['results'])} issue(s).")

    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print("Report saved.")
else:
    print(result.stderr)