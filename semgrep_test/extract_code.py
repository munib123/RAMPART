import json
import ast

REPORT_FILE = "report.json"
OUTPUT_FILE = "extracted_code.py"


def extract_function(file_path, vulnerable_line):
    """
    Extract the entire function containing the vulnerable line.
    """

    with open(file_path, "r", encoding="utf-8") as f:
        source = f.read()

    tree = ast.parse(source)
    lines = source.splitlines()

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno

            if hasattr(node, "end_lineno") and node.end_lineno:
                end = node.end_lineno
            else:
                end = max(
                    getattr(n, "lineno", start)
                    for n in ast.walk(node)
                )

            if start <= vulnerable_line <= end:
                function_code = "\n".join(lines[start - 1:end])

                return {
                    "function_name": node.name,
                    "start_line": start,
                    "end_line": end,
                    "code": function_code,
                }

    return None


def main():
    with open(REPORT_FILE, "r", encoding="utf-8") as f:
        report = json.load(f)

    results = report.get("results", [])

    if not results:
        print("No vulnerabilities found.")
        return

    output_lines = []

    for i, finding in enumerate(results, 1):

        file_path = finding["path"]
        vulnerable_line = finding["start"]["line"]

        print("=" * 70)
        print(f"Finding #{i}")
        print(f"File: {file_path}")
        print(f"Vulnerable Line: {vulnerable_line}")

        function = extract_function(file_path, vulnerable_line)

        if function:

            print(f"\nFunction: {function['function_name']}")
            print(f"Lines: {function['start_line']} - {function['end_line']}")

            print("\nExtracted Function:\n")
            print(function["code"])

            output_lines.append(function["code"])

            print(f"\nCode written to '{OUTPUT_FILE}'")

        else:
            print("Could not locate containing function.")

        print("=" * 70)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n\n".join(output_lines))


if __name__ == "__main__":
    main()