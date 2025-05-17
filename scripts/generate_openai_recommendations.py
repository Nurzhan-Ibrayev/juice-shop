import json
import sys
import os
from openai import OpenAI
from openai import OpenAIError
from dotenv import load_dotenv

load_dotenv()

def detect_language(issue):
    """Detects programming language from check_id or file extension."""
    check_id = issue.get("check_id", "")
    file_path = issue.get("path", "")
    extension_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".java": "Java", ".go": "Go", ".php": "PHP", ".rb": "Ruby",
        ".c": "C", ".cpp": "C++", ".cs": "C#", ".sol": "Solidity"
    }
    for lang in ["python", "javascript", "typescript", "java", "go", "php", "ruby", "c", "cpp", "csharp", "solidity"]:
        if lang in check_id.lower():
            return lang.capitalize()
    ext = os.path.splitext(file_path)[1].lower()
    return extension_map.get(ext, "Unknown")

def get_openai_recommendation(issue):
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    metadata = issue.get("extra", {}).get("metadata", {})
    severity = issue.get("extra", {}).get("severity", "UNKNOWN")
    cwe = ", ".join(metadata.get("cwe", [])) if metadata.get("cwe") else "N/A"
    owasp = ", ".join(metadata.get("owasp", [])) if metadata.get("owasp") else "N/A"
    language = detect_language(issue)
    prompt = f"""
You are a code security expert. The following issue was found by Semgrep:
- File: {issue['path']}
- Line: {issue['start']['line']}
- Issue: {issue['extra']['message']}
- Rule: {issue['check_id']}
- Severity: {severity}
- CWE: {cwe}
- OWASP: {owasp}
- Language: {language}

Provide a clear and concise recommendation to fix this issue in {language}. Use Markdown formatting, include a code example if relevant, and keep it under 100 words. Reference provided URLs if relevant: {', '.join(metadata.get('references', []))}.
"""
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful code security assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=150,
            temperature=0.7
        )
        return response.choices[0].message.content
    except OpenAIError as e:
        return f"**Error**: Failed to get recommendation from Open AI: {str(e)}"
    except Exception as e:
        return f"**Error**: Unexpected error: {str(e)}"

def main():
    if len(sys.argv) != 2:
        print("Usage: python generate_openai_recommendations.py <semgrep.json>")
        sys.exit(1)
    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found")
        sys.exit(1)
    with open(input_file) as f:
        data = json.load(f)
    recommendations = []
    cache = {}
    for issue in data.get("results", [])[:10]:
        severity = issue.get("extra", {}).get("severity")
        if severity in ["ERROR", "WARNING"]:
            cache_key = f"{issue['check_id']}:{issue['extra']['message']}"
            if cache_key in cache:
                reco = cache[cache_key]
            else:
                reco = get_openai_recommendation(issue)
                cache[cache_key] = reco
            recommendations.append(
                f"### Issue in {issue['path']}:{issue['start']['line']}\n"
                f"**Rule**: {issue['check_id']}\n"
                f"**Severity**: {severity}\n"
                f"**Message**: {issue['extra']['message']}\n"
                f"**Language**: {detect_language(issue)}\n"
                f"**Recommendation**:\n{reco}\n"
            )
    output_file = "recommendations.md"
    with open(output_file, "w") as f:
        if recommendations:
            f.write("# Semgrep + Open AI Recommendations\n\n")
            f.write("\n".join(recommendations))
        else:
            f.write("No critical issues found by Semgrep.")

if __name__ == "__main__":
    main()
