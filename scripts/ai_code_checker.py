#!/usr/bin/env python3
"""
AI Code Checker
Detecta patrones problemáticos específicos de código generado por IA
"""

import re
import ast
from pathlib import Path
from typing import List, Dict

class AICodeChecker:
    """Detecta patrones problemáticos en código generado por IA"""

    # Patrones sospechosos específicos de IA
    PATTERNS = {
        'hardcoded_secrets': {
            'patterns': [
                r'api_key\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']',
                r'secret\s*=\s*["\'].+["\']',
                r'password\s*=\s*["\'].+["\']',
                r'token\s*=\s*["\'][A-Za-z0-9_\-\.]{20,}["\']',
            ],
            'severity': 'CRITICAL',
            'description': 'Hardcoded secret detected'
        },
        'weak_crypto': {
            'patterns': [
                r'hashlib\.md5',
                r'hashlib\.sha1',
                r'import md5',
            ],
            'severity': 'HIGH',
            'description': 'Weak cryptographic algorithm'
        },
        'sql_injection_risk': {
            'patterns': [
                r'execute\s*\(\s*f["\']',  # f-strings in execute
                r'execute\s*\([^)]*\+',    # String concatenation
                r'\.format\([^)]*\).*execute',  # .format() in SQL
            ],
            'severity': 'CRITICAL',
            'description': 'SQL injection vulnerability'
        },
        'todo_comments': {
            'patterns': [
                r'#\s*TODO.*(?:fix|hack|temp)',
                r'#\s*HACK',
                r'#\s*FIXME',
            ],
            'severity': 'MEDIUM',
            'description': 'Temporary code markers'
        },
        'commented_code': {
            'patterns': [
                r'#\s*(def|class|import|from)\s+',
            ],
            'severity': 'LOW',
            'description': 'Commented code (AI generation artifact)'
        }
    }

    def __init__(self):
        self.issues = []

    def check_file(self, filepath: str) -> List[Dict]:
        """
        Analiza un archivo Python buscando patrones problemáticos

        Args:
            filepath: Path al archivo a analizar

        Returns:
            Lista de issues encontrados
        """
        try:
            with open(filepath, 'r') as f:
                content = f.read()
        except Exception as e:
            return [{'error': f"Could not read file: {e}"}]

        issues = []
        lines = content.split('\n')

        for category, config in self.PATTERNS.items():
            for pattern in config['patterns']:
                for i, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        issues.append({
                            'file': filepath,
                            'line': i,
                            'category': category,
                            'severity': config['severity'],
                            'description': config['description'],
                            'code': line.strip()[:80]  # Primeros 80 chars
                        })

        return issues

    def generate_report(self, issues: List[Dict]) -> str:
        """
        Genera reporte legible de issues

        Args:
            issues: Lista de issues encontrados

        Returns:
            Reporte formateado
        """
        if not issues:
            return "✅ No AI-specific issues found!"

        # Agrupar por severidad
        by_severity = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }

        for issue in issues:
            severity = issue.get('severity', 'MEDIUM')
            by_severity[severity].append(issue)

        report = "\n" + "="*70 + "\n"
        report += "🤖 AI CODE ANALYSIS REPORT\n"
        report += "="*70 + "\n\n"
        report += f"Total issues found: {len(issues)}\n\n"

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_issues = by_severity[severity]
            if not severity_issues:
                continue

            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '⚪'}[severity]
            report += f"\n{icon} {severity} ({len(severity_issues)} issues)\n"
            report += "-" * 70 + "\n"

            for issue in severity_issues[:5]:  # Mostrar primeros 5
                report += f"\n  File: {issue['file']}:{issue['line']}\n"
                report += f"  Issue: {issue['description']}\n"
                report += f"  Code: {issue['code']}\n"

        return report

# Función helper para usar en CLI
def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python ai_code_checker.py <file_or_directory>")
        sys.exit(1)

    checker = AICodeChecker()
    target = Path(sys.argv[1])

    all_issues = []

    if target.is_file():
        issues = checker.check_file(str(target))
        all_issues.extend(issues)
    elif target.is_dir():
        for py_file in target.rglob('*.py'):
            issues = checker.check_file(str(py_file))
            all_issues.extend(issues)

    print(checker.generate_report(all_issues))

    # Exit code basado en severidad
    critical = sum(1 for i in all_issues if i.get('severity') == 'CRITICAL')
    if critical > 0:
        print(f"\n❌ Found {critical} critical issues. Failing build.")
        sys.exit(1)
    else:
        print("\n✅ No critical issues found.")
        sys.exit(0)

if __name__ == '__main__':
    main()
