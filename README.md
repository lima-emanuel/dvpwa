# Projeto Básico de Exame – DevSecOps com LLM

Emanuel Lima de Sousa

## Objetivo

Construir uma esteira simples e reproduzível de segurança de software para o DVPWA – Damn Vulnerable Python Web Application.

### Passos

Scan Inicial → Triagem com LLM → Remediação com LLM → Patches Manuais → Segunda Esteira de Validação

## Reprodução

Para reproduzir os resultados, basta rodar os pipelines na aba de Actions, escolher o workflow e então clicar em Run Workflow.

## Prompt de Triagem com LLM

Using the prompt triage-prompt.md and the json files at the scan-before folder, do the following tasks:

- Group duplicated or equivalent findings
- Identify probable false positives and explain them
- Prioritize findings that look explorable on this repo
- Choose at least 2 candidate vulnerabilities to correct
- For each vulnerability, identify evidence, file and line numbers, probable cause and correction strategy

Output:

- Table with: ID, Tool, File, Severity, Decision, Justification
- Final section: selected vulnerabilities for remediation

Write your output on the llm/llm-triage.md file

## Prompt de Remediação com LLM

Given the triage at llm/llm-triage, do the following:

- For each selected vulnerability, explain it's root cause
- Propose a minimal and safe patch
- Indicate which functional tests should still pass
- Indicate a regression test that demonstrates that the exploit no longer works
- Avoid fixes that just hide the alert without fixing the root cause

Output format:

- Vulnerability
- Root cause
- Proposed patch
- Regression test
- How to confirm on a second vulnerability scan

Write your output on the llm/llm-remediation.md file

## Pull Request

<https://github.com/lima-emanuel/dvpwa/pull/1>

P.S.: O README original está [aqui](__README.md).
