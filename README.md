# DNotifier Security Lens

A cross-platform VS Code extension for fast, local-first security checks. It combines deterministic static rules and OSV dependency advisories with a DNotifier workflow agent that prioritizes findings. The scanner is a hackathon MVP, not a replacement for a full SAST/SCA product.

## What it does

- Scans workspace source/config files locally for common exposed credentials and a small set of risky coding patterns.
- Checks pinned npm and Python requirements against the OSV vulnerability database after explicit user consent.
- Publishes findings as VS Code diagnostics and to the **DNotifier Security Lens** output channel.
- Runs a DNotifier workflow with a `security-lens-triage-agent` to explain and prioritize findings.
- Keeps DNotifier credentials in VS Code `SecretStorage`; no credentials are checked into project files.
- Works on Windows, macOS, and Linux through VS Code's Node.js extension host.

## Data handling

- Source text is read locally and is never sent to DNotifier or OSV.
- Detected secret values are never included in findings, output, diagnostics, or AI input.
- OSV checks are opt-in. If allowed, only package names and exact versions are sent to `https://api.osv.dev`.
- DNotifier AI triage is separately confirmed for every run. It receives finding rule IDs, severity, redacted titles/recommendations, and dependency names/versions where applicable. File paths and source code are excluded.
- DNotifier app ID and secret are entered through the extension command and stored in VS Code SecretStorage.
- The AI result is advisory. Validate findings and remediation yourself.

## DNotifier and open-model setup

1. Create/choose a DNotifier app in [app.dnotifier.com](https://app.dnotifier.com).
2. In **Projects → AI Studio → Providers**, configure an open-model provider. For example, configure an Ollama endpoint that DNotifier's AI runtime can reach, then pull a model such as `llama3.2`. DNotifier cloud workers cannot reach `127.0.0.1` on your laptop; use a reachable host/tunnel or another supported open-model provider.
3. In VS Code settings, set `dnotifierSecurityLens.provider` to the exact DNotifier provider ID (default: `ollama`) and `dnotifierSecurityLens.model` to the model ID exposed by that provider (default: `llama3.2`).
4. Run **DNotifier Security Lens: Configure DNotifier Credentials** and enter the DNotifier app ID and newly rotated app secret.
5. Run **DNotifier Security Lens: Scan Workspace**, then **DNotifier Security Lens: Triage Findings with DNotifier Agent**.

The agent is a DNotifier classic agent registered in a DNotifier workflow, with observability enabled and AI history saving disabled. Configure the selected provider/model in the DNotifier dashboard before running it.

## Run from source

Requirements: Node.js 18+, npm, and VS Code.

```sh
npm install
npm test
```

To try the extension locally, open this folder in VS Code, press **F5**, and run the commands listed above in the Extension Development Host.

## Scan coverage and limitations

- Scans common source/config extensions, `.env` files, `package.json`, and `requirements.txt`. It skips generated/dependency directories and files larger than 1 MiB; at most 5,000 files are considered per scan.
- OSV checks support pinned entries in `requirements.txt`, exact versions in `package.json`, and direct npm dependencies whose exact versions are present in `package-lock.json` / `npm-shrinkwrap.json`.
- Unpinned dependencies and other lockfile formats are not queried yet. A clean result does not prove a project is secure.
- Secret and code checks are heuristic; false positives and missed issues are possible. No dependency is installed or modified by this extension.

## Demo flow

1. Open a small sample project with a harmless fake token and an intentionally vulnerable pinned package.
2. Run a scan and show local diagnostics plus OSV results.
3. Configure DNotifier credentials and run the agent triage.
4. Show the DNotifier workflow execution in the dashboard, then discuss the privacy boundary: source and secret values stay local.
