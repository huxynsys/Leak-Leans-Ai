# DNotifier Security Lens

**Find security issues earlier, without uploading your source code.**

DNotifier Security Lens is a cross-platform Visual Studio Code extension that checks your workspace for a small set of common security risks, optionally looks up pinned dependencies in the OSV vulnerability database, and uses DNotifier AI to help prioritize findings.

Scanning happens locally in the extension. DNotifier receives a limited summary of findings only when you choose to run AI triage. This is a hackathon MVP and an educational aid—not a replacement for a full security review, SAST, or software-composition analysis product.

## At a glance

- **Local checks:** Detects selected credential patterns and risky code patterns in supported workspace files.
- **Dependency advisories:** Optionally queries OSV with supported package names and exact versions.
- **DNotifier AI triage:** Runs a workflow containing a classic DNotifier agent to explain and prioritize findings.
- **VS Code integration:** Shows findings as editor diagnostics and in an output channel.
- **Credential storage:** Saves the DNotifier app ID and secret in VS Code SecretStorage, not in project settings.
- **Cross-platform:** Runs in the VS Code extension host on Windows, macOS, and Linux.

## Quick start

### Requirements

- Visual Studio Code 1.85 or later
- Node.js 18 or later
- npm
- A DNotifier app with AI enabled and a provider/model configured if you want AI triage

### Run the extension from source

1. Clone or download this repository and open its folder in VS Code.
2. In a terminal at the project root, install dependencies and run the tests:

   ```sh
   npm install
   npm test
   ```

3. Press **F5** in VS Code to launch the **Extension Development Host**.
4. In the Extension Development Host, open the project folder you want to scan.
5. Open the Command Palette (**Ctrl+Shift+P** on Windows/Linux, **Cmd+Shift+P** on macOS) and run **DNotifier Security Lens: Scan Workspace**.
6. The first scan asks whether to check supported pinned dependencies with OSV. Choose **Allow OSV checks** or **Static checks only**.
7. To use AI triage, configure DNotifier as described below, then run **DNotifier Security Lens: Triage Findings with DNotifier Agent**.

You can find findings in the editor's **Problems** panel and in **View → Output**, under **DNotifier Security Lens**.

### Install a packaged extension

To create a VSIX package from source:

```sh
npm install
npm run package
```

This creates a `.vsix` file in the project folder. In VS Code, open the Extensions view, select **… → Install from VSIX…**, and choose that file.

## Configure DNotifier

The extension defines a DNotifier workflow at runtime and registers the `security-lens-triage-agent` with it. The workflow is named `security-lens-triage`. The agent uses the provider and model selected in VS Code settings.

1. In the DNotifier dashboard, choose the app you intend to use.
2. Enable AI for that app and configure a provider/model supported by your DNotifier account.
3. If using a self-hosted or local model provider such as Ollama, make sure the DNotifier runtime can reach the provider. A cloud-hosted DNotifier runtime generally cannot reach `localhost` on your computer.
4. In VS Code, set these settings to the exact provider and model identifiers configured in DNotifier:

   | Setting | Default | Purpose |
   | --- | --- | --- |
   | `dnotifierSecurityLens.provider` | `ollama` | DNotifier AI provider ID |
   | `dnotifierSecurityLens.model` | `llama3.2` | Model ID available through that provider |

5. In the Command Palette, run **DNotifier Security Lens: Configure DNotifier Credentials**. Enter your app ID and app secret when prompted. The secret input is masked and both values are stored in VS Code SecretStorage.
6. Run a workspace scan and then run **DNotifier Security Lens: Triage Findings with DNotifier Agent**. The extension asks for confirmation before sending finding metadata.

The workflow has observability enabled and the agent's AI request uses `saveHistory: false`. This does **not** mean workflow observability or execution metadata is disabled. Whether and where an execution appears in the DNotifier dashboard depends on the app, account, and DNotifier observability features available to you. A workflow defined in extension code is not, by itself, a saved workflow configured in the dashboard.

## Commands

| Command | What it does |
| --- | --- |
| **DNotifier Security Lens: Scan Workspace** | Scans the open workspace, displays findings, and asks for OSV consent the first time. |
| **DNotifier Security Lens: Configure DNotifier Credentials** | Stores the DNotifier app ID and secret in VS Code SecretStorage. |
| **DNotifier Security Lens: Triage Findings with DNotifier Agent** | After a scan with findings, asks for confirmation and sends limited finding metadata to DNotifier. |
| **DNotifier Security Lens: Reset OSV Check Consent** | Clears the saved OSV choice so the extension asks again on the next scan. |

## What is checked

### Local source and configuration checks

The scanner searches supported source and configuration file types for these heuristic patterns:

- Private-key material
- AWS access-key identifiers
- GitHub tokens
- Slack tokens
- Credential-like values assigned directly in source
- Dynamic code evaluation using `eval` or `new Function`
- Disabled TLS certificate verification in selected common forms
- MD5 or SHA-1 hashing calls

Potential findings are shown with a severity, rule ID, file location, and remediation suggestion. These rules are intentionally limited: they can report false positives and miss issues that require deeper analysis.

### Optional OSV dependency checks

If you allow OSV checks, the extension queries `https://api.osv.dev` with package names, ecosystems, and exact versions. The current implementation supports:

- Exact npm dependency versions in `package.json`
- npm dependency versions resolved from supported `package-lock.json` or `npm-shrinkwrap.json` `packages` entries
- Pinned Python entries using `==` in `requirements.txt`

Dependency ranges, unpinned Python requirements, and other ecosystems or lockfile formats are not comprehensively checked. No packages are installed, changed, or removed.

## Privacy and data handling

| Data | Where it goes |
| --- | --- |
| Workspace file contents | Read locally for scanning; not included in the DNotifier or OSV request payloads |
| Detected credential values | Not retained in findings or sent to DNotifier; matching is used to create a generic finding |
| File paths | Used locally to show editor diagnostics and output; excluded from the DNotifier triage summary |
| OSV dependency lookup data | Only package name, ecosystem, and exact version are sent to OSV, and only after you allow checks |
| DNotifier triage data | Sent only after you choose the triage command and confirm the prompt; includes summary counts and at most 40 finding records |
| DNotifier app credentials | App ID and secret are used to connect to DNotifier and stored in VS Code SecretStorage |

The DNotifier triage summary includes scanned-file and dependency counts, counts by severity, and selected finding metadata: rule ID, title, severity, source category, recommendation, package name/version, and advisory ID where available. It does not include source text, file paths, or the detected secret value.

Requests to DNotifier are subject to DNotifier's service, provider, and account logging and retention behavior. Disabling AI history saving in the agent request should not be treated as disabling workflow observability or all service-side logging. Do not send findings to a provider or service unless its data-handling terms are acceptable to you.

## Scan limits and known limitations

- Scans supported source/configuration extensions, `.env` files, `package.json`, supported npm lockfiles, and `requirements.txt`.
- Skips common generated and dependency directories, including `.git`, `node_modules`, `dist`, `build`, `coverage`, and `.venv`.
- Skips files larger than 1 MiB and considers at most 5,000 matching files per scan.
- Uses pattern-based rules rather than full language parsing or control/data-flow analysis.
- Does not install or modify dependencies.
- A clean scan does not establish that a project is secure.
- DNotifier AI output is advisory. Verify findings and recommendations before acting on them.

## Troubleshooting

### The scan command is missing

Make sure a workspace folder is open. When developing from source, press **F5** and run the command in the newly opened Extension Development Host—not in the original VS Code window.

### No findings appear

The scanner only checks supported file types and listed patterns. Confirm that the relevant files are inside the open workspace, are not in an ignored directory, and are no larger than 1 MiB. Heuristic checks can miss issues.

### OSV did not check dependencies

Choose **Allow OSV checks** when prompted. The current scanner only queries the supported exact/pinned dependency formats described above. If OSV is unavailable or returns an error, local scanning still completes and reports the lookup error.

To change a saved consent choice, run **DNotifier Security Lens: Reset OSV Check Consent** and scan again.

### DNotifier triage fails

- Confirm that the app ID and secret are correct and belong to the selected DNotifier app.
- Confirm that AI is enabled for that app.
- Check that the provider and model settings exactly match a configured DNotifier provider/model.
- Ensure the provider is reachable from DNotifier's runtime.
- Run a scan with findings first; the triage command has nothing to send when there are no findings.

The extension reports connection, AI-configuration, and workflow errors in VS Code notifications and the **DNotifier Security Lens** output channel.

## Development

Install dependencies and run the project checks:

```sh
npm install
npm test
```

Other scripts:

```sh
npm run build       # Compile TypeScript into dist/
npm run typecheck   # Type-check without emitting files
npm run package     # Build and package a VSIX using vsce
```

### Project structure

```text
src/
  extension.ts       VS Code commands, settings, credentials, and UI
  scanner.ts         Local pattern checks and optional OSV queries
  dnotifierAgent.ts  DNotifier agent and workflow integration
test/
  scanner.test.cjs   Scanner tests
```

## Hackathon demo outline

1. Open a small sample workspace containing harmless test strings and supported dependency manifests.
2. Run **Scan Workspace** and show the findings in the Problems panel and output channel.
3. Explain the opt-in OSV lookup and the local-only source scan.
4. Configure the DNotifier app and run AI triage after reviewing the confirmation prompt.
5. Show the triage response and, if available for the configured DNotifier app, the observed workflow execution in its dashboard.
6. Explain the boundaries: deterministic checks run locally; only the limited finding summary is sent for AI triage.

## License

The project declares the MIT license in `package.json`.
