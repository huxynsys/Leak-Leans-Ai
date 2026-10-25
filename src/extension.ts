import * as path from "node:path";
import * as vscode from "vscode";
import { triageWithDNotifier } from "./dnotifierAgent";
import type { Finding, ScanReport, Severity } from "./scanner";
import { scanWorkspace } from "./scanner";

const APP_ID_STORAGE_KEY = "dnotifierSecurityLens.appId";
const CREDENTIAL_STORAGE_KEY = "dnotifierSecurityLens.secret";
const OSV_CONSENT_KEY = "dnotifierSecurityLens.osvConsent";

let latestReport: ScanReport | undefined;

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("DNotifier Security Lens");
  const diagnostics = vscode.languages.createDiagnosticCollection("dnotifier-security-lens");
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 10);
  status.text = "$(shield) Security Lens";
  status.tooltip = "Scan this workspace with DNotifier Security Lens";
  status.command = "dnotifierSecurityLens.scanWorkspace";
  status.show();

  context.subscriptions.push(
    output,
    diagnostics,
    status,
    vscode.commands.registerCommand("dnotifierSecurityLens.scanWorkspace", async () => {
      await runScan(context, output, diagnostics);
    }),
    vscode.commands.registerCommand("dnotifierSecurityLens.configureCredentials", async () => {
      await configureCredentials(context);
    }),
    vscode.commands.registerCommand("dnotifierSecurityLens.triageWithAgent", async () => {
      await runAgentTriage(context, output);
    }),
    vscode.commands.registerCommand("dnotifierSecurityLens.resetOsvConsent", async () => {
      await context.globalState.update(OSV_CONSENT_KEY, undefined);
      void vscode.window.showInformationMessage("OSV dependency-check consent will be requested on the next scan.");
    }),
  );
}

export function deactivate(): void {
  latestReport = undefined;
}

async function runScan(
  context: vscode.ExtensionContext,
  output: vscode.OutputChannel,
  diagnostics: vscode.DiagnosticCollection,
): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) {
    void vscode.window.showErrorMessage("Open a workspace folder before running a security scan.");
    return;
  }

  const checkDependencies = await getOsvConsent(context);
  if (checkDependencies === undefined) {
    return;
  }

  output.clear();
  output.appendLine("DNotifier Security Lens — local workspace scan");
  output.appendLine("Source files and credential values stay on this machine.");
  if (checkDependencies) {
    output.appendLine("Dependency names and exact versions will be sent to OSV for advisory lookup.");
  }
  diagnostics.clear();
  latestReport = undefined;

  try {
    const report = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "DNotifier Security Lens",
        cancellable: false,
      },
      () => scanWorkspace(folders.map((folder) => folder.uri.fsPath), checkDependencies),
    );
    latestReport = report;
    showDiagnostics(report.findings, diagnostics, folders.map((folder) => folder.uri.fsPath));
    renderReport(report, output);
    output.show(true);
    if (report.dependencyAuditError) {
      void vscode.window.showWarningMessage(`Local scan completed, but OSV dependency lookup failed: ${report.dependencyAuditError}`);
    } else {
      void vscode.window.showInformationMessage(
        `Security scan complete: ${report.findings.length} finding(s) across ${report.scannedFiles} file(s).`,
      );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    output.appendLine(`Scan failed: ${message}`);
    output.show(true);
    void vscode.window.showErrorMessage(`DNotifier Security Lens scan failed: ${message}`);
  }
}

async function getOsvConsent(context: vscode.ExtensionContext): Promise<boolean | undefined> {
  const stored = context.globalState.get<boolean>(OSV_CONSENT_KEY);
  if (stored !== undefined) {
    return stored;
  }
  const choice = await vscode.window.showInformationMessage(
    "Check pinned dependencies with OSV? This sends package names and exact versions only; no source files or credentials are uploaded.",
    "Allow OSV checks",
    "Static checks only",
  );
  if (!choice) {
    return undefined;
  }
  const consent = choice === "Allow OSV checks";
  await context.globalState.update(OSV_CONSENT_KEY, consent);
  return consent;
}

async function configureCredentials(context: vscode.ExtensionContext): Promise<void> {
  const currentAppId = await context.secrets.get(APP_ID_STORAGE_KEY);
  const appId = await vscode.window.showInputBox({
    title: "DNotifier app ID",
    prompt: "Stored in VS Code SecretStorage. Do not enter the app secret here.",
    value: currentAppId,
    ignoreFocusOut: true,
  });
  if (!appId?.trim()) {
    return;
  }
  const secret = await vscode.window.showInputBox({
    title: "DNotifier app secret",
    prompt: "Stored in VS Code SecretStorage and never written to workspace files.",
    password: true,
    ignoreFocusOut: true,
  });
  if (!secret?.trim()) {
    return;
  }
  await context.secrets.store(APP_ID_STORAGE_KEY, appId.trim());
  await context.secrets.store(CREDENTIAL_STORAGE_KEY, secret.trim());
  void vscode.window.showInformationMessage("DNotifier credentials saved to VS Code SecretStorage.");
}

async function runAgentTriage(context: vscode.ExtensionContext, output: vscode.OutputChannel): Promise<void> {
  if (!latestReport) {
    void vscode.window.showWarningMessage("Run a workspace scan first.");
    return;
  }
  if (latestReport.findings.length === 0) {
    void vscode.window.showInformationMessage("No findings to triage. Run the DNotifier agent after a scan with findings.");
    return;
  }
  const appId = await context.secrets.get(APP_ID_STORAGE_KEY);
  const secret = await context.secrets.get(CREDENTIAL_STORAGE_KEY);
  if (!appId || !secret) {
    const action = await vscode.window.showWarningMessage(
      "Configure your DNotifier app ID and secret before running the agent.",
      "Configure credentials",
    );
    if (action) {
      await configureCredentials(context);
    }
    return;
  }

  const configuration = vscode.workspace.getConfiguration("dnotifierSecurityLens");
  const provider = configuration.get<string>("provider", "ollama").trim();
  const model = configuration.get<string>("model", "llama3.2").trim();
  if (!provider || !model) {
    void vscode.window.showErrorMessage("Set both dnotifierSecurityLens.provider and dnotifierSecurityLens.model in VS Code settings.");
    return;
  }

  const confirmation = await vscode.window.showInformationMessage(
    "Send finding metadata (rule, severity, title, recommendations, and package/version where relevant) to your configured DNotifier AI provider? Source code, file paths, and detected secret values are excluded.",
    "Run DNotifier Agent",
  );
  if (confirmation !== "Run DNotifier Agent") {
    return;
  }

  try {
    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "DNotifier workflow is running",
        cancellable: false,
      },
      () => triageWithDNotifier(latestReport!, { appId, secret, provider, model }),
    );
    output.appendLine("");
    output.appendLine("DNotifier agent triage");
    output.appendLine("======================");
    output.appendLine(result.text);
    if (result.executionId) {
      output.appendLine(`DNotifier execution ID: ${result.executionId}`);
    }
    output.show(true);
    void vscode.window.showInformationMessage("DNotifier agent triage complete. See the Security Lens output channel.");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    output.appendLine(`DNotifier agent failed: ${message}`);
    output.show(true);
    void vscode.window.showErrorMessage(`DNotifier agent failed: ${message}`);
  }
}

function showDiagnostics(findings: Finding[], diagnostics: vscode.DiagnosticCollection, rootPaths: string[]): void {
  const byUri = new Map<string, vscode.Diagnostic[]>();
  for (const finding of findings) {
    const absolutePath = resolveFindingPath(rootPaths, finding.file);
    if (!absolutePath) {
      continue;
    }
    const uri = vscode.Uri.file(absolutePath);
    const message = `[${finding.ruleId}] ${finding.title}\n${finding.recommendation}`;
    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(finding.line, 0, finding.line, 1),
      message,
      diagnosticSeverity(finding.severity),
    );
    diagnostic.source = "DNotifier Security Lens";
    const items = byUri.get(uri.toString()) ?? [];
    items.push(diagnostic);
    byUri.set(uri.toString(), items);
  }
  for (const [uri, items] of byUri) {
    diagnostics.set(vscode.Uri.parse(uri), items);
  }
}

function resolveFindingPath(rootPaths: string[], relativePath: string): string | undefined {
  for (const rootPath of rootPaths) {
    const candidate = path.resolve(rootPath, relativePath);
    const relative = path.relative(rootPath, candidate);
    if (relative && !relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative)) {
      return candidate;
    }
  }
  return undefined;
}

function diagnosticSeverity(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
  }
}

function renderReport(report: ScanReport, output: vscode.OutputChannel): void {
  output.appendLine(`Scanned files: ${report.scannedFiles}`);
  output.appendLine(`Dependencies checked with OSV: ${report.checkedDependencies}`);
  if (report.dependencyAuditError) {
    output.appendLine(`OSV lookup error: ${report.dependencyAuditError}`);
  }
  output.appendLine(`Findings: ${report.findings.length}`);
  output.appendLine("");
  for (const finding of report.findings) {
    output.appendLine(
      `[${finding.severity.toUpperCase()}] ${finding.file}:${finding.line + 1} ${finding.title}`,
    );
    output.appendLine(`  ${finding.recommendation}`);
  }
  if (report.scannedFiles >= 5000) {
    output.appendLine("");
    output.appendLine("Scan file limit reached (5000); some workspace files may not have been scanned.");
  }
}
