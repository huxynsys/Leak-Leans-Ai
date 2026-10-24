import * as fs from "node:fs/promises";
import * as path from "node:path";

export type Severity = "critical" | "high" | "medium" | "low";
export type FindingSource = "secret" | "code" | "dependency";

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  file: string;
  line: number;
  source: FindingSource;
  recommendation: string;
  packageName?: string;
  packageVersion?: string;
  advisoryId?: string;
}

export interface ScanReport {
  findings: Finding[];
  scannedFiles: number;
  checkedDependencies: number;
  dependencyAuditError?: string;
}

interface SourceRule {
  id: string;
  title: string;
  severity: Severity;
  pattern: RegExp;
  recommendation: string;
  source: "secret" | "code";
  redactEvidence?: boolean;
}

interface Dependency {
  name: string;
  version: string;
  ecosystem: "npm" | "PyPI";
  manifest: string;
  line: number;
}

const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 5000;
const OSV_BATCH_SIZE = 100;
const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  ".next",
  ".turbo",
  ".venv",
  "__pycache__",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "out",
  "target",
  "vendor",
]);

const RULES: SourceRule[] = [
  {
    id: "secret.private-key",
    title: "Private key material in a file",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    recommendation: "Remove the key from the repository, revoke or rotate it, and load it from a secret manager.",
    source: "secret",
    redactEvidence: true,
  },
  {
    id: "secret.aws-access-key",
    title: "AWS access key identifier",
    severity: "high",
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
    recommendation: "Revoke or rotate the credential and move secrets to a secret manager.",
    source: "secret",
    redactEvidence: true,
  },
  {
    id: "secret.github-token",
    title: "GitHub token",
    severity: "high",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/,
    recommendation: "Revoke or rotate the token and move secrets to a secret manager.",
    source: "secret",
    redactEvidence: true,
  },
  {
    id: "secret.slack-token",
    title: "Slack token",
    severity: "high",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    recommendation: "Revoke or rotate the token and move secrets to a secret manager.",
    source: "secret",
    redactEvidence: true,
  },
  {
    id: "secret.hardcoded-credential",
    title: "Credential-like value assigned in source",
    severity: "high",
    pattern: /\b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|access[_-]?token)\b\s*[:=]\s*["'`]([^"'`]{8,})["'`]/i,
    recommendation: "Replace the hard-coded value with an environment variable or secret manager reference; rotate it if real.",
    source: "secret",
    redactEvidence: true,
  },
  {
    id: "code.dynamic-eval",
    title: "Dynamic code evaluation",
    severity: "high",
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(/,
    recommendation: "Avoid evaluating dynamically constructed code; use an explicit parser or allowlisted operation.",
    source: "code",
  },
  {
    id: "code.tls-verification-disabled",
    title: "TLS certificate verification disabled",
    severity: "high",
    pattern: /\brejectUnauthorized\s*:\s*false\b|\bverify\s*=\s*False\b/,
    recommendation: "Enable TLS certificate verification and configure a trusted CA when necessary.",
    source: "code",
  },
  {
    id: "code.weak-password-hash",
    title: "MD5 or SHA-1 used for hashing",
    severity: "medium",
    pattern: /\bcreateHash\s*\(\s*["'](?:md5|sha1)["']\s*\)|\bhashlib\.(?:md5|sha1)\s*\(/i,
    recommendation: "For password storage use a password hashing algorithm such as Argon2id, scrypt, or bcrypt; for other uses choose a modern hash.",
    source: "code",
  },
];

const SOURCE_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".cpp",
  ".cs",
  ".env",
  ".go",
  ".h",
  ".hpp",
  ".html",
  ".java",
  ".js",
  ".jsx",
  ".kt",
  ".php",
  ".properties",
  ".py",
  ".rb",
  ".rs",
  ".sh",
  ".swift",
  ".tf",
  ".toml",
  ".ts",
  ".tsx",
  ".vue",
  ".xml",
  ".yaml",
  ".yml",
]);

const OMITTED_SECRET_VALUES = /^(?:\$\{[^}]+\}|<[^>]+>|your[_ -].*|example|sample|placeholder|changeme|change-me|password|secret|none|null|undefined)$/i;

export function scanText(text: string, file: string): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((line, index) => {
    for (const rule of RULES) {
      const match = rule.pattern.exec(line);
      if (!match) {
        continue;
      }
      if (rule.id === "secret.hardcoded-credential") {
        const value = match[1]?.trim();
        if (!value || OMITTED_SECRET_VALUES.test(value) || /\bprocess\.env\b|\bos\.environ\b/i.test(value)) {
          continue;
        }
      }
      findings.push({
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        file,
        line: index,
        source: rule.source,
        recommendation: rule.recommendation,
      });
    }
  });
  return findings;
}

export function parseRequirements(text: string, manifest: string): Dependency[] {
  const dependencies: Dependency[] = [];
  text.split(/\r?\n/).forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) {
      return;
    }
    const match = /^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!-]*)/.exec(trimmed);
    const version = match ? normalizeExactVersion(match[2]) : undefined;
    if (match && version) {
      dependencies.push({
        name: match[1],
        version,
        ecosystem: "PyPI",
        manifest,
        line: index,
      });
    }
  });
  return dependencies;
}

export function normalizeExactVersion(specifier: string): string | undefined {
  const version = specifier.trim().replace(/^[=v]/i, "");
  return /^\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?$/.test(version) ? version : undefined;
}

export async function scanWorkspace(rootPaths: string[], checkDependencies: boolean): Promise<ScanReport> {
  const files: string[] = [];
  for (const rootPath of rootPaths) {
    await collectFiles(rootPath, files);
    if (files.length >= MAX_FILES) {
      break;
    }
  }

  const findings: Finding[] = [];
  const dependencyInputs: Array<{ path: string; text: string }> = [];
  const npmLocks: Array<{ path: string; text: string }> = [];
  let scannedFiles = 0;

  for (const filePath of files) {
    let stat: Awaited<ReturnType<typeof fs.stat>>;
    try {
      stat = await fs.stat(filePath);
    } catch {
      continue;
    }
    if (stat.size > MAX_FILE_BYTES) {
      continue;
    }

    let text: string;
    try {
      text = await fs.readFile(filePath, "utf8");
    } catch {
      continue;
    }
    if (text.includes("\u0000")) {
      continue;
    }
    scannedFiles++;
    const relativePath = rootRelativePath(rootPaths, filePath);
    findings.push(...scanText(text, relativePath));

    const baseName = path.basename(filePath).toLowerCase();
    if (baseName === "package.json" || baseName === "requirements.txt") {
      dependencyInputs.push({ path: relativePath, text });
    } else if (baseName === "package-lock.json" || baseName === "npm-shrinkwrap.json") {
      npmLocks.push({ path: relativePath, text });
    }
  }

  if (!checkDependencies) {
    return { findings, scannedFiles, checkedDependencies: 0 };
  }

  const dependencies = collectDependencies(dependencyInputs, npmLocks);
  try {
    const auditFindings = await auditDependencies(dependencies);
    findings.push(...auditFindings);
    return {
      findings,
      scannedFiles,
      checkedDependencies: dependencies.length,
    };
  } catch (error) {
    return {
      findings,
      scannedFiles,
      checkedDependencies: 0,
      dependencyAuditError: error instanceof Error ? error.message : String(error),
    };
  }
}

async function collectFiles(directory: string, files: string[]): Promise<void> {
  if (files.length >= MAX_FILES) {
    return;
  }
  let entries: any[];
  try {
    entries = (await fs.readdir(directory, { withFileTypes: true })) as any[];
  } catch {
    return;
  }
  for (const entry of entries) {
    if (files.length >= MAX_FILES) {
      return;
    }
    const entryName = String(entry.name);
    const fullPath = path.join(directory, entryName);
    if (entry.isDirectory()) {
      if (!IGNORED_DIRECTORIES.has(entryName)) {
        await collectFiles(fullPath, files);
      }
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    const baseName = entryName.toLowerCase();
    const extension = path.extname(baseName);
    if (
      SOURCE_EXTENSIONS.has(extension) ||
      baseName === ".env" ||
      baseName.startsWith(".env.") ||
      baseName === "package.json" ||
      baseName === "package-lock.json" ||
      baseName === "npm-shrinkwrap.json" ||
      baseName === "requirements.txt"
    ) {
      files.push(fullPath);
    }
  }
}

function rootRelativePath(rootPaths: string[], filePath: string): string {
  for (const rootPath of rootPaths) {
    const relative = path.relative(rootPath, filePath);
    if (relative && !relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative)) {
      return relative;
    }
  }
  return path.basename(filePath);
}

function collectDependencies(
  manifests: Array<{ path: string; text: string }>,
  lockFiles: Array<{ path: string; text: string }>,
): Dependency[] {
  const lockVersions = new Map<string, string>();
  for (const lock of lockFiles) {
    try {
      const parsed: unknown = JSON.parse(lock.text);
      if (!isRecord(parsed) || !isRecord(parsed.packages)) {
        continue;
      }
      for (const [lockPath, value] of Object.entries(parsed.packages)) {
        if (!isRecord(value) || typeof value.version !== "string") {
          continue;
        }
        const packageName =
          typeof value.name === "string"
            ? value.name
            : lockPath.startsWith("node_modules/")
              ? lockPath.slice("node_modules/".length).split("/node_modules/").at(-1)
              : undefined;
        if (packageName) {
          lockVersions.set(packageName, value.version);
        }
      }
    } catch {
      continue;
    }
  }

  const dependencies: Dependency[] = [];
  for (const manifest of manifests) {
    if (path.basename(manifest.path).toLowerCase() === "requirements.txt") {
      dependencies.push(...parseRequirements(manifest.text, manifest.path));
      continue;
    }
    try {
      const parsed: unknown = JSON.parse(manifest.text);
      if (!isRecord(parsed)) {
        continue;
      }
      for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
        const entries = parsed[section];
        if (!isRecord(entries)) {
          continue;
        }
        for (const [name, rawVersion] of Object.entries(entries)) {
          if (typeof rawVersion !== "string") {
            continue;
          }
          const version = lockVersions.get(name) ?? normalizeExactVersion(rawVersion);
          if (version) {
            dependencies.push({
              name,
              version,
              ecosystem: "npm",
              manifest: manifest.path,
              line: 0,
            });
          }
        }
      }
    } catch {
      continue;
    }
  }
  const seen = new Set<string>();
  return dependencies.filter((dependency) => {
    const key = `${dependency.ecosystem}:${dependency.name}@${dependency.version}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

async function auditDependencies(dependencies: Dependency[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (let start = 0; start < dependencies.length; start += OSV_BATCH_SIZE) {
    const batch = dependencies.slice(start, start + OSV_BATCH_SIZE);
    const response = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: batch.map((dependency) => ({
          package: { name: dependency.name, ecosystem: dependency.ecosystem },
          version: dependency.version,
        })),
      }),
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) {
      throw new Error(`OSV returned HTTP ${response.status}.`);
    }
    const payload: unknown = await response.json();
    if (!isRecord(payload) || !Array.isArray(payload.results)) {
      throw new Error("OSV returned an invalid response.");
    }
    payload.results.forEach((result, index) => {
      const dependency = batch[index];
      if (!dependency || !isRecord(result) || !Array.isArray(result.vulns)) {
        return;
      }
      for (const vulnerability of result.vulns) {
        if (!isRecord(vulnerability) || typeof vulnerability.id !== "string") {
          continue;
        }
        const summary = typeof vulnerability.summary === "string" ? vulnerability.summary : "Known vulnerable dependency";
        findings.push({
          ruleId: "dependency.osv-advisory",
          title: `${dependency.name}@${dependency.version}: ${summary}`,
          severity: osvSeverity(vulnerability),
          file: dependency.manifest,
          line: dependency.line,
          source: "dependency",
          recommendation: `Review ${vulnerability.id} and upgrade to a fixed version listed by OSV.`,
          packageName: dependency.name,
          packageVersion: dependency.version,
          advisoryId: vulnerability.id,
        });
      }
    });
  }
  return findings;
}

function osvSeverity(vulnerability: Record<string, unknown>): Severity {
  const databaseSpecific = vulnerability.database_specific;
  if (isRecord(databaseSpecific) && typeof databaseSpecific.severity === "string") {
    const severity = databaseSpecific.severity.toLowerCase();
    if (severity === "critical" || severity === "high" || severity === "medium" || severity === "low") {
      return severity;
    }
  }
  const severities = vulnerability.severity;
  if (Array.isArray(severities)) {
    for (const item of severities) {
      if (!isRecord(item) || typeof item.score !== "string") {
        continue;
      }
      const score = Number(item.score);
      if (Number.isFinite(score) && score >= 0 && score <= 10) {
        if (score >= 9) return "critical";
        if (score >= 7) return "high";
        if (score >= 4) return "medium";
        return "low";
      }
    }
  }
  return "medium";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
