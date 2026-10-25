const test = require("node:test");
const assert = require("node:assert/strict");
const { normalizeExactVersion, parseRequirements, scanText } = require("../dist/scanner.js");

test("detects secret patterns without including the secret in findings", () => {
  const secret = process.env.DNOTIFIER_TEST_SECRET || "ghp_testfakeplaceholdertoken12345";
  const findings = scanText(`const token = "${secret}";`, "src/config.ts");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "secret.github-token");
  assert.equal(JSON.stringify(findings).includes(secret), false);
});

test("finds high-risk code patterns and reports zero-based lines", () => {
  const findings = scanText(`const safe = true;\nconst result = ${"ev" + "al"}(input);`, "src/app.js");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "code.dynamic-eval");
  assert.equal(findings[0].line, 1);
});

test("does not flag environment variable references as hard-coded values", () => {
  const findings = scanText('const apiKey = process.env.API_KEY;\nconst token = "${TOKEN}";', "src/config.ts");
  assert.equal(findings.length, 0);
});

test("parses only pinned requirements for OSV queries", () => {
  const dependencies = parseRequirements(
    "requests==2.31.0\nflask>=3.0\n# comment\nurllib3[secure]==2.2.1",
    "requirements.txt",
  );
  assert.deepEqual(
    dependencies.map(({ name, version }) => [name, version]),
    [["requests", "2.31.0"], ["urllib3", "2.2.1"]],
  );
});

test("accepts exact package versions but skips ranges and wildcards", () => {
  assert.equal(normalizeExactVersion("1.2.3"), "1.2.3");
  assert.equal(normalizeExactVersion("=1.2.3"), "1.2.3");
  assert.equal(normalizeExactVersion("^1.2.3"), undefined);
  assert.equal(normalizeExactVersion("1.2.*"), undefined);
});
