// Test helpers that read Azure DevOps pipeline YAML as text and pull out what a step runs,
// so the worker scripts can be executed in tests exactly as the agent would run them.
// Steps sit at 10 spaces of indentation and their script body at 14 (the layout every
// azure-pipelines-*.yml in this repository uses).
import { execFileSync } from 'node:child_process';

const STEP_SEPARATOR = /\n {10}- /;
const SCRIPT_INDENT = /^ {14}/gm;

// The bash body of the `- script: |` step with this displayName, dedented.
export function stepScript(pipeline, displayName) {
  const step = pipeline
    .split(STEP_SEPARATOR)
    .find((chunk) => chunk.includes(`displayName: '${displayName}'`));
  if (!step) throw new Error(`No step named '${displayName}'.`);
  const body = step.match(/^script: \|\n([\s\S]*?)\n {12}displayName:/);
  if (!body) throw new Error(`Step '${displayName}' is not a script step.`);
  return body[1].replace(SCRIPT_INDENT, '');
}

// The env mapping of that step as { NAME: 'value as written in the YAML' }.
export function stepEnv(pipeline, displayName) {
  const step = pipeline
    .split(STEP_SEPARATOR)
    .find((chunk) => chunk.includes(`displayName: '${displayName}'`));
  const block = step?.match(/\n {12}env:\n((?: {14}[A-Z0-9_]+: .*\n?)+)/);
  if (!block) return {};
  return Object.fromEntries(
    block[1]
      .trim()
      .split('\n')
      .map((line) =>
        line
          .trim()
          .split(/: (.*)/s)
          .slice(0, 2),
      ),
  );
}

// The JavaScript of the n-th `node <<'NODE'` heredoc in a step script.
export function nodeHeredoc(script, index = 0) {
  const blocks = [...script.matchAll(/node <<'NODE'[^\n]*\n([\s\S]*?)\nNODE\n/g)];
  if (!blocks[index]) throw new Error(`No node heredoc #${index} in the script.`);
  return blocks[index][1];
}

// Runs JavaScript the way the heredoc does (`node` reading the program from stdin).
// Returns { ok, output } instead of throwing, so tests can assert on refusals.
export function runNode(source, env) {
  try {
    const output = execFileSync('node', [], {
      input: source,
      env: { PATH: process.env.PATH, ...env },
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return { ok: true, output };
  } catch (error) {
    return { ok: false, output: `${error.stdout || ''}${error.stderr || ''}` };
  }
}

// Runs a bash script with the given environment. Returns { ok, status, output }.
export function runBash(script, env) {
  try {
    const output = execFileSync('bash', ['-c', script], {
      env: { PATH: process.env.PATH, ...env },
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return { ok: true, status: 0, output };
  } catch (error) {
    return {
      ok: false,
      status: error.status,
      output: `${error.stdout || ''}${error.stderr || ''}`,
    };
  }
}

// The allowed values of a runtime parameter (`values:` list), or [] when it has none.
export function parameterValues(pipeline, name) {
  const block = pipeline.match(
    new RegExp(
      `\\n  - name: ${name}\\n(?: {4}(?!values:)[^\\n]*\\n)*? {4}values:\\n((?: {6}- [^\\n]*\\n)+)`,
    ),
  );
  if (!block) return [];
  return block[1]
    .trim()
    .split('\n')
    .map((line) => line.trim().replace(/^- /, ''));
}

// A top-level `variables:` entry (pipeline-level variables are fixed for every run).
export function pipelineVariable(pipeline, name) {
  const block = pipeline.match(/\nvariables:\n((?: {2}[^\n]*\n|#[^\n]*\n|\n)+)/);
  const line = block?.[1].match(new RegExp(`^ {2}${name}: (.+)$`, 'm'));
  return line ? line[1].trim() : undefined;
}
