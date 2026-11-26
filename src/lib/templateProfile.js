// SSI — OS template profiles: which packages a template build removes (docs/os-template-poc.md,
// "Template profili").
//
// A profile is chosen from a list, never typed: the list is the packages actually installed in
// the template (removal-impact.jsonl, written inside the build VM), each with the packages its
// removal would take along and its vulnerabilities. Protected packages (kernel, boot, SSH,
// cloud-init, package manager, guest agents, and every Essential or required package) can never
// be selected and may never be part of a removal. The build VM checks the same rules again
// right before it removes anything (guest/minimize.sh); this module is the shared definition for
// the build host and the SSI screen. Pure: no I/O.

export const PROFILE_VERSION = 'ssi.os-template-profile/v1';
export const MAX_REMOVALS = 500;

// Debian package names: lower-case letters, digits, '+', '-', '.', at least two characters,
// starting with a letter or digit (Debian Policy 5.6.1). Nothing else can reach apt.
const PACKAGE_NAME = /^[a-z0-9][a-z0-9+.-]+$/;
const PATTERN = /^[a-z0-9*][a-z0-9+.*-]*$/;
const PROFILE_NAME = /^[a-z0-9][a-z0-9-]{1,62}$/;

export class TemplateProfileError extends Error {
  constructor(problems) {
    super(problems.join(' '));
    this.name = 'TemplateProfileError';
    this.statusCode = 422;
    this.problems = problems;
  }
}

export const isPackageName = (value) => typeof value === 'string' && PACKAGE_NAME.test(value);

// protected-packages.txt: one pattern per line, '*' as the only wildcard, '#' comments.
export function parseProtectedPatterns(text) {
  const patterns = [];
  for (const raw of String(text || '').split('\n')) {
    const line = raw.replace(/#.*/, '').trim();
    if (!line) continue;
    if (!PATTERN.test(line))
      throw new TemplateProfileError([`Invalid protected package pattern: ${line}`]);
    patterns.push(line);
  }
  return patterns;
}

const globToRegExp = (pattern) =>
  new RegExp(`^${pattern.replace(/[.+]/g, '\\$&').replace(/\*/g, '.*')}$`);

export function protectionOf(name, patterns, impactEntry = null) {
  const pattern = patterns.find((candidate) => globToRegExp(candidate).test(name));
  if (pattern) return `protected (${pattern})`;
  if (impactEntry?.essential) return 'essential package';
  if (impactEntry?.required) return 'required-priority package';
  if (impactEntry?.refused) return 'apt refuses to remove it (the system needs it)';
  return null;
}

// removal-impact.jsonl (guest/removal-impact.py) → Map(package → { version, essential, required,
// refused, cascade }).
export function parseRemovalImpact(text) {
  const impact = new Map();
  for (const line of String(text || '').split('\n')) {
    if (!line.trim()) continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      throw new TemplateProfileError(['removal-impact.jsonl holds a line that is not JSON.']);
    }
    if (
      !isPackageName(entry.package) ||
      !Array.isArray(entry.cascade) ||
      !entry.cascade.every(isPackageName)
    ) {
      throw new TemplateProfileError([
        `removal-impact.jsonl holds an invalid entry: ${String(entry.package)}`,
      ]);
    }
    impact.set(entry.package, {
      version: String(entry.version || ''),
      essential: entry.essential === true,
      required: entry.required === true,
      refused: entry.refused === true,
      cascade: [...new Set([entry.package, ...entry.cascade])].sort(),
    });
  }
  return impact;
}

// Validates a profile document and returns it normalised (sorted, unique removals).
export function validateProfile(profile, { protectedPatterns = [] } = {}) {
  const problems = [];
  if (!profile || typeof profile !== 'object' || Array.isArray(profile))
    throw new TemplateProfileError(['A profile must be a JSON object.']);
  if (profile.profileVersion !== PROFILE_VERSION)
    problems.push(`profileVersion must be ${PROFILE_VERSION}.`);
  if (!PROFILE_NAME.test(String(profile.name || '')))
    problems.push('name may hold lower-case letters, digits and dashes (2-63 characters).');
  if (!PROFILE_NAME.test(String(profile.baseTemplate || '')))
    problems.push('baseTemplate is missing or invalid.');
  const remove = Array.isArray(profile.remove) ? profile.remove : null;
  if (!remove) problems.push('remove must be a list of package names.');
  else {
    if (remove.length > MAX_REMOVALS)
      problems.push(`A profile removes at most ${MAX_REMOVALS} packages.`);
    for (const name of remove) {
      if (!isPackageName(name)) problems.push(`Not a package name: ${JSON.stringify(name)}.`);
      else {
        const reason = protectionOf(name, protectedPatterns);
        if (reason) problems.push(`${name} cannot be removed: ${reason}.`);
      }
    }
  }
  if (problems.length > 0) throw new TemplateProfileError(problems);
  return {
    profileVersion: PROFILE_VERSION,
    name: profile.name,
    description: String(profile.description || '').slice(0, 500),
    baseTemplate: profile.baseTemplate,
    remove: [...new Set(remove)].sort(),
  };
}

const vulnerabilityCounts = (vulnerabilities) => {
  const byPackage = new Map();
  for (const item of vulnerabilities) {
    const counts = byPackage.get(item.pkg) || { total: 0, critical: 0, high: 0, ids: new Set() };
    counts.total += 1;
    if (item.severity === 'CRITICAL') counts.critical += 1;
    if (item.severity === 'HIGH') counts.high += 1;
    counts.ids.add(item.id);
    byPackage.set(item.pkg, counts);
  }
  return byPackage;
};

// The list the screen shows: every installed package, what removing it would take along, its
// vulnerabilities, and whether it may be chosen. Packages with the most findings come first.
export function selectablePackages({ impact, vulnerabilities = [], protectedPatterns = [] }) {
  const counts = vulnerabilityCounts(vulnerabilities);
  const rows = [];
  for (const [name, entry] of impact) {
    const own = protectionOf(name, protectedPatterns, entry);
    const takesProtected = entry.cascade.filter(
      (other) => other !== name && protectionOf(other, protectedPatterns, impact.get(other)),
    );
    const cascadeCves = new Set(
      entry.cascade.flatMap((other) => [...(counts.get(other)?.ids ?? [])]),
    );
    const mine = counts.get(name) || { total: 0, critical: 0, high: 0 };
    rows.push({
      package: name,
      version: entry.version,
      vulnerabilities: { total: mine.total, critical: mine.critical, high: mine.high },
      alsoRemoves: entry.cascade.filter((other) => other !== name),
      cvesClosed: cascadeCves.size,
      selectable: !own && takesProtected.length === 0,
      reason:
        own ||
        (takesProtected.length > 0 ? `would also remove ${takesProtected.join(', ')}` : null),
    });
  }
  return rows.sort(
    (a, b) =>
      b.vulnerabilities.critical - a.vulnerabilities.critical ||
      b.vulnerabilities.total - a.vulnerabilities.total ||
      a.package.localeCompare(b.package),
  );
}

// What a selection would do, before the build: everything that goes, what blocks it, how many
// distinct CVEs leave the template. The build VM's own simulation stays authoritative (two
// removals together can take slightly more than their separate cascades).
export function previewRemoval({ selected, impact, vulnerabilities = [], protectedPatterns = [] }) {
  const requested = [...new Set(selected)].sort();
  const unknown = requested.filter((name) => !impact.has(name));
  const removes = new Set();
  for (const name of requested)
    for (const other of impact.get(name)?.cascade ?? []) removes.add(other);
  const blocked = [...removes]
    .map((name) => ({
      package: name,
      reason: protectionOf(name, protectedPatterns, impact.get(name)),
    }))
    .filter((item) => item.reason)
    .sort((a, b) => a.package.localeCompare(b.package));
  const counts = vulnerabilityCounts(vulnerabilities);
  const cves = new Set([...removes].flatMap((name) => [...(counts.get(name)?.ids ?? [])]));
  return {
    requested,
    alsoRemoved: [...removes].filter((name) => !requested.includes(name)).sort(),
    total: removes.size,
    cvesClosed: cves.size,
    unknown,
    blocked,
    allowed: blocked.length === 0 && unknown.length === 0,
  };
}
