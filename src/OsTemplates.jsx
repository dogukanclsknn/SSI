// OS Templates (docs/os-template-poc.md, "Windows" and "Ubuntu"): up-to-date operating system
// templates. An operator requests a build from a pinned official source (a Windows Server ISO or
// the Ubuntu 24.04 cloud image); the worker of that OS builds it offline and reports back
// (signed); an approver accepts the template into the catalog. The rules live in src/lib/osTemplate.js and on the server; this screen shows the
// requests and offers only what the server would accept (it re-checks everything).
//   renderPanel(build)  the Azure DevOps panel of one request (the same panel the other screens use)
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  CheckCircle2,
  Clock3,
  Copy,
  Download,
  HardDrive,
  Loader2,
  PackageCheck,
  Plus,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import {
  createOsTemplate,
  createOsTemplateDownload,
  decideOsTemplate,
  getOsTemplate,
  listOsTemplates,
} from './lib/api.js';
import { OS_TEMPLATE_OS, validateBuildRequest } from './lib/osTemplate.js';

const STATUS = {
  Requested: { label: 'Requested', tone: 'wait', icon: Clock3 },
  Built: { label: 'Built · awaiting approval', tone: 'next', icon: PackageCheck },
  Approved: { label: 'Approved', tone: 'ok', icon: CheckCircle2 },
  Rejected: { label: 'Rejected', tone: 'bad', icon: XCircle },
};

// Index → edition of the Windows Server 2025 media (dism /Get-WimInfo); other media may differ.
const EDITIONS = [
  { value: 1, label: '1 · Standard (Server Core)' },
  { value: 2, label: '2 · Standard (Desktop Experience)' },
  { value: 3, label: '3 · Datacenter (Server Core)' },
  { value: 4, label: '4 · Datacenter (Desktop Experience)' },
];

const EMPTY_FORMS = {
  [OS_TEMPLATE_OS.WINDOWS]: {
    isoFile: 'WS2025_EVAL_en-us.iso',
    isoSha256: '',
    imageIndex: 2,
    product: 'Windows Server 2025',
    templateName: 'ssi-ws2025-std-de',
  },
  [OS_TEMPLATE_OS.UBUNTU]: {
    os: OS_TEMPLATE_OS.UBUNTU,
    baseImageUrl:
      'https://cloud-images.ubuntu.com/releases/noble/release-YYYYMMDD/ubuntu-24.04-server-cloudimg-amd64.img',
    baseImageSha256: '',
    templateName: 'ssi-ubuntu-2404',
    diskSizeGb: 20,
    aptMirror: '',
  },
};

const OS_LABELS = {
  [OS_TEMPLATE_OS.WINDOWS]: 'Windows Server',
  [OS_TEMPLATE_OS.UBUNTU]: 'Ubuntu 24.04',
};

const CVE_SOURCE = {
  [OS_TEMPLATE_OS.WINDOWS]: 'MSRC',
  [OS_TEMPLATE_OS.UBUNTU]: 'Trivy',
};

const formatCount = (value) => (Number.isFinite(value) ? value.toLocaleString('en-US') : '-');

function formatTime(value) {
  const date = new Date(value);
  if (!value || Number.isNaN(date.getTime())) return '-';
  const pad = (part) => String(part).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function formatGiB(bytes) {
  return Number.isFinite(bytes) ? `${(bytes / 1024 ** 3).toFixed(2)} GiB` : '-';
}

function StatusChip({ status }) {
  const { label, tone, icon: Icon } = STATUS[status] || STATUS.Requested;
  return (
    <span className={`ost-status ost-${tone}`}>
      <Icon size={13} aria-hidden="true" />
      {label}
    </span>
  );
}

// "Requested" form: the same rules as the server and the worker pipeline (validateBuildRequest).
function RequestForm({ onCreated }) {
  const [os, setOs] = useState(OS_TEMPLATE_OS.WINDOWS);
  const [form, setForm] = useState(EMPTY_FORMS[OS_TEMPLATE_OS.WINDOWS]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const problem = useMemo(() => {
    try {
      validateBuildRequest(form);
      return '';
    } catch (invalid) {
      return invalid.message;
    }
  }, [form]);
  const field =
    (name, transform = (value) => value) =>
    (event) =>
      setForm((current) => ({ ...current, [name]: transform(event.target.value) }));

  async function submit(event) {
    event.preventDefault();
    if (problem) return;
    setBusy(true);
    setError('');
    try {
      const result = await createOsTemplate(validateBuildRequest(form));
      setForm(EMPTY_FORMS[os]);
      onCreated(result.data);
    } catch (createError) {
      setError(createError.message || 'The build request was not created.');
    } finally {
      setBusy(false);
    }
  }

  const chooseOs = (event) => {
    setOs(event.target.value);
    setForm(EMPTY_FORMS[event.target.value]);
    setError('');
  };

  return (
    <form className="panel ost-form" onSubmit={submit}>
      <div className="ost-form-head">
        <Plus size={17} aria-hidden="true" />
        <h3>New template build</h3>
      </div>
      <label className="ost-os">
        <span>Operating system</span>
        <select value={os} onChange={chooseOs}>
          {Object.entries(OS_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </label>
      {os === OS_TEMPLATE_OS.UBUNTU ? (
        <UbuntuFields form={form} field={field} />
      ) : (
        <WindowsFields form={form} field={field} />
      )}
      {(problem || error) && <p className="ost-error">{error || problem}</p>}
      <button className="primary-action" type="submit" disabled={busy || Boolean(problem)}>
        <Plus size={16} />
        {busy ? 'Requesting…' : 'Request build'}
      </button>
    </form>
  );
}

function WindowsFields({ form, field }) {
  return (
    <>
      <p className="ost-note">
        The source ISO must already be on the build machine (<code>E:\SSI-Image\iso</code>) with the
        cumulative update in <code>E:\SSI-Image\updates</code>. The build refuses an ISO whose
        SHA-256 differs from the one pinned here.
      </p>
      <div className="ost-grid">
        <label>
          <span>Source ISO file</span>
          <input
            value={form.isoFile}
            onChange={field('isoFile', (value) => value.trim())}
            maxLength={125}
            spellCheck={false}
          />
        </label>
        <label className="ost-wide">
          <span>Source ISO SHA-256</span>
          <input
            value={form.isoSha256}
            onChange={field('isoSha256', (value) => value.trim().toLowerCase())}
            placeholder="64 hex characters (certutil -hashfile … SHA256)"
            maxLength={64}
            spellCheck={false}
          />
        </label>
        <label>
          <span>Edition (install.wim index)</span>
          <select value={form.imageIndex} onChange={field('imageIndex', Number)}>
            {EDITIONS.map((edition) => (
              <option key={edition.value} value={edition.value}>
                {edition.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Product (as MSRC names it)</span>
          <input value={form.product} onChange={field('product')} maxLength={60} />
        </label>
        <label>
          <span>Template name</span>
          <input
            value={form.templateName}
            onChange={field('templateName', (value) => value.trim())}
            maxLength={41}
            spellCheck={false}
          />
        </label>
      </div>
    </>
  );
}

function UbuntuFields({ form, field }) {
  return (
    <>
      <p className="ost-note">
        Take the URL and the SHA-256 from the same dated folder of{' '}
        <code>cloud-images.ubuntu.com/releases/noble/</code> (its <code>SHA256SUMS</code>, the line
        of <code>ubuntu-24.04-server-cloudimg-amd64.img</code>). The build refuses an image whose
        SHA-256 differs.
      </p>
      <div className="ost-grid">
        <label className="ost-wide">
          <span>Cloud image URL</span>
          <input
            value={form.baseImageUrl}
            onChange={field('baseImageUrl', (value) => value.trim())}
            maxLength={300}
            spellCheck={false}
          />
        </label>
        <label className="ost-wide">
          <span>Cloud image SHA-256</span>
          <input
            value={form.baseImageSha256}
            onChange={field('baseImageSha256', (value) => value.trim().toLowerCase())}
            placeholder="64 hex characters from SHA256SUMS"
            maxLength={64}
            spellCheck={false}
          />
        </label>
        <label>
          <span>Template name</span>
          <input
            value={form.templateName}
            onChange={field('templateName', (value) => value.trim())}
            maxLength={41}
            spellCheck={false}
          />
        </label>
        <label>
          <span>Disk size (GiB)</span>
          <input
            type="number"
            min={10}
            max={200}
            value={form.diskSizeGb}
            onChange={field('diskSizeGb', Number)}
          />
        </label>
        <label className="ost-wide">
          <span>Internal Ubuntu mirror (optional)</span>
          <input
            value={form.aptMirror}
            onChange={field('aptMirror', (value) => value.trim())}
            placeholder="empty = archive.ubuntu.com"
            maxLength={200}
            spellCheck={false}
          />
        </label>
      </div>
    </>
  );
}

function UbuntuFacts({ template }) {
  const { cvesBefore, cvesAfter } = template;
  return (
    <dl className="ost-facts">
      <div>
        <dt>Template</dt>
        <dd>
          <span>
            {template.name} {template.version}
          </span>
          <small>{template.edition}</small>
        </dd>
      </div>
      <div>
        <dt>Kernel</dt>
        <dd>
          <span>
            {template.kernelBefore} → <strong>{template.kernelAfter}</strong>
          </span>
          <small>{formatCount(template.packagesUpgraded)} packages upgraded</small>
        </dd>
      </div>
      <div>
        <dt>CVEs with a fix (Trivy)</dt>
        <dd>
          <span>
            {formatCount(cvesBefore.fixable)} →{' '}
            <strong className="ost-zero">{cvesAfter.fixable}</strong>
          </span>
          <small>
            {formatCount(cvesBefore.total)} CVEs before ({formatCount(cvesBefore.critical)}{' '}
            critical), {formatCount(cvesAfter.total)} after, none of them with a released fix
          </small>
        </dd>
      </div>
      <div>
        <dt>Scan</dt>
        <dd>
          <span>Recognised as {template.scannedAs}</span>
          <small>
            Trivy {template.trivy.version} · database {formatTime(template.trivy.dbUpdatedAt)}
          </small>
        </dd>
      </div>
      <div className="ost-wide">
        <dt>Files</dt>
        <dd>
          {template.artifacts.map((artifact) => (
            <span key={artifact.format} className="ost-artifact">
              <span>
                <code className="ost-break">{artifact.file}</code> · {formatGiB(artifact.sizeBytes)}{' '}
                · {artifact.platforms.join(', ')}
              </span>
              <small>
                SHA-256 <code className="ost-break">{artifact.sha256}</code>
              </small>
            </span>
          ))}
          <small>
            Azure DevOps run {template.location.adoBuildId}, artifact{' '}
            <code>{template.location.artifact}</code>
          </small>
        </dd>
      </div>
    </dl>
  );
}

function TemplateFacts({ template }) {
  if (!template) return null;
  if (template.os === OS_TEMPLATE_OS.UBUNTU) return <UbuntuFacts template={template} />;
  const { iso } = template;
  return (
    <dl className="ost-facts">
      <div>
        <dt>Template</dt>
        <dd>
          <span>
            {template.name} {template.version}
          </span>
          <small>{template.edition}</small>
        </dd>
      </div>
      <div>
        <dt>Windows build</dt>
        <dd>
          <span>
            {template.baseBuild} → <strong>{template.build}</strong>
          </span>
        </dd>
      </div>
      <div>
        <dt>Open CVEs (MSRC)</dt>
        <dd>
          <span>
            {template.openBefore} ({template.criticalBefore} critical) →{' '}
            <strong className="ost-zero">{template.openAfter}</strong>
          </span>
        </dd>
      </div>
      <div>
        <dt>Update applied</dt>
        <dd>{template.update || 'none (already current)'}</dd>
      </div>
      <div className="ost-wide">
        <dt>ISO</dt>
        <dd>
          <span>
            <code className="ost-break">{iso.file}</code> · {formatGiB(iso.sizeBytes)}
          </span>
          <small>
            SHA-256 <code className="ost-break">{iso.sha256}</code>
          </small>
          <small>
            On <code className="ost-break">{`${iso.host}:${iso.path}`}</code>
          </small>
        </dd>
      </div>
    </dl>
  );
}

// The template's files, streamed from its Azure DevOps run through SSI. A click asks the server
// for a one-time link (permission, audit, the artifact still exists) and then lets the browser
// save it: the page never holds the file. Each file is checked with its SHA-256 afterwards.
function Downloads({ build, permitted }) {
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [started, setStarted] = useState('');
  const [copied, setCopied] = useState('');
  const downloads = build.downloads || [];

  if (downloads.length === 0) {
    return build.downloadsUnavailable && build.template ? (
      <p className="ost-note">{build.downloadsUnavailable}</p>
    ) : null;
  }

  async function start(download) {
    setBusy(download.id);
    setError('');
    setStarted('');
    try {
      const link = await createOsTemplateDownload(build.id, download.id);
      const anchor = document.createElement('a');
      anchor.href = link.url;
      anchor.download = link.fileName;
      anchor.rel = 'noopener';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setStarted(download.id);
    } catch (downloadError) {
      setError(downloadError.message || 'The download could not be started.');
    } finally {
      setBusy('');
    }
  }

  async function copy(command) {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(command);
    } catch {
      setCopied('');
    }
  }

  return (
    <section className="ost-downloads" aria-label="Downloads">
      <h4>Downloads</h4>
      <p className="ost-note">
        Each download is a zip from Azure DevOps run {downloads[0].runId}. After unzipping, check
        every file against its SHA-256 below before you import it. Over plain HTTP, Chrome holds the
        download back as &quot;insecure&quot;: choose Keep within five minutes.
      </p>
      {!permitted && (
        <p className="ost-note">
          Requires the os-template:download permission (operator or approver).
        </p>
      )}
      <ul>
        {downloads.map((download) => (
          <li key={download.id}>
            <div className="ost-download-head">
              <span>
                <strong>{download.label}</strong>
                <small>
                  {download.fileName}
                  {Number.isFinite(download.sizeBytes) ? ` · ${formatGiB(download.sizeBytes)}` : ''}
                </small>
              </span>
              <button
                type="button"
                className="secondary-action"
                disabled={!permitted || Boolean(busy)}
                onClick={() => start(download)}
              >
                {busy === download.id ? (
                  <Loader2 size={15} className="ost-spin" aria-hidden="true" />
                ) : (
                  <Download size={15} aria-hidden="true" />
                )}
                {busy === download.id ? 'Preparing…' : 'Download'}
              </button>
            </div>
            {started === download.id && (
              <p className="ost-note">The download started in your browser.</p>
            )}
            {download.files.map((file) => {
              const command = `certutil -hashfile ${file.file} SHA256`;
              return (
                <div key={file.file} className="ost-verify">
                  <small>
                    <code className="ost-break">{file.file}</code> SHA-256{' '}
                    <code className="ost-break">{file.sha256}</code>
                  </small>
                  <button
                    type="button"
                    className="ost-copy"
                    onClick={() => copy(command)}
                    title="Copy the Windows check command"
                  >
                    <Copy size={13} aria-hidden="true" />
                    {copied === command ? 'Copied' : 'certutil'}
                  </button>
                </div>
              );
            })}
          </li>
        ))}
      </ul>
      {error && <p className="ost-error">{error}</p>}
    </section>
  );
}

// Approve or reject: the server enforces the rules (four eyes, approve only Built); the screen
// only says beforehand what it would refuse.
function Decision({ build, actorId, onDecided }) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const own =
    Boolean(actorId) && actorId.toLowerCase() === String(build.requestedBy || '').toLowerCase();

  async function decide(decision) {
    setBusy(decision);
    setError('');
    try {
      const result = await decideOsTemplate(build.id, decision, reason.trim());
      setReason('');
      onDecided(result.data);
    } catch (decideError) {
      setError(decideError.message || 'The decision was not recorded.');
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="ost-decision">
      <label>
        <span>Reason (required to reject)</span>
        <textarea
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          maxLength={500}
          rows={2}
        />
      </label>
      {own && (
        <p className="ost-note">
          You requested this build; another approver must decide it (four eyes).
        </p>
      )}
      {error && <p className="ost-error">{error}</p>}
      <div className="ost-actions">
        {build.status === 'Built' && (
          <button
            className="primary-action"
            type="button"
            disabled={Boolean(busy)}
            onClick={() => decide('approve')}
          >
            <ShieldCheck size={16} />
            {busy === 'approve' ? 'Approving…' : 'Approve into catalog'}
          </button>
        )}
        <button
          className="secondary-action"
          type="button"
          disabled={Boolean(busy) || !reason.trim()}
          onClick={() => decide('reject')}
        >
          <XCircle size={16} />
          {busy === 'reject' ? 'Rejecting…' : 'Reject'}
        </button>
      </div>
    </div>
  );
}

function Detail({ build, permitApprove, permitDownload, actorId, renderPanel, onChanged }) {
  const open = ['Requested', 'Built'].includes(build.status);
  return (
    <section className="panel ost-detail" aria-label={`Build request ${build.id}`}>
      <div className="ost-detail-head">
        <div>
          <h3>{build.id}</h3>
          <span>
            {OS_LABELS[build.os] || OS_LABELS[OS_TEMPLATE_OS.WINDOWS]} ·{' '}
            {build.request.templateName} · requested by {build.requestedBy} ·{' '}
            {formatTime(build.createdAt)}
          </span>
        </div>
        <StatusChip status={build.status} />
      </div>
      <dl className="ost-facts">
        <div className="ost-wide">
          <dt>Source</dt>
          {build.os === OS_TEMPLATE_OS.UBUNTU ? (
            <dd>
              <span>
                <code className="ost-break">{build.request.baseImageUrl}</code>
              </span>
              <small>
                SHA-256 <code className="ost-break">{build.request.baseImageSha256}</code>
              </small>
              <small>
                {build.request.diskSizeGb} GiB disk · mirror{' '}
                {build.request.aptMirror || 'archive.ubuntu.com'}
              </small>
            </dd>
          ) : (
            <dd>
              <span>
                <code className="ost-break">{build.request.isoFile}</code> · index{' '}
                {build.request.imageIndex} · {build.request.product}
              </span>
              <small>
                SHA-256 <code className="ost-break">{build.request.isoSha256}</code>
              </small>
            </dd>
          )}
        </div>
      </dl>
      <TemplateFacts template={build.template} />
      {build.decision && (
        <p className={`ost-decided ost-${build.status === 'Approved' ? 'ok' : 'bad'}`}>
          {build.status} by {build.decision.by} · {formatTime(build.decision.at)}
          {build.decision.reason ? ` · ${build.decision.reason}` : ''}
        </p>
      )}
      {build.retention && (
        <p className={`ost-note ${build.retention.secured ? '' : 'ost-warn'}`}>
          {build.retention.secured
            ? `Files retained in Azure DevOps: run ${build.retention.runId} is kept by lease ${build.retention.leaseId}.`
            : `Files not yet retained: ${build.retention.reason}`}
        </p>
      )}
      <Downloads build={build} permitted={permitDownload} />
      {build.status === 'Requested' && renderPanel(build)}
      {open && permitApprove && <Decision build={build} actorId={actorId} onDecided={onChanged} />}
    </section>
  );
}

export function OsTemplates({ permitBuild, permitApprove, permitDownload, actorId, renderPanel }) {
  const [state, setState] = useState({ loading: true, builds: [], source: '', error: '' });
  const [selectedId, setSelectedId] = useState('');
  const [detail, setDetail] = useState(null);

  const refresh = useCallback(async () => {
    const result = await listOsTemplates();
    setState({
      loading: false,
      builds: Array.isArray(result.data) ? result.data : [],
      source: result.source,
      error: result.error,
    });
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const selected = state.builds.find((build) => build.id === selectedId) || state.builds[0] || null;
  const selectedKey = selected ? `${selected.id}|${selected.updatedAt}` : '';
  useEffect(() => {
    let cancelled = false;
    if (!selected) {
      setDetail(null);
      return undefined;
    }
    getOsTemplate(selected.id)
      .then((result) => !cancelled && setDetail(result.data))
      .catch(() => !cancelled && setDetail(selected));
    return () => {
      cancelled = true;
    };
    // The selected request and its saved version decide when to read it again.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedKey]);

  const catalog = state.builds.filter((build) => build.status === 'Approved' && build.template);
  const changed = (build) => {
    if (build?.id) setSelectedId(build.id);
    refresh();
  };

  return (
    <div className="ost">
      <section className="panel ost-intro">
        <HardDrive size={20} aria-hidden="true" />
        <div>
          <h2>Operating system templates</h2>
          <p>
            Each template is built offline from an official source pinned by SHA-256 and brought up
            to date. Windows Server: the latest cumulative update, re-scanned against
            Microsoft&apos;s Security Update Guide, accepted only with no open CVE. Ubuntu 24.04:
            every package upgraded, re-scanned with Trivy, accepted only with no CVE that has a
            released fix; delivered as QCOW2, OVA and VHDX. An approver other than the requester
            admits a template to the catalog.
          </p>
        </div>
      </section>

      <section className="panel ost-catalog" aria-label="Approved templates">
        <h3>Catalog</h3>
        {catalog.length === 0 ? (
          <p className="ost-note">No approved template yet.</p>
        ) : (
          <ul>
            {catalog.map((build) => (
              <li key={build.id}>
                <button type="button" onClick={() => setSelectedId(build.id)}>
                  <strong>
                    {build.template.name} {build.template.version}
                  </strong>
                  <span>
                    {build.template.edition} ·{' '}
                    {build.template.os === OS_TEMPLATE_OS.UBUNTU
                      ? `kernel ${build.template.kernelAfter} · 0 CVEs with a fix · QCOW2, OVA, VHDX`
                      : `${build.template.build} · 0 open CVEs`}{' '}
                    · approved by {build.decision?.by}
                  </span>
                  <code className="ost-break">
                    {build.template.os === OS_TEMPLATE_OS.UBUNTU
                      ? `qcow2 ${build.template.artifacts.find((item) => item.format === 'qcow2')?.sha256}`
                      : build.template.iso.sha256}
                  </code>
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="ost-body">
        <section className="panel ost-list" aria-label="Build requests">
          <h3>Build requests</h3>
          {state.loading && (
            <p className="ost-note">
              <Loader2 size={14} className="ost-spin" aria-hidden="true" /> Loading…
            </p>
          )}
          {state.error && <p className="ost-error">{state.error}</p>}
          {!state.loading && state.builds.length === 0 && (
            <p className="ost-note">No build request yet.</p>
          )}
          <ul>
            {state.builds.map((build) => (
              <li key={build.id}>
                <button
                  type="button"
                  className={selected?.id === build.id ? 'is-shown' : ''}
                  aria-current={selected?.id === build.id ? 'true' : undefined}
                  onClick={() => setSelectedId(build.id)}
                >
                  <span className="ost-row-head">
                    <strong>{build.id}</strong>
                    <StatusChip status={build.status} />
                  </span>
                  <span>
                    {build.request.templateName} · {OS_LABELS[build.os] || OS_LABELS.windows}
                  </span>
                  <span className="ost-row-meta">
                    {build.template?.os === OS_TEMPLATE_OS.UBUNTU
                      ? `${formatCount(build.template.cvesBefore.fixable)} → ${build.template.cvesAfter.fixable} CVEs with a fix (${CVE_SOURCE[build.os]}) · `
                      : build.template
                        ? `${build.template.openBefore} → ${build.template.openAfter} open CVEs (${CVE_SOURCE.windows}) · `
                        : ''}
                    {build.requestedBy} · {formatTime(build.createdAt)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>

        <div className="ost-side">
          {detail && (
            <Detail
              key={detail.id}
              build={detail}
              permitApprove={permitApprove}
              permitDownload={permitDownload}
              actorId={actorId}
              renderPanel={(build) => renderPanel(build, () => changed(build))}
              onChanged={changed}
            />
          )}
          {permitBuild && <RequestForm onCreated={changed} />}
        </div>
      </div>
    </div>
  );
}
