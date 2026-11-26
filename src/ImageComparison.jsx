// SSI — "What changed": two images side by side, from ssi.image-comparison/v1
// (src/lib/imageComparison.js):
//   - ImageComparisonPanel: the source image of a verified RM-EXEC job vs its patched output
//   - ScanComparePanel: any two scanned images (Scan Results), compared by vulnerability
// Any dimension is rendered from its columns, so a new dimension needs no change here.
import { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, ClipboardCheck, Copy, Download, FileDiff, Info, Search, ShieldAlert } from 'lucide-react';
import { compareScannedImages, getRemediationComparison } from './lib/api.js';
import { copyText } from './lib/clipboard.js';
import {
  dimensionCsv,
  formatBytes,
  IMAGE_INSPECTION_PIPELINE,
  scanReportReference,
} from './lib/imageComparison.js';

const PAGE_SIZE = 25;

const CHANGE_LABELS = {
  new: 'New',
  fixed: 'Fixed',
  remaining: 'Remaining',
  changed: 'Changed',
  added: 'Added',
  removed: 'Removed',
  restored: 'Restored',
  unchanged: 'Unchanged',
};

const LEVEL_ICONS = { high: ShieldAlert, warning: AlertTriangle, info: Info };

const SIDE_LABELS = { source: 'Source', patched: 'Patched', base: 'Base', compared: 'Compared' };

function shortDigest(digest) {
  return digest ? `${digest.slice(0, 19)}…` : '—';
}

function download(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

// Copy with visible feedback: the copied control shows a check for a moment. Works on plain
// HTTP too (src/lib/clipboard.js), where navigator.clipboard does not exist.
function useCopy() {
  const [copied, setCopied] = useState('');
  useEffect(() => {
    if (!copied) return undefined;
    const timer = setTimeout(() => setCopied(''), 1500);
    return () => clearTimeout(timer);
  }, [copied]);
  const copy = (key, value) =>
    copyText(value)
      .then(() => setCopied(key))
      .catch(() => setCopied(''));
  return [copied, copy];
}

function ImageSide({ image }) {
  const [copied, copy] = useCopy();
  return (
    <div className="cmp-side">
      <span>{SIDE_LABELS[image.role] || image.role}</span>
      <strong title={image.reference}>{image.reference || '—'}</strong>
      <button
        type="button"
        className="cmp-digest"
        title={copied ? 'Copied' : `Copy ${image.digest}`}
        aria-label={`Copy the ${SIDE_LABELS[image.role] || image.role} digest`}
        onClick={() => copy('digest', image.digest)}
      >
        <code>{shortDigest(image.digest)}</code>
        {copied ? <ClipboardCheck size={12} /> : <Copy size={12} />}
      </button>
      {image.role === 'base' || image.role === 'compared' ? (
        <small className={image.inspectedAt ? 'cmp-inspected' : 'cmp-inspected missing'}>
          {image.inspectedAt
            ? `Inspected ${image.inspectedAt.replace('T', ' ').slice(0, 16)} UTC`
            : 'Not inspected'}
        </small>
      ) : null}
    </div>
  );
}

// Free comparison: what to run so packages, layers and configuration can be compared too.
function InspectionHint({ comparison }) {
  const [copied, copy] = useCopy();
  const missing = [comparison.base, comparison.head].filter((image) => !image.inspectedAt);
  if (comparison.kind !== 'images' || missing.length === 0) return null;
  return (
    <div className="cmp-inspect" role="note">
      <strong>Compare packages, layers and configuration too</strong>
      <span>
        Run <b>{IMAGE_INSPECTION_PIPELINE}</b> in Azure DevOps once for{' '}
        {missing.length === 2 ? 'each image' : 'this image'}, with this <code>imageReference</code>:
      </span>
      {missing.map((image) => {
        const reference = image.registryReference || image.immutableReference;
        return (
          <button
            key={image.role}
            type="button"
            className="cmp-inspect-ref"
            title={copied === image.role ? 'Copied' : `Copy ${reference}`}
            onClick={() => copy(image.role, reference)}
          >
            <em>{SIDE_LABELS[image.role]}</em>
            <code>{reference}</code>
            {copied === image.role ? <ClipboardCheck size={12} /> : <Copy size={12} />}
          </button>
        );
      })}
    </div>
  );
}

// The numbers a reviewer reads first; '—' when the evidence for it is not there yet.
function Headline({ kind, headline }) {
  const value = (number) => (number === null || number === undefined ? '—' : number);
  const items =
    kind === 'images' ? imageDiffItems(headline, value) : remediationItems(headline, value);
  return (
    <div className="cmp-headline">
      {items.map((item) => (
        <div key={item.label} className={`cmp-stat ${item.tone}`}>
          <strong>{item.value}</strong>
          <span>{item.label}</span>
          {item.detail && <small>{item.detail}</small>}
        </div>
      ))}
    </div>
  );
}

// Two scanned images: only the vulnerability comparison exists.
function imageDiffItems(headline, value) {
  return [
    { label: 'Fixed in compared image', value: value(headline.vulnerabilitiesFixed), tone: 'good' },
    {
      label: 'New in compared image',
      value: value(headline.vulnerabilitiesNew),
      // Findings in packages with the same version in both images come from newer scan data.
      detail:
        headline.vulnerabilitiesNewUnchangedPackages > 0
          ? `+${headline.vulnerabilitiesNewUnchangedPackages} in same-version packages`
          : '',
      tone: headline.vulnerabilitiesNew > 0 ? 'bad' : 'good',
    },
    { label: 'In both images', value: value(headline.vulnerabilitiesRemaining), tone: '' },
    {
      label: 'Findings (base → compared)',
      value:
        headline.findingsBase === null
          ? '—'
          : `${headline.findingsBase} → ${headline.findingsHead}`,
      tone:
        headline.findingsHead < headline.findingsBase
          ? 'good'
          : headline.findingsHead > headline.findingsBase
            ? 'bad'
            : '',
    },
    // From the image inspections, once both images are inspected.
    ...(headline.sameOs === null || headline.sameOs === undefined
      ? []
      : [
          {
            label: 'Operating system',
            value: headline.sameOs ? 'Same' : 'Different',
            tone: headline.sameOs ? 'good' : 'bad',
          },
          { label: 'Package differences', value: value(headline.packageDifferences), tone: '' },
          { label: 'Shared base layers', value: value(headline.layersShared), tone: '' },
          {
            label: 'Size change',
            value:
              headline.sizeDeltaBytes === null || headline.sizeDeltaBytes === undefined
                ? '—'
                : `${headline.sizeDeltaBytes > 0 ? '+' : ''}${formatBytes(headline.sizeDeltaBytes)}`,
            tone: '',
          },
        ]),
  ];
}

function remediationItems(headline, value) {
  return [
    { label: 'Vulnerabilities fixed', value: value(headline.vulnerabilitiesFixed), tone: 'good' },
    {
      label: 'New in patched image',
      value: value(headline.vulnerabilitiesNew),
      // Findings in packages the patch did not change come from newer scan data (candidate test).
      detail:
        headline.vulnerabilitiesNewUnchangedPackages > 0
          ? `+${headline.vulnerabilitiesNewUnchangedPackages} in unchanged packages`
          : '',
      tone: headline.vulnerabilitiesNew > 0 ? 'bad' : 'good',
    },
    { label: 'Remaining', value: value(headline.vulnerabilitiesRemaining), tone: '' },
    {
      label: 'Packages changed',
      value: value(headline.packagesChanged),
      detail:
        headline.packagesUnplanned > 0
          ? `${headline.packagesUnplanned} not planned`
          : headline.packagesChanged === null
            ? ''
            : 'all planned',
      tone: headline.packagesUnplanned > 0 ? 'bad' : '',
    },
    {
      label: 'Configuration',
      value:
        headline.configuration === null
          ? '—'
          : headline.configuration === 'preserved'
            ? 'Preserved'
            : 'Restored',
      tone: headline.configuration ? 'good' : '',
    },
    {
      label: 'Runtime test',
      value: headline.runtimePassed === null ? '—' : headline.runtimePassed ? 'Pass' : 'Fail',
      tone: headline.runtimePassed === false ? 'bad' : headline.runtimePassed ? 'good' : '',
    },
    { label: 'Layers added', value: value(headline.layersAdded), tone: '' },
    {
      label: 'Size change',
      value:
        headline.sizeDeltaBytes === null || headline.sizeDeltaBytes === undefined
          ? '—'
          : `${headline.sizeDeltaBytes > 0 ? '+' : ''}${formatBytes(headline.sizeDeltaBytes)}`,
      tone: '',
    },
  ];
}

function Attention({ points }) {
  if (points.length === 0) {
    return (
      <div className="cmp-attention none">
        Nothing needs special attention in the available evidence.
      </div>
    );
  }
  return (
    <ul className="cmp-attention" aria-label="Points to review">
      {points.map((point) => {
        const Icon = LEVEL_ICONS[point.level] || Info;
        return (
          <li key={`${point.dimension}-${point.code}`} className={point.level}>
            <Icon size={15} />
            <span>{point.message}</span>
          </li>
        );
      })}
    </ul>
  );
}

function DimensionTable({ dimension }) {
  const [onlyChanges, setOnlyChanges] = useState(true);
  const [severity, setSeverity] = useState('all');
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const hasSeverity = dimension.columns.some((column) => column.key === 'severity');

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return dimension.rows.filter(
      (row) =>
        (!onlyChanges || row.changed) &&
        (severity === 'all' || row.severity === severity) &&
        (!needle ||
          dimension.columns.some((column) =>
            String(row[column.key] ?? '')
              .toLowerCase()
              .includes(needle),
          )),
    );
  }, [dimension, onlyChanges, severity, query]);

  useEffect(() => setPage(1), [dimension.id, onlyChanges, severity, query]);
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const current = Math.min(page, pages);
  const visible = rows.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);

  return (
    <>
      <div className="cmp-filters">
        <label className="cmp-toggle">
          <input
            type="checkbox"
            checked={onlyChanges}
            onChange={(event) => setOnlyChanges(event.target.checked)}
          />
          Only changes
        </label>
        {hasSeverity && (
          <select
            aria-label="Severity"
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
          >
            <option value="all">All severities</option>
            {['Critical', 'High', 'Medium', 'Low', 'Unknown'].map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
        )}
        <div className="search-box cmp-search">
          <Search size={14} />
          <input
            aria-label={`Search ${dimension.title}`}
            placeholder="Search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
        <span className="cmp-count">
          {rows.length} of {dimension.rows.length}
        </span>
      </div>
      <div className="cmp-table-wrap">
        <table className="cmp-table">
          <thead>
            <tr>
              {dimension.columns.map((column) => (
                <th key={column.key} scope="col">
                  {column.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 && (
              <tr>
                <td colSpan={dimension.columns.length} className="cmp-empty">
                  {dimension.rows.length === 0
                    ? 'Nothing to compare.'
                    : 'No rows match the filters.'}
                </td>
              </tr>
            )}
            {visible.map((row, index) => (
              <tr
                key={`${index}-${row.cve || row.name || row.field || row.id || row.digest || row.item}`}
                className={`chg-${row.change}`}
              >
                {dimension.columns.map((column) => (
                  <td key={column.key}>
                    {column.key === 'change' ? (
                      <span className={`cmp-change ${row.change}`}>
                        {CHANGE_LABELS[row.change] || row.change}
                      </span>
                    ) : column.key === 'severity' ? (
                      <span className={`severity ${String(row.severity).toLowerCase()}`}>
                        {row.severity}
                      </span>
                    ) : (
                      <span className="cmp-cell">{String(row[column.key] ?? '')}</span>
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {pages > 1 && (
        <div className="cmp-pages">
          <button
            type="button"
            className="secondary-action"
            disabled={current <= 1}
            onClick={() => setPage(current - 1)}
          >
            Previous
          </button>
          <span>
            Page {current} of {pages}
          </span>
          <button
            type="button"
            className="secondary-action"
            disabled={current >= pages}
            onClick={() => setPage(current + 1)}
          >
            Next
          </button>
        </div>
      )}
    </>
  );
}

// Loads a comparison and keeps the selected dimension (the first available one). `refresh`
// changes when the record behind the same comparison changes (e.g. a candidate test result
// arrived): the comparison is read again while the current one stays on screen, and the
// selected dimension is kept when it is still available.
function useComparison(load, key, refresh = '') {
  const [state, setState] = useState({ loading: Boolean(key), error: '', data: null, warning: '' });
  const [active, setActive] = useState('');
  const loadedKey = useRef(null);

  useEffect(() => {
    if (!key) {
      loadedKey.current = null;
      setState({ loading: false, error: '', data: null, warning: '' });
      return undefined;
    }
    let mounted = true;
    const sameComparison = loadedKey.current === key;
    setState((current) =>
      sameComparison
        ? { ...current, loading: true }
        : { loading: true, error: '', data: null, warning: '' },
    );
    load()
      .then((result) => {
        if (!mounted) return;
        loadedKey.current = key;
        setState({ loading: false, error: '', data: result.data, warning: result.error });
        const available = result.data.dimensions.filter((item) => item.status === 'available');
        const first = available[0]?.id || result.data.dimensions[0]?.id || '';
        setActive((current) =>
          sameComparison && available.some((item) => item.id === current) ? current : first,
        );
      })
      .catch(
        (error) =>
          mounted && setState({ loading: false, error: error.message, data: null, warning: '' }),
      );
    return () => {
      mounted = false;
    };
    // `key` identifies the comparison and `refresh` its version; `load` is recreated on
    // every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, refresh]);

  return { state, active, setActive };
}

function ComparisonView({
  title,
  exportName,
  state,
  active,
  setActive,
  controls = null,
  idle = null,
  // The manual "run SSI - Image Inspection" instructions are left out while SSI can start it.
  automatedInspection = false,
}) {
  const comparison = state.data;
  const dimension = comparison?.dimensions.find((item) => item.id === active);

  return (
    <section className="panel cmp-panel" lang="en" aria-label="What changed">
      <div className="panel-header">
        <div>
          <FileDiff size={19} />
          <h2>{title}</h2>
        </div>
        {comparison && (
          <div className="cmp-exports">
            <button
              type="button"
              className="text-action"
              onClick={() =>
                download(
                  `${exportName}-comparison.json`,
                  `${JSON.stringify(comparison, null, 2)}\n`,
                  'application/json;charset=utf-8',
                )
              }
            >
              <Download size={14} /> JSON
            </button>
            {dimension?.status === 'available' && (
              <button
                type="button"
                className="text-action"
                onClick={() =>
                  download(
                    `${exportName}-${dimension.id}.csv`,
                    `\uFEFF${dimensionCsv(dimension)}\n`,
                    'text/csv;charset=utf-8',
                  )
                }
              >
                <Download size={14} /> CSV
              </button>
            )}
          </div>
        )}
      </div>

      {controls}
      {!comparison && !state.loading && !state.error && idle}
      {state.loading && !comparison && <div className="cmp-note">Comparing the two images…</div>}
      {state.error && <div className="inline-error">{state.error}</div>}
      {comparison && (
        <>
          <div className="cmp-sides">
            <ImageSide image={comparison.base} />
            <span className="cmp-arrow" aria-hidden="true">
              →
            </span>
            <ImageSide image={comparison.head} />
          </div>
          <Headline kind={comparison.kind} headline={comparison.headline} />
          {!automatedInspection && <InspectionHint comparison={comparison} />}
          <Attention points={comparison.attention} />
          {state.warning && <div className="cmp-note">Registry: {state.warning}</div>}

          <div className="ab-tabs cmp-tabs" role="tablist" aria-label="Comparison dimensions">
            {comparison.dimensions.map((item) => {
              const changes = item.rows.filter((row) => row.changed).length;
              return (
                <button
                  key={item.id}
                  type="button"
                  role="tab"
                  aria-selected={active === item.id}
                  className={`${active === item.id ? 'active' : ''}${item.status !== 'available' ? ' muted' : ''}`}
                  onClick={() => setActive(item.id)}
                >
                  {item.title}
                  {item.status === 'available' && <em>{changes}</em>}
                </button>
              );
            })}
          </div>

          {dimension && (
            <div className="cmp-dimension" role="tabpanel">
              <div className="cmp-source">
                <span>Source of truth: {dimension.source}</span>
                {dimension.note && dimension.status === 'available' && (
                  <small>{dimension.note}</small>
                )}
              </div>
              {dimension.status === 'available' ? (
                <DimensionTable
                  key={`${comparison.head.digest}-${dimension.id}`}
                  dimension={dimension}
                />
              ) : (
                <div className="cmp-unavailable">
                  {dimension.note || 'No evidence for this dimension yet.'}
                </div>
              )}
            </div>
          )}
          <small className="cmp-generated">
            {comparison.contractVersion} · generated{' '}
            {comparison.generatedAt.replace('T', ' ').slice(0, 16)} UTC
          </small>
        </>
      )}
    </section>
  );
}

// jobId: a verified RM-EXEC job. version: changes whenever the job is saved (a candidate
// test, an inspection or supply-chain evidence arrived), so the tiles follow without a reload.
export function ImageComparisonPanel({ jobId, version = '' }) {
  const { state, active, setActive } = useComparison(
    () => getRemediationComparison(jobId),
    jobId,
    version,
  );
  return (
    <ComparisonView
      title="What changed — source vs patched image"
      exportName={String(jobId).toLowerCase()}
      state={state}
      active={active}
      setActive={setActive}
    />
  );
}

const shortHex = (digest) => String(digest || '').slice(7, 19);
const findingCount = (count) => `${count} finding${count === 1 ? '' : 's'}`;

// Scan Results: the selected scan (base) against any other visible scan. Images are
// addressed by digest, so a moved tag can never swap the compared image.
// inspectionPanel(reference, side, { onSettled, inspectedAt, onAvailability }): optional,
// renders the image inspection of one compared image (Azure DevOps); a finished run reloads the
// comparison, and onAvailability(true) replaces the manual instructions.
export function ScanComparePanel({ reports, base, inspectionPanel }) {
  const baseReference = scanReportReference(base);
  const [headReference, setHeadReference] = useState('');
  const [inspectionVersion, setInspectionVersion] = useState(0);
  const [automatedInspection, setAutomatedInspection] = useState(false);
  useEffect(() => setHeadReference(''), [baseReference]);

  const { sameRepository, others } = useMemo(() => {
    const repositoryOf = (reference) => reference.split('@')[0];
    const candidates = reports
      .map((report) => ({ report, reference: scanReportReference(report) }))
      .filter((item) => item.reference && item.report.digest !== base.digest)
      .sort((left, right) => String(left.report.image).localeCompare(String(right.report.image)));
    return {
      sameRepository: candidates.filter(
        (item) => repositoryOf(item.reference) === repositoryOf(baseReference),
      ),
      others: candidates.filter(
        (item) => repositoryOf(item.reference) !== repositoryOf(baseReference),
      ),
    };
  }, [reports, base.digest, baseReference]);

  const key = baseReference && headReference ? `${baseReference}|${headReference}` : '';
  const { state, active, setActive } = useComparison(
    () => compareScannedImages(baseReference, headReference),
    key,
    inspectionVersion,
  );
  const inspectionSettled = () => setInspectionVersion((value) => value + 1);
  const option = ({ report, reference }) => (
    <option key={reference} value={reference}>
      {report.image} · {shortHex(report.digest)} · {findingCount(report.findings?.length ?? 0)}
    </option>
  );

  if (!baseReference) return null;
  return (
    <>
    <ComparisonView
      automatedInspection={automatedInspection}
      title="Compare with another image"
      exportName={`compare-${shortHex(base.digest)}-${shortHex(state.data?.head?.digest)}`}
      state={state}
      active={active}
      setActive={setActive}
      controls={
        <div className="cmp-pick">
          <label>
            <span>Base</span>
            <strong title={base.image}>{base.image}</strong>
          </label>
          <label>
            <span>Compare with</span>
            <select
              aria-label="Image to compare with"
              value={headReference}
              onChange={(event) => setHeadReference(event.target.value)}
            >
              <option value="">Select a scanned image…</option>
              {sameRepository.length > 0 && (
                <optgroup label="Same repository">{sameRepository.map(option)}</optgroup>
              )}
              {others.length > 0 && (
                <optgroup label="Other repositories">{others.map(option)}</optgroup>
              )}
            </select>
          </label>
        </div>
      }
      idle={
        <div className="cmp-note">
          {sameRepository.length + others.length === 0
            ? 'No other scanned image to compare with.'
            : "Pick an image to see which vulnerabilities are new, fixed or remaining compared with the base image, from today's Harbor scans."}
        </div>
      }
    />
    {key && inspectionPanel && (
      <div className="cmp-inspections">
        {[
          [baseReference, 'Base', state.data?.base],
          [headReference, 'Compared', state.data?.head],
        ].map(([reference, side, image]) =>
          inspectionPanel(reference, side, {
            onSettled: inspectionSettled,
            inspectedAt: image?.inspectedAt || '',
            onAvailability: setAutomatedInspection,
          }),
        )}
      </div>
    )}
    </>
  );
}
