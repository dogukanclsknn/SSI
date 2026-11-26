import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Archive,
  Boxes,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  ClipboardCheck,
  Copy,
  Factory,
  FileKey2,
  Filter,
  FlaskConical,
  Gauge,
  HardDrive,
  GitBranch,
  History,
  Layers3,
  Lock,
  MessageSquareWarning,
  MinusCircle,
  PackageCheck,
  Play,
  Route,
  Workflow,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldOff,
  UploadCloud,
  BarChart3,
  CalendarClock,
  Database,
  Download,
  ExternalLink,
  FileText,
  PieChart,
  Printer,
  TrendingDown,
  DownloadCloud,
  ScanLine,
  Bug,
  Wrench,
  ArrowRight,
  UsersRound,
  Building2,
  UserCheck,
  LogOut,
  Trash2,
  Link2,
  X,
} from 'lucide-react';
import {
  approvePublishRequest,
  attachCandidateTestEvidence,
  attachCanonicalTrivyReport,
  attachSupplyChainEvidence,
  attachRemediationVerificationEvidence,
  createPublishRequest,
  createRemediationDryRun,
  getRemediationReport,
  getImageSbom,
  getPublishPolicy,
  getPublishWorkerHandoff,
  getRemediationExecutionReadiness,
  getRemediationWorkerHandoff,
  exportAuditEvents as downloadAuditExport,
  listAuditEvents,
  summarizeAuditEvents,
  listImages,
  listPublishRequests,
  listRemediationJobs,
  getPipelineRuns,
  startPipelineRun,
  getRecordPipelineRuns,
  startRecordPipelineRun,
  getImagePipelineRuns,
  startImagePipelineRun,
  listScanReports,
  remediationReportDocumentUrl,
  createOnboardingRequest,
  cancelOnboardingRequest,
  getSession,
  getClientIdentity,
  setClientIdentity,
  setSelectedTenant,
  listOnboardingRequests,
  loginWithPassword,
  logout,
  listUsers,
  createUser,
  updateUser,
  deleteUser,
  listExceptions,
  requestException,
  decideException,
  recordConsumerAcceptance,
  rejectPublishRequest,
  withdrawPublishRequest,
} from './lib/api.js';
import { AUDIT_CATEGORIES, AUDIT_EXPORT_MAX_ROWS, AUDIT_OTHER_CATEGORY, auditCategoryOf } from './lib/auditQuery.js';
import {
  EXCEPTION_REASONS,
  MIN_DECISION_NOTE_LENGTH,
  MIN_JUSTIFICATION_LENGTH,
  effectiveExceptionStatus,
  exceptionMaxDays,
  repositoryFromReference,
  severityForScope,
} from './lib/policyExceptions.js';
import { derivePublishGateView } from './lib/publishGateView.js';
import { WITHDRAWAL_CATEGORIES } from './lib/publishLifecycle.js';
import { candidateStageView, candidateTestParameters } from './lib/candidateTestView.js';
import { isApprovedCatalogImage, supplyChainCoverage } from './lib/supplyChainCoverage.js';
import {
  CVE_REMEDIATION_STATUS,
  cveRemediationStatus,
  indexVerifiedRemediations,
  summarizeCveRemediation,
} from './lib/cveRemediationStatus.js';
import { isTechnicalArtifact } from './lib/harbor.js';
import { isReportOnlyJob, WINDOWS_NOT_SUPPORTED_MESSAGE } from './lib/remediation.js';
import {
  planFreshness,
  remediationJobsForReport,
  scanTime,
  summarizeScanReport,
} from './lib/remediationPlanning.js';
import { isWindowsImage } from './lib/imageOs.js';
import { CANCELLATION_REASON_LENGTH, OPEN_ONBOARDING_STATES, parseImageReference } from './lib/onboarding.js';
import { copyText } from './lib/clipboard.js';
import { copaOutputReferenceOf } from './lib/pipelineRuns.js';
import { suggestPublishTarget } from './lib/publishTarget.js';
import { TeamManagement, TeamSwitcher, UserTeamMemberships } from './TeamManagement.jsx';
import { ImageComparisonPanel, ScanComparePanel } from './ImageComparison.jsx';
import { ImageJourney } from './ImageJourney.jsx';
import { OsTemplates } from './OsTemplates.jsx';
import { OnboardingProgress } from './OnboardingProgress.jsx';
import { cvssTone, epssTone } from './lib/security.js';

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: Gauge, group: 'Overview' },
  { id: 'journey', label: 'Image Journey', icon: Route, group: 'Pipeline' },
  { id: 'onboard', label: 'Onboard', icon: DownloadCloud, group: 'Pipeline' },
  { id: 'scan', label: 'Scan Results', icon: ScanLine, group: 'Pipeline' },
  { id: 'remediation', label: 'Remediation', icon: Wrench, group: 'Pipeline' },
  { id: 'publish', label: 'Publish', icon: UploadCloud, group: 'Pipeline' },
  { id: 'templates', label: 'OS Templates', icon: HardDrive, group: 'Pipeline', permission: 'os-template:read' },
  { id: 'catalog', label: 'Inventory', icon: Boxes, group: 'Management' },
  { id: 'reports', label: 'Reports', icon: BarChart3, group: 'Management' },
  { id: 'cve', label: 'CVE Queue', icon: Bug, group: 'Management' },
  { id: 'policy', label: 'Policy', icon: Lock, group: 'Management' },
  { id: 'exceptions', label: 'Exceptions', icon: FileKey2, group: 'Management' },
  { id: 'builder', label: 'App Builder', icon: Factory, group: 'Management' },
  { id: 'users', label: 'Users', icon: UsersRound, group: 'Management', permission: 'user:manage' },
  // Only while multi-tenancy is on (session.tenancy.enabled).
  { id: 'teams', label: 'Teams', icon: Building2, group: 'Management', permission: 'tenant:manage', requiresTenancy: true },
  { id: 'audit', label: 'Audit', icon: History, group: 'Management' },
];

const ROLE_OPTIONS = [
  { value: 'viewer', label: 'Viewer' },
  { value: 'operator', label: 'Operator' },
  { value: 'approver', label: 'Approver' },
  { value: 'admin', label: 'Admin' },
];
const roleLabel = (role) => ROLE_OPTIONS.find((option) => option.value === role)?.label || role || '—';

const pipelineSteps = [
  { key: 'ingest', label: 'Onboard', icon: DownloadCloud, view: 'onboard' },
  { key: 'scan', label: 'Scan', icon: ScanLine, view: 'scan' },
  { key: 'classify', label: 'Classify', icon: Filter, view: 'scan' },
  { key: 'remediate', label: 'Remediate', icon: Wrench, view: 'remediation' },
  { key: 'rebuild', label: 'Rebuild', icon: RefreshCw, view: 'remediation' },
  { key: 'verify', label: 'Verify', icon: ShieldCheck, view: 'remediation' },
  { key: 'publish', label: 'Publish', icon: UploadCloud, view: 'publish' },
  { key: 'report', label: 'Report', icon: BarChart3, view: 'reports' },
];

const emptyRemediationReport = {
  generatedAt: '',
  summary: {
    totalJobs: 0,
    verifiedJobs: 0,
    plannedJobs: 0,
    blockedJobs: 0,
    cvesRemediated: 0,
    publishBlocked: 0,
  },
  history: [],
  trend: [],
};

function DevLogin({ session, onLogin }) {
  const [subject, setSubject] = useState('demo.user');
  const [role, setRole] = useState('operator');
  const presets = [
    { role: 'viewer', label: 'Viewer — view only' },
    { role: 'operator', label: 'Operator — image / remediation / onboarding' },
    { role: 'approver', label: 'Approver — publish approval' },
    { role: 'admin', label: 'Admin — full access' },
  ];
  return (
    <div className="devlogin-screen" lang="en">
      <form
        className="devlogin-card"
        onSubmit={(event) => {
          event.preventDefault();
          if (subject.trim()) onLogin(subject.trim(), [role]);
        }}
      >
        <div className="devlogin-brand">SSI · Secure Image Factory</div>
        <h1>Sign in · Dev / Demo</h1>
        <p className="devlogin-note">
          Pick a user and role to see RBAC in action. This is not real authentication; production uses
          corporate SSO / LDAP.
        </p>
        <label className="devlogin-field">
          <span>User</span>
          <input value={subject} onChange={(event) => setSubject(event.target.value)} placeholder="name.surname" />
        </label>
        <label className="devlogin-field">
          <span>Role</span>
          <select value={role} onChange={(event) => setRole(event.target.value)}>
            {presets.map((preset) => (
              <option key={preset.role} value={preset.role}>
                {preset.label}
              </option>
            ))}
          </select>
        </label>
        <button className="primary-action wide full-span" type="submit">
          Sign in
        </button>
        {session.enforced ? null : (
          <p className="devlogin-hint">Note: enforcement is off. This screen only appears when SSI_RBAC_ENFORCED and SSI_DEV_LOGIN are on.</p>
        )}
      </form>
    </div>
  );
}

// Gerçek giriş formu (LDAP / lokal admin). Şifre HTTPS üzerinden sunucuya gider;
// sunucu imzalı oturum çerezini set eder. Başarıda sayfa yeniden yüklenir.
function LoginForm({ onSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    if (!username.trim() || !password) return;
    setBusy(true);
    setError('');
    try {
      await loginWithPassword(username.trim(), password);
      onSuccess();
    } catch (err) {
      setError(err.message || 'Sign-in failed.');
      setPassword('');
      setBusy(false);
    }
  }

  return (
    <div className="devlogin-screen" lang="en">
      <form className="devlogin-card" onSubmit={submit}>
        <div className="devlogin-brand">SSI · Secure Image Factory</div>
        <h1>Sign in</h1>
        <p className="devlogin-note">Sign in with your corporate (LDAP) account.</p>
        <label className="devlogin-field">
          <span>Username</span>
          <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" placeholder="name.surname" autoFocus />
        </label>
        <label className="devlogin-field">
          <span>Password</span>
          <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" />
        </label>
        {error && <p className="devlogin-error">{error}</p>}
        <button className="primary-action wide full-span" type="submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}

// What each role can do, mirroring ROLE_PERMISSIONS in lib/rbac.js (UI explanation only;
// the server enforces the real permission set).
const ROLE_DETAILS = {
  viewer: {
    summary: 'Read-only access to every screen',
    can: ['View inventory, scans and reports', 'View remediation and publish', 'View the audit log'],
    cannot: 'Change pipeline state or approve',
  },
  operator: {
    summary: 'Runs the pipeline',
    can: ['Everything a viewer can', 'Plan and manage remediation', 'Onboard images', 'Request publish and risk acceptance'],
    cannot: 'Approve publish or exceptions, or manage users',
  },
  approver: {
    summary: 'Approves what reaches production',
    can: ['Everything a viewer can', 'Approve publish requests', 'Approve, reject or revoke risk acceptances'],
    cannot: 'Run remediation or manage users',
  },
  admin: {
    summary: 'Full access, including users',
    can: ['All permissions', 'Manage users and roles'],
    cannot: '',
  },
};

const USER_FILTERS = [
  { key: 'all', label: 'All', match: () => true },
  ...ROLE_OPTIONS.slice()
    .reverse()
    .map((option) => ({ key: option.value, label: option.label, match: (user) => user.role === option.value })),
  { key: 'disabled', label: 'Disabled', match: (user) => user.status !== 'active' },
];

const EMPTY_NEW_USER = { username: '', displayName: '', email: '', role: 'viewer' };

function userInitials(user) {
  const source = String(user.displayName || user.username || '?').replace(/\(.*\)/, '').trim();
  return source
    .split(/[\s._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0])
    .join('')
    .toUpperCase();
}

function sameUser(a, b) {
  return Boolean(a) && String(a).trim().toLowerCase() === String(b || '').trim().toLowerCase();
}

// User management (admin only). LDAP authenticates; roles and access are managed here.
// The local admin is shown read-only.
function UserManagement({ currentUser, tenancyEnabled = false }) {
  const [users, setUsers] = useState([]);
  const [state, setState] = useState({ loading: true, error: '' });
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const [selected, setSelected] = useState('');
  const [creating, setCreating] = useState(false);
  const [actionError, setActionError] = useState('');
  const [saving, setSaving] = useState(false);

  async function refresh() {
    setState((current) => ({ ...current, loading: true }));
    try {
      const result = await listUsers();
      setUsers(Array.isArray(result.data) ? result.data : []);
      setState({ loading: false, error: '' });
    } catch (err) {
      setState({ loading: false, error: err.message || 'Users could not be loaded.' });
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  const needle = query.trim().toLowerCase();
  const searched = needle
    ? users.filter((user) =>
        [user.username, user.displayName, user.email].some((value) => String(value || '').toLowerCase().includes(needle)),
      )
    : users;
  const activeFilter = USER_FILTERS.find((item) => item.key === filter) || USER_FILTERS[0];
  const visible = searched.filter(activeFilter.match);
  const selectedUser = creating ? null : users.find((user) => user.username === selected) || visible[0] || null;

  async function run(action, fallbackMessage) {
    setSaving(true);
    setActionError('');
    try {
      await action();
      await refresh();
      return true;
    } catch (err) {
      setActionError(err.message || fallbackMessage);
      return false;
    } finally {
      setSaving(false);
    }
  }

  const selectUser = (username) => {
    setCreating(false);
    setActionError('');
    setSelected(username);
  };

  return (
    // lang="en": the shell is lang="tr", which would upper-case English labels with a dotted İ.
    <div className="catalog-layout inv-layout us-layout" lang="en">
      <section className="panel catalog-panel inv-panel">
        <div className="pub-stat-chips us-chips" role="group" aria-label="Filter">
          {USER_FILTERS.map((item) => (
            <button
              key={item.key}
              type="button"
              className={`psc ${item.key}${filter === item.key ? ' active' : ''}`}
              aria-pressed={filter === item.key}
              onClick={() => setFilter(item.key)}
            >
              <strong>{searched.filter(item.match).length}</strong>
              <span>{item.label}</span>
            </button>
          ))}
        </div>

        <div className="inv-toolbar">
          <div className="search-box inv-search">
            <Search size={16} />
            <input
              aria-label="User search"
              placeholder="Search name, username or email"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          <div className="inv-toolbar-spacer" />
          <button
            className="primary-action us-btn"
            type="button"
            onClick={() => {
              setActionError('');
              setCreating(true);
            }}
          >
            <Plus size={15} />
            Add user
          </button>
        </div>
        {state.error && <div className="inline-error">{state.error}</div>}

        <div className="us-table">
          <div className="us-row us-head">
            <span>User</span>
            <span>Role</span>
            <span>Sign-in</span>
            <span>Status</span>
            <span>Last sign-in</span>
          </div>
          {!state.loading && visible.length === 0 && (
            <div className="inv-empty">
              {users.length === 0
                ? 'No users yet. People who sign in with LDAP appear here; use Add user to assign a role in advance.'
                : 'No users match the current filters.'}
            </div>
          )}
          {visible.map((user) => (
            <button
              key={user.username}
              type="button"
              className={`us-row${selectedUser?.username === user.username ? ' selected' : ''}`}
              aria-pressed={selectedUser?.username === user.username}
              onClick={() => selectUser(user.username)}
            >
              <span className="us-user">
                <span className={`us-avatar ${user.role}`}>{userInitials(user)}</span>
                <span className="us-id">
                  <strong>
                    {user.displayName || user.username}
                    {sameUser(currentUser, user.username) && <em className="us-you">You</em>}
                  </strong>
                  <small>
                    {user.username}
                    {user.email ? ` · ${user.email}` : ''}
                  </small>
                </span>
              </span>
              <span>
                <span className={`us-role ${user.role}`}>{roleLabel(user.role)}</span>
              </span>
              <span className="us-source">
                {user.protected && <Lock size={13} />}
                {user.loginType === 'local' ? 'Local' : 'LDAP'}
              </span>
              <span>
                <Badge status={user.status === 'active' ? 'Approved' : 'Blocked'} label={user.status === 'active' ? 'Active' : 'Disabled'} />
              </span>
              <span className="inv-time">{user.lastLoginAt ? formatReportTime(user.lastLoginAt) : 'Never'}</span>
            </button>
          ))}
        </div>
      </section>

      {creating ? (
        <NewUserPanel
          saving={saving}
          error={actionError}
          onCancel={() => {
            setCreating(false);
            setActionError('');
          }}
          onCreate={async (form) => {
            const ok = await run(() => createUser(form), 'The user could not be created.');
            if (ok) {
              setCreating(false);
              setSelected(form.username.trim().toLowerCase());
            }
          }}
        />
      ) : (
        <UserDetailPanel
          key={selectedUser?.username || 'none'}
          user={selectedUser}
          tenancyEnabled={tenancyEnabled}
          isSelf={selectedUser ? sameUser(currentUser, selectedUser.username) : false}
          saving={saving}
          error={actionError}
          onSaveRole={(role) => run(() => updateUser(selectedUser.username, { role }), 'The role could not be saved.')}
          onToggleStatus={() =>
            run(
              () => updateUser(selectedUser.username, { status: selectedUser.status === 'active' ? 'disabled' : 'active' }),
              'The status could not be changed.',
            )
          }
          onRemove={async () => {
            const ok = await run(() => deleteUser(selectedUser.username), 'The user could not be removed.');
            if (ok) setSelected('');
          }}
        />
      )}
    </div>
  );
}

function RoleOptions({ value, disabled, onChange }) {
  return (
    <div className="us-roles" role="radiogroup" aria-label="Role">
      {ROLE_OPTIONS.map((option) => (
        <label key={option.value} className={`us-role-option${value === option.value ? ' on' : ''}${disabled ? ' disabled' : ''}`}>
          <input
            type="radio"
            name="user-role"
            value={option.value}
            checked={value === option.value}
            disabled={disabled}
            onChange={() => onChange(option.value)}
          />
          <span>
            <strong>{option.label}</strong>
            <small>{ROLE_DETAILS[option.value].summary}</small>
          </span>
        </label>
      ))}
    </div>
  );
}

function RolePermissions({ role }) {
  const details = ROLE_DETAILS[role];
  if (!details) return null;
  return (
    <div className="us-perms">
      <span>{roleLabel(role)} can</span>
      {details.can.map((item) => (
        <div key={item}>
          <CheckCircle2 size={13} />
          {item}
        </div>
      ))}
      {details.cannot && (
        <div className="no">
          <ShieldOff size={13} />
          Cannot: {details.cannot}
        </div>
      )}
    </div>
  );
}

function UserDetailPanel({ user, isSelf, tenancyEnabled, saving, error, onSaveRole, onToggleStatus, onRemove }) {
  const [role, setRole] = useState(user?.role || 'viewer');
  const [confirmName, setConfirmName] = useState('');

  if (!user) {
    return (
      <aside className="panel inspector inv-insp us-rail" aria-label="User detail">
        <div className="inv-empty">Select a user to manage their access.</div>
      </aside>
    );
  }

  const locked = Boolean(user.protected) || isSelf;
  const isLdap = user.loginType !== 'local';

  return (
    <aside className="panel inspector inv-insp us-rail" aria-label="User detail">
      <div className="us-profile">
        <span className={`us-avatar lg ${user.role}`}>{userInitials(user)}</span>
        <div>
          <h2>
            {user.displayName || user.username}
            {isSelf && <em className="us-you">You</em>}
          </h2>
          <small>{user.username}</small>
        </div>
        <Badge status={user.status === 'active' ? 'Approved' : 'Blocked'} label={user.status === 'active' ? 'Active' : 'Disabled'} />
      </div>

      <div className="inv-facts">
        <div className="detail full">
          <span>Email</span>
          <strong>{user.email || '—'}</strong>
        </div>
        <div className="detail">
          <span>Sign-in</span>
          <strong>{isLdap ? 'LDAP directory' : 'Local account'}</strong>
        </div>
        <div className="detail">
          <span>Last sign-in</span>
          <strong>{user.lastLoginAt ? formatReportTime(user.lastLoginAt) : 'Never'}</strong>
        </div>
        {user.createdAt && (
          <div className="detail">
            <span>Member since</span>
            <strong>{formatReportTime(user.createdAt).slice(0, 10)}</strong>
          </div>
        )}
      </div>

      {user.protected && (
        <div className="us-note">
          <Lock size={14} />
          Built-in local administrator for break-glass access. It is managed through server configuration and cannot be
          changed here.
        </div>
      )}
      {isSelf && !user.protected && (
        <div className="us-note">
          <Lock size={14} />
          You cannot change your own role or access. Ask another administrator.
        </div>
      )}

      <div className="inv-section-title">Role</div>
      <RoleOptions value={role} disabled={locked || saving} onChange={setRole} />
      <RolePermissions role={role} />

      {error && <div className="inline-error">{error}</div>}

      {/* Platform administrators act in every team, so only other roles have memberships. */}
      {tenancyEnabled && !user.protected && user.role !== 'admin' && (
        <UserTeamMemberships username={user.username} disabled={saving} />
      )}

      {!locked && (
        <>
          <div className="us-actions">
            <button
              className="primary-action us-btn"
              type="button"
              disabled={saving || role === user.role}
              onClick={() => onSaveRole(role)}
            >
              Save role
            </button>
            <button className="secondary-action us-btn" type="button" disabled={saving} onClick={onToggleStatus}>
              {user.status === 'active' ? 'Disable access' : 'Enable access'}
            </button>
          </div>

          <div className="us-danger">
            <div>
              <strong>Remove user</strong>
              <small>
                {isLdap
                  ? 'Removing does not block access: the user is re-created as Viewer at the next LDAP sign-in. Use Disable access to block sign-in.'
                  : 'The account and its role assignment are removed.'}
              </small>
            </div>
            <label className="us-confirm">
              <span>Type {user.username} to confirm</span>
              <input value={confirmName} onChange={(event) => setConfirmName(event.target.value)} aria-label="Confirm username" />
            </label>
            <button
              className="us-remove"
              type="button"
              disabled={saving || confirmName.trim().toLowerCase() !== user.username.toLowerCase()}
              onClick={onRemove}
            >
              <Trash2 size={14} />
              Remove user
            </button>
          </div>
        </>
      )}
    </aside>
  );
}

function NewUserPanel({ saving, error, onCancel, onCreate }) {
  const [form, setForm] = useState(EMPTY_NEW_USER);
  const update = (key) => (event) => setForm((current) => ({ ...current, [key]: event.target.value }));
  const usernameValid = /^[a-z0-9][a-z0-9._-]{1,63}$/i.test(form.username.trim());

  return (
    <aside className="panel inspector inv-insp us-rail" aria-label="Add user">
      <div className="us-profile">
        <span className="us-avatar lg viewer">
          <Plus size={18} />
        </span>
        <div>
          <h2>Add user</h2>
          <small>Assign a role before the first LDAP sign-in</small>
        </div>
      </div>
      <form
        className="us-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (usernameValid) onCreate({ ...form, username: form.username.trim() });
        }}
      >
        <label className="ab-field">
          <span>Username</span>
          <input value={form.username} onChange={update('username')} placeholder="name.surname" autoFocus />
          <small className={form.username && !usernameValid ? 'error' : ''}>
            {form.username && !usernameValid ? 'Use the LDAP account name (letters, digits, . _ -).' : 'The LDAP account name.'}
          </small>
        </label>
        <label className="ab-field">
          <span>Display name</span>
          <input value={form.displayName} onChange={update('displayName')} placeholder="Name Surname" />
        </label>
        <label className="ab-field">
          <span>Email</span>
          <input value={form.email} onChange={update('email')} placeholder="name.surname@company.com" />
        </label>
        <div className="inv-section-title">Role</div>
        <RoleOptions value={form.role} disabled={saving} onChange={(role) => setForm((current) => ({ ...current, role }))} />
        <RolePermissions role={form.role} />
        {error && <div className="inline-error">{error}</div>}
        <div className="us-actions">
          <button className="primary-action us-btn" type="submit" disabled={saving || !usernameValid}>
            Add user
          </button>
          <button className="secondary-action us-btn" type="button" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </aside>
  );
}

function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [images, setImages] = useState([]);
  const [inventoryState, setInventoryState] = useState({
    source: 'mock',
    loading: true,
    error: '',
  });
  const [sbomByImage, setSbomByImage] = useState({});
  const [sbomState, setSbomState] = useState({ imageId: '', loading: false, error: '' });
  const [exceptions, setExceptions] = useState([]);
  const [exceptionState, setExceptionState] = useState({ source: 'mock', loading: true, error: '' });
  const [exceptionDraft, setExceptionDraft] = useState(null);
  const [audit, setAudit] = useState([]);
  const [reporting, setReporting] = useState(emptyRemediationReport);
  const [reportState, setReportState] = useState({ source: 'mock', loading: false, error: '' });
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedImageId, setSelectedImageId] = useState('');
  const [builderForm, setBuilderForm] = useState({
    baseImageId: '',
    appName: 'payment-api',
    version: '1.4.8',
    port: '3000',
    command: 'node server.js',
    buildContext: '',
  });
  const [ingestJobs, setIngestJobs] = useState([]);
  const [onboardingState, setOnboardingState] = useState({ source: 'mock', loading: false, creating: false, error: '' });
  const [session, setSession] = useState({
    subject: '',
    displayName: '',
    roles: [],
    role: '',
    permissions: ['*'],
    authenticated: false,
    enforced: false,
    passwordLogin: false,
    tenancy: { enabled: false, tenantId: '', platformAdmin: false, teams: [] },
  });
  const [sessionLoaded, setSessionLoaded] = useState(false);
  const tenancy = session.tenancy || { enabled: false, teams: [] };
  const can = (permission) => session.permissions.includes('*') || session.permissions.includes(permission);
  const [devIdentity, setDevIdentity] = useState(() => getClientIdentity());
  // Gerçek giriş (LDAP/lokal admin): enforce açık, oturum yok ve şifreli giriş mümkün.
  const needsPasswordLogin = session.enforced && !session.authenticated && session.passwordLogin;
  // Dev/demo giriş: yalnızca SSI_DEV_LOGIN açık ve şifreli giriş yoksa.
  const needsDevLogin = session.enforced && session.devLogin && !session.passwordLogin && !devIdentity;
  // Data is requested only once the caller is known: before sign-in every API call would be
  // refused (401) and recorded as an access denial in the audit trail.
  // With multi-tenancy on, a member of several teams first gets a team selected (below).
  const canLoadData =
    sessionLoaded && (!session.enforced || session.authenticated) && !(tenancy.enabled && tenancy.selectionRequired);
  // Switching teams reloads the console, like signing in: every screen is read again in
  // the new team (the selection is kept per tab).
  function handleTeamSelect(tenantId) {
    setSelectedTenant(tenantId);
    window.location.reload();
  }
  function handleDevLogin(subject, roles) {
    setClientIdentity({ subject, roles });
    setDevIdentity({ subject, roles });
    window.location.reload();
  }
  async function handleLogout() {
    try {
      await logout();
    } catch {
      /* çerez yoksa sorun değil */
    }
    setClientIdentity(null);
    setDevIdentity(null);
    setSelectedTenant('');
    window.location.reload();
  }
  const [ingestForm, setIngestForm] = useState({ image: 'docker.io/library/nginx:1.27' });
  const [scans, setScans] = useState([]);
  const [scanState, setScanState] = useState({ source: 'mock', loading: false, error: '' });
  const [scanTargetId, setScanTargetId] = useState('');
  const [remediationJobs, setRemediationJobs] = useState([]);
  const [remediationState, setRemediationState] = useState({
    source: 'api',
    loading: false,
    creating: false,
    attaching: false,
    attachingEvidence: false,
    exportingHandoff: false,
    error: '',
  });
  const [remediationReadiness, setRemediationReadiness] = useState({
    data: null,
    source: 'api',
    loading: false,
    error: '',
  });
  const [remediationReportId, setRemediationReportId] = useState('');
  const [remediationJobId, setRemediationJobId] = useState('');
  // Planning mode: the Remediation screen shows the plan card for the selected scan
  // (remediationReportId) instead of a job, so the target image is always visible.
  const [remediationPlanning, setRemediationPlanning] = useState(false);
  const [publishPolicy, setPublishPolicy] = useState(null);
  const [publishRequests, setPublishRequests] = useState([]);
  const [publishRequestId, setPublishRequestId] = useState('');
  const [publishJobId, setPublishJobId] = useState('');
  const [journeyId, setJourneyId] = useState('');
  const [publishTarget, setPublishTarget] = useState({ repository: '', tag: '' });
  // Set once the person types in the target; the suggestion then leaves their values alone.
  const [publishTargetEdited, setPublishTargetEdited] = useState(false);
  // The publish boundary of the selected team (approved, or approved/<team> with multi-tenancy).
  const publishBoundaryPrefix = publishPolicy?.target?.repositoryPrefix || 'approved';
  const [publishApprovalReason, setPublishApprovalReason] = useState('');
  // Reject (pending request) and withdraw (published image) decisions, confirmed in the page.
  const [publishDecision, setPublishDecision] = useState({ reason: '', category: 'functional' });
  // Identity is not yet derived from a session; the requester and the approver are
  // entered explicitly so the separation-of-duties control has two distinct actors.
  const [publishState, setPublishState] = useState({
    source: 'api',
    loading: false,
    creating: false,
    approving: false,
    deciding: false,
    exporting: false,
    error: '',
  });

  const selectedImage = images.find((image) => image.id === selectedImageId) ?? images[0] ?? null;
  const selectedSbom = selectedImage ? sbomByImage[selectedImage.id] || [] : [];

  const searchedImages = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return images.filter((image) =>
      [image.name, image.version, image.runtime, image.status, ...(image.tags || [])].join(' ').toLowerCase().includes(needle),
    );
  }, [images, query]);

  const filteredImages = useMemo(
    () => searchedImages.filter((image) => matchesInventoryStatus(image, statusFilter)),
    [searchedImages, statusFilter],
  );

  const metrics = useMemo(() => {
    // Counts describe deployable images only (Cosign accessories and untagged manifests excluded).
    const deployable = images.filter((image) => !isTechnicalArtifact(image));
    // The approved catalog (published approved/ images), not every image with a clean scan.
    const approved = images.filter(isApprovedCatalogImage).length;
    const risky = deployable.filter((image) => image.critical > 0 || image.high > 0).length;
    // Publish requests that wait for an approver's decision.
    const awaitingApproval = publishRequests.filter((request) => request.status === 'ApprovalRequired').length;

    return {
      approved,
      risky,
      // Production gate: approved/ images with verified signature + SBOM evidence.
      gate: supplyChainCoverage(images),
      awaitingApproval,
    };
  }, [images, publishRequests]);

  useEffect(() => {
    if (activeView !== 'remediation') setRemediationPlanning(false);
  }, [activeView]);

  const verifiedPublishJobs = useMemo(
    () => remediationJobs.filter(
      (job) => job.mode === 'execution' && job.status === 'Verified' && job.verificationStatus === 'Passed',
    ),
    [remediationJobs],
  );
  // The target a new publish request suggests: approved/<image name> and the next free
  // verified-<date>-<source tag>-r<N> tag (src/lib/publishTarget.js). It follows the selected job
  // until the person edits it; choosing another job or creating the request suggests again.
  const publishJobImage = verifiedPublishJobs.find((job) => job.id === publishJobId)?.image || '';
  const suggestedPublishTarget = useMemo(
    () =>
      suggestPublishTarget({
        image: publishJobImage,
        repositoryPrefix: publishBoundaryPrefix,
        requests: publishRequests,
      }),
    [publishJobImage, publishBoundaryPrefix, publishRequests],
  );
  useEffect(() => {
    setPublishTargetEdited(false);
  }, [publishJobId]);
  useEffect(() => {
    if (!publishTargetEdited && suggestedPublishTarget) setPublishTarget(suggestedPublishTarget);
  }, [publishTargetEdited, suggestedPublishTarget]);

  // The Audit screen reads the log from the server itself each time it opens (paged, filtered).
  async function refreshReporting() {
    setReportState((current) => ({ ...current, loading: true, error: '' }));
    const reportResult = await getRemediationReport();
    setReporting(reportResult.data);
    setReportState({ source: reportResult.source, loading: false, error: reportResult.error });
  }

  useEffect(() => {
    if (!canLoadData) return undefined;
    let isMounted = true;

    setInventoryState((current) => ({ ...current, loading: true, error: '' }));

    listImages().then((result) => {
      if (!isMounted) {
        return;
      }

      setImages(result.data);
      setSelectedImageId((current) =>
        result.data.some((image) => image.id === current) ? current : result.data[0]?.id || current,
      );
      setInventoryState({
        source: result.source,
        loading: false,
        error: result.error,
      });
    });

    return () => {
      isMounted = false;
    };
  }, [canLoadData]);

  async function refreshPublishGate() {
    setPublishState((current) => ({ ...current, loading: true, error: '' }));

    try {
      const [policyResult, requestResult] = await Promise.all([
        getPublishPolicy(),
        listPublishRequests(),
      ]);
      setPublishPolicy(policyResult.data);
      setPublishRequests(requestResult.data);
      setPublishRequestId((current) =>
        requestResult.data.some((request) => request.id === current)
          ? current
          : requestResult.data[0]?.id || '',
      );
      setPublishState((current) => ({
        ...current,
        source: requestResult.source,
        loading: false,
        error: policyResult.error || requestResult.error,
      }));
    } catch (error) {
      setPublishState((current) => ({
        ...current,
        loading: false,
        error: error.message || 'The publish policy could not be loaded.',
      }));
    }
  }

  useEffect(() => {
    if (canLoadData) refreshPublishGate();
  }, [canLoadData]);

  async function refreshOnboarding() {
    setOnboardingState((current) => ({ ...current, loading: true, error: '' }));
    const result = await listOnboardingRequests();
    setIngestJobs(result.data);
    setOnboardingState((current) => ({ ...current, source: result.source, loading: false, error: result.error }));
  }

  useEffect(() => {
    if (canLoadData) refreshOnboarding();
  }, [canLoadData]);

  const hasOpenImports = ingestJobs.some((job) => OPEN_ONBOARDING_STATES.includes(job.status));
  useEffect(() => {
    if (!canLoadData || activeView !== 'onboard' || !hasOpenImports) return undefined;
    let cancelled = false;
    let timer;
    async function poll() {
      const result = await listOnboardingRequests();
      if (cancelled) return;
      if (!result.error) setIngestJobs(result.data);
      timer = setTimeout(poll, 15000);
    }
    timer = setTimeout(poll, 15000);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [canLoadData, activeView, hasOpenImports]);

  useEffect(() => {
    if (canLoadData && activeView === 'journey') refreshJourney();
    // Read again each time the journey is opened; the helpers are stable in effect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canLoadData, activeView]);

  useEffect(() => {
    getSession().then((result) => {
      const team = result.data?.tenancy;
      if (team?.enabled) {
        // A refused selection (e.g. the membership was removed): forget it; the server has
        // already answered without it.
        if (team.selectionError) setSelectedTenant('');
        // A member of several teams starts in the first one.
        const first = (team.teams || []).find((item) => item.status === 'active');
        if (team.selectionRequired && first) {
          handleTeamSelect(first.id);
          return;
        }
      }
      setSession(result.data);
      setSessionLoaded(true);
    });
  }, []);

  useEffect(() => {
    setPublishJobId((current) =>
      verifiedPublishJobs.some((job) => job.id === current)
        ? current
        : verifiedPublishJobs[0]?.id || '',
    );
  }, [verifiedPublishJobs]);

  useEffect(() => {
    if (!canLoadData) return undefined;
    let isMounted = true;

    setReportState((current) => ({ ...current, loading: true, error: '' }));

    getRemediationReport().then((reportResult) => {
      if (!isMounted) {
        return;
      }

      setReporting(reportResult.data);
      setReportState({ source: reportResult.source, loading: false, error: reportResult.error });
    });

    return () => {
      isMounted = false;
    };
  }, [canLoadData]);

  useEffect(() => {
    const selectedJob = remediationJobs.find((job) => job.id === remediationJobId) ?? remediationJobs[0];

    if (!selectedJob) {
      setRemediationReadiness({ data: null, source: 'api', loading: false, error: '' });
      return undefined;
    }

    let isMounted = true;
    setRemediationReadiness((current) => ({ ...current, loading: true, error: '' }));

    getRemediationExecutionReadiness(selectedJob).then((result) => {
      if (!isMounted) {
        return;
      }

      setRemediationReadiness({
        data: result.data,
        source: result.source,
        loading: false,
        error: result.error,
      });
    });

    return () => {
      isMounted = false;
    };
  }, [remediationJobId, remediationJobs]);

  useEffect(() => {
    if (inventoryState.loading || !selectedImage?.id || !selectedImage.sbom) {
      return undefined;
    }

    let isMounted = true;
    setSbomState({ imageId: selectedImage.id, loading: true, error: '' });

    getImageSbom(selectedImage.id).then((result) => {
      if (!isMounted) {
        return;
      }

      setSbomByImage((current) => ({ ...current, [selectedImage.id]: result.data }));
      setSbomState({
        imageId: selectedImage.id,
        loading: false,
        error: result.error,
      });
    });

    return () => {
      isMounted = false;
    };
  }, [inventoryState.loading, selectedImage?.id, selectedImage?.sbom]);

  useEffect(() => {
    if (!canLoadData) return undefined;
    let isMounted = true;

    setScanState((current) => ({ ...current, loading: true, error: '' }));

    listScanReports().then((result) => {
      if (!isMounted) {
        return;
      }

      setScans(result.data);
      setScanTargetId((current) =>
        result.data.some((report) => report.id === current) ? current : result.data[0]?.id || current,
      );
      setRemediationReportId((current) =>
        result.data.some((report) => report.id === current) ? current : result.data[0]?.id || '',
      );
      setScanState({
        source: result.source,
        loading: false,
        error: result.error,
      });
    });

    return () => {
      isMounted = false;
    };
  }, [canLoadData]);

  useEffect(() => {
    if (!canLoadData) return undefined;
    let isMounted = true;

    setRemediationState((current) => ({ ...current, loading: true, error: '' }));

    listRemediationJobs().then((result) => {
      if (!isMounted) {
        return;
      }

      // Report-only jobs from the earlier Windows flow stay stored but are not shown.
      const jobs = result.data.filter((job) => !isReportOnlyJob(job));
      setRemediationJobs(jobs);
      setRemediationJobId((current) => (jobs.some((job) => job.id === current) ? current : jobs[0]?.id || ''));
      setRemediationState({
        source: result.source,
        loading: false,
        creating: false,
        attaching: false,
        attachingEvidence: false,
        exportingHandoff: false,
        error: result.error,
      });
    });

    return () => {
      isMounted = false;
    };
  }, [canLoadData]);

  function updateIngestField(field, value) {
    setIngestForm((current) => ({ ...current, [field]: value }));
  }

  async function onboardImage(event) {
    event.preventDefault();
    const sourceReference = ingestForm.image.trim();
    if (!sourceReference) return;
    setOnboardingState((current) => ({ ...current, creating: true, error: '' }));
    try {
      const result = await createOnboardingRequest(sourceReference);
      setAudit((current) => [
        `${result.data.source?.reference || sourceReference} onboarding requested -> ${result.data.target?.tagReference || 'quarantine'}`,
        ...current,
      ]);
      await refreshOnboarding();
      setOnboardingState((current) => ({ ...current, creating: false, error: '' }));
    } catch (error) {
      setOnboardingState((current) => ({ ...current, creating: false, error: error.message || 'The onboarding request could not be created.' }));
    }
  }

  // Throws with the server's message, which the Onboard row shows next to the reason.
  async function cancelOnboarding(requestId, reason) {
    const result = await cancelOnboardingRequest(requestId, reason);
    setAudit((current) => [`${result.data.id || requestId} onboarding cancelled`, ...current]);
    await refreshOnboarding();
  }

  function updateBuilderField(field, value) {
    setBuilderForm((current) => ({ ...current, [field]: value }));
  }

  // App Builder hand-off: the request is downloaded for the build pipeline; nothing is registered here.
  function recordBuildHandoff(targetReference) {
    setAudit((current) => [`Build request for ${targetReference} downloaded`, ...current]);
  }

  // CVE Queue → Remediation for one affected image: always the plan card for that image.
  // Jobs that already cover the image are listed there (with whether they predate the
  // latest scan) instead of being opened silently: an older plan or a verified run of an
  // earlier scan is not the answer to "fix this finding now". Nothing is created
  // implicitly; the user confirms the dry run on the card.
  function openRemediationForReport(reportId, cveId) {
    setRemediationReportId(reportId);
    setRemediationState((current) => ({ ...current, error: '' }));
    setRemediationPlanning(true);
    setActiveView('remediation');
    setAudit((current) => [`${cveId}: ${reportId} opened in Remediation`, ...current]);
  }

  // "New Dry Run" opens the plan card; the current job's image is preselected when it is
  // still among the scanned images.
  function startRemediationPlanning(job) {
    if (job?.scanReportId && scans.some((report) => report.id === job.scanReportId)) {
      setRemediationReportId(job.scanReportId);
    }
    setRemediationState((current) => ({ ...current, error: '' }));
    setRemediationPlanning(true);
  }

  function openRemediationJob(jobId) {
    setRemediationJobId(jobId);
    setRemediationPlanning(false);
  }

  async function createDryRunRemediation() {
    if (!remediationReportId || scanState.loading) {
      return;
    }

    setRemediationState((current) => ({ ...current, creating: true, error: '' }));

    try {
      const result = await createRemediationDryRun(remediationReportId);
      setRemediationJobs((current) => [
        result.data,
        ...current.filter((job) => job.id !== result.data.id),
      ]);
      setRemediationJobId(result.data.id);
      setRemediationPlanning(false);
      setRemediationState({
        source: result.source,
        loading: false,
        creating: false,
        attaching: false,
        attachingEvidence: false,
        exportingHandoff: false,
        error: result.error,
      });
      refreshReporting();
    } catch (error) {
      setRemediationState((current) => ({
        ...current,
        creating: false,
        error: error.message,
      }));
    }
  }

  async function attachCanonicalReport(file) {
    const job = remediationJobs.find((item) => item.id === remediationJobId) ?? remediationJobs[0];
    if (!job || !file) {
      return;
    }

    if (file.size > 2 * 1024 * 1024) {
      setRemediationState((current) => ({
        ...current,
        error: 'Canonical Trivy JSON en fazla 2 MB olabilir.',
      }));
      return;
    }

    setRemediationState((current) => ({ ...current, attaching: true, error: '' }));

    try {
      const rawReport = await file.text();
      JSON.parse(rawReport);
      const result = await attachCanonicalTrivyReport(job.id, rawReport);
      setRemediationJobs((current) =>
        current.map((item) => (item.id === result.data.id ? result.data : item)),
      );
      setRemediationJobId(result.data.id);
      setRemediationState({
        source: result.source,
        loading: false,
        creating: false,
        attaching: false,
        attachingEvidence: false,
        exportingHandoff: false,
        error: result.error,
      });
      refreshReporting();
    } catch (error) {
      setRemediationState((current) => ({
        ...current,
        attaching: false,
        error: error.message || 'The canonical Trivy JSON could not be read.',
      }));
    }
  }

  async function attachSupplyChainEvidenceFile(file) {
    const job = remediationJobs.find((item) => item.id === remediationJobId) ?? remediationJobs[0];
    if (!job || !file) {
      return;
    }

    if (file.size > 2 * 1024 * 1024) {
      setRemediationState((current) => ({
        ...current,
        error: 'Supply-chain evidence can be at most 2 MB.',
      }));
      return;
    }

    setRemediationState((current) => ({ ...current, attaching: true, error: '' }));

    try {
      const rawEvidence = await file.text();
      JSON.parse(rawEvidence);
      const result = await attachSupplyChainEvidence(job.id, rawEvidence);
      setRemediationJobs((current) =>
        current.map((item) => (item.id === result.data.id ? result.data : item)),
      );
      setRemediationJobId(result.data.id);
      setRemediationState({
        source: result.source,
        loading: false,
        creating: false,
        attaching: false,
        attachingEvidence: false,
        exportingHandoff: false,
        error: result.error,
      });
      refreshReporting();
    } catch (error) {
      setRemediationState((current) => ({
        ...current,
        attaching: false,
        error: error.message || 'The supply-chain evidence could not be read.',
      }));
    }
  }

  async function attachCandidateTestFile(file) {
    const job = remediationJobs.find((item) => item.id === remediationJobId) ?? remediationJobs[0];
    if (!job || !file) {
      return;
    }

    if (file.size > 1024 * 1024) {
      setRemediationState((current) => ({
        ...current,
        error: 'A candidate test result can be at most 1 MB.',
      }));
      return;
    }

    setRemediationState((current) => ({ ...current, attaching: true, error: '' }));

    try {
      const rawEvidence = await file.text();
      JSON.parse(rawEvidence);
      const result = await attachCandidateTestEvidence(job.id, rawEvidence);
      setRemediationJobs((current) =>
        current.map((item) => (item.id === result.data.id ? result.data : item)),
      );
      setRemediationJobId(result.data.id);
      setRemediationState((current) => ({ ...current, source: result.source, attaching: false, error: result.error }));
      refreshReporting();
    } catch (error) {
      setRemediationState((current) => ({
        ...current,
        attaching: false,
        error: error.message || 'The candidate test result could not be read.',
      }));
    }
  }

  // Returns true when the decision was stored, so the form can close.
  async function recordConsumerDecision(payload) {
    const job = remediationJobs.find((item) => item.id === remediationJobId) ?? remediationJobs[0];
    if (!job) {
      return false;
    }

    setRemediationState((current) => ({ ...current, deciding: true, error: '' }));

    try {
      const result = await recordConsumerAcceptance(job.id, payload);
      setRemediationJobs((current) =>
        current.map((item) => (item.id === result.data.id ? result.data : item)),
      );
      setRemediationState((current) => ({ ...current, deciding: false, error: result.error }));
      refreshReporting();
      return true;
    } catch (error) {
      setRemediationState((current) => ({
        ...current,
        deciding: false,
        error: error.message || 'The decision could not be recorded.',
      }));
      return false;
    }
  }

  async function downloadWorkerHandoff() {
    const job = remediationJobs.find((item) => item.id === remediationJobId) ?? remediationJobs[0];
    if (!job) {
      return;
    }

    setRemediationState((current) => ({ ...current, exportingHandoff: true, error: '' }));

    try {
      const result = await getRemediationWorkerHandoff(job);
      downloadJson(`${job.id.toLowerCase()}-worker-handoff.json`, result.data);
      setRemediationState((current) => ({
        ...current,
        source: result.source,
        exportingHandoff: false,
        error: result.error,
      }));
      setAudit((current) => [
        `${job.id} credential-free worker handoff manifest exported; no dispatch was requested`,
        ...current,
      ]);
    } catch (error) {
      setRemediationState((current) => ({
        ...current,
        exportingHandoff: false,
        error: error.message || 'The worker handoff manifest could not be loaded.',
      }));
    }
  }

  async function attachVerificationEvidence(file) {
    const job = remediationJobs.find((item) => item.id === remediationJobId) ?? remediationJobs[0];
    if (!job || !file) {
      return;
    }

    if (file.size > 2 * 1024 * 1024) {
      setRemediationState((current) => ({
        ...current,
        error: 'Remediation evidence JSON en fazla 2 MB olabilir.',
      }));
      return;
    }

    setRemediationState((current) => ({ ...current, attachingEvidence: true, error: '' }));

    try {
      const evidence = JSON.parse(await file.text());
      const result = await attachRemediationVerificationEvidence(job.id, evidence);
      setRemediationJobs((current) => [
        result.data,
        ...current.filter((item) => item.id !== result.data.id),
      ]);
      setRemediationJobId(result.data.id);
      setRemediationState({
        source: result.source,
        loading: false,
        creating: false,
        attaching: false,
        attachingEvidence: false,
        exportingHandoff: false,
        error: result.error,
      });
      refreshReporting();
    } catch (error) {
      setRemediationState((current) => ({
        ...current,
        attachingEvidence: false,
        error: error.message || 'The remediation evidence JSON could not be read.',
      }));
    }
  }

  function updatePublishTarget(field, value) {
    setPublishTargetEdited(true);
    setPublishTarget((current) => ({ ...current, [field]: value }));
  }

  async function createPublishGateRequest(event) {
    event.preventDefault();
    if (!publishJobId) return;

    setPublishState((current) => ({ ...current, creating: true, error: '' }));
    try {
      const result = await createPublishRequest(publishJobId, publishTarget);
      setPublishRequests((current) => [
        result.data,
        ...current.filter((request) => request.id !== result.data.id),
      ]);
      setPublishRequestId(result.data.id);
      // The next suggestion moves on to the following free revision.
      setPublishTargetEdited(false);
      setPublishState((current) => ({
        ...current,
        source: result.source,
        creating: false,
        error: result.error,
      }));
      refreshReporting();
    } catch (error) {
      setPublishState((current) => ({
        ...current,
        creating: false,
        error: error.message || 'The publish policy evaluation could not be created.',
      }));
    }
  }

  async function approveSelectedPublishRequest(event) {
    event.preventDefault();
    if (!publishRequestId) return;

    setPublishState((current) => ({ ...current, approving: true, error: '' }));
    try {
      const result = await approvePublishRequest(publishRequestId, publishApprovalReason);
      setPublishRequests((current) =>
        current.map((request) => (request.id === result.data.id ? result.data : request)),
      );
      setPublishApprovalReason('');
      setPublishState((current) => ({
        ...current,
        source: result.source,
        approving: false,
        error: result.error,
      }));
      refreshReporting();
    } catch (error) {
      setPublishState((current) => ({
        ...current,
        approving: false,
        error: error.message || 'The publish approval could not be saved.',
      }));
    }
  }

  // Another approver may withdraw an image at any time: the publish screen reloads the jobs
  // with the queue so it can show it.
  async function reloadPublishJobs() {
    try {
      const result = await listRemediationJobs();
      setRemediationJobs(result.data.filter((job) => !isReportOnlyJob(job)));
    } catch (error) {
      setPublishState((current) => ({
        ...current,
        error: error.message || 'The remediation jobs could not be reloaded.',
      }));
    }
  }

  // A pipeline run started from the Remediation screen returns the updated job.
  function replaceRemediationJob(job) {
    setRemediationJobs((current) => current.map((item) => (item.id === job.id ? job : item)));
  }

  // A worker pipeline finished: its evidence (a new RM-EXEC job, a candidate test result) may
  // have reached SSI, so the jobs and the reports are read again.
  async function reloadRemediationJobs() {
    const result = await listRemediationJobs();
    if (!result.error) {
      setRemediationJobs(result.data.filter((job) => !isReportOnlyJob(job)));
    }
    refreshReporting();
  }

  // Image Journey: open the screen of a step with its record selected.
  function openJourneyStep(view, recordId = '') {
    if (view === 'remediation' && recordId) {
      setRemediationJobId(recordId);
      setRemediationPlanning(false);
    }
    if (view === 'publish' && recordId) {
      if (recordId.startsWith('RM-')) setPublishJobId(recordId);
      else setPublishRequestId(recordId);
    }
    setActiveView(view);
  }

  // Everything a journey reads: jobs, publish requests and onboarding requests.
  async function refreshJourney() {
    await Promise.all([reloadRemediationJobs(), refreshPublishGate(), refreshOnboarding()]);
  }

  async function refreshPublishScreen() {
    await Promise.all([refreshPublishGate(), reloadPublishJobs()]);
  }

  async function decideSelectedPublishRequest(event, kind) {
    event.preventDefault();
    if (!publishRequestId) return;

    setPublishState((current) => ({ ...current, deciding: true, error: '' }));
    let result;
    try {
      result =
        kind === 'withdraw'
          ? await withdrawPublishRequest(publishRequestId, publishDecision)
          : await rejectPublishRequest(publishRequestId, publishDecision.reason);
    } catch (error) {
      setPublishState((current) => ({
        ...current,
        deciding: false,
        error:
          error.message ||
          (kind === 'withdraw' ? 'The withdrawal could not be saved.' : 'The rejection could not be saved.'),
      }));
      return;
    }

    setPublishDecision({ reason: '', category: 'functional' });
    setPublishState((current) => ({ ...current, source: result.source, deciding: false, error: result.error }));
    // The decision is saved. A withdrawal also changes the other published requests of the
    // digest, the job and the production gate, so everything is reloaded; a failed reload
    // must not look like a failed decision.
    try {
      await Promise.all([
        refreshPublishScreen(),
        kind === 'withdraw' ? listImages().then((images) => setImages(images.data)) : Promise.resolve(),
        refreshReporting(),
      ]);
    } catch (error) {
      setPublishState((current) => ({
        ...current,
        error: `${kind === 'withdraw' ? 'Withdrawal' : 'Rejection'} saved, but the screen could not be refreshed: ${
          error.message || 'unknown error'
        }`,
      }));
    }
  }

  // A reason typed for one request must never carry over to another request or decision.
  useEffect(() => {
    setPublishDecision({ reason: '', category: 'functional' });
  }, [publishRequestId]);

  async function downloadPublishHandoff() {
    if (!publishRequestId) return;

    setPublishState((current) => ({ ...current, exporting: true, error: '' }));
    try {
      const result = await getPublishWorkerHandoff(publishRequestId);
      downloadJson(`${publishRequestId.toLowerCase()}-publish-handoff.json`, result.data);
      setPublishState((current) => ({
        ...current,
        source: result.source,
        exporting: false,
        error: result.error,
      }));
    } catch (error) {
      setPublishState((current) => ({
        ...current,
        exporting: false,
        error: error.message || 'The publish worker handoff could not be loaded.',
      }));
    }
  }

  async function refreshExceptions() {
    setExceptionState((current) => ({ ...current, loading: true }));
    const result = await listExceptions();
    setExceptions(Array.isArray(result.data) ? result.data : []);
    setExceptionState({ source: result.source, loading: false, error: result.error });
  }

  useEffect(() => {
    if (canLoadData) refreshExceptions();
  }, [canLoadData]);

  // Risk acceptance mutations: the server validates and audits; the lists are reloaded so the
  // Exceptions, CVE Queue and Audit views show the stored state.
  async function submitExceptionRequest(payload) {
    const result = await requestException(payload);
    await refreshExceptions();
    refreshReporting();
    return result.data;
  }

  async function decideOnException(exceptionId, decision, note) {
    const result = await decideException(exceptionId, decision, note);
    await refreshExceptions();
    refreshReporting();
    return result.data;
  }

  function openExceptionRequest(draft) {
    setExceptionDraft(draft);
    setActiveView('exceptions');
  }

  if (!sessionLoaded) {
    return <div className="boot-splash">Loading SSI…</div>;
  }

  if (needsPasswordLogin) {
    return <LoginForm onSuccess={() => window.location.reload()} />;
  }

  if (needsDevLogin) {
    return <DevLogin session={session} onLogin={handleDevLogin} />;
  }

  // İzin gerektiren menü öğeleri (ör. Kullanıcı Yönetimi) yalnızca yetkiliyse görünür.
  const visibleNav = navItems.filter(
    (item) => (!item.permission || can(item.permission)) && (!item.requiresTenancy || tenancy.enabled),
  );

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <svg className="brand-mark" viewBox="0 0 48 48" aria-hidden="true">
            <path d="M24 3 L41 9.5 V23 C41 33.5 33.7 40.6 24 45 C14.3 40.6 7 33.5 7 23 V9.5 Z" fill="#ffffff" />
            <path d="M24 14.5 L32 18.7 L24 22.9 L16 18.7 Z" fill="#5b8cf5" />
            <path d="M16 18.7 L24 22.9 V32.5 L16 28.3 Z" fill="#2563eb" />
            <path d="M32 18.7 L24 22.9 V32.5 L32 28.3 Z" fill="#2f6fe0" />
          </svg>
          <div>
            <strong>SSI</strong>
            <span>Secure Image Factory</span>
          </div>
        </div>

        <nav className="nav-list" aria-label="Main menu">
          {visibleNav.map((item, index) => {
            const Icon = item.icon;
            const showGroup = index === 0 || item.group !== visibleNav[index - 1].group;
            return (
              <React.Fragment key={item.id}>
                {showGroup && <span className="nav-group">{item.group}</span>}
                <button
                  className={activeView === item.id ? 'nav-item active' : 'nav-item'}
                  type="button"
                  onClick={() => setActiveView(item.id)}
                >
                  <Icon size={18} />
                  <span>{item.label}</span>
                </button>
              </React.Fragment>
            );
          })}
        </nav>

        <div className="sidebar-panel">
          <span className="panel-label">Production Gate</span>
          <strong>{metrics.gate.percent === null ? '—' : `${metrics.gate.percent}%`}</strong>
          <small>
            {metrics.gate.total === 0
              ? 'No approved images yet'
              : `${metrics.gate.covered}/${metrics.gate.total} approved signed + SBOM`}
          </small>
          {metrics.gate.withdrawn > 0 && (
            <small className="gate-withdrawn-note">
              {metrics.gate.withdrawn} withdrawn image{metrics.gate.withdrawn === 1 ? '' : 's'} still in approved/
            </small>
          )}
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Container Security Platform</p>
            <h1>{navItems.find((item) => item.id === activeView)?.label}</h1>
          </div>
          <div className="topbar-actions">
            <TeamSwitcher tenancy={tenancy} onSelect={handleTeamSelect} />
            {session.authenticated && (session.displayName || session.subject) && (
              <span className="topbar-user" title={`User: ${session.subject || '—'}`}>
                {session.displayName || session.subject}
              </span>
            )}
            <span className="role-badge" title={`Kimlik: ${session.subject || '—'}`}>
              {session.enforced ? roleLabel(session.role || session.roles[0]) : 'PoC · full access'}
            </span>
            {(session.authenticated || devIdentity) && (
              <button className="secondary-action" type="button" onClick={handleLogout} title="Logout">
                <LogOut size={15} /> Logout
              </button>
            )}
            {/* Opens App Builder, which prepares a build request for the build pipeline; SSI
                itself does not build images. */}
            <button
              className="primary-action"
              type="button"
              onClick={() => setActiveView('builder')}
              title="Prepare a build request on an approved base image"
            >
              <Plus size={18} />
              New build request
            </button>
          </div>
        </header>

        {activeView === 'dashboard' && (
          <Dashboard metrics={metrics} images={images} onSelect={setSelectedImageId} setActiveView={setActiveView} onStatusFilter={setStatusFilter} />
        )}

        {activeView === 'onboard' && (
          <Onboard form={ingestForm} jobs={ingestJobs} state={onboardingState} permitCreate={can('onboarding:create')} onField={updateIngestField} onSubmit={onboardImage} onCancel={cancelOnboarding} onRefresh={refreshOnboarding} />
        )}

        {activeView === 'scan' && (
          <ScanResults reports={scans} state={scanState} selectedId={scanTargetId} onSelect={setScanTargetId} permitManageRemediation={can('remediation:manage')} />
        )}

        {activeView === 'remediation' && (
          <Remediation
            jobs={remediationJobs}
            reports={scans}
            publishRequests={publishRequests}
            scanState={scanState}
            state={remediationState}
            readiness={remediationReadiness}
            selectedId={remediationJobId}
            selectedReportId={remediationReportId}
            onSelect={setRemediationJobId}
            onReportSelect={setRemediationReportId}
            onCreateDryRun={createDryRunRemediation}
            planning={remediationPlanning}
            onStartPlanning={startRemediationPlanning}
            onCancelPlanning={() => setRemediationPlanning(false)}
            onOpenJob={openRemediationJob}
            onAttachCanonicalReport={attachCanonicalReport}
            onAttachVerificationEvidence={attachVerificationEvidence}
            onAttachSupplyChainEvidence={attachSupplyChainEvidenceFile}
            onAttachCandidateTest={attachCandidateTestFile}
            onRecordConsumerDecision={recordConsumerDecision}
            onDownloadWorkerHandoff={downloadWorkerHandoff}
            onJobUpdated={replaceRemediationJob}
            onRunsSettled={reloadRemediationJobs}
            permitPlan={can('remediation:plan')}
            permitManage={can('remediation:manage')}
            permitAccept={can('remediation:accept')}
          />
        )}

        {activeView === 'journey' && (
          <ImageJourney
            jobs={remediationJobs}
            publishRequests={publishRequests}
            onboardingRequests={ingestJobs}
            selectedId={journeyId}
            onSelect={setJourneyId}
            onOpen={openJourneyStep}
            renderPanel={(kind, record) =>
              kind === 'publish' ? (
                <AzurePipelinePanel
                  key={record.id}
                  recordKey={record.id}
                  version={`${record.updatedAt}|${record.status}`}
                  load={() => getRecordPipelineRuns('publish-requests', record.id)}
                  start={(payload) => startRecordPipelineRun('publish-requests', record.id, payload)}
                  permitted={can('publish:approve')}
                  permissionHint="Requires the publish:approve permission (approver role)."
                  onStarted={refreshJourney}
                  onRunsSettled={refreshJourney}
                  note={`${record.id} · ${record.target?.tagReference || ''}`}
                  showWhenDisabled
                />
              ) : (
                <PipelineRunsPanel
                  key={record.id}
                  job={record}
                  permitManage={can('remediation:manage')}
                  onJobUpdated={replaceRemediationJob}
                  onRunsSettled={refreshJourney}
                />
              )
            }
          />
        )}

        {activeView === 'publish' && (
          <Publish
            jobs={verifiedPublishJobs}
            requests={publishRequests}
            policy={publishPolicy}
            state={publishState}
            selectedJobId={publishJobId}
            selectedRequestId={publishRequestId}
            target={publishTarget}
            approvalReason={publishApprovalReason}
            currentUser={session}
            onJobSelect={setPublishJobId}
            onRequestSelect={setPublishRequestId}
            onTarget={updatePublishTarget}
            onApprovalReason={setPublishApprovalReason}
            onCreate={createPublishGateRequest}
            onApprove={approveSelectedPublishRequest}
            decision={publishDecision}
            onDecision={setPublishDecision}
            onReject={(event) => decideSelectedPublishRequest(event, 'reject')}
            onWithdraw={(event) => decideSelectedPublishRequest(event, 'withdraw')}
            onDownloadHandoff={downloadPublishHandoff}
            onRefresh={refreshPublishScreen}
            permitApprove={can('publish:approve')}
            permitRequest={can('publish:request')}
          />
        )}

        {activeView === 'templates' && can('os-template:read') && (
          <OsTemplates
            permitBuild={can('os-template:build')}
            permitApprove={can('os-template:approve')}
            permitDownload={can('os-template:download')}
            actorId={session.authenticated ? session.subject : ''}
            renderPanel={(build, onChanged) => (
              <AzurePipelinePanel
                key={build.id}
                recordKey={build.id}
                version={`${build.updatedAt}|${build.status}`}
                load={() => getRecordPipelineRuns('os-templates', build.id)}
                start={(payload) => startRecordPipelineRun('os-templates', build.id, payload)}
                permitted={can('os-template:build')}
                permissionHint="Requires the os-template:build permission (operator role)."
                onStarted={onChanged}
                onRunsSettled={onChanged}
                title={`Azure DevOps · ${build.id}`}
                note={
                  build.os === 'ubuntu-24.04'
                    ? `${build.request.baseImageUrl.split('/').slice(-2).join('/')} → ${build.request.templateName} · LinuxPool`
                    : `${build.request.isoFile} (index ${build.request.imageIndex}) → ${build.request.templateName} · build machine pool SSI-Windows`
                }
                showWhenDisabled
              />
            )}
          />
        )}

        {activeView === 'catalog' && (
          <Catalog
            images={filteredImages}
            scopeImages={searchedImages}
            inventoryState={inventoryState}
            query={query}
            statusFilter={statusFilter}
            selectedImage={selectedImage}
            selectedSbom={selectedSbom}
            sbomState={sbomState}
            onQuery={setQuery}
            onStatusFilter={setStatusFilter}
            onSelect={setSelectedImageId}
          />
        )}

        {activeView === 'builder' && (
          <Builder
            form={builderForm}
            images={images}
            policy={publishPolicy}
            requestedBy={session.authenticated ? session.subject : ''}
            onField={updateBuilderField}
            onHandoff={recordBuildHandoff}
          />
        )}

        {activeView === 'cve' && (
          <CveQueue
            reports={scans}
            state={scanState}
            remediationJobs={remediationJobs}
            exceptions={exceptions}
            canRequestException={can('exception:request')}
            onRemediate={openRemediationForReport}
            onRequestException={openExceptionRequest}
          />
        )}

        {activeView === 'policy' && (
          <Policy
            policy={publishPolicy}
            requests={publishRequests}
            state={publishState}
            selectedId={publishRequestId}
            onSelect={setPublishRequestId}
            onRefresh={refreshPublishGate}
            onOpenPublish={(requestId) => {
              setPublishRequestId(requestId);
              setActiveView('publish');
            }}
          />
        )}

        {activeView === 'exceptions' && (
          <Exceptions
            exceptions={exceptions}
            state={exceptionState}
            policy={publishPolicy}
            reports={scans}
            publishRequests={publishRequests}
            currentUser={session.subject}
            canRequest={can('exception:request')}
            canDecide={can('exception:approve')}
            draft={exceptionDraft}
            onDraft={setExceptionDraft}
            onRequest={submitExceptionRequest}
            onDecide={decideOnException}
          />
        )}

        {activeView === 'reports' && <Reports images={images} report={reporting} state={reportState} />}

        {activeView === 'users' && can('user:manage') && (
          <UserManagement currentUser={session.subject} tenancyEnabled={tenancy.enabled} />
        )}

        {activeView === 'teams' && can('tenant:manage') && tenancy.enabled && <TeamManagement />}

        {activeView === 'audit' && <Audit notes={audit} />}
      </main>
    </div>
  );
}

function PipelineFlow({ onNavigate }) {
  const groups = [];
  pipelineSteps.forEach((step) => {
    const last = groups[groups.length - 1];
    if (last && last.view === step.view) {
      last.steps.push(step);
    } else {
      groups.push({ view: step.view, steps: [step] });
    }
  });

  let stepNumber = 0;
  return (
    <section className="panel pipeline-panel">
      <PanelHeader icon={GitBranch} title="Remediation Pipeline" />
      <div className="pipeline">
        {groups.map((group, groupIndex) => (
          <React.Fragment key={`${group.view}-${groupIndex}`}>
            <div className={group.steps.length > 1 ? 'pipeline-group multi' : 'pipeline-group'}>
              {group.steps.map((step) => {
                const Icon = step.icon;
                stepNumber += 1;
                const label = stepNumber < 10 ? `0${stepNumber}` : `${stepNumber}`;
                return (
                  <button
                    key={step.key}
                    className="pipeline-node"
                    type="button"
                    onClick={() => onNavigate(step.view)}
                  >
                    <span className="pipeline-icon">
                      <Icon size={18} />
                    </span>
                    <span className="pipeline-step">{label}</span>
                    <span className="pipeline-label">{step.label}</span>
                  </button>
                );
              })}
            </div>
            {groupIndex < groups.length - 1 && <ChevronRight className="pipeline-arrow" size={16} />}
          </React.Fragment>
        ))}
      </div>
    </section>
  );
}

function Dashboard({ metrics, images, onSelect, setActiveView, onStatusFilter }) {
  const approvedImages = images
    .filter(isApprovedCatalogImage)
    .sort(newestFirst)
    .slice(0, 5);
  const riskyImages = images
    .filter((image) => !isTechnicalArtifact(image) && (image.high > 0 || image.critical > 0))
    .sort((a, b) => b.critical - a.critical || b.high - a.high || b.medium - a.medium)
    .slice(0, 5);

  return (
    <div className="view-grid">
      <PipelineFlow onNavigate={setActiveView} />

      <section className="metrics-row">
        <MetricCard icon={PackageCheck} label="Approved Images" value={metrics.approved} tone="green" />
        <MetricCard icon={AlertTriangle} label="Risk Queue" value={metrics.risky} tone="orange" />
        <MetricCard
          icon={ShieldCheck}
          label="Approved signed + SBOM"
          value={metrics.gate.total === 0 ? '—' : `${metrics.gate.covered}/${metrics.gate.total}`}
          tone="blue"
          alert={metrics.gate.total > 0 && metrics.gate.covered < metrics.gate.total}
        />
        <MetricCard
          icon={Activity}
          label="Awaiting Approval"
          value={metrics.awaitingApproval}
          tone="violet"
          alert={metrics.awaitingApproval > 0}
        />
      </section>

      <section className="split-layout dashboard-split">
        <div className="panel large-panel">
          <PanelHeader icon={Layers3} title="Approved Catalog" action="View Catalog" onAction={() => { onStatusFilter('approved'); setActiveView('catalog'); }} />
          <div className="image-stack">
            {approvedImages.map((image) => (
              <button
                key={image.id}
                className="stack-row"
                type="button"
                onClick={() => {
                  onSelect(image.id);
                  setActiveView('catalog');
                }}
              >
                <div>
                  <strong>{image.name}</strong>
                  <span>{image.version}</span>
                </div>
                <div className="stack-meta">
                  <Badge status={image.status} />
                  <ChevronRight size={17} />
                </div>
              </button>
            ))}
            {approvedImages.length === 0 && (
              <div className="empty-copy">No image in the approved catalog yet. Published images appear here.</div>
            )}
          </div>
        </div>

        <div className="panel">
          <PanelHeader icon={AlertTriangle} title="Risk Board" action="View all" onAction={() => { onStatusFilter('blocked'); setActiveView('catalog'); }} />
          <div className="risk-list">
            {riskyImages.map((image) => (
              <div className="risk-row" key={image.id}>
                <div>
                  <strong>{image.name}</strong>
                  <span className="risk-counts">
                    <span className="risk-count risk-high">{image.high} high</span>
                    <span className="risk-count risk-medium">{image.medium} medium</span>
                  </span>
                </div>
                <Badge status={image.status} />
              </div>
            ))}
            {riskyImages.length === 0 && (
              <div className="empty-copy">No image with open critical or high findings.</div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}

// Inventory status filters. The same predicate drives the App-level filter and the
// chip counts, so a chip's number always equals the rows it filters to.
const INVENTORY_STATUS_FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'approved', label: 'Approved catalog' },
  { key: 'blocked', label: 'Blocked' },
  { key: 'unsigned', label: 'Unsigned' },
];

function matchesInventoryStatus(image, filter) {
  // The approved catalog, as on the Dashboard; a clean scan alone (status "Approved") does not count.
  if (filter === 'approved') return isApprovedCatalogImage(image);
  if (filter === 'blocked') return image.critical > 0 || image.high > 0;
  if (filter === 'unsigned') return !image.signature;
  return true;
}

// Newest first: Harbor push time ('YYYY-MM-DD HH:mm'); images without one sort last.
function newestFirst(a, b) {
  const at = String(a.rebuiltAt || '').replace(/^-$/, '');
  const bt = String(b.rebuiltAt || '').replace(/^-$/, '');
  return bt.localeCompare(at);
}

const INVENTORY_SEVERITIES = [
  { key: 'critical', label: 'Critical' },
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Medium' },
  { key: 'low', label: 'Low' },
];

// mapHarborArtifact falls back to 'Container' when the runtime is unknown.
const GENERIC_RUNTIME = 'Container';

function splitImageName(name) {
  const value = String(name || '');
  const index = value.lastIndexOf('/');
  return index === -1 ? { path: '', repo: value } : { path: value.slice(0, index + 1), repo: value.slice(index + 1) };
}

function imageSubtitle(image) {
  const { path, repo } = splitImageName(image.name);
  const runtime = String(image.runtime || '');
  const showRuntime = runtime && runtime !== GENERIC_RUNTIME && lower(runtime) !== lower(repo);
  return [path, showRuntime ? runtime : ''].filter(Boolean).join(' · ');
}

function maxCvssValue(image) {
  const score = Number(image.maxCvss);
  return Number.isFinite(score) && score > 0 ? score : null;
}

function Catalog({
  images,
  scopeImages,
  inventoryState,
  query,
  statusFilter,
  selectedImage,
  selectedSbom,
  sbomState,
  onQuery,
  onStatusFilter,
  onSelect,
}) {
  const [imagePage, setImagePage] = useState(1);
  const [showArtifacts, setShowArtifacts] = useState(false);
  const imagePageSize = 10;
  useEffect(() => {
    setImagePage(1);
  }, [query, statusFilter, showArtifacts]);

  const artifactCount = scopeImages.filter(isTechnicalArtifact).length;
  const visibleScope = showArtifacts ? scopeImages : scopeImages.filter((image) => !isTechnicalArtifact(image));
  const visibleImages = (showArtifacts ? images : images.filter((image) => !isTechnicalArtifact(image)))
    .slice()
    .sort(newestFirst);
  const imageTotalPages = Math.max(1, Math.ceil(visibleImages.length / imagePageSize));
  const imageCurrentPage = Math.min(Math.max(imagePage, 1), imageTotalPages);
  const imageStart = (imageCurrentPage - 1) * imagePageSize;
  const pagedImages = visibleImages.slice(imageStart, imageStart + imagePageSize);

  return (
    // lang="en": the shell is lang="tr", which would upper-case English labels with a dotted İ.
    <div className="catalog-layout inv-layout" lang="en">
      <section className="panel catalog-panel inv-panel">
        <div className="pub-stat-chips inv-chips" role="group" aria-label="Status">
          {INVENTORY_STATUS_FILTERS.map((filter) => (
            <button
              key={filter.key}
              type="button"
              className={`psc ${filter.key}${statusFilter === filter.key ? ' active' : ''}`}
              aria-pressed={statusFilter === filter.key}
              onClick={() => onStatusFilter(filter.key)}
            >
              <strong>{visibleScope.filter((image) => matchesInventoryStatus(image, filter.key)).length}</strong>
              <span>{filter.label}</span>
            </button>
          ))}
        </div>

        <div className="inv-toolbar">
          <div className="search-box inv-search">
            <Search size={16} />
            <input
              aria-label="Image search"
              value={query}
              placeholder="Search images"
              onChange={(event) => onQuery(event.target.value)}
            />
          </div>
          {artifactCount > 0 && (
            <label className="toggle inv-toggle" title="Show signatures, attestations and untagged manifests">
              <input type="checkbox" checked={showArtifacts} onChange={(event) => setShowArtifacts(event.target.checked)} />
              <span>Technical artifacts</span>
              <em>{artifactCount}</em>
            </label>
          )}
          <div className="inv-toolbar-spacer" />
          <DataSourceBadge state={inventoryState} />
          <button className="secondary-action inv-export" type="button" onClick={() => exportInventory(visibleImages)}>
            <Download size={16} />
            Export CSV
          </button>
        </div>

        <div className="inv-table">
          <div className="inv-row inv-head">
            <span>Image</span>
            <span>Status</span>
            <span>Vulnerabilities</span>
            <span>Max CVSS</span>
            <span>Last scan</span>
          </div>
          {pagedImages.length === 0 && <div className="inv-empty">No images match the current filters.</div>}
          {pagedImages.map((image) => {
            const { repo } = splitImageName(image.name);
            const score = maxCvssValue(image);
            return (
              <button
                className={`inv-row${image.id === selectedImage?.id ? ' selected' : ''}`}
                key={image.id}
                type="button"
                aria-pressed={image.id === selectedImage?.id}
                onClick={() => onSelect(image.id)}
              >
                <span className="inv-img">
                  <strong title={`${image.name}:${image.version}`}>
                    {repo}
                    <em>:{image.version}</em>
                  </strong>
                  <small>{imageSubtitle(image)}</small>
                </span>
                <span className="inv-status">
                  <Badge status={image.status} />
                  {image.withdrawn && <span className="badge withdrawn">Withdrawn</span>}
                </span>
                <span>
                  <SeverityChips image={image} />
                </span>
                <span>
                  {score === null ? (
                    <span className="inv-muted">—</span>
                  ) : (
                    <span className={`cvss-pill ${cvssTone(score)}`}>{score.toFixed(1)}</span>
                  )}
                </span>
                <span className="inv-time">{image.lastScanned}</span>
              </button>
            );
          })}
        </div>
        <div className="inv-pagination">
          <PaginationBar
            page={imageCurrentPage}
            totalPages={imageTotalPages}
            totalItems={visibleImages.length}
            pageSize={imagePageSize}
            onPage={setImagePage}
          />
        </div>
      </section>

      {selectedImage ? (
        <ImageInspector image={selectedImage} sbomComponents={selectedSbom} sbomState={sbomState} />
      ) : (
        <aside className="panel inspector inv-insp" aria-label="Image detail">
          <div className="inv-empty">No images in the inventory yet.</div>
        </aside>
      )}
    </div>
  );
}

function SeverityChips({ image }) {
  const present = INVENTORY_SEVERITIES.filter((severity) => Number(image[severity.key]) > 0);
  if (present.length === 0) {
    return <span className="inv-clean">Clean</span>;
  }
  return (
    <span className="inv-sev">
      {present.map((severity) => (
        <i key={severity.key} className={severity.key} title={`${image[severity.key]} ${severity.label}`}>
          {image[severity.key]}
        </i>
      ))}
    </span>
  );
}

function DataSourceBadge({ state = {} }) {
  const source = String(state.source || '');

  if (state.loading) {
    return <span className="data-source-badge loading">Loading API</span>;
  }

  if (source.includes('postgres')) {
    return <span className="data-source-badge live">Live API · PostgreSQL</span>;
  }

  if (source.includes('memory')) {
    return (
      <span className="data-source-badge fallback" title="Records reset on process restart">
        Live API · Memory
      </span>
    );
  }

  if (source === 'api') {
    return <span className="data-source-badge live">Live API</span>;
  }

  if (source === 'fixture' || source === 'trivy-fixture') {
    return (
      <span className="data-source-badge mock" title="SSI_FIXTURES=true — sample data, not a real registry">
        Sample data
      </span>
    );
  }

  if (source === 'harbor') {
    return <span className="data-source-badge live">Harbor API</span>;
  }

  if (source === 'harbor-partial') {
    return (
      <span className="data-source-badge fallback" title={state.error || 'Some Harbor scan results are pending'}>
        Harbor partial
      </span>
    );
  }

  if (source === 'harbor-scan-pending') {
    return (
      <span className="data-source-badge fallback" title={state.error || 'Harbor scan is still running'}>
        Harbor scan pending
      </span>
    );
  }

  if (source === 'harbor-scan-error') {
    return (
      <span className="data-source-badge fallback" title={state.error || 'Harbor scan result is unavailable'}>
        Harbor scan unavailable
      </span>
    );
  }

  if (source === 'harbor-empty') {
    return (
      <span className="data-source-badge fallback" title={state.error || 'Harbor project is empty'}>
        Harbor empty
      </span>
    );
  }

  if (source === 'harbor-error') {
    return (
      <span className="data-source-badge fallback" title={state.error || 'Harbor API unavailable'}>
        Harbor unavailable
      </span>
    );
  }

  if (source === 'unconfigured') {
    return (
      <span className="data-source-badge fallback" title={state.error || 'Harbor is not configured'}>
        Harbor not configured
      </span>
    );
  }

  if (source === 'unavailable') {
    return (
      <span className="data-source-badge fallback" title={state.error || 'The SSI API is unavailable'}>
        API unavailable
      </span>
    );
  }

  return <span className="data-source-badge mock">Mock data</span>;
}

const SBOM_FORMAT_LABELS = { 'cyclonedx-json': 'CycloneDX JSON', 'spdx-json': 'SPDX JSON' };

// `components` is a component list when one is served (sample data); `summary` is what the
// signing worker verified for a live image (format, component count, SBOM digest). The live
// component list stays in Harbor as the signed SBOM attestation of the image.
function SbomPanel({ components, generated, summary, state }) {
  if (!generated) {
    return null;
  }
  const count = components.length > 0 ? components.length : (summary?.componentCount ?? null);
  return (
    <details className="rem-collapse flush inv-sbom">
      <summary>
        <FileKey2 size={15} />
        SBOM components
        <em>{state.loading ? 'Loading…' : (count ?? '—')}</em>
      </summary>
      <div className="sbom">
        {state.loading ? (
          <div className="fix-empty">Loading SBOM components from the API.</div>
        ) : components.length === 0 && summary ? (
          <div className="sbom-summary">
            <div className="detail-grid">
              <Detail label="Format" value={SBOM_FORMAT_LABELS[summary.format] || summary.format || '-'} />
              <Detail label="Components" value={summary.componentCount.toLocaleString('en')} />
              <Detail label="Generated by" value={summary.tool || '-'} />
              <Detail label="Verified" value={summary.verifiedAt ? formatReportTime(summary.verifiedAt) : '-'} />
            </div>
            <div className="detail" title={summary.sbomDigest}>
              <span>SBOM digest</span>
              <strong className="mono">{shortDigest(summary.sbomDigest)}</strong>
            </div>
            <p className="sbom-note">
              The full component list is attached to this image in Harbor as a signed SBOM attestation, verified by
              the signing worker against this digest.
            </p>
          </div>
        ) : components.length === 0 ? (
          <div className="fix-empty">
            SBOM generated. The component list is attached to this image in Harbor as its SBOM attestation.
          </div>
        ) : (
          <div className="sbom-list">
            {components.map((component) => (
              <div className="sbom-row" key={component.name}>
                <div>
                  <strong>{component.name}</strong>
                  <span>{component.version}</span>
                </div>
                <span className="sbom-license">{component.license}</span>
              </div>
            ))}
          </div>
        )}
        {state.error && <div className="sbom-note">The SBOM component service is unavailable.</div>}
      </div>
    </details>
  );
}

const INVENTORY_SUPPLY_CHAIN = [
  { key: 'sbom', label: 'SBOM' },
  { key: 'signature', label: 'Signature' },
  { key: 'provenance', label: 'Provenance' },
];

const FULL_SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/i;

// Harbor images carry a shortened `digest` for display and the full one in `fullDigest`.
// Copying and pinning need the full digest: the only form a registry or pipeline accepts.
function fullImageDigest(image) {
  const digest = String(image?.fullDigest || image?.digest || '');
  return FULL_SHA256_DIGEST.test(digest) ? digest.toLowerCase() : '';
}

function hasInventoryValue(value) {
  const text = String(value ?? '').trim();
  return text !== '' && text !== '-';
}

function ImageInspector({ image, sbomComponents, sbomState }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    setCopied(false);
  }, [image.id]);

  const { path, repo } = splitImageName(image.name);
  const score = maxCvssValue(image);
  const nonRoot = !(image.tags || []).includes('root');
  const fullDigest = fullImageDigest(image);
  const canCopyDigest = Boolean(fullDigest);
  // Placeholder values (e.g. Harbor's '-' base OS, owner equal to the source, 0 consumers)
  // carry no information, so only populated facts are rendered.
  const facts = [
    { label: 'Max CVSS', value: score === null ? '—' : score.toFixed(1) },
    { label: 'Size', value: image.size },
    { label: 'Onboarded', value: image.firstOnboarded },
    { label: 'Last scan', value: image.lastScanned },
    { label: 'Base OS', value: image.baseOs },
    { label: 'Owner', value: image.owner !== image.source ? image.owner : '' },
    // Multi-tenancy: the team the image belongs to; a published image names its publisher.
    { label: image.tenantArea === 'approved' ? 'Published by' : 'Team', value: image.tenantName || '' },
    { label: 'Consumers', value: Number(image.consumers) > 0 ? image.consumers : '' },
  ].filter((fact) => hasInventoryValue(fact.value));

  const copyDigest = () => {
    // copyText also works over plain HTTP, where navigator.clipboard does not exist.
    copyText(fullDigest)
      .then(() => setCopied(true))
      .catch(() => setCopied(false));
  };

  return (
    <aside className="panel inspector inv-insp" aria-label="Image detail">
      <div className="inv-insp-head">
        <div>
          {path && <span className="inv-insp-path">{path}</span>}
          <h2 title={`${image.name}:${image.version}`}>
            {repo}
            <em>:{image.version}</em>
          </h2>
        </div>
        <Badge status={image.status} />
      </div>

      {image.withdrawn && (
        <div className="inv-withdrawn" role="alert">
          <ShieldOff size={16} />
          <span>
            <strong>Withdrawn — do not use this image.</strong> {image.withdrawn.reason} ({image.withdrawn.withdrawnBy},{' '}
            {formatReportTime(image.withdrawn.withdrawnAt)})
          </span>
        </div>
      )}

      <div className="inv-sev-summary">
        {INVENTORY_SEVERITIES.map((severity) => (
          <div key={severity.key} className={`${severity.key}${Number(image[severity.key]) > 0 ? '' : ' zero'}`}>
            <strong>{Number(image[severity.key]) || 0}</strong>
            <span>{severity.label}</span>
          </div>
        ))}
      </div>

      <div className="inv-facts">
        {facts.map((fact) => (
          <div className="detail" key={fact.label}>
            <span>{fact.label}</span>
            <strong>{fact.value}</strong>
          </div>
        ))}
        <div className="detail full">
          <span>Digest</span>
          <strong className="inv-digest" title={fullDigest || undefined}>
            {shortDigest(fullDigest || image.digest)}
            {canCopyDigest && (
              <button type="button" className="inv-copy" onClick={copyDigest}>
                <Copy size={13} />
                {copied ? 'Copied' : 'Copy'}
              </button>
            )}
          </strong>
        </div>
      </div>

      <div className="inv-section-title">Supply chain</div>
      <div className="inv-supply">
        {INVENTORY_SUPPLY_CHAIN.map((item) => (
          <div key={item.key} className={image[item.key] ? 'ok' : 'unverified'}>
            {image[item.key] ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
            <strong>{item.label}</strong>
            <small>{image[item.key] ? 'Verified' : 'Not verified'}</small>
          </div>
        ))}
        <div className={nonRoot ? 'ok' : 'bad'}>
          {nonRoot ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
          <strong>Non-root</strong>
          <small>{nonRoot ? 'Yes' : 'Runs as root'}</small>
        </div>
      </div>

      <SbomPanel components={sbomComponents} generated={image.sbom} summary={image.sbomSummary} state={sbomState} />
    </aside>
  );
}

// App Builder produces a build specification (Dockerfile + build request) on an approved base
// image. It never builds or registers an image itself: the build pipeline scans, signs and
// publishes the result, which then appears in Inventory through the normal flow.
const APP_NAME_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const IMAGE_TAG_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const BUILD_USER = '65532:65532';

function validateBuildForm(form, base) {
  const errors = {};
  if (!base) errors.base = 'Select an approved base image.';
  if (!APP_NAME_PATTERN.test(form.appName)) errors.appName = 'Lowercase letters, digits and dashes (max 63).';
  if (!IMAGE_TAG_PATTERN.test(form.version) || form.version.toLowerCase() === 'latest') {
    errors.version = 'A valid image tag; "latest" is not allowed.';
  }
  const port = Number(form.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) errors.port = 'A port between 1 and 65535.';
  if (!form.command.trim()) errors.command = 'The command that starts the application.';
  return errors;
}

function buildSpecification({ form, base, policy, requestedBy }) {
  const registry = policy?.target?.registry || '';
  const project = policy?.target?.project || '';
  const prefix = policy?.target?.repositoryPrefix || 'approved';
  const baseReference = [registry, `${base.name}:${base.version}`].filter(Boolean).join('/');
  const pinnedDigest = fullImageDigest(base);
  const targetRepository = [registry, project, `${prefix}/${form.appName}`].filter(Boolean).join('/');
  const command = form.command.trim().split(/\s+/);
  const dockerfile = [
    '# Generated by SSI App Builder; do not edit by hand.',
    `# Base: approved in Inventory (${base.critical || 0} critical, ${base.high || 0} high).`,
    pinnedDigest ? null : '# The build pipeline pins the base digest.',
    `FROM ${baseReference}${pinnedDigest ? `@${pinnedDigest}` : ''}`,
    'WORKDIR /app',
    `COPY --chown=${BUILD_USER} . .`,
    `USER ${BUILD_USER}`,
    `EXPOSE ${Number(form.port)}`,
    `ENTRYPOINT ${JSON.stringify(command)}`,
    `LABEL org.opencontainers.image.title="${form.appName}" \\`,
    `      org.opencontainers.image.version="${form.version}" \\`,
    `      ssi.base="${base.name}:${base.version}"`,
    '',
  ]
    .filter((line) => line !== null)
    .join('\n');
  const request = {
    kind: 'ssi.app-build-request/v1',
    generatedAt: new Date().toISOString(),
    requestedBy: requestedBy || null,
    application: form.appName,
    version: form.version,
    base: {
      reference: baseReference,
      digest: pinnedDigest || null,
      inventoryId: base.id,
      status: base.status,
      critical: base.critical || 0,
      high: base.high || 0,
    },
    target: { repository: targetRepository, tag: form.version },
    container: { port: Number(form.port), user: BUILD_USER, command },
    buildContext: form.buildContext.trim() || null,
    pipeline: ['build', 'scan', 'sbom', 'sign', 'publish-gate'],
    publishPolicy: policy?.version || null,
    dockerfile,
  };
  return { dockerfile, request, targetReference: `${targetRepository}:${form.version}` };
}

function Builder({ form, images, policy, requestedBy, onField, onHandoff }) {
  const [previewTab, setPreviewTab] = useState('dockerfile');
  const [copied, setCopied] = useState(false);
  // A base must be in the approved catalog and still scan clean: an onboarded image is not
  // approved for building just because its scan has no blocking findings.
  const bases = images.filter((image) => isApprovedCatalogImage(image) && image.status === 'Approved');
  const base = bases.find((image) => image.id === form.baseImageId) || null;
  const errors = validateBuildForm(form, base);
  const valid = Object.keys(errors).length === 0;
  const spec = valid ? buildSpecification({ form, base, policy, requestedBy }) : null;

  const field = (key, label, hint, props = {}) => (
    <label className={`ab-field${props.full ? ' full' : ''}`}>
      <span>{label}</span>
      <input
        value={form[key]}
        aria-invalid={Boolean(errors[key])}
        placeholder={props.placeholder}
        inputMode={props.inputMode}
        onChange={(event) => {
          setCopied(false);
          onField(key, event.target.value);
        }}
      />
      <small className={errors[key] ? 'error' : ''}>{errors[key] || hint}</small>
    </label>
  );

  const copyDockerfile = () => {
    if (!spec) return;
    copyText(spec.dockerfile)
      .then(() => setCopied(true))
      .catch(() => setCopied(false));
  };
  const downloadRequest = () => {
    if (!spec) return;
    downloadJson(`ssi-build-request-${form.appName}-${form.version}.json`, spec.request);
    onHandoff(spec.targetReference);
  };

  return (
    // lang="en": the shell is lang="tr", which would upper-case English labels with a dotted İ.
    <div className="view-grid ab-view" lang="en">
      <section className="panel ab-head">
        <div className="ab-head-title">
          <span className="ab-mark">
            <Layers3 size={20} />
          </span>
          <div>
            <h2>Application build request</h2>
            <span>
              Build your application on an approved base image. SSI generates the build specification; the build
              pipeline scans, signs and publishes the result.
            </span>
          </div>
        </div>
      </section>

      <div className="ab-layout">
        <section className="panel ab-card">
          <PanelHeader icon={Boxes} title="Build specification" />

          <div className="ab-section">Base image</div>
          {bases.length === 0 ? (
            <div className="empty-copy">No approved catalog image with a clean scan yet. Publish a base image to the approved catalog before building on it.</div>
          ) : (
            <label className="ab-field full">
              <select
                className="ab-select"
                aria-label="Base image"
                value={form.baseImageId}
                onChange={(event) => {
                  setCopied(false);
                  onField('baseImageId', event.target.value);
                }}
              >
                <option value="">Select an approved base image…</option>
                {bases.map((image) => (
                  <option key={image.id} value={image.id}>
                    {image.name}:{image.version}
                  </option>
                ))}
              </select>
            </label>
          )}
          {base && (
            <div className="ab-base">
              <div className="ab-base-head">
                <span className="inv-img">
                  <strong>
                    {splitImageName(base.name).repo}
                    <em>:{base.version}</em>
                  </strong>
                  <small>{splitImageName(base.name).path}</small>
                </span>
                <Badge status={base.status} />
              </div>
              <div className="ab-chips">
                <SeverityChips image={base} />
                <span className={`ab-tag${base.signature ? ' ok' : ''}`}>
                  {base.signature ? <CheckCircle2 size={13} /> : <AlertTriangle size={13} />}
                  {base.signature ? 'Signature verified' : 'Signature not verified'}
                </span>
              </div>
            </div>
          )}

          <div className="ab-section">Application</div>
          <div className="ab-form">
            {field('appName', 'Application name', 'Lowercase letters, digits and dashes.', { placeholder: 'payment-api' })}
            {field('version', 'Version', 'Becomes the image tag.', { placeholder: '1.4.8' })}
            {field('port', 'Container port', 'The port the application listens on.', { placeholder: '8080', inputMode: 'numeric' })}
            {field('command', 'Start command', 'Run as the image entrypoint, without a shell.', { placeholder: 'node server.js' })}
            {field('buildContext', 'Build context', 'Optional: the repository and branch the pipeline checks out.', {
              full: true,
              placeholder: 'https://dev.azure.com/<org>/<project>/_git/payment-api @ main',
            })}
          </div>
          <div className="ab-target">
            <span>Target after the publish gate</span>
            <code>{spec ? spec.targetReference : '—'}</code>
          </div>
        </section>

        <aside className="panel ab-card ab-preview">
          <div className="panel-header">
            <div>
              <FileText size={19} />
              <h2>Preview</h2>
            </div>
            <div className="ab-tabs" role="tablist">
              <button
                type="button"
                role="tab"
                aria-selected={previewTab === 'dockerfile'}
                className={previewTab === 'dockerfile' ? 'active' : ''}
                onClick={() => setPreviewTab('dockerfile')}
              >
                Dockerfile
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={previewTab === 'request'}
                className={previewTab === 'request' ? 'active' : ''}
                onClick={() => setPreviewTab('request')}
              >
                build-request.json
              </button>
            </div>
          </div>
          {spec ? (
            <pre className="ab-code">
              <code>{previewTab === 'dockerfile' ? spec.dockerfile : `${JSON.stringify(spec.request, null, 2)}\n`}</code>
            </pre>
          ) : (
            <div className="ab-code-empty">Complete the specification to generate the build files.</div>
          )}
          <div className="ab-actions">
            <button className="primary-action ab-btn" type="button" disabled={!spec} onClick={downloadRequest}>
              <Download size={15} />
              Download build request
            </button>
            <button className="secondary-action ab-btn" type="button" disabled={!spec} onClick={copyDockerfile}>
              <Copy size={15} />
              {copied ? 'Copied' : 'Copy Dockerfile'}
            </button>
          </div>
          <p className="ab-foot">
            Nothing is built here. Hand the request to the build pipeline; the image appears in Inventory after it is
            scanned and signed.
          </p>
        </aside>
      </div>
    </div>
  );
}

const CVE_SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

function severityRank(severity) {
  return CVE_SEVERITY_RANK[String(severity || '').toLowerCase()] || 0;
}

// Aggregates the findings of every loaded scan report into one row per CVE. Remediation
// stays image-scoped: each affected image keeps its own scan report id so the queue can
// open that report in Remediation, where the dry-run plans all fixable findings at once.
// `remediationIndex` (indexVerifiedRemediations) marks, per image, whether a verified
// remediation removed the finding or it survived the verification re-scan.
function aggregateCveQueue(reports, remediationIndex) {
  const byId = new Map();
  for (const report of reports) {
    const reportLabel = report.image || report.id;
    for (const finding of report.findings || []) {
      if (!finding.cve) continue;
      const entry = byId.get(finding.cve) || {
        id: finding.cve,
        severity: finding.severity || 'Unknown',
        cvss: null,
        epss: null,
        packages: new Set(),
        scanners: new Set(),
        lastSeen: '',
        images: new Map(),
        imagePackages: new Map(),
      };
      if (severityRank(finding.severity) > severityRank(entry.severity)) entry.severity = finding.severity;
      if (Number.isFinite(Number(finding.cvss))) entry.cvss = Math.max(entry.cvss ?? 0, Number(finding.cvss));
      if (finding.epss != null && Number.isFinite(Number(finding.epss))) {
        entry.epss = Math.max(entry.epss ?? 0, Number(finding.epss));
      }
      if (finding.package) entry.packages.add(finding.package);
      if (report.scanner) entry.scanners.add(report.scanner);
      if (String(report.scannedAt || '') > entry.lastSeen) entry.lastSeen = String(report.scannedAt || '');
      const fixable = finding.status === 'Fix available';
      const imagePackages = entry.imagePackages.get(report.id) || new Set();
      if (finding.package) imagePackages.add(finding.package);
      entry.imagePackages.set(report.id, imagePackages);
      const existing = entry.images.get(report.id);
      if (!existing || (fixable && !existing.fixable)) {
        entry.images.set(report.id, {
          reportId: report.id,
          label: reportLabel,
          digest: report.digest || '',
          package: finding.package || '',
          installed: finding.installed || '',
          fixed: fixable ? finding.fixed || '' : '',
          fixable,
        });
      }
      byId.set(finding.cve, entry);
    }
  }
  return [...byId.values()].map((entry) => {
    const images = [...entry.images.values()].map((image) => ({
      ...image,
      remediation: cveRemediationStatus(remediationIndex, image, entry.id, [
        ...(entry.imagePackages.get(image.reportId) || []),
      ]),
    }));
    const fixableImage = images.find((image) => image.fixable);
    return {
      id: entry.id,
      severity: entry.severity,
      cvss: entry.cvss,
      epss: entry.epss,
      packages: [...entry.packages],
      scanners: [...entry.scanners],
      lastSeen: entry.lastSeen,
      images,
      fixable: Boolean(fixableImage),
      installed: (fixableImage || images[0])?.installed || '',
      fixed: fixableImage?.fixed || '',
      remediation: summarizeCveRemediation(images),
    };
  });
}

// Queue-row wording for the remediation roll-up of one CVE across its affected images.
function cveRemediationLabel(summary) {
  if (!summary || summary.total === 0) return '';
  if (summary.status === CVE_REMEDIATION_STATUS.REMEDIATED) return 'Remediated';
  if (summary.status === CVE_REMEDIATION_STATUS.REMAINING) return 'Remaining';
  return summary.remediated > 0 ? `${summary.remediated}/${summary.total} fixed` : '';
}

function cveRemediationExportValue(summary) {
  if (!summary || summary.total === 0) return '';
  return `${summary.remediated} remediated / ${summary.remaining} remaining / ${summary.open} open`;
}

const CVE_QUEUE_FILTERS = [
  { key: 'all', label: 'All', match: () => true },
  { key: 'critical', label: 'Critical', match: (cve) => severityRank(cve.severity) === 4 },
  { key: 'high', label: 'High', match: (cve) => severityRank(cve.severity) === 3 },
  { key: 'fix', label: 'Fix available', match: (cve) => cve.fixable },
  { key: 'nofix', label: 'No fix', match: (cve) => !cve.fixable },
  { key: 'remediated', label: 'Remediated', match: (cve) => cve.remediation?.remediated > 0 },
  { key: 'remaining', label: 'Remaining', match: (cve) => cve.remediation?.remaining > 0 },
];

const CVE_QUEUE_SORTS = {
  risk: (a, b) =>
    severityRank(b.severity) - severityRank(a.severity) ||
    (b.cvss ?? 0) - (a.cvss ?? 0) ||
    (b.epss ?? 0) - (a.epss ?? 0) ||
    a.id.localeCompare(b.id),
  images: (a, b) => b.images.length - a.images.length || CVE_QUEUE_SORTS.risk(a, b),
  id: (a, b) => b.id.localeCompare(a.id),
};

const CVE_AFFECTED_PREVIEW = 5;

function exportCveQueue(cves) {
  exportCsv(
    'ssi-cve-queue.csv',
    ['CVE', 'Severity', 'CVSS', 'EPSS', 'Packages', 'Fixed version', 'Remediation', 'Affected images'],
    cves.map((cve) => [
      cve.id,
      cve.severity,
      cve.cvss ?? '',
      cve.epss == null ? '' : `${Math.round(cve.epss * 100)}%`,
      cve.packages.join(' '),
      cve.fixed || 'No fix',
      cveRemediationExportValue(cve.remediation),
      cve.images.map((image) => image.label).join(' '),
    ]),
  );
}

// The active risk acceptance that covers a CVE in an image's repository, if any.
function acceptanceFor(exceptions, cveId, label, packageName, now) {
  const repository = repositoryFromReference(label);
  return (exceptions || []).find(
    (item) =>
      effectiveExceptionStatus(item, now) === 'Approved' &&
      String(item.cve).toUpperCase() === String(cveId).toUpperCase() &&
      item.repository === repository &&
      (!item.package || !packageName || item.package === packageName),
  );
}

function CveQueue({ reports, state, remediationJobs, exceptions, canRequestException, onRemediate, onRequestException }) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const [sort, setSort] = useState('risk');
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState('');
  const [showAllImages, setShowAllImages] = useState(false);
  const pageSize = 10;

  const remediationIndex = useMemo(() => indexVerifiedRemediations(remediationJobs), [remediationJobs]);
  const cves = useMemo(() => aggregateCveQueue(reports, remediationIndex), [reports, remediationIndex]);
  const needle = query.trim().toLowerCase();
  const searched = needle
    ? cves.filter((cve) => [cve.id, ...(cve.packages || [])].join(' ').toLowerCase().includes(needle))
    : cves;
  const activeFilter = CVE_QUEUE_FILTERS.find((item) => item.key === filter) || CVE_QUEUE_FILTERS[0];
  const visible = searched.filter(activeFilter.match).sort(CVE_QUEUE_SORTS[sort] || CVE_QUEUE_SORTS.risk);
  const totalPages = Math.max(1, Math.ceil(visible.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const paged = visible.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const selected = visible.find((cve) => cve.id === selectedId) || paged[0] || null;
  const hasEpss = cves.some((cve) => cve.epss != null);

  const resetPaging = (update) => (value) => {
    update(value);
    setPage(1);
  };
  const selectCve = (id) => {
    setSelectedId(id);
    setShowAllImages(false);
  };

  return (
    // lang="en": the shell is lang="tr", which would upper-case English labels with a dotted İ.
    <div className="catalog-layout inv-layout cq-layout" lang="en">
      <section className="panel catalog-panel inv-panel">
        <div className="pub-stat-chips cq-chips" role="group" aria-label="Filter">
          {CVE_QUEUE_FILTERS.map((item) => (
            <button
              key={item.key}
              type="button"
              className={`psc ${item.key}${filter === item.key ? ' active' : ''}`}
              aria-pressed={filter === item.key}
              onClick={() => resetPaging(setFilter)(item.key)}
            >
              <strong>{searched.filter(item.match).length}</strong>
              <span>{item.label}</span>
            </button>
          ))}
        </div>

        <div className="inv-toolbar">
          <div className="search-box inv-search">
            <Search size={16} />
            <input
              aria-label="CVE search"
              value={query}
              placeholder="Search CVE or package"
              onChange={(event) => resetPaging(setQuery)(event.target.value)}
            />
          </div>
          <label className="select-mini" title="Risk = severity, then CVSS, then EPSS">
            <span>Sort</span>
            <select value={sort} onChange={(event) => resetPaging(setSort)(event.target.value)}>
              <option value="risk">Risk</option>
              <option value="images">Most images</option>
              <option value="id">Newest</option>
            </select>
          </label>
          <div className="inv-toolbar-spacer" />
          <DataSourceBadge state={state} />
          <button className="secondary-action inv-export" type="button" onClick={() => exportCveQueue(visible)}>
            <Download size={16} />
            Export CSV
          </button>
        </div>

        <div className="cq-table">
          <div className={`cq-row cq-head${hasEpss ? '' : ' no-epss'}`}>
            <span>CVE</span>
            <span>Severity</span>
            <span>CVSS</span>
            {hasEpss && <span>Exploit (EPSS)</span>}
            <span>Fix / Status</span>
            <span>Images</span>
          </div>
          {paged.length === 0 && (
            <div className="inv-empty">
              {cves.length === 0 ? 'No vulnerabilities in the loaded scan reports.' : 'No CVEs match the current filters.'}
            </div>
          )}
          {paged.map((cve) => (
            <button
              key={cve.id}
              type="button"
              className={`cq-row${hasEpss ? '' : ' no-epss'}${selected?.id === cve.id ? ' selected' : ''}`}
              aria-pressed={selected?.id === cve.id}
              onClick={() => selectCve(cve.id)}
            >
              <span className="cq-id">
                <strong>{cve.id}</strong>
                <small>
                  {cve.packages[0] || '-'} {cve.installed}
                  {cve.packages.length > 1 ? ` +${cve.packages.length - 1}` : ''}
                </small>
              </span>
              <span>
                <span className={`severity ${String(cve.severity).toLowerCase()}`}>{cve.severity}</span>
              </span>
              <span>
                {cve.cvss == null ? (
                  <span className="inv-muted">—</span>
                ) : (
                  <span className={`cvss-pill ${cvssTone(cve.cvss)}`}>{cve.cvss.toFixed(1)}</span>
                )}
              </span>
              {hasEpss && (
                <span className="cq-ep">
                  {cve.epss == null ? (
                    <span className="inv-muted">—</span>
                  ) : (
                    <>
                      <span className="cq-epss">
                        <i style={{ width: `${Math.round(cve.epss * 100)}%` }} />
                      </span>
                      <em>{Math.round(cve.epss * 100)}%</em>
                    </>
                  )}
                </span>
              )}
              <span className="cq-fixcell">
                {cve.fixable ? <span className="cq-fix">{cve.fixed}</span> : <span className="cq-nofix">No fix</span>}
                <CveRemediationTag summary={cve.remediation} />
              </span>
              <span className="cq-imgs">{cve.images.length}</span>
            </button>
          ))}
        </div>
        <div className="inv-pagination">
          <PaginationBar
            page={currentPage}
            totalPages={totalPages}
            totalItems={visible.length}
            pageSize={pageSize}
            onPage={setPage}
          />
        </div>
      </section>

      <CveDetail
        cve={selected}
        showAllImages={showAllImages}
        onToggleImages={() => setShowAllImages((current) => !current)}
        onRemediate={onRemediate}
        exceptions={exceptions}
        canRequestException={canRequestException}
        onRequestException={onRequestException}
      />
    </div>
  );
}

function CveRemediationTag({ summary }) {
  const label = cveRemediationLabel(summary);
  if (!label) return null;
  const tone = summary.status === CVE_REMEDIATION_STATUS.OPEN ? 'partial' : summary.status;
  const title =
    `${summary.remediated} of ${summary.total} affected image(s) remediated by verified jobs` +
    (summary.remaining > 0 ? `; still present in ${summary.remaining} after the verification re-scan` : '');
  return (
    <small className={`cq-st ${tone}`} title={title}>
      {label}
    </small>
  );
}

// Per-image evidence line in the CVE detail rail: which verified job removed the finding,
// or that it survived that job's verification re-scan.
function CveImageRemediation({ remediation }) {
  if (remediation?.status === CVE_REMEDIATION_STATUS.REMEDIATED) {
    return (
      <small className="cq-st-line remediated" title={remediation.patchedImageTag || remediation.jobId}>
        <CheckCircle2 size={12} />
        Removed by {remediation.jobId}
        {remediation.patchedImageTag ? ` → ${remediation.patchedImageTag.split('/').pop()}` : ''}
      </small>
    );
  }
  if (remediation?.status === CVE_REMEDIATION_STATUS.REMAINING) {
    return (
      <small className="cq-st-line remaining" title="Still present after the verification re-scan">
        <AlertTriangle size={12} />
        Still present after {remediation.jobId}
      </small>
    );
  }
  return null;
}

function CveDetail({ cve, showAllImages, onToggleImages, onRemediate, exceptions, canRequestException, onRequestException }) {
  if (!cve) {
    return (
      <aside className="panel inspector inv-insp cq-detail" aria-label="CVE detail">
        <div className="inv-empty cq-detail-empty">Select a CVE to see the affected images.</div>
      </aside>
    );
  }
  const severityKey = String(cve.severity).toLowerCase();
  const images = showAllImages ? cve.images : cve.images.slice(0, CVE_AFFECTED_PREVIEW);
  const now = Date.now();
  return (
    <aside className="panel inspector inv-insp cq-detail" aria-label="CVE detail">
      <div className="inv-insp-head">
        <div>
          <span className="inv-insp-path">{cve.packages.join(', ') || '-'}</span>
          <h2>{cve.id}</h2>
        </div>
        <span className={`severity ${severityKey}`}>{cve.severity}</span>
      </div>

      <div className="cq-metrics">
        <div>
          <strong className={cve.cvss == null ? '' : cvssTone(cve.cvss)}>{cve.cvss == null ? '—' : cve.cvss.toFixed(1)}</strong>
          <span>CVSS</span>
        </div>
        {/* EPSS is shown only when the scanner provides it (Harbor/Trivy reports do not). */}
        {cve.epss != null && (
          <div>
            <strong>{`${Math.round(cve.epss * 100)}%`}</strong>
            <span>EPSS</span>
          </div>
        )}
        <div>
          <strong>{cve.images.length}</strong>
          <span>Images</span>
        </div>
      </div>

      <div className="inv-facts">
        <div className="detail">
          <span>Package</span>
          <strong>{cve.packages.join(', ') || '-'}</strong>
        </div>
        <div className="detail">
          <span>Fix</span>
          <strong className="cq-fixv">{cve.fixable ? `${cve.installed || '?'} → ${cve.fixed}` : 'No fix available'}</strong>
        </div>
        <div className="detail">
          <span>Scanner</span>
          <strong>{cve.scanners.join(', ') || '-'}</strong>
        </div>
        <div className="detail">
          <span>Last seen</span>
          <strong>{cve.lastSeen || '-'}</strong>
        </div>
        <div className="detail">
          <span>Remediation</span>
          <strong>
            {cve.remediation.remediated} of {cve.remediation.total} remediated
            {cve.remediation.remaining > 0 ? ` · ${cve.remediation.remaining} remaining` : ''}
          </strong>
        </div>
      </div>

      <div className="inv-section-title">Affected images</div>
      <div className="cq-affected">
        {images.map((image) => {
          const reference = splitImageReference(image.label);
          const accepted = acceptanceFor(exceptions, cve.id, image.label, image.package, now);
          return (
            <div className="cq-aff" key={image.reportId}>
              <span className="inv-img">
                <strong title={image.label}>
                  {reference.repo || image.label}
                  {reference.tag && <em>:{reference.tag}</em>}
                </strong>
                {reference.path && <small>{reference.path}</small>}
                <CveImageRemediation remediation={image.remediation} />
                {accepted && (
                  <small className="cq-accepted" title={`${accepted.id} · ${accepted.repository}`}>
                    <ShieldCheck size={12} />
                    Accepted until {formatReportTime(accepted.expiresAt).slice(0, 10)}
                  </small>
                )}
              </span>
              {canRequestException &&
                !accepted &&
                image.remediation.status !== CVE_REMEDIATION_STATUS.REMEDIATED &&
                repositoryFromReference(image.label).includes('/') && (
                <button
                  type="button"
                  className="secondary-action cq-rem"
                  title="Request a time-limited risk acceptance for this CVE in this repository"
                  onClick={() =>
                    onRequestException({
                      cve: cve.id,
                      repository: repositoryFromReference(image.label),
                      package: image.package,
                      digest: image.digest,
                      fixable: image.fixable,
                    })
                  }
                >
                  <ShieldOff size={14} />
                  Accept risk
                </button>
              )}
              {image.remediation.status === CVE_REMEDIATION_STATUS.REMEDIATED ? (
                <span className="cq-done">
                  <CheckCircle2 size={14} />
                  Fixed
                </span>
              ) : image.fixable ? (
                <button
                  type="button"
                  className="secondary-action cq-rem"
                  title="Open this image's scan report in Remediation"
                  onClick={() => onRemediate(image.reportId, cve.id)}
                >
                  <Wrench size={14} />
                  Remediate
                </button>
              ) : (
                <span className="cq-nofix">No fix available</span>
              )}
            </div>
          );
        })}
        {cve.images.length > CVE_AFFECTED_PREVIEW && (
          <button type="button" className="text-action cq-more" onClick={onToggleImages}>
            {showAllImages ? 'Show fewer' : `Show all ${cve.images.length} images`}
          </button>
        )}
      </div>

      {/^CVE-\d{4}-\d+$/i.test(cve.id) && (
        <a
          className="cq-ext"
          href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`}
          target="_blank"
          rel="noopener noreferrer"
        >
          <ExternalLink size={14} />
          View on NVD
        </a>
      )}
    </aside>
  );
}

// Policy rule catalog. Ids match the checks emitted by evaluatePublishPolicy (lib/publishPolicy.js),
// grouped like the Publish screen; 'separate-approver' and 'risk-acceptance' are approval-time rules with
// no decision check of their own (accepted findings show up in the Critical/High threshold details).
function policyRuleCatalog(policy) {
  const thresholds = policy.thresholds || {};
  const target = policy.target || {};
  const approval = policy.approval || {};
  const requirements = policy.requirements || {};
  const always = (value) => ({ value, enforcement: 'enforced' });
  const requirement = (key) =>
    requirements[key] ? { value: 'Required', enforcement: 'enforced' } : { value: 'Not required', enforcement: 'off' };
  const definitions = {
    'verified-remediation': { short: 'Verified result', ...always('Accepted RM-EXEC result required') },
    'immutable-output-digest': { short: 'Digest pin', ...always('sha256 output digest pin') },
    'verification-evidence': { short: 'Evidence binding', ...always('Evidence bound to the output digest') },
    'full-image-rescan': { short: 'Full re-scan', ...always('Re-scan of the output digest') },
    'image-config-preserved': { short: 'Image config', ...always('Same runtime config as the source') },
    'candidate-smoke-test': { short: 'Candidate test', ...always('Side-by-side test of the output digest') },
    'image-not-withdrawn': { short: 'Not withdrawn', ...always('A withdrawn image is never published again') },
    'consumer-acceptance': {
      short: 'Consumer acceptance',
      value: requirements.consumerAcceptance
        ? 'Required · the requester cannot accept'
        : 'Not required · reported issues still block',
      enforcement: requirements.consumerAcceptance ? 'enforced' : 'off',
    },
    'canonical-os-zero': { short: 'OS findings', ...always('0 remaining') },
    'critical-threshold': { short: 'Critical threshold', ...always(`Max ${thresholds.maxCritical ?? 0}`) },
    'high-threshold': { short: 'High threshold', ...always(`Max ${thresholds.maxHigh ?? 0}`) },
    'target-boundary': {
      short: 'Registry boundary',
      ...always([target.registry, target.project, target.repositoryPrefix].filter(Boolean).join('/') + '/'),
    },
    'approval-control-ready': {
      short: 'Trusted approval',
      value: approval.configured
        ? `Trusted identity · ${(approval.approverRoles || []).join(', ') || 'approver'}`
        : 'No trusted identity configured',
      enforcement: approval.configured ? 'enforced' : 'failclosed',
    },
    'separate-approver': {
      short: 'Two-person rule',
      label: 'Separation of duties (two-person rule)',
      value: approval.requireSeparateApprover ? 'Requester cannot approve' : 'Requester may approve',
      enforcement: approval.requireSeparateApprover ? 'enforced' : 'off',
    },
    'risk-acceptance': {
      short: 'Risk acceptance',
      label: 'Risk acceptance (policy exceptions)',
      value: policy.riskAcceptance
        ? `Two-person approval · max ${policy.riskAcceptance.maxDays} days (Critical ${policy.riskAcceptance.maxDaysCritical})`
        : 'Not available',
      enforcement: policy.riskAcceptance ? 'enforced' : 'off',
    },
    'sbom-requirement': { short: 'SBOM', ...requirement('sbom') },
    'signature-requirement': { short: 'Signature', ...requirement('signature') },
    'provenance-requirement': { short: 'Provenance', ...requirement('provenance') },
  };
  const labels = {
    'verified-remediation': 'Verified remediation result',
    'immutable-output-digest': 'Immutable output digest',
    'verification-evidence': 'Verification evidence binding',
    'full-image-rescan': 'Full-image verification re-scan',
    'image-config-preserved': 'Image configuration preserved',
    'candidate-smoke-test': 'Candidate smoke test passed',
    'consumer-acceptance': 'Consumer acceptance',
    'canonical-os-zero': 'Canonical OS findings remediated',
    'critical-threshold': 'Critical severity threshold',
    'high-threshold': 'High severity threshold',
    'target-boundary': 'Approved registry boundary',
    'approval-control-ready': 'Trusted approval control',
    'image-not-withdrawn': 'Image not withdrawn',
    'sbom-requirement': 'SBOM requirement',
    'signature-requirement': 'Signature requirement',
    'provenance-requirement': 'Provenance requirement',
  };
  return PUBLISH_CHECK_GROUPS.map((group) => {
    const ids = group.key === 'governance' ? [...group.ids, 'separate-approver', 'risk-acceptance'] : group.ids;
    return {
      ...group,
      rules: ids.map((id) => ({ id, label: labels[id], ...definitions[id] })),
    };
  });
}

const POLICY_ENFORCEMENT_LABELS = { enforced: 'Enforced', off: 'Not enforced', failclosed: 'Fail closed' };
const POLICY_DECISIONS_PAGE_SIZE = 6;

function requestTag(request) {
  const reference = request.target?.tag || request.target?.tagReference || '';
  return reference.includes(':') ? reference.slice(reference.lastIndexOf(':') + 1) : reference;
}

function Policy({ policy, requests, state, selectedId, onSelect, onRefresh, onOpenPublish }) {
  const [decisionPage, setDecisionPage] = useState(1);
  const groups = policy ? policyRuleCatalog(policy) : [];
  const rules = groups.flatMap((group) => group.rules);
  const enforced = rules.filter((rule) => rule.enforcement === 'enforced');
  const notEnforced = rules.filter((rule) => rule.enforcement !== 'enforced');

  const failCounts = new Map();
  for (const request of requests) {
    for (const check of request.decision?.checks || []) {
      if (check.status === 'fail') failCounts.set(check.id, (failCounts.get(check.id) || 0) + 1);
    }
  }
  const blockedCount = requests.filter((request) => request.status === 'Blocked').length;
  const mostViolated = rules
    .filter((rule) => failCounts.get(rule.id))
    .sort((a, b) => failCounts.get(b.id) - failCounts.get(a.id))[0];

  const decisionPages = Math.max(1, Math.ceil(requests.length / POLICY_DECISIONS_PAGE_SIZE));
  const currentDecisionPage = Math.min(decisionPage, decisionPages);
  const pagedRequests = requests.slice(
    (currentDecisionPage - 1) * POLICY_DECISIONS_PAGE_SIZE,
    currentDecisionPage * POLICY_DECISIONS_PAGE_SIZE,
  );
  const request = requests.find((item) => item.id === selectedId) ?? requests[0];
  const checks = request?.decision?.checks || [];
  const failedChecks = checks.filter((check) => check.status === 'fail');

  const kpis = [
    { label: 'Rules enforced', value: policy ? enforced.length : '-', note: policy ? `of ${rules.length} rules` : 'loading policy' },
    {
      label: 'Not enforced',
      value: policy ? notEnforced.length : '-',
      note: !policy ? 'loading policy' : notEnforced.length ? notEnforced.map((rule) => rule.short).join(', ') : 'all rules enforced',
      tone: notEnforced.length ? 'warn' : '',
    },
    {
      label: 'Requests evaluated',
      value: requests.length,
      note: `${requests.length - blockedCount} passed · ${blockedCount} blocked`,
    },
    {
      label: 'Most violated',
      value: mostViolated ? mostViolated.short : 'None',
      note: mostViolated
        ? `blocked ${failCounts.get(mostViolated.id)} request${failCounts.get(mostViolated.id) === 1 ? '' : 's'}`
        : 'no failed checks',
      tone: mostViolated ? 'critical text' : 'text',
    },
  ];

  return (
    // lang="en": the shell is lang="tr", which would upper-case English labels with a dotted İ.
    <div className="view-grid pl-view" lang="en">
      <section className="panel pl-head">
        <div className="pl-head-title">
          <span className="pl-mark">
            <ShieldCheck size={20} />
          </span>
          <div>
            <h2>
              Publish policy {policy?.version && <code>{policy.version}</code>}
            </h2>
            <span>Fail-closed gate for verified remediation outputs · evaluated on every publish request</span>
          </div>
        </div>
        <div className="pl-head-actions">
          <DataSourceBadge state={state} />
          <button className="icon-button pl-refresh" type="button" title="Refresh policy and decisions" onClick={onRefresh}>
            <RefreshCw size={16} />
          </button>
        </div>
      </section>

      {state.error && <div className="inline-error">{state.error}</div>}

      <section className="rp-kpis">
        {kpis.map((kpi) => (
          <div className={`panel rp-kpi${kpi.tone ? ` ${kpi.tone}` : ''}`} key={kpi.label}>
            <span>{kpi.label}</span>
            <strong>{kpi.value}</strong>
            <small>{kpi.note}</small>
          </div>
        ))}
      </section>

      <div className="pl-layout">
        <section className="panel pl-card">
          <div className="panel-header">
            <div>
              <Lock size={19} />
              <h2>Policy rules</h2>
            </div>
            <span className="pl-legend">
              <i className="enforced" />
              Enforced
              <i className="off" />
              Not enforced
            </span>
          </div>
          {!policy && <div className="empty-copy">Loading policy configuration…</div>}
          <div className="pl-groups">
            {groups.map((group) => (
              <div className="pl-group" key={group.key}>
                <div className="pl-group-head">
                  <strong>{group.title}</strong>
                  <em>
                    {group.rules.filter((rule) => rule.enforcement === 'enforced').length}/{group.rules.length} enforced
                  </em>
                </div>
                {group.rules.map((rule) => {
                  const fails = failCounts.get(rule.id) || 0;
                  return (
                    <div className={`pl-rule ${rule.enforcement}`} key={rule.id}>
                      <span className="pl-rule-icon">
                        {rule.enforcement === 'enforced' ? (
                          <CheckCircle2 size={16} />
                        ) : rule.enforcement === 'failclosed' ? (
                          <AlertTriangle size={16} />
                        ) : (
                          <MinusCircle size={16} />
                        )}
                      </span>
                      <span className="pl-rule-text">
                        <strong>{rule.label}</strong>
                        <small title={rule.value}>{rule.value}</small>
                      </span>
                      <span className={`pl-impact${fails ? ' hit' : ''}`} title="Publish requests blocked by this rule">
                        {fails ? `Blocked ${fails}` : '—'}
                      </span>
                      <span className={`pl-enf ${rule.enforcement}`}>{POLICY_ENFORCEMENT_LABELS[rule.enforcement]}</span>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </section>

        <aside className="panel pl-rail">
          <PanelHeader icon={Filter} title="Recent decisions" />
          {requests.length === 0 ? (
            <div className="empty-copy">No publish requests have been evaluated yet.</div>
          ) : (
            <>
              <div className="pl-decisions">
                {pagedRequests.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    className={`pl-decision${item.id === request?.id ? ' selected' : ''}`}
                    aria-pressed={item.id === request?.id}
                    onClick={() => onSelect(item.id)}
                  >
                    <span className="pl-decision-main">
                      <strong>{item.id}</strong>
                      <small>:{requestTag(item) || '-'}</small>
                    </span>
                    <span className="pl-decision-meta">
                      <Badge status={item.status} label={PUBLISH_STATUS_LABELS[item.status]} />
                      <small>{shortTime(item.updatedAt)}</small>
                    </span>
                  </button>
                ))}
              </div>
              <PaginationBar
                page={currentDecisionPage}
                totalPages={decisionPages}
                totalItems={requests.length}
                pageSize={POLICY_DECISIONS_PAGE_SIZE}
                onPage={setDecisionPage}
              />
              {request && (
                <div className="pl-selected">
                  <div className="pl-selected-head">
                    <strong>{request.id}</strong>
                    <Badge status={request.status} label={PUBLISH_STATUS_LABELS[request.status]} />
                  </div>
                  <div className={failedChecks.length ? 'admission fail pl-admission' : 'admission pass pl-admission'}>
                    {failedChecks.length ? <ShieldOff size={20} /> : <ShieldCheck size={20} />}
                    <div>
                      <strong>
                        {failedChecks.length
                          ? `${failedChecks.length} rule${failedChecks.length === 1 ? '' : 's'} failed`
                          : 'All rules passed'}
                      </strong>
                      <span>
                        {checks.length - failedChecks.length} of {checks.length} checks passed
                      </span>
                    </div>
                  </div>
                  {failedChecks.length > 0 && (
                    <div className="pl-failed">
                      {failedChecks.map((check) => (
                        <div className="pl-failed-item" key={check.id}>
                          <strong>{check.label}</strong>
                          <small>{check.detail}</small>
                        </div>
                      ))}
                    </div>
                  )}
                  <button type="button" className="text-action pl-open" onClick={() => onOpenPublish(request.id)}>
                    Open in Publish
                    <ArrowRight size={14} />
                  </button>
                </div>
              )}
            </>
          )}
        </aside>
      </div>
    </div>
  );
}

// Risk acceptance (policy exceptions). The server owns the lifecycle and the rules (two-person
// rule, maximum duration by severity, publish gate effect); this screen lists, requests and
// decides. "Expiring" is a view of an active exception that ends within EXCEPTION_EXPIRING_DAYS.
const EXCEPTION_EXPIRING_DAYS = 14;
const EXCEPTION_PAGE_SIZE = 8;
const EXCEPTION_DAY_MS = 24 * 60 * 60 * 1000;
const EXCEPTION_FILTERS = [
  { key: 'all', label: 'All', match: () => true },
  { key: 'requested', label: 'Requested', match: (item) => item.view === 'Requested' },
  { key: 'active', label: 'Active', match: (item) => item.view === 'Active' || item.view === 'Expiring' },
  { key: 'expiring', label: `Expiring ≤ ${EXCEPTION_EXPIRING_DAYS}d`, match: (item) => item.view === 'Expiring' },
  { key: 'expired', label: 'Expired', match: (item) => item.view === 'Expired' },
  { key: 'closed', label: 'Rejected · Revoked', match: (item) => item.view === 'Rejected' || item.view === 'Revoked' },
];
const EXCEPTION_VIEW_BADGES = {
  Requested: ['Pending', 'Requested'],
  Active: ['Approved', 'Active'],
  Expiring: ['Review', 'Expiring'],
  Expired: ['Deprecated', 'Expired'],
  Rejected: ['Blocked', 'Rejected'],
  Revoked: ['Blocked', 'Revoked'],
};
const EXCEPTION_REASON_HELP = {
  not_affected: 'The vulnerable code is not present or not reachable in this image.',
  no_fix_available: 'The distribution has not released a fixed package.',
  compensating_control: 'Another control (network, WAF, configuration) blocks exploitation.',
  accepted_risk: 'The business accepts the risk for a limited time.',
};
const EXCEPTION_HISTORY_LABELS = { requested: 'requested', approved: 'approved', rejected: 'rejected', revoked: 'revoked' };

function daysUntil(value, now) {
  const time = Date.parse(value);
  if (Number.isNaN(time)) return null;
  return Math.ceil((time - now) / EXCEPTION_DAY_MS);
}

function exceptionView(exception, now) {
  const status = effectiveExceptionStatus(exception, now);
  const daysLeft = daysUntil(exception.expiresAt, now);
  let view = status;
  if (status === 'Approved') view = daysLeft !== null && daysLeft <= EXCEPTION_EXPIRING_DAYS ? 'Expiring' : 'Active';
  return { ...exception, view, daysLeft };
}

function ExceptionBadge({ view }) {
  const [status, label] = EXCEPTION_VIEW_BADGES[view] || ['Pending', view];
  return <Badge status={status} label={label} />;
}

function SeverityTag({ severity, verified = true }) {
  const key = String(severity || 'unknown').toLowerCase();
  return (
    <span className={`severity ${key}`} title={verified ? undefined : 'Not confirmed by the scans'}>
      {key.charAt(0).toUpperCase() + key.slice(1)}
      {verified ? '' : '?'}
    </span>
  );
}

function exceptionScopeText(exception) {
  const parts = [exception.digest ? `digest ${exception.digest.slice(0, 19)}…` : 'All digests in the repository'];
  parts.push(exception.package ? `package ${exception.package} only` : 'any package');
  return parts.join(' · ');
}

function exportExceptions(rows) {
  exportCsv(
    `ssi-risk-acceptances-${new Date().toISOString().slice(0, 10)}.csv`,
    ['ID', 'CVE', 'Severity', 'Repository', 'Package', 'Digest', 'Reason', 'Status', 'Expires', 'Requested by', 'Requested at', 'Decided by', 'Decision note', 'Justification'],
    rows.map((item) => [
      item.id,
      item.cve,
      item.severity,
      item.repository,
      item.package || '',
      item.digest || '',
      EXCEPTION_REASONS[item.reasonCode] || item.reasonCode,
      item.view,
      item.expiresAt,
      item.requestedBy,
      item.requestedAt,
      item.decidedBy || '',
      item.revokeReason || item.decisionNote || '',
      item.justification,
    ]),
  );
}

// Repositories and packages that the loaded scans report for a CVE, for the request form.
function exceptionScopeOptions(reports, cve) {
  const wanted = String(cve || '').trim().toUpperCase();
  const byRepository = new Map();
  for (const report of reports || []) {
    const repository = repositoryFromReference(report.image || report.id);
    if (!repository.includes('/')) continue;
    const entry = byRepository.get(repository) || new Set();
    for (const finding of report.findings || []) {
      if (wanted && String(finding.cve || '').toUpperCase() === wanted && finding.package) entry.add(finding.package);
    }
    byRepository.set(repository, entry);
  }
  return [...byRepository.entries()]
    .map(([repository, packages]) => ({ repository, packages: [...packages].sort(), affected: packages.size > 0 }))
    .sort((a, b) => Number(b.affected) - Number(a.affected) || a.repository.localeCompare(b.repository));
}

function Exceptions({
  exceptions,
  state,
  policy,
  reports,
  publishRequests,
  currentUser,
  canRequest,
  canDecide,
  draft,
  onDraft,
  onRequest,
  onDecide,
}) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const [reason, setReason] = useState('all');
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState('');
  const now = Date.now();

  const rows = exceptions.map((item) => exceptionView(item, now));
  const needle = query.trim().toLowerCase();
  const searched = rows.filter(
    (item) =>
      (reason === 'all' || item.reasonCode === reason) &&
      (!needle ||
        [item.id, item.cve, item.repository, item.package, item.requestedBy].some((value) =>
          String(value || '').toLowerCase().includes(needle),
        )),
  );
  const activeFilter = EXCEPTION_FILTERS.find((item) => item.key === filter) || EXCEPTION_FILTERS[0];
  const visible = searched.filter(activeFilter.match);
  const totalPages = Math.max(1, Math.ceil(visible.length / EXCEPTION_PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const paged = visible.slice((currentPage - 1) * EXCEPTION_PAGE_SIZE, currentPage * EXCEPTION_PAGE_SIZE);
  const selected = rows.find((item) => item.id === selectedId) || paged[0] || null;
  const resetPage = (apply) => (value) => {
    apply(value);
    setPage(1);
  };

  return (
    // lang="en": the shell is lang="tr", which would upper-case English labels with a dotted İ.
    <div className="view-grid ex-view" lang="en">
      <ExceptionTimeline rows={rows} now={now} onSelect={setSelectedId} />

      <div className="catalog-layout inv-layout ex-layout">
        <section className="panel catalog-panel inv-panel">
          <div className="pub-stat-chips ex-chips" role="group" aria-label="Filter">
            {EXCEPTION_FILTERS.map((item) => (
              <button
                key={item.key}
                type="button"
                className={`psc st-${item.key}${filter === item.key ? ' active' : ''}`}
                aria-pressed={filter === item.key}
                onClick={() => resetPage(setFilter)(item.key)}
              >
                <strong>{searched.filter(item.match).length}</strong>
                <span>{item.label}</span>
              </button>
            ))}
          </div>

          <div className="inv-toolbar">
            <div className="search-box inv-search">
              <Search size={16} />
              <input
                aria-label="Exception search"
                placeholder="Search CVE, package, repository or ID"
                value={query}
                onChange={(event) => resetPage(setQuery)(event.target.value)}
              />
            </div>
            <label className="select-mini ex-reason-filter">
              <select
                aria-label="Reason"
                value={reason}
                onChange={(event) => resetPage(setReason)(event.target.value)}
              >
                <option value="all">All reasons</option>
                {Object.entries(EXCEPTION_REASONS).map(([key, label]) => (
                  <option key={key} value={key}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <div className="inv-toolbar-spacer" />
            <DataSourceBadge state={state} />
            <button
              className="icon-button ex-icon"
              type="button"
              title="Export CSV"
              aria-label="Export CSV"
              disabled={visible.length === 0}
              onClick={() => exportExceptions(visible)}
            >
              <Download size={16} />
            </button>
            {canRequest && (
              <button className="primary-action ex-btn" type="button" onClick={() => onDraft({})}>
                <Plus size={15} />
                Request exception
              </button>
            )}
          </div>
          {state.error && <div className="inline-error">{state.error}</div>}

          <div className="ex-table">
            <div className="ex-row ex-head">
              <span>Finding</span>
              <span>Repository · package</span>
              <span>Reason</span>
              <span>Status</span>
              <span>Expires</span>
            </div>
            {!state.loading && visible.length === 0 && (
              <div className="inv-empty">
                {rows.length === 0
                  ? 'No risk acceptances yet. Request one from the CVE Queue when a finding cannot be fixed before the next release.'
                  : 'No exceptions match the current filters.'}
              </div>
            )}
            {paged.map((item) => (
              <button
                key={item.id}
                type="button"
                className={`ex-row${selected?.id === item.id ? ' selected' : ''}${
                  ['Expired', 'Rejected', 'Revoked'].includes(item.view) ? ' muted' : ''
                }`}
                aria-pressed={selected?.id === item.id}
                onClick={() => setSelectedId(item.id)}
              >
                <span className="ex-find">
                  <strong>{item.cve}</strong>
                  <small>
                    <SeverityTag severity={item.severity} verified={item.severityVerified} />
                    <code>{item.id}</code>
                  </small>
                </span>
                <span className="ex-find">
                  <span className="ex-repo" title={item.repository}>
                    {item.repository}
                  </span>
                  <small>
                    {item.package ? <code>{item.package}</code> : 'any package'} · by {item.requestedBy}
                  </small>
                </span>
                <span>
                  <span className="ex-reason">{EXCEPTION_REASONS[item.reasonCode] || item.reasonCode}</span>
                </span>
                <span>
                  <ExceptionBadge view={item.view} />
                </span>
                <ExceptionExpiry item={item} policy={policy} />
              </button>
            ))}
          </div>
          <div className="inv-pagination">
            <PaginationBar
              page={currentPage}
              totalPages={totalPages}
              totalItems={visible.length}
              pageSize={EXCEPTION_PAGE_SIZE}
              onPage={setPage}
            />
          </div>
        </section>

        <ExceptionDetailPanel
          key={selected?.id || 'none'}
          item={selected}
          publishRequests={publishRequests}
          currentUser={currentUser}
          canDecide={canDecide}
          onDecide={onDecide}
        />
      </div>

      {draft && (
        <RequestExceptionDialog
          draft={draft}
          policy={policy}
          reports={reports}
          onCancel={() => onDraft(null)}
          onSubmit={async (payload) => {
            const created = await onRequest(payload);
            setFilter('all');
            setSelectedId(created.id);
            onDraft(null);
          }}
        />
      )}
    </div>
  );
}

function ExceptionExpiry({ item, policy }) {
  const date = formatReportTime(item.expiresAt).slice(0, 10);
  if (item.view === 'Rejected') {
    return (
      <span className="ex-exp">
        <strong>—</strong>
        <small>not granted</small>
      </span>
    );
  }
  if (item.view === 'Revoked') {
    return (
      <span className="ex-exp">
        <strong>{formatReportTime(item.revokedAt).slice(0, 10)}</strong>
        <small>revoked early</small>
      </span>
    );
  }
  if (item.view === 'Expired') {
    return (
      <span className="ex-exp">
        <strong>{date}</strong>
        <small className="bad">{item.daysLeft === 0 ? 'today' : `${Math.abs(item.daysLeft)} days ago`}</small>
      </span>
    );
  }
  if (item.view === 'Requested' && item.daysLeft <= 0) {
    return (
      <span className="ex-exp">
        <strong>{date}</strong>
        <small className="bad">requested expiry passed</small>
      </span>
    );
  }
  const scale = policy?.riskAcceptance?.maxDays || 90;
  const warn = item.daysLeft <= EXCEPTION_EXPIRING_DAYS;
  return (
    <span className="ex-exp">
      <strong>{date}</strong>
      <span className="ex-bar">
        <i className={warn ? 'warn' : ''} style={{ width: `${Math.max(4, Math.min(100, (item.daysLeft / scale) * 100))}%` }} />
      </span>
      <small className={warn && item.view !== 'Requested' ? 'warn' : ''}>
        {item.view === 'Requested' ? `ends in ${item.daysLeft} days if approved` : `${item.daysLeft} days left`}
      </small>
    </span>
  );
}

// Open and recently expired exceptions on one time axis: today, the expiring window and the
// end date of each acceptance.
function ExceptionTimeline({ rows, now, onSelect }) {
  const windowStart = now - 30 * EXCEPTION_DAY_MS;
  const items = rows
    .filter((item) => ['Requested', 'Active', 'Expiring'].includes(item.view) || (item.view === 'Expired' && item.daysLeft >= -30))
    .sort((a, b) => Date.parse(a.expiresAt) - Date.parse(b.expiresAt));
  if (items.length === 0) return null;
  const shown = items.slice(0, 6);
  const lastEnd = Math.max(...shown.map((item) => Date.parse(item.expiresAt)));
  const windowEnd = Math.max(lastEnd + 7 * EXCEPTION_DAY_MS, now + 60 * EXCEPTION_DAY_MS);
  const span = windowEnd - windowStart;
  const at = (time) => `${(Math.min(Math.max(time, windowStart), windowEnd) - windowStart) / span * 100}%`;
  const months = [];
  const cursor = new Date(windowStart);
  cursor.setDate(1);
  cursor.setHours(0, 0, 0, 0);
  for (cursor.setMonth(cursor.getMonth() + 1); cursor.getTime() < windowEnd; cursor.setMonth(cursor.getMonth() + 1)) {
    months.push({ key: cursor.getTime(), label: cursor.toLocaleString('en', { month: 'short' }) });
  }
  const tone = { Requested: 'pending', Active: 'ok', Expiring: 'warn', Expired: 'gone' };

  return (
    <section className="panel ex-tl" aria-label="Expiry timeline">
      <div className="ex-tl-head">
        <h2>Expiry timeline</h2>
        <div className="ex-legend">
          <span>
            <i className="ok" />
            Active
          </span>
          <span>
            <i className="warn" />
            Expiring ≤ {EXCEPTION_EXPIRING_DAYS}d
          </span>
          <span>
            <i className="pending" />
            Requested
          </span>
          <span>
            <i className="gone" />
            Expired
          </span>
        </div>
      </div>
      <div className="ex-tl-grid">
        <div className="ex-tl-axis">
          <span />
          <div className="ex-tl-scale">
            {months.map((month) => (
              <em key={month.key} style={{ left: at(month.key) }}>
                {month.label}
              </em>
            ))}
          </div>
        </div>
        {shown.map((item) => {
          const start = Date.parse(item.decidedAt || item.requestedAt) || now;
          const end = Date.parse(item.expiresAt);
          return (
            <button type="button" className="ex-tl-row" key={item.id} onClick={() => onSelect(item.id)}>
              <span className="ex-tl-label">
                <strong>{item.cve}</strong>
                <small>
                  {item.id} · {item.repository}
                </small>
              </span>
              <span className="ex-tl-track">
                <span
                  className="ex-tl-zone"
                  style={{ left: at(now), width: `${(EXCEPTION_EXPIRING_DAYS * EXCEPTION_DAY_MS) / span * 100}%` }}
                />
                <i
                  className={`ex-tl-bar ${tone[item.view]}${start < windowStart ? ' cut' : ''}`}
                  style={{ left: at(start), width: `calc(${at(end)} - ${at(start)})` }}
                />
                <b className="ex-tl-end" style={{ left: at(end) }}>
                  {formatReportTime(item.expiresAt).slice(5, 10)}
                </b>
                <span className="ex-tl-today" style={{ left: at(now) }} />
              </span>
            </button>
          );
        })}
        {items.length > shown.length && (
          <p className="ex-tl-more">+{items.length - shown.length} more in the table below</p>
        )}
      </div>
    </section>
  );
}

const EXCEPTION_STEPS = ['Requested', 'Decision', 'Active', 'Ended'];

// Lifecycle stepper: a rejected request never became active, so that step stays empty.
function exceptionStepClass(view, index) {
  const current = { Requested: 1, Active: 2, Expiring: 2 }[view];
  if (current !== undefined) return index < current ? 'done' : index === current ? 'now' : '';
  if (index === 3) return 'end';
  if (view === 'Rejected' && index === 2) return '';
  return 'done';
}

function ExceptionDetailPanel({ item, publishRequests, currentUser, canDecide, onDecide }) {
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');

  if (!item) {
    return (
      <aside className="panel inspector inv-insp ex-rail" aria-label="Exception detail">
        <div className="inv-empty">Select an exception to see its scope, history and policy effect.</div>
      </aside>
    );
  }

  const isRequester = sameUser(currentUser, item.requestedBy);
  const ended = ['Expired', 'Rejected', 'Revoked'].includes(item.view);
  const appliedTo = (publishRequests || []).filter((request) =>
    (request.decision?.exceptions?.appliedExceptions || []).some((applied) => applied.id === item.id),
  );
  const decide = async (decision) => {
    setBusy(decision);
    setError('');
    try {
      await onDecide(item.id, decision, note.trim());
      setNote('');
    } catch (err) {
      setError(err.message || 'The decision could not be saved.');
    } finally {
      setBusy('');
    }
  };
  const noteValid = note.trim().length >= MIN_DECISION_NOTE_LENGTH;
  const effect = {
    Requested: `When approved, the publish gate stops counting this finding in the ${
      item.severity === 'high' ? 'High' : 'Critical/High'
    } threshold for ${item.repository} until ${formatReportTime(item.expiresAt).slice(0, 10)}. Until then it still counts.`,
    Active: `The publish gate does not count this finding in the Critical/High thresholds for ${item.repository}. The other checks are unaffected.`,
    Expiring: `Ends in ${item.daysLeft} days. After that the finding counts again and blocks publishing until it is fixed or a new exception is approved.`,
    Expired: 'Ended. The finding counts again in the publish gate.',
    Rejected: 'Not granted. The finding counts in the publish gate.',
    Revoked: 'Closed early. The finding counts again in the publish gate.',
  }[item.view];

  return (
    <aside className="panel inspector inv-insp ex-rail" aria-label="Exception detail">
      <div className="inv-insp-head">
        <div>
          <span className="inv-insp-path">
            {item.id} · requested {formatReportTime(item.requestedAt)}
          </span>
          <h2 className="ex-h">{item.cve}</h2>
          <div className="ex-hsub">
            <SeverityTag severity={item.severity} verified={item.severityVerified} />
            <span>{item.package || 'any package'}</span>
          </div>
        </div>
        <ExceptionBadge view={item.view} />
      </div>

      <div className="ex-steps" aria-label="Lifecycle">
        {EXCEPTION_STEPS.map((label, index) => (
          <span key={label} className={exceptionStepClass(item.view, index)}>
            <i />
            {index === 3 && ended ? item.view : label}
          </span>
        ))}
      </div>

      <div className="inv-facts">
        <div className="detail full">
          <span>Scope</span>
          <strong className="ex-mono">{item.repository}</strong>
          <small className="ex-fine">{exceptionScopeText(item)}</small>
        </div>
        <div className="detail">
          <span>Reason</span>
          <strong>{EXCEPTION_REASONS[item.reasonCode] || item.reasonCode}</strong>
        </div>
        <div className="detail">
          <span>{item.view === 'Requested' ? 'Expires if approved' : 'Expires'}</span>
          <strong>
            {formatReportTime(item.expiresAt).slice(0, 10)}
            {item.daysLeft > 0 && !ended ? ` · ${item.daysLeft} days` : ''}
          </strong>
        </div>
        <div className="detail">
          <span>Requested by</span>
          <strong>{item.requestedBy}</strong>
        </div>
        <div className="detail">
          <span>{item.view === 'Revoked' ? 'Revoked by' : 'Decided by'}</span>
          <strong>{item.revokedBy || item.decidedBy || '—'}</strong>
        </div>
      </div>

      <div className="inv-section-title">Justification</div>
      <p className="ex-quote">{item.justification}</p>

      <div className={`ex-effect${ended ? ' muted' : ''}`}>
        <ShieldCheck size={15} />
        <div>
          <strong>Policy effect</strong>
          <span>{effect}</span>
        </div>
      </div>

      {appliedTo.length > 0 && (
        <>
          <div className="inv-section-title">Applied to publish requests</div>
          <div className="ex-applied">
            {appliedTo.map((request) => (
              <span key={request.id}>
                <code>{request.id}</code>
                <Badge status={request.status} label={request.status === 'ApprovalRequired' ? 'Approval required' : request.status} />
              </span>
            ))}
          </div>
        </>
      )}

      <div className="inv-section-title">History</div>
      <ol className="ex-history">
        {(item.history || []).map((entry) => (
          <li key={`${entry.action}-${entry.at}`}>
            <b className={entry.action} />
            <span>
              <strong>{entry.actor}</strong> {EXCEPTION_HISTORY_LABELS[entry.action] || entry.action}
              {entry.action !== 'requested' && entry.note && <em>{entry.note}</em>}
            </span>
            <time>{formatReportTime(entry.at)}</time>
          </li>
        ))}
      </ol>

      {canDecide && (item.view === 'Requested' || item.view === 'Active' || item.view === 'Expiring') && (
        <div className="ex-decision">
          <div className="inv-section-title">{item.view === 'Requested' ? 'Decision' : 'Revoke early'}</div>
          {item.view === 'Requested' && isRequester ? (
            <p className="ex-two">
              <Lock size={13} />
              Two-person rule: you requested this exception, so another approver must decide on it.
            </p>
          ) : (
            <>
              <textarea
                className="ex-note"
                value={note}
                aria-label="Decision note"
                placeholder={item.view === 'Requested' ? 'Decision note (required)' : 'Why is it no longer needed? (required)'}
                onChange={(event) => setNote(event.target.value)}
              />
              {error && <div className="inline-error">{error}</div>}
              <div className="ex-actions">
                {item.view === 'Requested' ? (
                  <>
                    <button
                      className="primary-action ex-btn ok"
                      type="button"
                      disabled={!noteValid || Boolean(busy)}
                      onClick={() => decide('approve')}
                    >
                      <CheckCircle2 size={15} />
                      {busy === 'approve' ? 'Approving…' : 'Approve'}
                    </button>
                    <button
                      className="secondary-action ex-btn danger"
                      type="button"
                      disabled={!noteValid || Boolean(busy)}
                      onClick={() => decide('reject')}
                    >
                      <X size={15} />
                      {busy === 'reject' ? 'Rejecting…' : 'Reject'}
                    </button>
                  </>
                ) : (
                  <button
                    className="secondary-action ex-btn danger"
                    type="button"
                    disabled={!noteValid || Boolean(busy)}
                    onClick={() => decide('revoke')}
                  >
                    <MinusCircle size={15} />
                    {busy === 'revoke' ? 'Revoking…' : 'Revoke exception'}
                  </button>
                )}
              </div>
              <p className="ex-two">
                <Lock size={13} />
                {item.view === 'Requested'
                  ? `Two-person rule: ${item.requestedBy} cannot decide on this request.`
                  : 'Revoking takes effect on the next publish evaluation.'}
              </p>
            </>
          )}
        </div>
      )}
      {!canDecide && item.view === 'Requested' && (
        <p className="ex-two">
          <Lock size={13} />
          An approver decides on this request.
        </p>
      )}
    </aside>
  );
}

const EXCEPTION_DURATIONS = [7, 14, 30, 60, 90];

function RequestExceptionDialog({ draft, policy, reports, onCancel, onSubmit }) {
  const fromQueue = Boolean(draft.cve && draft.repository);
  const [cve, setCve] = useState(draft.cve || '');
  const [repository, setRepository] = useState(draft.repository || '');
  const [packageName, setPackageName] = useState(draft.package || '');
  const [digestOnly, setDigestOnly] = useState(false);
  const [reasonCode, setReasonCode] = useState(draft.fixable === false ? 'no_fix_available' : '');
  const [justification, setJustification] = useState('');
  const [days, setDays] = useState(30);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const limits = policy?.riskAcceptance || { maxDays: 90, maxDaysCritical: 30 };
  const options = exceptionScopeOptions(reports, cve);
  const scope = options.find((item) => item.repository === repository);
  const severity = severityForScope(reports, { cve, repository, package: packageName });
  const maxDays = exceptionMaxDays(severity || 'critical', limits);
  const duration = Math.min(days, maxDays);
  const expiresAt = new Date(Date.now() + duration * EXCEPTION_DAY_MS);
  const justificationLength = justification.trim().length;
  const valid =
    /^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$/i.test(cve.trim()) &&
    repository.includes('/') &&
    Boolean(reasonCode) &&
    justificationLength >= MIN_JUSTIFICATION_LENGTH;

  const submit = async (event) => {
    event.preventDefault();
    if (!valid || saving) return;
    setSaving(true);
    setError('');
    try {
      await onSubmit({
        cve: cve.trim(),
        repository,
        package: packageName || undefined,
        digest: digestOnly && draft.digest ? draft.digest : undefined,
        reasonCode,
        justification: justification.trim(),
        // The server computes the expiry from its own clock.
        durationDays: duration,
      });
    } catch (err) {
      setError(err.message || 'The request could not be submitted.');
      setSaving(false);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onCancel()}>
      <form className="ex-modal" role="dialog" aria-modal="true" aria-labelledby="ex-modal-title" onSubmit={submit} lang="en">
        <div className="ex-m-head">
          <div>
            <span className="inv-insp-path">{fromQueue ? 'From CVE Queue' : 'Risk acceptance'}</span>
            <h2 id="ex-modal-title">Request exception</h2>
          </div>
          <button type="button" className="modal-close" aria-label="Close" onClick={onCancel}>
            <X size={18} />
          </button>
        </div>

        <div className="ex-m-grid">
          <div>
            <div className="ex-prefill">
              <label>
                <span>CVE</span>
                <input
                  value={cve}
                  readOnly={fromQueue}
                  placeholder="CVE-2026-12345"
                  onChange={(event) => {
                    setCve(event.target.value.toUpperCase());
                    setPackageName('');
                  }}
                />
              </label>
              <label>
                <span>Repository</span>
                <select
                  value={repository}
                  disabled={fromQueue}
                  onChange={(event) => {
                    setRepository(event.target.value);
                    setPackageName('');
                  }}
                >
                  <option value="">Select a repository…</option>
                  {(fromQueue && !scope ? [{ repository, packages: [], affected: true }, ...options] : options).map(
                    (item) => (
                      <option key={item.repository} value={item.repository}>
                        {item.repository}
                        {cve && item.affected ? ' · affected' : ''}
                      </option>
                    ),
                  )}
                </select>
              </label>
              <label>
                <span>Package</span>
                <select value={packageName} onChange={(event) => setPackageName(event.target.value)}>
                  <option value="">Any package</option>
                  {[...new Set([...(scope?.packages || []), ...(draft.package ? [draft.package] : [])])].map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>
              <div className="ex-prefill-sev">
                <span>Severity in scans</span>
                {severity ? (
                  <SeverityTag severity={severity} />
                ) : (
                  <small>Not found in the loaded scans · Critical limit applies</small>
                )}
              </div>
            </div>

            <div className="ex-lbl">Scope</div>
            <div className="ex-seg" role="group" aria-label="Scope">
              <button type="button" className={digestOnly ? '' : 'active'} onClick={() => setDigestOnly(false)}>
                All digests in repository
              </button>
              <button
                type="button"
                className={digestOnly ? 'active' : ''}
                disabled={!draft.digest}
                title={draft.digest ? draft.digest : 'Open the request from an image in the CVE Queue to bind it to one digest'}
                onClick={() => setDigestOnly(true)}
              >
                This digest only
              </button>
            </div>
            <small className="ex-fine">
              Recommended: remediation creates a new digest on every rebuild; a digest-bound exception stops matching after the
              next rebuild.
            </small>

            <div className="ex-lbl">Reason</div>
            <div className="ex-reasons" role="radiogroup" aria-label="Reason">
              {Object.entries(EXCEPTION_REASONS).map(([key, label]) => (
                <label key={key} className={`ex-ropt${reasonCode === key ? ' on' : ''}`}>
                  <input type="radio" name="ex-reason" value={key} checked={reasonCode === key} onChange={() => setReasonCode(key)} />
                  <span>
                    <strong>{label}</strong>
                    <small>{EXCEPTION_REASON_HELP[key]}</small>
                  </span>
                </label>
              ))}
            </div>
          </div>

          <div>
            <div className="ex-lbl">
              Justification
              <em className={justificationLength >= MIN_JUSTIFICATION_LENGTH ? 'ok' : ''}>
                {justificationLength} / min {MIN_JUSTIFICATION_LENGTH}
              </em>
            </div>
            <textarea
              className="ex-ta"
              value={justification}
              aria-label="Justification"
              placeholder="Why can this finding not be fixed now, and what limits the risk until then?"
              onChange={(event) => setJustification(event.target.value)}
            />

            <div className="ex-lbl">Expires</div>
            <div className="ex-seg" role="group" aria-label="Duration">
              {EXCEPTION_DURATIONS.map((value) => (
                <button
                  key={value}
                  type="button"
                  className={duration === value ? 'active' : ''}
                  disabled={value > maxDays}
                  onClick={() => setDays(value)}
                >
                  {value} days
                </button>
              ))}
            </div>
            <small className="ex-fine">
              <Lock size={12} /> Critical findings: maximum {limits.maxDaysCritical} days (others: {limits.maxDays} days). Ends{' '}
              {formatReportTime(expiresAt.toISOString()).slice(0, 10)}.
            </small>

            <div className="ex-effect">
              <ShieldCheck size={15} />
              <div>
                <strong>What happens next</strong>
                <span>
                  The request is recorded and audited. An approver other than you decides on it; until then the publish gate
                  still counts this finding.
                </span>
              </div>
            </div>
            {error && <div className="inline-error">{error}</div>}
          </div>
        </div>

        <div className="ex-m-foot">
          <span className="ex-fine">Recorded in the audit log as exception.requested</span>
          <div>
            <button type="button" className="secondary-action ex-btn" onClick={onCancel}>
              Cancel
            </button>
            <button type="submit" className="primary-action ex-btn" disabled={!valid || saving}>
              {saving ? 'Submitting…' : 'Submit request'}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}

// Audit: the append-only audit_events log, newest first. Filters run on the server
// (src/lib/auditQuery.js); the screen reads AUDIT_FETCH_SIZE events at a time and shows them
// AUDIT_PAGE_SIZE per page, loading older ones on request. Categories come from the same module.
const AUDIT_FETCH_SIZE = 100;
const AUDIT_PAGE_SIZE = 10;
const AUDIT_SEARCH_DELAY_MS = 300;
const AUDIT_SESSION_CATEGORY = { key: 'session', label: 'Session note' };

// Events recorded before the server summaries were switched to English. The stored record is
// never changed; the original text stays visible in the detail rail as "Recorded as".
const LEGACY_AUDIT_SUMMARIES = [
  [/^Giriş başarılı: (\S+) \((.*), ([^,]*)\)$/u, (m) => `Signed in: ${m[1]} (${m[2] === 'rol yok' ? 'no role' : m[2]}, ${m[3]})`],
  [/^Giriş başarısız: (.*)$/u, (m) => `Sign-in failed: ${m[1] === 'bilinmeyen' ? 'unknown' : m[1]}`],
  [/^Kullanıcı oluşturuldu: (.*)$/u, (m) => `User created: ${m[1]}`],
  [/^Kullanıcı güncellendi: (\S+) \(rol=(.*), durum=(.*)\)$/u, (m) => `User updated: ${m[1]} (role=${m[2]}, status=${m[3]})`],
  [/^Kullanıcı silindi: (.*)$/u, (m) => `User removed: ${m[1]}`],
];

function englishAuditSummary(summary) {
  const text = String(summary || '');
  for (const [pattern, translate] of LEGACY_AUDIT_SUMMARIES) {
    const match = text.match(pattern);
    if (match) return translate(match);
  }
  return text;
}

// A date input (YYYY-MM-DD, the viewer's own day) as the ISO start of that day; dayOffset 1
// gives the start of the next day, so "To" includes the whole chosen day.
function auditDayStart(value, dayOffset = 0) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || '')) return '';
  const date = new Date(`${value}T00:00:00`);
  if (Number.isNaN(date.getTime())) return '';
  date.setDate(date.getDate() + dayOffset);
  return date.toISOString();
}

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

// Server events keep every recorded field; plain strings are notes the browser added during this
// session after an action. They are not audit records and are labelled as such.
function normalizeAuditEvent(item, index) {
  if (typeof item === 'string') {
    return { id: `session-${index}`, summary: item, recordedSummary: '', category: AUDIT_SESSION_CATEGORY, local: true };
  }
  const eventType = item.eventType || item.action || '';
  const summary = englishAuditSummary(item.summary || eventType);
  return {
    ...item,
    id: item.id || `event-${index}`,
    eventType,
    summary,
    recordedSummary: item.summary && item.summary !== summary ? item.summary : '',
    category: auditCategoryOf(eventType),
    resource: [item.resourceType, item.resourceId].filter(Boolean).join(':'),
    failed: item.outcome !== 'success',
  };
}

function formatAuditTimestamp(value) {
  const date = new Date(value);
  if (!value || Number.isNaN(date.getTime())) return '';
  const pad = (part) => String(part).padStart(2, '0');
  return `${formatReportTime(value)}:${pad(date.getSeconds())}`;
}

function AuditOutcome({ event }) {
  if (event.local) return <Badge status="Review" label="Not recorded" />;
  const label = event.outcome ? event.outcome.charAt(0).toUpperCase() + event.outcome.slice(1) : 'Unknown';
  return <Badge status={event.failed ? 'Blocked' : 'Approved'} label={label} />;
}

function Audit({ notes }) {
  const [query, setQuery] = useState('');
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('all');
  const [failuresOnly, setFailuresOnly] = useState(false);
  const [correlation, setCorrelation] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [events, setEvents] = useState([]);
  const [nextCursor, setNextCursor] = useState('');
  const [summary, setSummary] = useState(null);
  const [state, setState] = useState({ source: 'api', loading: true, error: '' });
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState('');
  const [exportState, setExportState] = useState({ busy: false, error: '', message: '' });
  const generation = useRef(0);

  // The search box waits for a pause in typing before it asks the server.
  useEffect(() => {
    const timer = setTimeout(() => setSearch(query.trim()), AUDIT_SEARCH_DELAY_MS);
    return () => clearTimeout(timer);
  }, [query]);

  const rangeError = fromDate && toDate && fromDate > toDate ? '"From" must not be after "To".' : '';
  const filters = useMemo(
    () => ({
      category,
      failuresOnly,
      correlationId: correlation,
      q: search,
      from: auditDayStart(fromDate),
      to: auditDayStart(toDate, 1),
    }),
    [category, failuresOnly, correlation, search, fromDate, toDate],
  );

  // First page and the per-category counts for the current filters. A response for filters
  // that have since changed is dropped (generation), so a slow answer never overwrites a newer one.
  useEffect(() => {
    if (rangeError) return undefined;
    const current = ++generation.current;
    setState((previous) => ({ ...previous, loading: true, error: '' }));
    Promise.all([listAuditEvents(AUDIT_FETCH_SIZE, { filters }), summarizeAuditEvents(filters)]).then(
      ([list, counts]) => {
        if (current !== generation.current) return;
        setEvents(list.data);
        setNextCursor(list.nextCursor);
        setSummary(counts.data);
        setState({ source: list.source, loading: false, error: list.error || counts.error });
        setPage(1);
      },
    );
    // Leaving the screen or changing the filters makes this response stale.
    return () => {
      generation.current += 1;
    };
  }, [filters, rangeError]);

  async function loadOlder() {
    const current = generation.current;
    setLoadingOlder(true);
    const result = await listAuditEvents(AUDIT_FETCH_SIZE, { before: nextCursor, filters });
    setLoadingOlder(false);
    if (current !== generation.current) return;
    if (result.error) {
      setState((previous) => ({ ...previous, error: result.error }));
      return;
    }
    setEvents((previous) => [...previous, ...result.data]);
    setNextCursor(result.nextCursor);
  }

  // Notes this browser added after an action are shown only in the unfiltered view.
  const unfiltered = !correlation && !failuresOnly && !search && !fromDate && !toDate;
  const sessionNotes = unfiltered && category === 'all' ? (notes || []).filter((item) => typeof item === 'string') : [];
  const shown = [...sessionNotes, ...events].map(normalizeAuditEvent);

  const totalPages = Math.max(1, Math.ceil(shown.length / AUDIT_PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pageEvents = shown.slice((currentPage - 1) * AUDIT_PAGE_SIZE, currentPage * AUDIT_PAGE_SIZE);
  const selected = pageEvents.find((event) => event.id === selectedId) || pageEvents[0] || null;
  const matching = summary?.categories?.[category] ?? null;

  const change = (apply) => (value) => {
    apply(value);
    setPage(1);
  };
  const showRequest = (correlationId) => {
    setCorrelation(correlationId);
    setCategory('all');
    setFailuresOnly(false);
    setQuery('');
    setSearch('');
    setFromDate('');
    setToDate('');
    setPage(1);
  };

  const exportBlocked = !fromDate || !toDate || Boolean(rangeError);
  const overLimit = matching != null && matching > AUDIT_EXPORT_MAX_ROWS;
  async function exportPeriod() {
    setExportState({ busy: true, error: '', message: '' });
    try {
      const file = await downloadAuditExport(filters);
      saveBlob(file.blob, file.filename);
      setExportState({ busy: false, error: '', message: `${file.rows.toLocaleString('en-US')} events exported to ${file.filename}.` });
    } catch (error) {
      setExportState({ busy: false, error: error.message, message: '' });
    }
  }

  return (
    // lang="en": the shell is lang="tr", which would upper-case English labels with a dotted İ.
    <div className="catalog-layout inv-layout au-layout" lang="en">
      <section className="panel catalog-panel inv-panel au-panel">
        <div className="pub-stat-chips au-chips" role="group" aria-label="Event category">
          {[...AUDIT_CATEGORIES, AUDIT_OTHER_CATEGORY].map((item) => (
            <button
              key={item.key}
              type="button"
              className={`psc ${item.key}${category === item.key ? ' active' : ''}`}
              aria-pressed={category === item.key}
              onClick={() => change(setCategory)(item.key)}
            >
              <strong>{summary ? (summary.categories?.[item.key] ?? 0).toLocaleString('en-US') : '—'}</strong>
              <span>{item.label}</span>
            </button>
          ))}
        </div>

        <div className="inv-toolbar">
          <div className="search-box inv-search">
            <Search size={16} />
            <input
              aria-label="Audit search"
              placeholder="Search summary, actor, resource or correlation ID"
              maxLength={200}
              value={query}
              onChange={(event) => change(setQuery)(event.target.value)}
            />
          </div>
          <label className="au-date">
            <span>From</span>
            <input type="date" value={fromDate} max={toDate || undefined} onChange={(event) => change(setFromDate)(event.target.value)} />
          </label>
          <label className="au-date">
            <span>To</span>
            <input type="date" value={toDate} min={fromDate || undefined} onChange={(event) => change(setToDate)(event.target.value)} />
          </label>
          <label className="toggle">
            <input type="checkbox" checked={failuresOnly} onChange={(event) => change(setFailuresOnly)(event.target.checked)} />
            <span>Failures only</span>
          </label>
          <div className="inv-toolbar-spacer" />
          <DataSourceBadge state={state} />
          <button
            className="secondary-action au-btn"
            type="button"
            disabled={exportBlocked || overLimit || exportState.busy || matching === 0}
            title={
              exportBlocked
                ? 'Choose a period (From and To) to export'
                : overLimit
                  ? `One export holds at most ${AUDIT_EXPORT_MAX_ROWS.toLocaleString('en-US')} events; narrow the period`
                  : 'Export every matching event in the period as CSV'
            }
            onClick={exportPeriod}
          >
            <Download size={15} />
            {exportState.busy ? 'Exporting…' : 'Export CSV'}
          </button>
        </div>

        {rangeError && <div className="inline-error">{rangeError}</div>}
        {exportState.error && <div className="inline-error">The export was refused: {exportState.error}</div>}
        {exportState.message && <p className="au-window">{exportState.message} The export is recorded in the audit log.</p>}
        {correlation && (
          <div className="au-filter">
            <Link2 size={14} />
            <span>
              Request <code>{correlation}</code> · {matching ?? '…'} {matching === 1 ? 'event' : 'events'}
            </span>
            <button type="button" onClick={() => change(setCorrelation)('')}>
              <X size={14} />
              Clear
            </button>
          </div>
        )}
        {state.error && <div className="inline-error">The audit log could not be loaded: {state.error}</div>}

        <div className="au-table">
          <div className="au-row au-head">
            <span>Time</span>
            <span>Event</span>
            <span>Actor</span>
            <span>Resource</span>
            <span>Outcome</span>
          </div>
          {!state.loading && shown.length === 0 && (
            <div className="inv-empty">
              {unfiltered && category === 'all' ? 'No audit events recorded yet.' : 'No events match the current filters.'}
            </div>
          )}
          {pageEvents.map((event) => (
            <button
              key={event.id}
              type="button"
              className={`au-row${selected?.id === event.id ? ' selected' : ''}${event.failed ? ' fail' : ''}`}
              aria-pressed={selected?.id === event.id}
              onClick={() => setSelectedId(event.id)}
            >
              <span className="au-time">{formatAuditTimestamp(event.occurredAt) || (event.local ? 'This session' : '—')}</span>
              <span className="au-ev">
                <strong title={event.summary}>{event.summary}</strong>
                <small>
                  <span className={`au-cat ${event.category.key}`}>{event.category.label}</span>
                  {event.eventType && <code>{event.eventType}</code>}
                </small>
              </span>
              <span className="au-actor">{event.actorId || '—'}</span>
              <span className="au-res" title={event.resource}>
                {event.resource || '—'}
              </span>
              <span>
                <AuditOutcome event={event} />
              </span>
            </button>
          ))}
        </div>

        <div className="au-foot">
          <PaginationBar
            page={currentPage}
            totalPages={totalPages}
            totalItems={shown.length}
            pageSize={AUDIT_PAGE_SIZE}
            onPage={(next) => setPage(Math.min(Math.max(next, 1), totalPages))}
          />
          {(nextCursor || (matching != null && events.length < matching)) && (
            <p className="au-window">
              {events.length.toLocaleString('en-US')} of {matching != null ? matching.toLocaleString('en-US') : 'more'} matching events
              loaded.
              {nextCursor && (
                <button className="au-older" type="button" disabled={loadingOlder} onClick={loadOlder}>
                  {loadingOlder ? 'Loading…' : 'Load older events'}
                </button>
              )}
            </p>
          )}
        </div>
      </section>

      <AuditDetailPanel
        key={selected?.id || 'none'}
        event={selected}
        filteredByRequest={Boolean(correlation)}
        onShowRequest={showRequest}
      />
    </div>
  );
}

function AuditDetailPanel({ event, filteredByRequest, onShowRequest }) {
  const [copied, setCopied] = useState(false);

  if (!event) {
    return (
      <aside className="panel inspector inv-insp au-rail" aria-label="Event detail">
        <div className="inv-empty">Select an event to see its details.</div>
      </aside>
    );
  }

  if (event.local) {
    return (
      <aside className="panel inspector inv-insp au-rail" aria-label="Event detail">
        <div className="inv-insp-head">
          <div>
            <span className="inv-insp-path">Session note</span>
            <h2 className="au-title">{event.summary}</h2>
          </div>
          <AuditOutcome event={event} />
        </div>
        <div className="us-note">
          <History size={14} />
          This browser added the note after an action in this session. It is not part of the audit log and disappears
          when the page reloads; the server records its own event for the action.
        </div>
      </aside>
    );
  }

  const metadata = event.metadata && Object.keys(event.metadata).length > 0 ? event.metadata : null;
  const copyCorrelation = () => {
    copyText(event.correlationId)
      .then(() => setCopied(true))
      .catch(() => setCopied(false));
  };

  return (
    <aside className="panel inspector inv-insp au-rail" aria-label="Event detail">
      <div className="inv-insp-head">
        <div>
          <span className="inv-insp-path">{event.eventType || 'event'}</span>
          <h2 className="au-title">{event.summary}</h2>
        </div>
        <AuditOutcome event={event} />
      </div>

      <div className="inv-facts">
        <div className="detail">
          <span>Time</span>
          <strong className="au-num">{formatAuditTimestamp(event.occurredAt) || '—'}</strong>
        </div>
        <div className="detail">
          <span>Category</span>
          <strong>{event.category.label}</strong>
        </div>
        <div className="detail">
          <span>Actor</span>
          <strong>{event.actorId || '—'}</strong>
        </div>
        <div className="detail">
          <span>Severity</span>
          <strong>{event.severity || '—'}</strong>
        </div>
        <div className="detail full">
          <span>Resource</span>
          <strong className="au-mono">{event.resource || '—'}</strong>
        </div>
        <div className="detail full">
          <span>Correlation ID</span>
          <strong className="au-mono">
            {event.correlationId || '—'}
            {event.correlationId && (
              <button type="button" className="au-copy" onClick={copyCorrelation}>
                <Copy size={12} />
                {copied ? 'Copied' : 'Copy'}
              </button>
            )}
          </strong>
        </div>
        {event.recordedSummary && (
          <div className="detail full">
            <span>Recorded as</span>
            <strong className="au-recorded">{event.recordedSummary}</strong>
          </div>
        )}
      </div>

      <div className="inv-section-title">Metadata</div>
      {metadata ? (
        <pre className="au-json">
          <code>{JSON.stringify(metadata, null, 2)}</code>
        </pre>
      ) : (
        <div className="au-none">No metadata recorded.</div>
      )}

      {event.correlationId && !filteredByRequest && (
        <button className="secondary-action au-btn au-related" type="button" onClick={() => onShowRequest(event.correlationId)}>
          <Link2 size={15} />
          Show every event in this request
        </button>
      )}
    </aside>
  );
}

// Severity dağılımını donut (SVG) olarak çizer. Renkler severity rampasıyla
// aynı: critical=kırmızı, high=turuncu, medium=amber, low=slate.
function SeverityDonut({ counts, total }) {
  const segments = [
    { key: 'critical', value: counts.critical || 0, color: '#dc2626' },
    { key: 'high', value: counts.high || 0, color: '#ea7317' },
    { key: 'medium', value: counts.medium || 0, color: '#d9a209' },
    { key: 'low', value: counts.low || 0, color: '#64748b' },
  ];
  const sum = total || segments.reduce((acc, seg) => acc + seg.value, 0) || 1;
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const arcs = [];
  for (const seg of segments) {
    if (seg.value > 0) {
      const len = (seg.value / sum) * circumference;
      arcs.push(
        <circle
          key={seg.key}
          r={radius}
          cx="70"
          cy="70"
          fill="none"
          stroke={seg.color}
          strokeWidth="18"
          strokeDasharray={`${len} ${circumference - len}`}
          strokeDashoffset={-offset}
          transform="rotate(-90 70 70)"
        />,
      );
      offset += len;
    }
  }
  return (
    <svg className="scan-donut" width="140" height="140" viewBox="0 0 140 140" role="img" aria-label="Severity distribution">
      <circle r={radius} cx="70" cy="70" fill="none" stroke="#eceef3" strokeWidth="18" />
      {arcs}
      <text x="70" y="64" textAnchor="middle" className="donut-num">{total}</text>
      <text x="70" y="84" textAnchor="middle" className="donut-lbl">findings</text>
    </svg>
  );
}

// Tıklanabilir severity legend: bir satıra tıkla → tabloyu o severity'e filtrele
// (aktifken tekrar tıkla → filtreyi kaldır).
function SeverityLegend({ counts, total, active, onPick }) {
  const rows = [
    { key: 'critical', label: 'Critical', value: counts.critical || 0 },
    { key: 'high', label: 'High', value: counts.high || 0 },
    { key: 'medium', label: 'Medium', value: counts.medium || 0 },
    { key: 'low', label: 'Low', value: counts.low || 0 },
  ];
  const denom = Math.max(1, total || 0);
  return (
    <div className="sev-legend">
      {rows.map((row) => (
        onPick ? (
          <button
            type="button"
            key={row.key}
            className={`sev-legend-row ${row.key}${active === row.key ? ' active' : ''}`}
            onClick={() => onPick(active === row.key ? 'all' : row.key)}
            aria-pressed={active === row.key}
          >
            <SeverityLegendCells row={row} denom={denom} />
          </button>
        ) : (
          <div key={row.key} className={`sev-legend-row static ${row.key}`}>
            <SeverityLegendCells row={row} denom={denom} />
          </div>
        )
      ))}
    </div>
  );
}

function SeverityLegendCells({ row, denom }) {
  return (
    <>
      <span className="dot" />
      <span className="lbl">{row.label}</span>
      <span className="bar">
        <i style={{ width: `${(row.value / denom) * 100}%` }} />
      </span>
      <strong>{row.value}</strong>
    </>
  );
}

// Sayfalama için sayfa numarası penceresi üretir: 1 … (n-1) n (n+1) … son.
function pageWindow(current, total, span = 1) {
  const pages = new Set([1, total, current]);
  for (let i = 1; i <= span; i += 1) {
    pages.add(current - i);
    pages.add(current + i);
  }
  const ordered = [...pages].filter((p) => p >= 1 && p <= total).sort((a, b) => a - b);
  const out = [];
  let prev = 0;
  for (const p of ordered) {
    if (p - prev > 1) out.push('…');
    out.push(p);
    prev = p;
  }
  return out;
}

// Sabit yükseklikli tablolar için sayfalama çubuğu (X–Y / Z + 1 2 3 …).
function PaginationBar({ page, totalPages, totalItems, pageSize, onPage }) {
  if (totalItems === 0) return null;
  const from = (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, totalItems);
  return (
    <div className="pagination">
      <span className="pagination-info">
        {from}–{to} / {totalItems}
      </span>
      <div className="pagination-controls">
        <button
          type="button"
          className="pagination-btn"
          onClick={() => onPage(page - 1)}
          disabled={page <= 1}
          aria-label="Previous page"
        >
          <ChevronLeft size={16} />
        </button>
        {pageWindow(page, totalPages).map((entry, index) =>
          entry === '…' ? (
            <span className="pagination-gap" key={`gap-${index}`}>
              …
            </span>
          ) : (
            <button
              type="button"
              key={entry}
              className={`pagination-btn ${entry === page ? 'is-active' : ''}`}
              onClick={() => onPage(entry)}
              aria-current={entry === page ? 'page' : undefined}
            >
              {entry}
            </button>
          ),
        )}
        <button
          type="button"
          className="pagination-btn"
          onClick={() => onPage(page + 1)}
          disabled={page >= totalPages}
          aria-label="Next page"
        >
          <ChevronRight size={16} />
        </button>
      </div>
    </div>
  );
}

function ScanResults({ reports, state, selectedId, onSelect, permitManageRemediation = false }) {
  const [findingsPage, setFindingsPage] = useState(1);
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [fixableOnly, setFixableOnly] = useState(false);
  const [sortBy, setSortBy] = useState('cvss');
  const findingsPageSize = 12;
  useEffect(() => {
    setFindingsPage(1);
  }, [selectedId, query, severityFilter, fixableOnly, sortBy]);
  if (reports.length === 0) {
    const emptyState = {
      'harbor-empty': {
        title: 'No artifacts to scan in the Harbor project yet',
        description: 'After the first image push, Harbor starts a Trivy scan automatically and the results appear here from live data.',
      },
      'harbor-scan-pending': {
        title: 'Waiting for the Harbor scan to finish',
        description: 'The artifact may already be stored; once the Trivy result is ready this screen shows the normalised findings automatically.',
      },
      'harbor-scan-error': {
        title: 'The Harbor scan result cannot be read right now',
        description: 'Check registry access and the scan result details. No fixture data is shown; the data-source badge above shows the current state.',
      },
    }[state.source] || {
      title: 'No scan results yet',
      description: 'Package-level CVE findings appear here once a new image has been scanned.',
    };

    return (
      <div className="view-grid">
        <section className="reports-toolbar">
          <div>
            <p className="eyebrow">Scan Results</p>
            <span className="reports-sub">Live Harbor / Trivy data</span>
          </div>
          <DataSourceBadge state={state} />
        </section>

        <section className="panel scan-empty-state">
          <div className="scan-empty-icon">
            <ScanLine size={28} />
          </div>
          <div>
            <h2>{emptyState.title}</h2>
            <p>{emptyState.description}</p>
            {state.error && <span className="scan-empty-detail">{state.error}</span>}
          </div>
        </section>
      </div>
    );
  }

  const report = reports.find((item) => item.id === selectedId) ?? reports[0];
  const allFindings = report.findings || [];
  const counts = allFindings.reduce((acc, finding) => {
    const key = lower(finding.severity);
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const maxCvss = allFindings.reduce((max, finding) => Math.max(max, finding.cvss), 0);
  const fixableCount = allFindings.filter((finding) => finding.status === 'Fix available').length;
  const criticalHigh = (counts.critical || 0) + (counts.high || 0);
  const hasEpss = allFindings.some((finding) => finding.epss != null);

  // Filtre + arama + sıralama tamamen client-side (mevcut veri üzerinde).
  const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };
  const normalizedQuery = query.trim().toLowerCase();
  const filteredFindings = allFindings.filter((finding) => {
    if (severityFilter !== 'all' && lower(finding.severity) !== severityFilter) return false;
    if (fixableOnly && finding.status !== 'Fix available') return false;
    if (
      normalizedQuery &&
      !lower(finding.cve).includes(normalizedQuery) &&
      !lower(finding.package).includes(normalizedQuery)
    ) {
      return false;
    }
    return true;
  });
  const findings = [...filteredFindings].sort((a, b) => {
    if (sortBy === 'severity') {
      return (
        (severityRank[lower(a.severity)] ?? 9) - (severityRank[lower(b.severity)] ?? 9) ||
        b.cvss - a.cvss
      );
    }
    if (sortBy === 'epss') {
      return (b.epss ?? -1) - (a.epss ?? -1) || b.cvss - a.cvss;
    }
    return b.cvss - a.cvss || (b.epss ?? -1) - (a.epss ?? -1);
  });

  const severityTabs = [
    { key: 'all', label: 'All', value: allFindings.length },
    { key: 'critical', label: 'Critical', value: counts.critical || 0 },
    { key: 'high', label: 'High', value: counts.high || 0 },
    { key: 'medium', label: 'Medium', value: counts.medium || 0 },
    { key: 'low', label: 'Low', value: counts.low || 0 },
  ];

  const findingsTotalPages = Math.max(1, Math.ceil(findings.length / findingsPageSize));
  const findingsCurrentPage = Math.min(Math.max(findingsPage, 1), findingsTotalPages);
  const findingsStart = (findingsCurrentPage - 1) * findingsPageSize;
  const pagedFindings = findings.slice(findingsStart, findingsStart + findingsPageSize);

  return (
    <div className="view-grid">
      <section className="reports-toolbar">
        <div>
          <p className="eyebrow">Scan Results</p>
          <span className="reports-sub">
            {report.scanner} · {report.scannedAt}
            {report.os ? ` · ${report.os}` : ''}
          </span>
        </div>
        <DataSourceBadge state={state} />
        <label className="select-row scan-select">
          <span>Scanned Image</span>
          <select value={report.id} onChange={(event) => onSelect(event.target.value)}>
            {reports.map((item) => (
              <option key={item.id} value={item.id}>
                {item.image || item.id}
              </option>
            ))}
          </select>
        </label>
      </section>

      <section className="panel scan-hero">
        <SeverityDonut counts={counts} total={allFindings.length} />
        <div className="scan-hero-body">
          <div className="triage-stats">
            <div className="triage-stat is-risk">
              <span>Critical + High</span>
              <strong>{criticalHigh}</strong>
            </div>
            <div className="triage-stat">
              <span>Max CVSS</span>
              <strong>{maxCvss.toFixed(1)}</strong>
            </div>
            <div className="triage-stat is-ok">
              <span>Fixable</span>
              <strong>
                {fixableCount}
                <i> / {allFindings.length}</i>
              </strong>
            </div>
          </div>
          <SeverityLegend counts={counts} total={allFindings.length} active={severityFilter} onPick={setSeverityFilter} />
          {!hasEpss && (
            <p className="scan-note">
              This scan has no EPSS data, so findings are sorted by CVSS.
            </p>
          )}
        </div>
      </section>

      <section className="panel">
        <PanelHeader icon={ScanLine} title="Vulnerability Findings" />
        <div className="scan-toolbar">
          <div className="search-box">
            <Search size={16} />
            <input
              aria-label="Search findings"
              value={query}
              placeholder="Search CVE or package…"
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          <div className="sev-filter" role="group" aria-label="Severity filter">
            {severityTabs.map((tab) => (
              <button
                key={tab.key}
                type="button"
                className={`sev-pill ${tab.key}${severityFilter === tab.key ? ' active' : ''}`}
                onClick={() => setSeverityFilter(tab.key)}
              >
                {tab.label}
                <em>{tab.value}</em>
              </button>
            ))}
          </div>
          <label className="toggle">
            <input type="checkbox" checked={fixableOnly} onChange={(event) => setFixableOnly(event.target.checked)} />
            <span>Fixable only</span>
          </label>
          <div className="scan-toolbar-spacer" />
          <label className="select-mini">
            <span>Sort</span>
            <select value={sortBy} onChange={(event) => setSortBy(event.target.value)}>
              <option value="cvss">CVSS ↓</option>
              <option value="severity">Severity</option>
              {hasEpss && <option value="epss">EPSS ↓</option>}
            </select>
          </label>
          <button className="secondary-action" type="button" onClick={() => exportFindings(findings, report)}>
            <Download size={16} />
            Export CSV
          </button>
        </div>

        <div className="scan-scroll">
          <div className={`scan-table${hasEpss ? '' : ' no-epss'}`}>
            <div className="scan-row scan-head">
              <span>CVE</span>
              <span>Package</span>
              <span>Installed → Fixed</span>
              <span>Severity</span>
              <span>CVSS</span>
              {hasEpss && <span>EPSS</span>}
              <span>Status</span>
            </div>
            {pagedFindings.length === 0 && <div className="scan-empty-row">No findings match the filter.</div>}
            {pagedFindings.map((finding) => (
              <div className="scan-row" key={`${finding.cve}-${finding.package}-${finding.installed}`}>
                <span>
                  <strong>{finding.cve}</strong>
                </span>
                <span>{finding.package}</span>
                <span className="scan-ver">
                  {finding.installed} → {finding.fixed}
                </span>
                <span>
                  <span className={`severity ${lower(finding.severity)}`}>{finding.severity}</span>
                </span>
                <span>
                  <span className={`cvss-pill ${cvssTone(finding.cvss)}`}>{finding.cvss.toFixed(1)}</span>
                </span>
                {hasEpss && (
                  <span>
                    {finding.epss == null ? (
                      <span className="cvss-pill low">N/A</span>
                    ) : (
                      <span className={`cvss-pill ${epssTone(finding.epss)}`}>{Math.round(finding.epss * 100)}%</span>
                    )}
                  </span>
                )}
                <Badge status={finding.status} />
              </div>
            ))}
          </div>
        </div>
        <PaginationBar
          page={findingsCurrentPage}
          totalPages={findingsTotalPages}
          totalItems={findings.length}
          pageSize={findingsPageSize}
          onPage={setFindingsPage}
        />
      </section>
      <ScanComparePanel
        reports={reports}
        base={report}
        inspectionPanel={(reference, side, { onSettled, inspectedAt, onAvailability }) => (
          <AzurePipelinePanel
            key={reference}
            recordKey={reference}
            load={() => getImagePipelineRuns(reference)}
            start={(payload) => startImagePipelineRun(reference, payload)}
            permitted={permitManageRemediation}
            permissionHint={REQUIRES_MANAGE}
            onRunsSettled={onSettled}
            onAvailability={onAvailability}
            title={`${side} image · ${inspectedAt ? `inspected ${formatReportTime(inspectedAt)}` : 'not inspected yet'}`}
            note={reference}
            className={`ado-compact${inspectedAt ? ' ado-done' : ''}`}
          />
        )}
      />
    </div>
  );
}

// Policy check'lerini ekranda mantıksal gruplara ayırır (yalnızca sunum; check id'leri
// publishPolicy.js'te sabittir). Bilinmeyen yeni bir id "Diğer" grubuna düşer.
const PUBLISH_CHECK_GROUPS = [
  { key: 'integrity', title: 'Integrity', ids: ['verified-remediation', 'immutable-output-digest', 'verification-evidence', 'full-image-rescan', 'image-config-preserved'] },
  { key: 'testing', title: 'Pre-release testing', ids: ['candidate-smoke-test', 'consumer-acceptance'] },
  { key: 'vulnerability', title: 'Vulnerability thresholds', ids: ['canonical-os-zero', 'critical-threshold', 'high-threshold'] },
  { key: 'governance', title: 'Governance', ids: ['target-boundary', 'approval-control-ready', 'image-not-withdrawn'] },
  { key: 'supply', title: 'Supply chain', ids: ['sbom-requirement', 'signature-requirement', 'provenance-requirement'] },
];
const PUBLISH_REQUIREMENT_KEYS = {
  'sbom-requirement': 'sbom',
  'signature-requirement': 'signature',
  'provenance-requirement': 'provenance',
  'consumer-acceptance': 'consumerAcceptance',
};
const PUBLISH_STATUS_LABELS = {
  Blocked: 'Blocked',
  ApprovalRequired: 'Approval required',
  Approved: 'Approved',
  Published: 'Published',
  Rejected: 'Rejected',
  Withdrawn: 'Withdrawn',
  Cancelled: 'Cancelled',
};
const PUBLISH_QUEUE_FILTERS = [
  { key: 'Blocked', label: 'Blocked' },
  { key: 'ApprovalRequired', label: 'Approval' },
  { key: 'Approved', label: 'Approved' },
  { key: 'Published', label: 'Published' },
  { key: 'Rejected', label: 'Rejected' },
  { key: 'Withdrawn', label: 'Withdrawn' },
  { key: 'Cancelled', label: 'Cancelled' },
];
const WITHDRAWAL_CATEGORY_LABELS = {
  functional: 'Functional defect',
  security: 'Security issue',
  compliance: 'Compliance',
  other: 'Other',
};
const DECISION_REASON_MIN_LENGTH = 10;

// Lifecycle of a request cancelled because its image was withdrawn: the steps it had
// reached stay done, the step it stopped at is blocked.
function cancelledLifecycle(previousStatus) {
  if (previousStatus === 'Approved') return ['done', 'done', 'blocked', 'pending'];
  if (previousStatus === 'ApprovalRequired') return ['done', 'blocked', 'pending', 'pending'];
  if (previousStatus === 'Blocked') return ['blocked', 'pending', 'pending', 'pending'];
  return undefined;
}

function shortDigest(value) {
  const digest = String(value || '');
  return digest.length > 24 ? `${digest.slice(0, 15)}…${digest.slice(-4)}` : digest || '-';
}

// One date format across the console: local time, YYYY-MM-DD HH:mm.
function shortTime(value) {
  return formatReportTime(value);
}

function Publish({
  jobs,
  requests,
  policy,
  state,
  selectedJobId,
  selectedRequestId,
  target,
  approvalReason,
  currentUser,
  onJobSelect,
  onRequestSelect,
  onTarget,
  onApprovalReason,
  onCreate,
  onApprove,
  decision = { reason: '', category: 'functional' },
  onDecision = () => {},
  onReject = () => {},
  onWithdraw = () => {},
  permitApprove = true,
  permitRequest = true,
  onDownloadHandoff,
  onRefresh,
}) {
  const [queueFilter, setQueueFilter] = useState('');
  // Reject / withdraw open an in-page confirmation (no browser dialogs).
  const [decisionMode, setDecisionMode] = useState('');
  const [queuePage, setQueuePage] = useState(1);
  const queuePageSize = 5;
  useEffect(() => {
    setQueuePage(1);
  }, [queueFilter]);

  const job = jobs.find((item) => item.id === selectedJobId) ?? jobs[0];
  const request = requests.find((item) => item.id === selectedRequestId) ?? requests[0];
  const counts = {
    Blocked: requests.filter((item) => item.status === 'Blocked').length,
    ApprovalRequired: requests.filter((item) => item.status === 'ApprovalRequired').length,
    Approved: requests.filter((item) => item.status === 'Approved').length,
    Published: requests.filter((item) => item.status === 'Published').length,
    Rejected: requests.filter((item) => item.status === 'Rejected').length,
    Withdrawn: requests.filter((item) => item.status === 'Withdrawn').length,
    Cancelled: requests.filter((item) => item.status === 'Cancelled').length,
  };
  // Requester and approver are always the signed-in user; the server takes both from the
  // trusted session identity and enforces the two-person rule.
  const actorId = String(currentUser?.subject || '').trim();
  const actorName = currentUser?.displayName || actorId || '—';
  const ownRequest = sameUser(actorId, request?.requestedBy);
  const separationBlocksApproval = Boolean(policy?.approval.requireSeparateApprover) && ownRequest;
  const canApprove =
    request?.status === 'ApprovalRequired' &&
    policy?.approval.configured &&
    Boolean(actorId) &&
    !separationBlocksApproval;
  const canExport = request?.status === 'Approved';
  const canDecide = Boolean(policy?.approval.configured) && Boolean(actorId) && permitApprove;
  // The image of a still-open request may have been withdrawn after the request was
  // evaluated; the server then refuses approval and handoff, so say it before anyone tries.
  const requestJob = request ? jobs.find((item) => item.id === request.jobId) : null;
  const imageWithdrawnLater =
    Boolean(requestJob?.publishWithdrawal) && ['ApprovalRequired', 'Approved', 'Published'].includes(request?.status);
  const closeDecision = () => {
    setDecisionMode('');
    onDecision({ reason: '', category: 'functional' });
  };
  const decisionReasonValid = decision.reason.trim().length >= DECISION_REASON_MIN_LENGTH;
  useEffect(() => {
    setDecisionMode('');
  }, [request?.id, request?.status]);

  const filteredRequests = queueFilter ? requests.filter((item) => item.status === queueFilter) : requests;
  const queueTotalPages = Math.max(1, Math.ceil(filteredRequests.length / queuePageSize));
  const queueCurrentPage = Math.min(Math.max(queuePage, 1), queueTotalPages);
  const queueStart = (queueCurrentPage - 1) * queuePageSize;
  const pagedRequests = filteredRequests.slice(queueStart, queueStart + queuePageSize);

  const checks = request?.decision?.checks || [];
  const passedChecks = checks.filter((item) => item.status === 'pass').length;
  const failedChecks = checks.length - passedChecks;
  const knownIds = new Set(PUBLISH_CHECK_GROUPS.flatMap((group) => group.ids));
  const otherChecks = checks.filter((item) => !knownIds.has(item.id));
  const checkGroups = [
    ...PUBLISH_CHECK_GROUPS.map((group) => ({
      ...group,
      items: group.ids.map((id) => checks.find((item) => item.id === id)).filter(Boolean),
    })),
    { key: 'other', title: 'Other', items: otherChecks },
  ].filter((group) => group.items.length > 0);
  const isNotEnforced = (check) => {
    const key = PUBLISH_REQUIREMENT_KEYS[check.id];
    return Boolean(key && policy?.requirements && policy.requirements[key] === false && check.status === 'pass');
  };

  const status = request?.status;
  const lifecycle = {
    Blocked: ['blocked', 'pending', 'pending', 'pending'],
    ApprovalRequired: ['done', 'active', 'pending', 'pending'],
    Approved: ['done', 'done', 'active', 'pending'],
    Published: ['done', 'done', 'done', 'current'],
    Rejected: ['done', 'blocked', 'pending', 'pending'],
    Withdrawn: ['done', 'done', 'done', 'blocked'],
  }[status] || cancelledLifecycle(request?.cancellation?.previousStatus) || ['pending', 'pending', 'pending', 'pending'];
  const lifecycleSteps = ['Evaluated', 'Approval', 'Handoff', status === 'Withdrawn' ? 'Withdrawn' : 'Published'].map((label, index) => ({
    label,
    state: lifecycle[index],
  }));
  const stepIcon = { done: '✓', current: '✓', active: '•', pending: '', blocked: '!' };

  const outcome = !request
    ? null
    : status === 'Withdrawn'
      ? {
          tone: 'fail',
          title: `Withdrawn — ${request.id}: do not use this image`,
          detail: `${WITHDRAWAL_CATEGORY_LABELS[request.withdrawal?.category] || 'Withdrawn'} · ${
            request.withdrawal?.withdrawnBy || 'unknown'
          } · ${shortTime(request.withdrawal?.withdrawnAt)} — ${request.withdrawal?.reason || ''}`,
        }
    : status === 'Cancelled'
      ? {
          tone: 'fail',
          title: `Cancelled — ${request.id}: the image was withdrawn before publish`,
          detail: `${PUBLISH_STATUS_LABELS[request.cancellation?.previousStatus] || 'Open'} when cancelled · ${
            request.cancellation?.cancelledBy || 'unknown'
          } · ${shortTime(request.cancellation?.cancelledAt)} — ${request.cancellation?.reason || ''}`,
        }
    : status === 'Rejected'
      ? {
          tone: 'fail',
          title: `Rejected — ${request.id}`,
          detail: `${request.rejection?.rejectedBy || 'unknown'} · ${shortTime(request.rejection?.rejectedAt)} — ${
            request.rejection?.reason || ''
          }`,
        }
    : status === 'Published'
      ? {
          tone: 'pass',
          title: `Digest-preserving publish verified — ${request.id}`,
          detail: request.publish?.receipt?.targetReference || request.target.tagReference,
        }
      : status === 'Blocked'
        ? {
            tone: 'fail',
            title: `Policy blocked — ${request.id}: ${failedChecks} check${failedChecks === 1 ? '' : 's'} failed`,
            detail: request.target.tagReference,
          }
        : status === 'ApprovalRequired'
          ? {
              tone: 'plan',
              title: `Awaiting approval — ${request.id} passed the policy checks`,
              detail: 'Approval is required from a trusted identity other than the requester.',
            }
          : status === 'Approved'
            ? {
                tone: 'plan',
                title: `Approved — worker handoff ready for ${request.id}`,
                detail: 'Only the isolated worker writes to the registry; the manifest contains no credentials.',
              }
            : { tone: 'plan', title: `${request.id} · ${status}`, detail: request.target.tagReference };

  return (
    <div className="view-grid">
      <section className="reports-toolbar">
        <div>
          <p className="eyebrow">Controlled publish</p>
          <span className="reports-sub">Policy decision, two-person approval and isolated worker handoff</span>
        </div>
        <div className="toolbar-actions">
          <DataSourceBadge state={state} />
          <button className="icon-button" type="button" title="Refresh publish queue" onClick={onRefresh}>
            <RefreshCw size={17} />
          </button>
        </div>
      </section>

      {state.error && <div className="inline-error">{state.error}</div>}

      {request && (
        <section className="panel rem-hero">
          <div className="rem-steps">
            {lifecycleSteps.map((step, index) => (
              <React.Fragment key={step.label}>
                <span className={`rem-step ${step.state}`}>
                  <span className="ic">{stepIcon[step.state]}</span>
                  {step.label}
                </span>
                {index < lifecycleSteps.length - 1 && <span className="rem-conn" />}
              </React.Fragment>
            ))}
          </div>
          <div className="rem-hero-stats">
            <div className="s">
              <span>Request</span>
              <strong>{request.id}</strong>
            </div>
            <div className={`s ${failedChecks > 0 ? 'bad' : ''}`}>
              <span>Checks</span>
              <strong>
                {passedChecks}/{checks.length}
              </strong>
            </div>
            <div
              className={`s ${status === 'Published' ? 'ok' : ['Blocked', 'Rejected', 'Withdrawn', 'Cancelled'].includes(status) ? 'bad' : ''}`}
            >
              <span>Status</span>
              <strong>{PUBLISH_STATUS_LABELS[status] || status}</strong>
            </div>
          </div>
        </section>
      )}

      {imageWithdrawnLater && (
        <section className="admission fail">
          <ShieldOff size={24} />
          <div>
            <strong>The image of {request.id} has been withdrawn</strong>
            <span>
              {requestJob.publishWithdrawal.withdrawnBy} · {shortTime(requestJob.publishWithdrawal.withdrawnAt)} —{' '}
              {String(requestJob.publishWithdrawal.reason || '').replace(/[.\s]+$/, '')}.{' '}
              {request.status === 'Published'
                ? 'This tag is still recorded as published; withdraw it to close it.'
                : request.status === 'ApprovalRequired'
                  ? 'It can no longer be approved or published; reject the request to close it.'
                  : 'It can no longer be published.'}
            </span>
          </div>
        </section>
      )}

      {outcome && !imageWithdrawnLater && (
        <section className={`admission ${outcome.tone}`}>
          {outcome.tone === 'pass' ? (
            <PackageCheck size={24} />
          ) : outcome.tone === 'fail' ? (
            <ShieldOff size={24} />
          ) : (
            <ShieldCheck size={24} />
          )}
          <div>
            <strong>{outcome.title}</strong>
            <span>{outcome.detail}</span>
          </div>
        </section>
      )}

      <div className="rem-rail-layout">
        <div className="main-col">
          {!request && (
            <section className="panel">
              <div className="empty-copy">
                No publish request yet. Use the form on the right to start a policy evaluation for a
                verified remediation result.
              </div>
            </section>
          )}

          {status === 'ApprovalRequired' && (
            <section className="panel">
              <PanelHeader icon={FileKey2} title="Approval" />
              <form className="pub-form" onSubmit={onApprove}>
                <div className="form-field">
                  <span>Approving as</span>
                  <strong className="pub-actor">{actorName}</strong>
                </div>
                <label className="form-field">
                  <span>Approval reason</span>
                  <input
                    value={approvalReason}
                    onChange={(event) => onApprovalReason(event.target.value)}
                    placeholder="At least 10 characters"
                  />
                </label>
                {!policy?.approval.configured && (
                  <span className="pub-note full">
                    Approval stays disabled until a trusted identity source is configured.
                  </span>
                )}
                {separationBlocksApproval && (
                  <span className="pub-note full">
                    You requested this publish. A different approver must approve it (two-person rule).
                  </span>
                )}
                <div className="pub-form-actions full">
                  <button
                    className="primary-action"
                    type="submit"
                    disabled={!canApprove || !permitApprove || state.approving || imageWithdrawnLater}
                  >
                    <FileKey2 size={17} />
                    {state.approving ? 'Approving…' : 'Approve'}
                  </button>
                </div>
              </form>
            </section>
          )}

          {status === 'ApprovalRequired' && (
            <PublishDecisionPanel
              kind="reject"
              open={decisionMode === 'reject'}
              onOpen={() => setDecisionMode('reject')}
              onCancel={closeDecision}
              actorName={actorName}
              decision={decision}
              onDecision={onDecision}
              onSubmit={onReject}
              canDecide={canDecide}
              reasonValid={decisionReasonValid}
              busy={state.deciding}
            />
          )}

          {status === 'Published' && (
            <PublishDecisionPanel
              kind="withdraw"
              open={decisionMode === 'withdraw'}
              onOpen={() => setDecisionMode('withdraw')}
              onCancel={closeDecision}
              actorName={actorName}
              decision={decision}
              onDecision={onDecision}
              onSubmit={onWithdraw}
              canDecide={canDecide}
              reasonValid={decisionReasonValid}
              busy={state.deciding}
              reference={request.publish?.receipt?.targetReference || request.target.tagReference}
              digest={request.source.digest}
            />
          )}

          {status === 'Approved' && (
            <section className="panel pub-handoff">
              <div>
                <strong>Worker handoff ready</strong>
                <span>The manifest contains no credentials; only the isolated worker writes to the registry.</span>
              </div>
              <button
                className="secondary-action"
                type="button"
                disabled={!canExport || state.exporting || imageWithdrawnLater}
                onClick={onDownloadHandoff}
              >
                <DownloadCloud size={17} />
                {state.exporting ? 'Preparing...' : 'Download worker handoff'}
              </button>
            </section>
          )}

          {request && ['Approved', 'Published'].includes(status) && !imageWithdrawnLater && (
            <AzurePipelinePanel
              recordKey={request.id}
              version={`${request.updatedAt}|${status}`}
              load={() => getRecordPipelineRuns('publish-requests', request.id)}
              start={(payload) => startRecordPipelineRun('publish-requests', request.id, payload)}
              permitted={permitApprove}
              permissionHint="Requires the publish:approve permission (approver role)."
              onStarted={() => onRefresh?.()}
              onRunsSettled={() => onRefresh?.()}
              note="SSI fills in every pipeline parameter from this approved request. Publishing and signing are started by an approver."
            />
          )}

          {request && checks.length > 0 && (
            <section className="panel">
              <div className="pub-checks-head">
                <PanelHeader icon={Filter} title="Policy checks" />
                <span className={`pub-pass${failedChecks > 0 ? ' fail' : ''}`}>
                  {passedChecks} / {checks.length} passed
                </span>
              </div>
              {(['Withdrawn', 'Rejected', 'Cancelled'].includes(status) || imageWithdrawnLater) && (
                <span className="pub-note pub-checks-note">
                  Checks as evaluated on {shortTime(request.decision?.evaluatedAt || request.createdAt)}; the decision
                  above came later.
                </span>
              )}
              <div className="pc-grid">
                {checkGroups.map((group) => {
                  const groupFailed = group.items.filter((item) => item.status !== 'pass').length;
                  return (
                    <div className={`pc-group${groupFailed ? ' has-fail' : ''}`} key={group.key}>
                      <div className="pc-gh">
                        <strong>{group.title}</strong>
                        <em className={groupFailed ? 'fail' : ''}>
                          {group.items.length - groupFailed}/{group.items.length}
                        </em>
                      </div>
                      {group.items.map((item) => {
                        const failed = item.status !== 'pass';
                        const muted = isNotEnforced(item);
                        return (
                          <div className={`pc-item${failed ? ' fail' : muted ? ' muted' : ''}`} key={item.id}>
                            <span className="pc-dot" />
                            <span>{item.label}</span>
                            {failed && <small>{item.detail}</small>}
                            {muted && <small>Not enforced</small>}
                          </div>
                        );
                      })}
                    </div>
                  );
                })}
              </div>
              <details className="rem-collapse flush">
                <summary>
                  <Filter size={14} />
                  Show check details
                  <em>{checks.length}</em>
                </summary>
                <div className="pub-check-details">
                  {checks.map((item) => (
                    <div className={`pub-check-detail ${item.status}`} key={item.id}>
                      {item.status === 'pass' ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
                      <div>
                        <strong>{item.label}</strong>
                        <span title={item.detail}>{item.detail}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </details>
            </section>
          )}
        </div>

        <aside className="rail">
          <section className="panel">
            <PanelHeader icon={UploadCloud} title="New publish request" />
            {jobs.length > 0 ? (
              <form className="pub-form compact" onSubmit={onCreate}>
                <label className="form-field">
                  <span>Verified remediation job</span>
                  <select value={job?.id || ''} onChange={(event) => onJobSelect(event.target.value)}>
                    {jobs.map((item) => (
                      <option value={item.id} key={item.id}>
                        {item.id} · {item.patchedImageTag}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="form-field">
                  <span>Target repository</span>
                  <input value={target.repository} onChange={(event) => onTarget('repository', event.target.value)} />
                  <small className="hint">
                    <Lock size={11} /> Boundary: {policy?.target.registry || '-'}/{policy?.target.project || '-'}/
                    {policy?.target.repositoryPrefix || ''}/
                  </small>
                </label>
                <label className="form-field">
                  <span>Immutable tag</span>
                  <input value={target.tag} onChange={(event) => onTarget('tag', event.target.value)} />
                </label>
                <div className="form-field">
                  <span>Requesting as</span>
                  <strong className="pub-actor">{actorName}</strong>
                </div>
                <div className="pub-form-actions">
                  <button
                    className="primary-action"
                    type="submit"
                    disabled={state.creating || !actorId || !permitRequest}
                  >
                    <Filter size={17} />
                    {state.creating ? 'Evaluating…' : 'Evaluate policy'}
                  </button>
                </div>
              </form>
            ) : (
              <div className="empty-copy">The publish gate needs a verified RM-EXEC remediation result.</div>
            )}
          </section>

          <section className="panel">
            <PanelHeader icon={Archive} title="Publish Queue" />
            <div className="pub-stat-chips">
              {PUBLISH_QUEUE_FILTERS.map((filter) => (
                <button
                  key={filter.key}
                  type="button"
                  className={`psc ${filter.key.toLowerCase()}${queueFilter === filter.key ? ' active' : ''}`}
                  aria-pressed={queueFilter === filter.key}
                  onClick={() => setQueueFilter(queueFilter === filter.key ? '' : filter.key)}
                >
                  <strong>{counts[filter.key]}</strong>
                  <span>{filter.label}</span>
                </button>
              ))}
            </div>
            <div className="pub-queue">
              {pagedRequests.map((item) => (
                <button
                  key={item.id}
                  className={`pub-qrow${request?.id === item.id ? ' selected' : ''}`}
                  type="button"
                  onClick={() => onRequestSelect(item.id)}
                >
                  <div className="q-main">
                    <strong>{item.id}</strong>
                    <span title={item.target.tagReference}>{item.target.tagReference}</span>
                  </div>
                  <div className="q-meta">
                    <Badge status={item.status} />
                  </div>
                </button>
              ))}
              {filteredRequests.length === 0 && (
                <div className="empty-copy">{queueFilter ? 'No requests match this filter.' : 'The publish queue is empty.'}</div>
              )}
            </div>
            <PaginationBar
              page={queueCurrentPage}
              totalPages={queueTotalPages}
              totalItems={filteredRequests.length}
              pageSize={queuePageSize}
              onPage={setQueuePage}
            />
          </section>

          {request && (
            <section className="panel">
              <PanelHeader icon={FileText} title="Request Detail" />
              <div className="pub-details">
                <Detail label="Request" value={request.id} />
                <Detail label="Requester" value={request.requestedBy || '-'} />
                <Detail label="Original image / source version" value={request.source.originalReference || '-'} />
                <Detail label="Policy" value={request.policyVersion || '-'} />
                {request.publish?.receipt?.latestReference && (
                  <>
                    <Detail label="Latest alias updated at publication" value={request.publish.receipt.latestReference} />
                    <Detail label="Published version" value={request.target.tag} />
                    <Detail label="Published digest" value={request.publish.receipt.latestDigest} />
                  </>
                )}
                <Detail label="Updated" value={shortTime(request.updatedAt)} />
                <div className="detail" title={request.source.digest}>
                  <span>Source digest</span>
                  <strong className="mono">{shortDigest(request.source.digest)}</strong>
                </div>
                <div className="detail" title={request.target.tagReference}>
                  <span>Target tag</span>
                  <strong>{request.target.tag || request.target.tagReference.split(':').pop()}</strong>
                </div>
              </div>
            </section>
          )}
        </aside>
      </div>
    </div>
  );
}

// Reject (a request waiting for approval) or withdraw (a published image). Both are final, so
// the action is confirmed inside the page with a mandatory reason.
function PublishDecisionPanel({
  kind,
  open,
  onOpen,
  onCancel,
  actorName,
  decision,
  onDecision,
  onSubmit,
  canDecide,
  reasonValid,
  busy,
  reference = '',
  digest = '',
}) {
  const withdraw = kind === 'withdraw';
  const title = withdraw ? 'Withdraw published image' : 'Reject request';
  const disabledReason = canDecide ? '' : 'Requires the publish:approve permission (approver or admin role).';

  if (!open) {
    return (
      <section className="panel pub-decision closed">
        <div>
          <strong>{withdraw ? 'Problem found after publish?' : 'Not going to approve this request?'}</strong>
          <span>
            {withdraw
              ? 'Withdraw the image so it is flagged everywhere and can never be published again.'
              : 'Reject it with a reason so it no longer waits in the approval queue.'}
          </span>
        </div>
        <button className="danger-action" type="button" onClick={onOpen} disabled={!canDecide} title={disabledReason || undefined}>
          {withdraw ? <ShieldOff size={17} /> : <X size={17} />}
          {withdraw ? 'Withdraw image…' : 'Reject request…'}
        </button>
      </section>
    );
  }

  return (
    <section className="panel pub-decision">
      <PanelHeader icon={withdraw ? ShieldOff : X} title={title} />
      <form className="pub-form" onSubmit={onSubmit}>
        {withdraw && (
          <div className="pub-decision-warning full">
            <AlertTriangle size={16} />
            <span>
              This withdraws <strong className="mono">{shortDigest(digest)}</strong> for good, including every other tag
              published with the same digest. The image stays in Harbor until it is removed there; tell its consumers
              to stop using <strong>{reference}</strong>.
            </span>
          </div>
        )}
        <div className="form-field">
          <span>{withdraw ? 'Withdrawing as' : 'Rejecting as'}</span>
          <strong className="pub-actor">{actorName}</strong>
        </div>
        {withdraw && (
          <label className="form-field">
            <span>Category</span>
            <select value={decision.category} onChange={(event) => onDecision({ ...decision, category: event.target.value })}>
              {WITHDRAWAL_CATEGORIES.map((category) => (
                <option value={category} key={category}>
                  {WITHDRAWAL_CATEGORY_LABELS[category] || category}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="form-field full">
          <span>Reason</span>
          <input
            value={decision.reason}
            maxLength={1000}
            onChange={(event) => onDecision({ ...decision, reason: event.target.value })}
            placeholder={
              withdraw
                ? 'What is wrong, where it was seen (at least 10 characters)'
                : 'Why this request is not approved (at least 10 characters)'
            }
          />
        </label>
        <div className="pub-form-actions full">
          <button className="secondary-action" type="button" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button className="danger-action" type="submit" disabled={!canDecide || !reasonValid || busy}>
            {withdraw ? <ShieldOff size={17} /> : <X size={17} />}
            {busy ? 'Saving…' : withdraw ? 'Confirm withdrawal' : 'Confirm rejection'}
          </button>
        </div>
      </form>
    </section>
  );
}

function BeforeAfter({ before, after }) {
  const rows = [
    { label: 'Critical', before: before.critical, after: after.critical, color: '#dc2626' },
    { label: 'High', before: before.high, after: after.high, color: '#ea7317' },
    { label: 'Medium', before: before.medium, after: after.medium, color: '#b4820a' },
    { label: 'Low', before: before.low, after: after.low, color: '#64748b' },
  ];
  return (
    <div className="ba-grid">
      {rows.map((row) => {
        const delta = row.before - row.after;
        return (
          <div className="ba-row" key={row.label}>
            <span className="ba-label" style={{ color: row.color }}>
              {row.label}
            </span>
            <span className="ba-before">{row.before}</span>
            <ArrowRight size={16} />
            <span className="ba-after">{row.after}</span>
            <span className="ba-delta">{delta > 0 ? `-${delta}` : '0'}</span>
          </div>
        );
      })}
    </div>
  );
}

const REQUIRES_PLAN = 'Requires the remediation:plan permission (operator role).';
const REQUIRES_MANAGE = 'Requires the remediation:manage permission (operator role).';

function DryRunPlanner({
  reports,
  jobs = [],
  scanState,
  state,
  selectedReportId,
  onReportSelect,
  onCreateDryRun,
  onOpenJob,
  onCancel,
  permitPlan = true,
}) {
  const hasReports = reports.length > 0;
  const selectedReport = reports.find((report) => report.id === selectedReportId) || reports[0] || null;
  // The create action plans selectedReportId: keep it in sync with what the card shows.
  useEffect(() => {
    if (selectedReport && selectedReport.id !== selectedReportId) onReportSelect(selectedReport.id);
  }, [selectedReport, selectedReportId, onReportSelect]);
  // Windows is not supported yet; the server refuses it too (fail-closed).
  const windowsSelected = Boolean(selectedReport) && isWindowsImage(selectedReport.os);
  const unavailableReason = scanState.error || 'A scan result is required first.';
  const reference = splitImageReference(selectedReport?.image || selectedReport?.id || '');
  const summary = summarizeScanReport(selectedReport);
  const existingJobs = remediationJobsForReport(jobs, selectedReport);
  const latestJob = existingJobs[0] || null;
  const latestFreshness = latestJob ? planFreshness(latestJob, selectedReport) : 'unknown';
  const digest = String(selectedReport?.digest || '');
  const createDisabled =
    !permitPlan || !selectedReport || state.creating || state.loading || scanState.loading || windowsSelected;

  return (
    <div className="view-grid">
      <section className="reports-toolbar">
        <div>
          <p className="eyebrow">Remediation Planning</p>
          <span className="reports-sub">OS package scope · patching runs in the isolated Copa worker pipeline</span>
        </div>
      </section>

      <section className="panel remediation-empty">
        <PanelHeader icon={Wrench} title="Create dry-run remediation plan" />
        <p>
          Choose the scanned image to remediate. The dry run only plans eligible OS package updates; it does not pull
          the image, run the Copa patch, push to the registry or re-scan.
        </p>

        {hasReports ? (
          <>
            <label className="select-row scan-select plan-source">
              <span>Source scan</span>
              <select value={selectedReport?.id || ''} onChange={(event) => onReportSelect(event.target.value)}>
                {reports.map((report) => (
                  <option key={report.id} value={report.id}>
                    {report.image || report.id}
                  </option>
                ))}
              </select>
            </label>

            {selectedReport && (
              <div className="plan-target" aria-label="Image to remediate">
                <div className="plan-target-head">
                  <span className="plan-target-label">Image to remediate</span>
                  <strong title={selectedReport.image || selectedReport.id}>
                    {reference.repo || selectedReport.image || selectedReport.id}
                    {reference.tag && <em>:{reference.tag}</em>}
                  </strong>
                  {reference.path && <small>{reference.path}</small>}
                </div>
                <div className="plan-target-facts">
                  <div>
                    <span>Digest</span>
                    <strong className="mono" title={digest || undefined}>
                      {digest ? `${digest.slice(0, 19)}…` : '-'}
                    </strong>
                  </div>
                  <div>
                    <span>Last scan</span>
                    {/* Harbor reports UTC; shown in local time like the job times below. */}
                    <strong>{formatReportTime(scanTime(selectedReport.scannedAt))}</strong>
                  </div>
                  <div>
                    <span>Scanner</span>
                    <strong>{selectedReport.scanner || '-'}</strong>
                  </div>
                  <div>
                    <span>Findings</span>
                    <strong>
                      {summary.total} · {summary.withFix} with a fixed version
                    </strong>
                  </div>
                </div>
                <div className="plan-target-sev">
                  {['critical', 'high', 'medium', 'low'].map((key) => (
                    <span key={key} className={`severity ${key}`}>
                      {summary.severity[key]} {key.charAt(0).toUpperCase() + key.slice(1)}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {latestJob && (
              <div className={`remediation-message plan-existing${latestFreshness === 'stale' ? ' warning' : ''}`}>
                <History size={18} />
                <span>
                  <strong>{latestJob.id}</strong> ({latestJob.status},{' '}
                  {formatReportTime(latestJob.verifiedAt || latestJob.createdAt)})
                  {latestFreshness === 'stale'
                    ? ' was created before the latest scan of this image. Create a new plan to include the current findings.'
                    : latestFreshness === 'current'
                      ? ' was created from the latest scan of this image. Open it to continue, or create a separate plan.'
                      : ' already covers this image. A new dry run creates a separate plan from the latest scan.'}
                  {existingJobs.length > 1 ? ` ${existingJobs.length} jobs cover this image in total.` : ''}
                </span>
                {onOpenJob && (
                  <button className="secondary-action" type="button" onClick={() => onOpenJob(latestJob.id)}>
                    Open {latestJob.id}
                  </button>
                )}
              </div>
            )}

            <div className="remediation-plan-controls">
              <button
                className="primary-action"
                type="button"
                onClick={onCreateDryRun}
                disabled={createDisabled}
                title={permitPlan ? undefined : REQUIRES_PLAN}
              >
                <Play size={17} />
                {state.creating ? 'Preparing plan…' : 'Create dry-run plan'}
              </button>
              {onCancel && (
                <button className="secondary-action" type="button" onClick={onCancel} disabled={state.creating}>
                  Cancel
                </button>
              )}
            </div>
          </>
        ) : (
          <div className="remediation-message warning">
            <AlertTriangle size={18} />
            <span>{unavailableReason}</span>
          </div>
        )}
        {windowsSelected && (
          <div className="remediation-message warning">
            <AlertTriangle size={18} />
            <span>{WINDOWS_NOT_SUPPORTED_MESSAGE}</span>
          </div>
        )}
        {state.error && hasReports && (
          <div className="remediation-message error">
            <ShieldOff size={18} />
            <span>{state.error}</span>
          </div>
        )}
      </section>
    </div>
  );
}

function Remediation({
  jobs,
  reports,
  publishRequests,
  scanState,
  state,
  readiness,
  selectedId,
  selectedReportId,
  onSelect,
  onReportSelect,
  onCreateDryRun,
  onAttachCanonicalReport,
  onAttachVerificationEvidence,
  onAttachSupplyChainEvidence,
  onAttachCandidateTest,
  onRecordConsumerDecision,
  onDownloadWorkerHandoff,
  onJobUpdated,
  onRunsSettled,
  planning = false,
  onStartPlanning,
  onCancelPlanning,
  onOpenJob,
  permitPlan = true,
  permitManage = true,
  permitAccept = true,
}) {
  const [remainingPage, setRemainingPage] = useState(1);
  const [plannedPage, setPlannedPage] = useState(1);
  // Azure DevOps automation answers for this job: the manual path becomes a fallback.
  const [adoEnabled, setAdoEnabled] = useState(false);
  const remainingPageSize = 12;
  const plannedPageSize = 12;
  useEffect(() => {
    setRemainingPage(1);
    setPlannedPage(1);
  }, [selectedId]);
  const job = jobs.find((item) => item.id === selectedId) ?? jobs[0];

  if (!job || planning) {
    return (
      <DryRunPlanner
        reports={reports}
        jobs={jobs}
        scanState={scanState}
        state={state}
        selectedReportId={selectedReportId}
        onReportSelect={onReportSelect}
        onCreateDryRun={onCreateDryRun}
        onOpenJob={onOpenJob}
        onCancel={job ? onCancelPlanning : undefined}
        permitPlan={permitPlan}
      />
    );
  }

  const isDryRun = job.mode === 'dry-run';
  const isVerified = job.lifecycleState === 'verified' || job.status === 'Verified';
  const hasExecutionFailure = job.status === 'Failed' || job.status === 'Blocked';
  const lifecycleLabel =
    {
      queued: 'Queued',
      running: 'Running',
      patched: 'Patched',
      rescanning: 'Re-scanning',
      verified: 'Verified',
      failed: 'Failed',
      blocked: 'Blocked',
    }[job.lifecycleState] || job.status;
  const plannedFindings = isDryRun ? job.plannedFixes || [] : job.fixed || [];
  const outstandingFindings = [
    ...(job.remaining || []),
    ...(isDryRun ? job.excluded || [] : []),
  ];
  const fixedCount = plannedFindings.length;
  const remainingCount = outstandingFindings.length;
  const remainingTotalPages = Math.max(1, Math.ceil(outstandingFindings.length / remainingPageSize));
  const remainingCurrentPage = Math.min(Math.max(remainingPage, 1), remainingTotalPages);
  const remainingStart = (remainingCurrentPage - 1) * remainingPageSize;
  const pagedOutstanding = outstandingFindings.slice(remainingStart, remainingStart + remainingPageSize);
  const plannedTotalPages = Math.max(1, Math.ceil(plannedFindings.length / plannedPageSize));
  const plannedCurrentPage = Math.min(Math.max(plannedPage, 1), plannedTotalPages);
  const plannedStart = (plannedCurrentPage - 1) * plannedPageSize;
  const pagedPlanned = plannedFindings.slice(plannedStart, plannedStart + plannedPageSize);
  const criticalHighCleared =
    job.after && job.before
      ? job.before.critical + job.before.high - (job.after.critical + job.after.high)
      : 'Pending';
  const withdrawal = job.publishWithdrawal || null;
  const admissionClass =
    isDryRun || !isVerified
      ? hasExecutionFailure
        ? 'admission fail'
        : 'admission plan'
      : withdrawal
        ? 'admission fail'
        : 'admission pass';
  const sourceTag = job.fromTag || job.image;
  // A Dry Run's output tag is decided when its patch starts; an execution carries the real one.
  const outputTag = isDryRun
    ? copaOutputReferenceOf(job)
    : job.patchedImageTag || job.proposedPatchedTag || job.toTag || '';
  const targetTag = outputTag || (isDryRun ? 'Assigned when the patch starts' : 'Pending');
  const jobTime = job.createdAt || job.startedAt || '-';
  const executionReadiness =
    readiness.data?.jobId === job.id ? readiness.data : job.executionReadiness || null;
  const readinessRequirements = executionReadiness?.requirements || [];
  const handoffRequirement = readinessRequirements.find((item) => item.id === 'credential-free-worker-handoff');
  const canDownloadWorkerHandoff = Boolean(job.canonicalReport && handoffRequirement?.met);
  const canAttachVerificationEvidence = Boolean(
    isDryRun && job.canonicalReport && plannedFindings.length > 0,
  );
  const fullImageComparison =
    job.fullImageComparison?.status === 'available' ? job.fullImageComparison : null;
  const publishGateView = derivePublishGateView({ job, publishRequests });
  const osBeforeCount = job.before
    ? Object.values(job.before).reduce((total, count) => total + Number(count || 0), 0)
    : null;
  const osAfterCount = job.after
    ? Object.values(job.after).reduce((total, count) => total + Number(count || 0), 0)
    : null;
  const readyReqCount = readinessRequirements.filter((item) => item.met).length;
  const totalReqCount = readinessRequirements.length || 1;
  // The job's own prerequisites, apart from whether SSI can start the worker itself.
  const jobPrerequisitesMet = readinessRequirements
    .filter((item) => item.id !== 'isolated-worker')
    .every((item) => item.met);
  const readinessState = executionReadiness?.dispatchAllowed
    ? { label: 'Ready to patch', tone: 'ok' }
    : jobPrerequisitesMet && !executionReadiness?.workerConfigured
      ? { label: 'Manual worker', tone: 'wait' }
      : { label: 'Not ready', tone: 'wait' };
  const hasWorkflowAction =
    isDryRun && (!job.canonicalReport || canDownloadWorkerHandoff || canAttachVerificationEvidence);
  const pipelineSteps = [
    { label: 'Plan', state: hasExecutionFailure ? 'blocked' : 'done' },
    { label: 'Copa patch', state: isVerified ? 'done' : 'pending' },
    { label: 'Re-scan', state: isVerified ? 'done' : 'pending' },
    { label: 'Verify', state: isVerified ? 'current' : 'pending' },
  ];

  return (
    <div className="view-grid">
      <section className="reports-toolbar remediation-toolbar">
        <div>
          <p className="eyebrow">Remediation & Verify</p>
          <span className="reports-sub">
            {job.engine}{job.engineVersion ? ` ${job.engineVersion}` : ''} · {isDryRun ? 'Dry Run' : lifecycleLabel}
          </span>
        </div>
        <div className="remediation-toolbar-actions">
          <label className="select-row scan-select">
            <span>Remediation Job</span>
            <select value={job.id} onChange={(event) => onSelect(event.target.value)}>
              {jobs.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.id} · {item.image}
                </option>
              ))}
            </select>
          </label>
          <button
            className="primary-action"
            type="button"
            onClick={() => onStartPlanning?.(job)}
            disabled={!permitPlan || scanState.loading || reports.length === 0}
            title={permitPlan ? 'Choose the scanned image to plan' : REQUIRES_PLAN}
          >
            <Play size={17} />
            New Dry Run
          </button>
        </div>
      </section>

      <section className="panel rem-hero">
        <div className="rem-steps">
          {pipelineSteps.map((step, index) => (
            <React.Fragment key={step.label}>
              <span className={`rem-step ${step.state}`}>
                <span className="ic">{step.state === 'blocked' ? '!' : step.state === 'pending' ? '' : '✓'}</span>
                {step.label}
              </span>
              {index < pipelineSteps.length - 1 && <span className="rem-conn" />}
            </React.Fragment>
          ))}
        </div>
        <div className="rem-hero-stats">
          <div className="s">
            <span>{isDryRun ? 'Planned' : 'Fixed'}</span>
            <strong>{fixedCount}</strong>
          </div>
          <div className="s">
            <span>Crit+High ↓</span>
            <strong>{criticalHighCleared}</strong>
          </div>
          <div className={`s ${isVerified ? 'ok' : hasExecutionFailure ? 'bad' : ''}`}>
            <span>Status</span>
            <strong>{job.status}</strong>
          </div>
        </div>
      </section>

      <section className={admissionClass}>
        {isDryRun ? (
          <ClipboardCheck size={24} />
        ) : isVerified && !withdrawal ? (
          <ShieldCheck size={24} />
        ) : (
          <ShieldOff size={24} />
        )}
        <div>
          <strong>
            {isDryRun
              ? job.status === 'Blocked'
                ? 'Dry run blocked — no applicable OS package updates'
                : `Dry run planned — ${fixedCount} OS package finding${fixedCount === 1 ? '' : 's'} can be fixed`
              : isVerified && withdrawal
                ? 'Withdrawn after publish — do not use this image'
              : isVerified
                ? `Verification passed — ${fixedCount} OS package finding${fixedCount === 1 ? '' : 's'} fixed`
                : hasExecutionFailure
                  ? 'Remediation execution failed'
                  : `Execution ${lifecycleLabel} — waiting for re-scan verification`}
          </strong>
          <span>
            {withdrawal
              ? `${WITHDRAWAL_CATEGORY_LABELS[withdrawal.category] || 'Withdrawn'} · ${withdrawal.withdrawnBy} · ${formatReportTime(
                  withdrawal.withdrawnAt,
                )} — ${withdrawal.reason}`
              : outputTag
                ? `${sourceTag} → ${outputTag}`
                : sourceTag}
          </span>
        </div>
      </section>

      {state.error && (
        <div className="remediation-message error">
          <ShieldOff size={18} />
          <span>{state.error}</span>
        </div>
      )}

      <div className="rem-rail-layout">
        <div className="main-col">
          {/* Before an approval: what the fix changed (vulnerabilities, packages, configuration, runtime). */}
          {isVerified && !isDryRun && <ImageComparisonPanel jobId={job.id} version={job.updatedAt} />}

          {isVerified && job.after && (
            <section className="panel">
              <PanelHeader icon={TrendingDown} title="Before → After (re-scan)" />
              <BeforeAfter before={job.before} after={job.after} />
            </section>
          )}

          {isVerified && (
            <section className="panel supply-chain-panel">
              <PanelHeader icon={FileKey2} title="Supply Chain Evidence (signature · SBOM · provenance)" />
              <div className="supply-chain-badges">
                <Check label="Signature (Cosign)" ok={Boolean(job.supplyChain?.signature)} />
                <Check label="SBOM (Syft · CycloneDX)" ok={Boolean(job.supplyChain?.sbom)} />
                <Check label="Provenance" ok={Boolean(job.supplyChain?.provenance)} />
              </div>
              {job.supplyChain?.details ? (
                <div className="detail-grid supply-chain-detail">
                  <Detail label="Signing key" value={job.supplyChain.details.signature?.keyId || '-'} />
                  <Detail
                    label="SBOM"
                    value={
                      job.supplyChain.details.sbom?.present
                        ? `${job.supplyChain.details.sbom.format} · ${job.supplyChain.details.sbom.componentCount} components`
                        : '-'
                    }
                  />
                  <Detail label="Verifier" value={job.supplyChain.verifier || '-'} />
                  <Detail label="Received via" value={evidenceIntakeLabel(job.supplyChain.intake)} />
                </div>
              ) : (
                <p className="supply-chain-empty">
                  No signature, SBOM or provenance evidence has been attached to this image yet.
                </p>
              )}
              {onAttachSupplyChainEvidence && (
                <label
                  className={state.attaching || !permitManage ? 'secondary-action file-upload-action disabled' : 'secondary-action file-upload-action'}
                  title={permitManage ? undefined : REQUIRES_MANAGE}
                >
                  <UploadCloud size={17} />
                  <span>{state.attaching ? 'Processing…' : 'Upload evidence'}</span>
                  <input
                    type="file"
                    accept="application/json,.json"
                    disabled={state.attaching || !permitManage}
                    onChange={(event) => {
                      const file = event.target.files?.[0];
                      if (file) {
                        onAttachSupplyChainEvidence(file);
                      }
                      event.target.value = '';
                    }}
                  />
                </label>
              )}
            </section>
          )}

          {isVerified && !isDryRun && (
            <CandidateTestPanel
              job={job}
              state={state}
              permitManage={permitManage}
              permitAccept={permitAccept}
              onAttachCandidateTest={onAttachCandidateTest}
              onRecordConsumerDecision={onRecordConsumerDecision}
            />
          )}

          <section className="panel">
            <PanelHeader icon={CheckCircle2} title={`${isDryRun ? 'Planned fixes' : 'Fixed CVEs'} (${fixedCount})`} />
            <div className="fix-list">
              {plannedFindings.length === 0 && (
                <div className="fix-empty">No OS package update could be planned for this scan.</div>
              )}
              {pagedPlanned.map((finding, index) => (
                <div className="fix-row" key={`${finding.cve}-${finding.package}-${index}`}>
                  <div>
                    <strong>{finding.cve}</strong>
                    <span className="fix-ver">
                      {finding.package}: {finding.from} → {finding.to}
                    </span>
                  </div>
                  <span className={`severity ${lower(finding.severity)}`}>{finding.severity}</span>
                </div>
              ))}
            </div>
            <PaginationBar
              page={plannedCurrentPage}
              totalPages={plannedTotalPages}
              totalItems={plannedFindings.length}
              pageSize={plannedPageSize}
              onPage={setPlannedPage}
            />
          </section>

          <section className="panel">
            <PanelHeader icon={AlertTriangle} title={`Remaining / excluded (${remainingCount})`} />
            <div className="fix-list">
              {outstandingFindings.length === 0 && (
                <div className="fix-empty">No findings are out of scope or without a fixed version.</div>
              )}
              {pagedOutstanding.map((finding, index) => (
                <div className="fix-row" key={`${finding.cve}-${finding.package}-${index}`}>
                  <div>
                    <strong>{finding.cve}</strong>
                    <span>{finding.reason}</span>
                  </div>
                  <span className={`severity ${lower(finding.severity)}`}>{finding.severity}</span>
                </div>
              ))}
            </div>
            <PaginationBar
              page={remainingCurrentPage}
              totalPages={remainingTotalPages}
              totalItems={outstandingFindings.length}
              pageSize={remainingPageSize}
              onPage={setRemainingPage}
            />
          </section>
        </div>

        <aside className="rail">
          {hasWorkflowAction && (
            <section className="panel rem-actions">
              <PanelHeader icon={Play} title="Workflow Actions" />
              <p className="act-note">
                {adoEnabled
                  ? 'Next: run the next step from the Azure DevOps card below. The manual path stays available as a fallback.'
                  : !job.canonicalReport
                    ? 'To continue, upload a canonical Trivy JSON that matches the immutable source digest.'
                    : 'Canonical Trivy JSON attached. Next: download the worker handoff or upload verification evidence.'}
              </p>
              <WorkflowFallback collapsed={adoEnabled}>
              <div className="act-btns">
                {!job.canonicalReport && (
                  <label
                    className={state.attaching || !permitManage ? 'primary-action file-upload-action disabled' : 'primary-action file-upload-action'}
                    title={permitManage ? undefined : REQUIRES_MANAGE}
                  >
                    <UploadCloud size={15} />
                    <span>{state.attaching ? 'Processing report…' : 'Upload canonical Trivy JSON'}</span>
                    <input
                      aria-label="Select canonical Trivy JSON report"
                      type="file"
                      accept="application/json,.json"
                      disabled={state.attaching || !permitManage}
                      onChange={(event) => {
                        const [file] = event.target.files || [];
                        if (file) {
                          onAttachCanonicalReport(file);
                        }
                        event.target.value = '';
                      }}
                    />
                  </label>
                )}
                {canDownloadWorkerHandoff && (
                  <button
                    className="secondary-action"
                    type="button"
                    onClick={onDownloadWorkerHandoff}
                    disabled={state.exportingHandoff}
                  >
                    <Download size={15} />
                    {state.exportingHandoff ? 'Preparing…' : 'Worker handoff JSON'}
                  </button>
                )}
                {canAttachVerificationEvidence && (
                  <label
                    className={state.attachingEvidence || !permitManage ? 'primary-action file-upload-action disabled' : 'primary-action file-upload-action'}
                    title={permitManage ? undefined : REQUIRES_MANAGE}
                  >
                    <UploadCloud size={15} />
                    <span>{state.attachingEvidence ? 'Verifying…' : 'Select verification evidence'}</span>
                    <input
                      aria-label="Select remediation verification evidence"
                      type="file"
                      accept="application/json,.json"
                      disabled={state.attachingEvidence || !permitManage}
                      onChange={(event) => {
                        const [file] = event.target.files || [];
                        if (file) {
                          onAttachVerificationEvidence(file);
                        }
                        event.target.value = '';
                      }}
                    />
                  </label>
                )}
              </div>
              </WorkflowFallback>
            </section>
          )}

          <PipelineRunsPanel
            key={job.id}
            job={job}
            permitManage={permitManage}
            onJobUpdated={onJobUpdated}
            onRunsSettled={onRunsSettled}
            onAvailability={setAdoEnabled}
          />

          {isDryRun && executionReadiness && (
            <section className="panel">
              <PanelHeader icon={Lock} title="Execution readiness" />
              <div className="rem-rdy-head">
                <div className={`rem-rdy-bar ${hasExecutionFailure ? 'bad' : ''}`}>
                  <i style={{ width: `${Math.round((readyReqCount / totalReqCount) * 100)}%` }} />
                </div>
                <strong>
                  {readyReqCount} / {totalReqCount} ready
                </strong>
                <span className={`rem-rdy-state ${readinessState.tone}`}>{readinessState.label}</span>
              </div>
              <details className="rem-collapse flush">
                <summary>
                  <Filter size={14} />
                  Show requirements
                  <em>{totalReqCount}</em>
                </summary>
                <div className="rem-rdy-list">
                  {readinessRequirements.map((requirement) => (
                    <div
                      className={`rem-rq ${requirement.met ? 'ok' : 'wait'}`}
                      key={requirement.id}
                      title={requirement.detail}
                    >
                      {requirement.met ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
                      <span>{requirement.label}</span>
                      <em>{requirement.met ? 'Ready' : 'Waiting'}</em>
                    </div>
                  ))}
                </div>
              </details>
            </section>
          )}

          {isVerified && (
            <section className="panel">
              <div className="verification-comparison-head">
                <PanelHeader icon={ShieldCheck} title="Verified Result" />
                <span className={`verification-gate gate-${publishGateView.tone}`}>{publishGateView.label}</span>
              </div>
              <div className="rem-rail-sum">
                <div className="rem-rs-row">
                  <span>Canonical OS scope</span>
                  <strong className="ok">
                    {osBeforeCount ?? '-'} → {osAfterCount ?? '-'}
                  </strong>
                </div>
                <div className="rem-rs-row">
                  <span>Full image scan</span>
                  <strong>
                    {fullImageComparison
                      ? `${fullImageComparison.source.findings} → ${fullImageComparison.output.findings}`
                      : '—'}
                  </strong>
                </div>
                <div className="rem-rs-row">
                  <span>Outside OS scope</span>
                  <strong>{fullImageComparison?.remainingOutsideCanonicalOsScope ?? '-'}</strong>
                </div>
                <div className="rem-rs-row">
                  <span>Patched digest</span>
                  <strong className="mono ct-digest-cell">
                    <span title={job.patchedImageDigest || ''}>
                      {job.patchedImageDigest ? `${job.patchedImageDigest.slice(0, 16)}…` : '-'}
                    </span>
                    {job.patchedImageDigest && <CopyButton value={job.patchedImageDigest} label="patched digest" />}
                  </strong>
                </div>
              </div>
              <p className={`publish-gate-note gate-${publishGateView.tone}`}>{publishGateView.reason}</p>
            </section>
          )}

          <section className="panel">
            <PanelHeader icon={Archive} title="Job Detail" />
            <div className="detail-grid">
              <Detail label="Image" value={job.image} />
              <Detail label={isDryRun ? 'Patch output' : 'Output tag'} value={targetTag} />
              <Detail label="Engine" value={`${job.engine}${job.engineVersion ? ` ${job.engineVersion}` : ''}`} />
              <Detail label="Scope" value={job.scope || 'OS packages'} />
              <Detail label="Created" value={jobTime} />
              <Detail label="Verification" value={job.verificationStatus || job.verifiedAt || 'Pending'} />
              {job.parentJobId && <Detail label="Planned job" value={job.parentJobId} />}
              {job.canonicalReport?.trivyVersion && <Detail label="Trivy" value={job.canonicalReport.trivyVersion} />}
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
}

// The registry an image reference points at (docker.io when it names none), or '—'.
function sourceRegistryOf(reference) {
  try {
    return parseImageReference(reference).registry || '—';
  } catch {
    return '—';
  }
}

function Onboard({
  form,
  jobs,
  state = {},
  permitCreate = true,
  onField,
  onSubmit,
  onCancel = async () => {},
  onRefresh,
}) {
  // The open request whose Azure DevOps import pipeline is shown (one at a time).
  const [pipelineFor, setPipelineFor] = useState('');
  const pipelineRequest = jobs.find((item) => item.id === pipelineFor) || null;
  const listRef = useRef(null);
  const queueRef = useRef(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(6);
  // One request at a time is being cancelled, inside its own queue row (no browser dialogs).
  const [cancelling, setCancelling] = useState(null);
  const cancelReason = cancelling?.reason.trim() || '';
  const cancelReasonValid =
    cancelReason.length >= CANCELLATION_REASON_LENGTH.min && cancelReason.length <= CANCELLATION_REASON_LENGTH.max;
  const submitCancel = async (event) => {
    event.preventDefault();
    if (!cancelling || !cancelReasonValid || cancelling.busy) return;
    setCancelling({ ...cancelling, busy: true, error: '' });
    try {
      await onCancel(cancelling.id, cancelReason);
      setCancelling(null);
    } catch (error) {
      setCancelling((current) =>
        current && { ...current, busy: false, error: error.message || 'The request could not be cancelled.' },
      );
    }
  };

  // Kuyruk panelini, gerçek konumundan ölçerek viewport'un dibine (sidebar ile hizalı)
  // oturt; kalan yüksekliğe sığacak kadar satır göster, fazlasını sayfala (< >). Panel
  // konumu ve satır yüksekliği runtime'da ölçülür → her ekran/zoom'da kendini ayarlar,
  // sabit offset yok, satır boyutuyla oynamaya gerek kalmaz.
  useEffect(() => {
    const list = listRef.current;
    const panel = queueRef.current;
    if (!list || !panel) return undefined;
    const GAP = 10;
    // Sidebar padding = 22px → Production Gate panelinin alt kenarı innerHeight-22'de.
    // Kuyruk panelini de aynı hizaya oturtmak için dipten 22px bırak.
    const BOTTOM_MARGIN = 22;
    const recompute = () => {
      const top = panel.getBoundingClientRect().top;
      const height = Math.max(220, window.innerHeight - top - BOTTOM_MARGIN);
      panel.style.height = `${height}px`;
      const row = list.querySelector('.ingest-row');
      const rowH = row ? row.getBoundingClientRect().height : 66;
      const fit = Math.floor((list.clientHeight + GAP) / (rowH + GAP));
      setPageSize(Math.max(1, fit));
    };
    recompute();
    window.addEventListener('resize', recompute);
    return () => window.removeEventListener('resize', recompute);
  }, [jobs.length]);

  const totalPages = Math.max(1, Math.ceil(jobs.length / pageSize));
  const currentPage = Math.min(Math.max(page, 1), totalPages);
  useEffect(() => {
    if (page !== currentPage) setPage(currentPage);
  }, [page, currentPage]);
  const pageJobs = jobs.slice((currentPage - 1) * pageSize, (currentPage - 1) * pageSize + pageSize);

  return (
    <div className="onboard-layout">
      <section className="panel">
        <PanelHeader icon={DownloadCloud} title="Image Ingest" />
        <form className="ingest-bar" onSubmit={onSubmit}>
          <label className="f-image">
            <span>Image Reference</span>
            <input
              value={form.image}
              placeholder="registry/namespace/image:tag"
              onChange={(event) => onField('image', event.target.value)}
            />
          </label>
          {/* Read from the reference and fixed by the import worker: shown, not chosen. The
              server accepts only approved source registries (ONBOARD_ALLOWED_REGISTRIES). */}
          <div className="f-sel f-readonly">
            <span>Source Registry</span>
            <strong title="Taken from the image reference">{sourceRegistryOf(form.image)}</strong>
          </div>
          <div className="f-sel f-readonly">
            <span>Scanner</span>
            <strong title="Every onboarded image is scanned with Trivy in Harbor">Trivy</strong>
          </div>
          <button className="primary-action" type="submit" disabled={state.creating || !permitCreate}>
            <DownloadCloud size={18} />
            {state.creating ? 'Requesting…' : 'Request Import'}
          </button>
        </form>
        {!permitCreate && (
          <p role="status">Import requires the Operator role (onboarding:create). Ask an administrator to update your role in Users.</p>
        )}
        <p>Scanning checks the existing image; it does not upgrade its version. To upgrade, import the desired source version, then scan, patch and test it.</p>
        {state.error && <div className="ingest-error">{state.error}</div>}
      </section>

      {pipelineRequest && (
        <AzurePipelinePanel
          recordKey={pipelineRequest.id}
          version={`${pipelineRequest.updatedAt || ''}|${pipelineRequest.status}`}
          load={() => getRecordPipelineRuns('onboarding', pipelineRequest.id)}
          start={(payload) => startRecordPipelineRun('onboarding', pipelineRequest.id, payload)}
          permitted={permitCreate}
          permissionHint="Requires the onboarding:create permission (operator role)."
          onStarted={() => onRefresh?.()}
          onRunsSettled={() => onRefresh?.()}
          title={`Azure DevOps · ${pipelineRequest.id}`}
          note={`${pipelineRequest.source?.reference || pipelineRequest.id} → ${pipelineRequest.target?.tagReference || 'quarantine'}`}
          className="onboard-ado"
          showWhenDisabled
        />
      )}

      <section className="panel queue-panel" ref={queueRef}>
        <div className="onboard-queue-head">
          <PanelHeader icon={History} title="Onboarding Queue" />
          <DataSourceBadge state={state} />
        </div>
        <div className="ingest-list" ref={listRef}>
          {jobs.length === 0 && <div className="fix-empty">No onboarding requests yet.</div>}
          {pageJobs.map((job) => {
            const reference = job.source?.reference || job.image || job.id;
            const sourceRegistry = job.source?.registry || (typeof job.source === 'string' ? job.source : '');
            const target = job.target?.tagReference || '';
            // Same local "YYYY-MM-DD HH:mm" as the other screens; the exact time stays in the tooltip.
            const when = job.createdAt ? formatReportTime(job.createdAt) : job.at || '';
            if (cancelling?.id === job.id) {
              return (
                <form className="ingest-row ingest-cancel" key={job.id} onSubmit={submitCancel}>
                  <label>
                    <span className={cancelling.error ? 'error' : ''} role={cancelling.error ? 'alert' : undefined}>
                      {cancelling.error || `Cancel ${job.id} · ${reference} — reason (at least ${CANCELLATION_REASON_LENGTH.min} characters)`}
                    </span>
                    <input
                      autoFocus
                      value={cancelling.reason}
                      maxLength={CANCELLATION_REASON_LENGTH.max}
                      placeholder="Why no worker will finish this request"
                      aria-label={`Reason for cancelling ${job.id}`}
                      onChange={(event) => setCancelling({ ...cancelling, reason: event.target.value, error: '' })}
                    />
                  </label>
                  <div className="ingest-cancel-actions">
                    <button className="secondary-action" type="button" onClick={() => setCancelling(null)} disabled={cancelling.busy}>
                      Keep
                    </button>
                    <button className="danger-action" type="submit" disabled={!cancelReasonValid || cancelling.busy}>
                      <X size={16} />
                      {cancelling.busy ? 'Cancelling…' : 'Cancel request'}
                    </button>
                  </div>
                </form>
              );
            }
            const cancellable = permitCreate && OPEN_ONBOARDING_STATES.includes(job.status);
            const lateImport = job.status === 'Cancelled' ? job.importAfterCancellation : null;
            const detail =
              job.status === 'Cancelled' && job.cancellation
                ? ` · cancelled by ${job.cancellation.cancelledBy} — ${job.cancellation.reason}`
                : `${sourceRegistry ? ` · ${sourceRegistry}` : ''}${target ? ` → ${target}` : ''}`;
            return (
              <div className="ingest-row" key={job.id}>
                <div>
                  <strong>{reference}</strong>
                  <span title={`${job.id}${detail}`}>
                    {job.id}
                    {detail}
                  </span>
                  <OnboardingProgress request={job} />
                </div>
                <div className="ingest-meta">
                  <span className="ingest-badges">
                    {lateImport && (
                      <span
                        className="badge late-import"
                        title={
                          lateImport.status === 'imported'
                            ? `The worker imported ${lateImport.importedDigest} to ${lateImport.targetReference} after the cancellation. It is in quarantine; remove it in Harbor if it is not needed.`
                            : 'The worker reported a failed import after the cancellation.'
                        }
                      >
                        {lateImport.status === 'imported' ? 'Imported after cancel' : 'Failed after cancel'}
                      </span>
                    )}
                    <Badge status={job.status} />
                    {OPEN_ONBOARDING_STATES.includes(job.status) && (
                      <button
                        className="ingest-cancel-btn ingest-run-btn"
                        type="button"
                        aria-pressed={pipelineFor === job.id}
                        title={`Import ${job.id} with Azure DevOps`}
                        onClick={() => setPipelineFor((current) => (current === job.id ? '' : job.id))}
                      >
                        {pipelineFor === job.id ? 'Hide import' : 'Import…'}
                      </button>
                    )}
                    {cancellable && (
                      <button
                        className="ingest-cancel-btn"
                        type="button"
                        title={`Cancel ${job.id}`}
                        onClick={() => setCancelling({ id: job.id, reason: '', busy: false, error: '' })}
                      >
                        Cancel…
                      </button>
                    )}
                  </span>
                  <span className="ingest-time" title={job.createdAt || undefined}>
                    {when}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
        <PaginationBar
          page={currentPage}
          totalPages={totalPages}
          totalItems={jobs.length}
          pageSize={pageSize}
          onPage={setPage}
        />
      </section>
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, tone, alert }) {
  return (
    <div className={`metric-card ${tone}${alert ? ' is-alert' : ''}`}>
      <Icon size={22} />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

const PIPELINE_RUN_POLL_MS = 15000;
const PIPELINE_RUN_HINTS = {
  'canonical-scan':
    'Produces canonical-trivy.json for this source digest and sends it back to this job. Upload it above only if it does not arrive.',
  'copa-prepare': 'Checks the canonical input only. Nothing is patched or pushed.',
  'copa-execute': 'Patches the image, pushes a new copa-poc test tag to Harbor and re-scans it. Evidence comes back to SSI.',
  'candidate-test': 'Tests the candidate side by side with the source image. The result comes back to SSI.',
  'onboard-check': 'Reads the work order and checks the source image. Nothing is imported.',
  'onboard-import': 'Imports the image by digest into the team quarantine folder and reports back to SSI.',
  'publish-check': 'Reads the approved handoff and checks the target. Nothing is written to approved/.',
  'publish-execute': 'Copies the approved digest to its approved/ target and reports back to SSI.',
  'supply-chain-sign': 'Signs the published digest with Cosign and attaches the SBOM and provenance. Evidence comes back to SSI.',
  'image-inspection': 'Reads the image (packages, layers, size, runtime configuration) for the comparison. Nothing is written.',
  'os-template-build':
    'Builds the template ISO offline on the Windows build machine (about 4.5 hours): scan, update, re-scan, ISO. The signed result comes back to SSI.',
  'os-template-build-ubuntu':
    'Builds the Ubuntu 24.04 template offline on LinuxPool (about 15 minutes): scan, upgrade, re-scan, seal, QCOW2 + OVA + VHDX. The signed result comes back to SSI.',
};

// Steps that write to a registry ask once more, in the page (no browser dialogs).
const PIPELINE_RUN_CONFIRM = {
  'copa-execute': ['This pushes a new copa-poc test tag to Harbor. Start the patch?', 'Yes, start the patch'],
  'onboard-import': ['This imports the image into the quarantine folder in Harbor. Start the import?', 'Yes, import'],
  'publish-execute': ['This writes the approved digest to its approved/ target in Harbor. Publish now?', 'Yes, publish'],
  'supply-chain-sign': ['This signs the published image and attaches SBOM and provenance in Harbor. Sign now?', 'Yes, sign'],
  'os-template-build': [
    'This occupies the Windows build machine for about 4.5 hours and writes a new template ISO there. Start the build?',
    'Yes, build',
  ],
  'os-template-build-ubuntu': [
    'This occupies a LinuxPool agent for about 15 minutes and publishes the template disk images as a run artifact. Start the build?',
    'Yes, build',
  ],
};

const PIPELINE_RUN_LABELS = {
  'canonical-scan': 'Canonical Trivy scan',
  'copa-prepare': 'Copa input check',
  'copa-execute': 'Copa patch + re-scan',
  'candidate-test': 'Candidate test',
  'onboard-check': 'Import check',
  'onboard-import': 'Import into quarantine',
  'publish-check': 'Publish check',
  'publish-execute': 'Publish to approved/',
  'supply-chain-sign': 'Sign + SBOM + provenance',
  'image-inspection': 'Image inspection',
  'os-template-build': 'Build the template ISO',
  'os-template-build-ubuntu': 'Build the Ubuntu template',
};

function pipelineRunTone(run) {
  if (run.state !== 'completed') return 'wait';
  return run.result === 'succeeded' ? 'ok' : 'bad';
}

function pipelineRunStatus(run) {
  if (run.state === 'inProgress') return 'Running';
  if (run.state === 'canceling') return 'Canceling';
  if (run.state !== 'completed') return 'Unknown';
  return { succeeded: 'Succeeded', failed: 'Failed', canceled: 'Canceled' }[run.result] || 'Completed';
}

// Starts the worker pipelines of one record in Azure DevOps and follows their runs. Hidden when
// the automation is not configured, so the screen is unchanged without it.
//   recordKey   what the panel is about (a job, request or image); a change starts over
//   version     changes when the record was saved, so the actions are asked again
//   load()      → { data: { enabled, actions, runs }, error }
//   start(body) → the started run's response; onStarted(response) lets the screen update
function AzurePipelinePanel({
  recordKey,
  version = '',
  load,
  start: startRun,
  permitted,
  permissionHint,
  onStarted,
  onRunsSettled,
  note = 'SSI fills in every pipeline parameter from this record. Approval gates stay where they are.',
  className = '',
  title = 'Azure DevOps',
  showWhenDisabled = false,
  onAvailability,
}) {
  const [data, setData] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [reload, setReload] = useState(0);
  const [busy, setBusy] = useState('');
  const [confirming, setConfirming] = useState('');
  const [buildId, setBuildId] = useState('');
  const [error, setError] = useState('');
  const activeRuns = useRef(null);

  useEffect(() => {
    activeRuns.current = null;
    setConfirming('');
    setError('');
  }, [recordKey]);

  useEffect(() => {
    let cancelled = false;
    load().then((result) => {
      if (cancelled) return;
      setData(result.data);
      setLoadError(result.error);
      onAvailability?.(Boolean(result.data.enabled));
      const active = result.data.runs.filter((run) => run.state !== 'completed').length;
      if (activeRuns.current !== null && active < activeRuns.current) onRunsSettled?.();
      activeRuns.current = active;
    });
    return () => {
      cancelled = true;
    };
    // `load` and `onRunsSettled` are fresh functions on every render of the parent; the record,
    // its saved version and the reload counter decide when to ask again.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recordKey, version, reload]);

  const hasActiveRun = Boolean(data?.runs.some((run) => run.state !== 'completed'));
  useEffect(() => {
    if (!hasActiveRun) return undefined;
    const timer = setTimeout(() => setReload((value) => value + 1), PIPELINE_RUN_POLL_MS);
    return () => clearTimeout(timer);
  }, [hasActiveRun, reload]);

  if (!data?.enabled) {
    if (!showWhenDisabled || !data) return null;
    return (
      <section className={`panel rem-actions ado-runs ${className}`.trim()}>
        <PanelHeader icon={Workflow} title={title} />
        <p className="act-note">{loadError || 'Azure DevOps automation is not configured; run the pipeline in Azure DevOps.'}</p>
      </section>
    );
  }

  async function start(action) {
    setBusy(action);
    setError('');
    try {
      const payload = { action };
      if (action === 'copa-prepare' && buildId.trim()) payload.canonicalBuildId = buildId.trim();
      const result = await startRun(payload);
      onStarted?.(result);
      setConfirming('');
      setBuildId('');
      setReload((value) => value + 1);
    } catch (startError) {
      setError(startError.message || 'The pipeline could not be started.');
    } finally {
      setBusy('');
    }
  }

  return (
    <section className={`panel rem-actions ado-runs ${className}`.trim()}>
      <PanelHeader icon={Workflow} title={title} />
      <p className="act-note">{note}</p>
      <div className="ado-actions">
        {data.actions.map((item) => {
          const disabled = !permitted || !item.available || Boolean(busy);
          const hint = !permitted ? permissionHint : item.reason || undefined;
          const confirmText = PIPELINE_RUN_CONFIRM[item.action];
          return (
            <div className="ado-action" key={item.action}>
              <div className="ado-action-head">
                <strong>{item.label}</strong>
                <span>{PIPELINE_RUN_HINTS[item.action]}</span>
                {!item.available && <em>{item.reason}</em>}
              </div>
              {item.action === 'copa-prepare' && item.available && item.needsBuildId && (
                <label className="ado-build-id">
                  <span>Canonical scan Build ID</span>
                  <input
                    inputMode="numeric"
                    placeholder="e.g. 774757"
                    value={buildId}
                    maxLength={10}
                    onChange={(event) => setBuildId(event.target.value.replace(/\D/g, ''))}
                    disabled={!permitted}
                  />
                </label>
              )}
              {confirmText && confirming === item.action ? (
                <div className="ado-confirm" role="group" aria-label={`Confirm ${item.label}`}>
                  <span>{confirmText[0]}</span>
                  <div>
                    <button className="primary-action" type="button" disabled={disabled} onClick={() => start(item.action)}>
                      {busy === item.action ? 'Starting…' : confirmText[1]}
                    </button>
                    <button className="secondary-action" type="button" disabled={Boolean(busy)} onClick={() => setConfirming('')}>
                      Back
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  className={confirmText ? 'primary-action' : 'secondary-action'}
                  type="button"
                  disabled={disabled || (item.needsBuildId && !buildId)}
                  title={item.needsBuildId && !buildId ? 'Enter the Build ID of the canonical scan run' : hint}
                  onClick={() => (confirmText ? setConfirming(item.action) : start(item.action))}
                >
                  <Play size={15} />
                  {busy === item.action ? 'Starting…' : 'Run in Azure DevOps'}
                </button>
              )}
            </div>
          );
        })}
      </div>
      {error && <p className="ado-error">{error}</p>}
      {loadError && <p className="ado-error">{loadError}</p>}
      {data.runs.length > 0 && (
        <div className="ado-runs-list">
          <div className="inv-section-title">Runs</div>
          {data.runs.slice(0, 6).map((run) => (
            <div className="ado-run" key={run.runId}>
              <span className={`ct-stage ct-${pipelineRunTone(run)}`}>{pipelineRunStatus(run)}</span>
              <div>
                <strong>{PIPELINE_RUN_LABELS[run.action] || run.action}</strong>
                <span>
                  #{run.runName || run.runId} · {run.requestedBy} · {formatReportTime(run.requestedAt)}
                </span>
                {run.refreshError && <span className="ado-stale">{run.refreshError}</span>}
                {run.webUrl && (
                  <a className="ado-open" href={run.webUrl} target="_blank" rel="noopener noreferrer">
                    Open in Azure DevOps
                    <ExternalLink size={12} />
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

// The manual upload/download buttons of a job; folded away as "Manual fallback" while Azure
// DevOps automation runs the workers.
function WorkflowFallback({ collapsed, children }) {
  if (!collapsed) return children;
  return (
    <details className="rem-collapse flush act-fallback">
      <summary>
        <Filter size={14} />
        Manual fallback
      </summary>
      {children}
    </details>
  );
}

// The remediation job's worker pipelines (canonical scan, Copa, candidate test).
function PipelineRunsPanel({ job, permitManage, onJobUpdated, onRunsSettled, onAvailability }) {
  return (
    <AzurePipelinePanel
      recordKey={job.id}
      version={[job.updatedAt, job.status, job.lifecycleState, job.canonicalReport?.contentDigest].join('|')}
      load={() => getPipelineRuns(job.id)}
      start={(payload) => startPipelineRun(job.id, payload)}
      permitted={permitManage}
      permissionHint={REQUIRES_MANAGE}
      onStarted={(result) => onJobUpdated?.(result.data.job)}
      onRunsSettled={onRunsSettled}
      onAvailability={onAvailability}
      note="SSI fills in every pipeline parameter from this job. Approval gates stay where they are."
    />
  );
}

function PanelHeader({ icon: Icon, title, action, onAction }) {
  return (
    <div className="panel-header">
      <div>
        <Icon size={19} />
        <h2>{title}</h2>
      </div>
      {action && (
        <button className="text-action" type="button" onClick={onAction}>
          {action}
          <ChevronRight size={16} />
        </button>
      )}
    </div>
  );
}

function CopyButton({ value, label }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return undefined;
    const timer = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(timer);
  }, [copied]);
  return (
    <button
      type="button"
      className="ct-copy-btn"
      disabled={!value}
      aria-label={`Copy ${label}`}
      title={copied ? 'Copied' : `Copy ${label}`}
      onClick={() =>
        copyText(value)
          .then(() => setCopied(true))
          .catch(() => setCopied(false))
      }
    >
      {copied ? <ClipboardCheck size={14} /> : <Copy size={14} />}
    </button>
  );
}

function CopyValue({ label, value }) {
  return (
    <div className="ct-copy">
      <span>{label}</span>
      <code title={value}>{value || '-'}</code>
      <CopyButton value={value} label={label} />
    </div>
  );
}

const REQUIRES_ACCEPT = 'Requires the remediation:accept permission (operator or approver role).';
const CANDIDATE_CHECK_LABELS = {
  'image-config': 'Runtime configuration',
  startup: 'Startup with the default command',
  healthcheck: 'Health check',
  'package-inventory': 'OS packages',
};
const PACKAGE_PAGE_SIZE = 10;

// Unplanned, removed, added and major-version changes are listed first: they are the ones a
// consumer team should look at before accepting the candidate.
function packageChangeWeight(change) {
  return (
    (change.change === 'removed' ? 8 : 0) +
    (change.planned ? 0 : 4) +
    (change.majorVersionChange ? 2 : 0) +
    (change.change === 'added' ? 1 : 0)
  );
}

function CandidateTestPanel({ job, state, permitManage, permitAccept, onAttachCandidateTest, onRecordConsumerDecision }) {
  const view = candidateStageView(job);
  const parameters = candidateTestParameters(job);
  const [decision, setDecision] = useState('');
  const [environment, setEnvironment] = useState('');
  const [note, setNote] = useState('');
  const [page, setPage] = useState(1);
  useEffect(() => {
    setDecision('');
    setEnvironment('');
    setNote('');
    setPage(1);
  }, [job.id]);

  const changes = [...(view.test?.packageChanges?.changes || [])].sort(
    (left, right) => packageChangeWeight(right) - packageChangeWeight(left) || left.name.localeCompare(right.name),
  );
  const summary = view.test?.packageChanges?.summary;
  const totalPages = Math.max(1, Math.ceil(changes.length / PACKAGE_PAGE_SIZE));
  const currentPage = Math.min(Math.max(page, 1), totalPages);
  const pagedChanges = changes.slice((currentPage - 1) * PACKAGE_PAGE_SIZE, currentPage * PACKAGE_PAGE_SIZE);

  const stage = view.withdrawn
    ? { tone: 'bad', label: 'Withdrawn' }
    : view.ready
    ? { tone: 'ok', label: 'Ready for publish' }
    : view.acceptanceStatus === 'issue-found'
      ? { tone: 'bad', label: 'Issue reported' }
      : view.testStatus === 'failed'
        ? { tone: 'bad', label: 'Candidate test failed' }
        : view.testStatus === 'passed'
          ? { tone: 'wait', label: 'Waiting for consumer acceptance' }
          : { tone: 'wait', label: 'Waiting for candidate test' };

  const trimmedEnvironment = environment.trim();
  const trimmedNote = note.trim();
  const formValid =
    trimmedEnvironment.length >= 3 &&
    trimmedEnvironment.length <= 120 &&
    trimmedNote.length <= 1000 &&
    (decision !== 'issue-found' || trimmedNote.length >= 10);

  async function submitDecision() {
    if (!formValid || !onRecordConsumerDecision) return;
    const stored = await onRecordConsumerDecision({ decision, environment: trimmedEnvironment, note: trimmedNote });
    if (stored) {
      setDecision('');
      setNote('');
    }
  }

  return (
    <section className="panel ct-panel">
      <div className="verification-comparison-head">
        <PanelHeader icon={FlaskConical} title="Pre-release testing" />
        <span className={`ct-stage ct-${stage.tone}`}>{stage.label}</span>
      </div>
      <p className="ct-intro">
        Before publish, this candidate must behave like the source image in an automatic side-by-side test, and a
        consumer team must try it in its own environment.
      </p>

      <div className="ct-step">
        <div className="inv-section-title">1 · Automatic candidate test</div>
        {view.test ? (
          <>
            <div className="ct-checks">
              {view.test.checks.map((check) =>
                check.status === 'not-applicable' ? (
                  <div className="check ct-na" key={check.id} title={check.detail}>
                    <MinusCircle size={17} />
                    <span>{CANDIDATE_CHECK_LABELS[check.id] || check.id}: not applicable</span>
                  </div>
                ) : (
                  <div key={check.id} title={check.detail}>
                    <Check label={`${CANDIDATE_CHECK_LABELS[check.id] || check.id}: ${check.detail}`} ok={check.status === 'pass'} />
                  </div>
                ),
              )}
            </div>
            <div className="detail-grid ct-facts">
              <Detail label="Tested" value={formatReportTime(view.test.generatedAt)} />
              <Detail label="Platform" value={view.test.platform || '-'} />
              <Detail label="Run" value={[view.test.runner?.pipeline, view.test.runner?.buildId].filter(Boolean).join(' · ') || '-'} />
              <Detail label="Received via" value={evidenceIntakeLabel(view.test.intake)} />
            </div>
          </>
        ) : (
          <p className="supply-chain-empty">No candidate test result yet. Run the SSI - Candidate Test pipeline with these parameters:</p>
        )}
        {parameters && (
          <div className="ct-params">
            <CopyValue label="remediationJobId" value={parameters.remediationJobId} />
            <CopyValue label="sourceReference" value={parameters.sourceReference} />
            <CopyValue label="candidateReference" value={parameters.candidateReference} />
          </div>
        )}
        {onAttachCandidateTest && (
          <label
            className={state.attaching || !permitManage ? 'secondary-action file-upload-action disabled' : 'secondary-action file-upload-action'}
            title={permitManage ? 'Upload candidate-test-result.json from the pipeline artifact' : REQUIRES_MANAGE}
          >
            <UploadCloud size={17} />
            <span>{state.attaching ? 'Processing…' : 'Upload test result'}</span>
            <input
              type="file"
              accept="application/json,.json"
              disabled={state.attaching || !permitManage}
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) {
                  onAttachCandidateTest(file);
                }
                event.target.value = '';
              }}
            />
          </label>
        )}
      </div>

      {summary && (
        <div className="ct-step">
          <div className="inv-section-title">
            Package changes · {summary.changed} changed · {summary.added} added · {summary.removed} removed ·{' '}
            {summary.unplanned} outside the remediation plan
          </div>
          {changes.length === 0 ? (
            <p className="supply-chain-empty">No OS package changed.</p>
          ) : (
            <>
              <div className="ct-table" role="table" aria-label="Package changes">
                <div className="ct-row ct-head" role="row">
                  <span role="columnheader">Package</span>
                  <span role="columnheader">From → To</span>
                  <span role="columnheader">Review</span>
                </div>
                {pagedChanges.map((change) => (
                  <div className="ct-row" role="row" key={`${change.name}-${change.arch}`}>
                    <span role="cell" className="mono">{change.name}</span>
                    <span role="cell" className="mono">
                      {change.from || '—'} → {change.to || '—'}
                    </span>
                    <span role="cell" className="ct-flags">
                      {change.change === 'removed' && <em className="ct-flag bad">Removed</em>}
                      {change.change === 'added' && <em className="ct-flag">Added</em>}
                      {!change.planned && <em className="ct-flag warn">Unplanned</em>}
                      {change.majorVersionChange && <em className="ct-flag warn">Major version</em>}
                      {change.planned && change.change === 'changed' && !change.majorVersionChange && <em className="ct-flag ok">Planned fix</em>}
                    </span>
                  </div>
                ))}
              </div>
              <PaginationBar
                page={currentPage}
                totalPages={totalPages}
                totalItems={changes.length}
                pageSize={PACKAGE_PAGE_SIZE}
                onPage={setPage}
              />
            </>
          )}
        </div>
      )}

      <div className="ct-step">
        <div className="inv-section-title">2 · Consumer acceptance</div>
        {view.acceptance ? (
          <div className={`ct-decision ct-${view.acceptanceStatus === 'accepted' ? 'ok' : 'bad'}`}>
            {view.acceptanceStatus === 'accepted' ? <UserCheck size={17} /> : <MessageSquareWarning size={17} />}
            <div>
              <strong>
                {view.acceptanceStatus === 'accepted' ? 'Tested — OK' : 'Issue found'} · {view.acceptance.environment}
              </strong>
              <span>
                {view.acceptance.decidedBy} · {formatReportTime(view.acceptance.decidedAt)}
              </span>
              {view.acceptance.note && <p>{view.acceptance.note}</p>}
              {view.openIssues.length > 1 && <span>{view.openIssues.length - 1} more open issue(s) in the history below.</span>}
              {view.acceptanceStatus === 'issue-found' && view.acceptances.length > 0 && (
                <span>
                  Accepted by {view.acceptances.slice(0, 5).map((item) => item.decidedBy).join(', ')}
                  {view.acceptances.length > 5 ? ` and ${view.acceptances.length - 5} more` : ''}, but open issues block
                  publish.
                </span>
              )}
            </div>
          </div>
        ) : (
          <p className="supply-chain-empty">
            Pull the candidate into your own test project by its digest (candidateReference above), run your tests, then
            record the result here.
          </p>
        )}
        <p className="ct-hint">
          <Lock size={13} />
          Four-eyes rule: the person who requests publishing cannot be the one who accepts the candidate. Only the
          person who reported an issue can withdraw it, by marking the candidate tested — OK.
        </p>
        {view.manualUploader && (
          <p className="ct-hint">
            <Lock size={13} />
            The test result was uploaded manually by {view.manualUploader}, who cannot accept this candidate.
          </p>
        )}

        {decision ? (
          <div className="ct-form">
            <label>
              <span>Project or environment where you tried the image</span>
              <input
                value={environment}
                maxLength={120}
                placeholder="e.g. html-hello-world (DUY Self Service)"
                onChange={(event) => setEnvironment(event.target.value)}
              />
            </label>
            <label>
              <span>{decision === 'issue-found' ? 'What went wrong? (required)' : 'Note (optional)'}</span>
              <textarea
                className="ex-note"
                value={note}
                maxLength={1000}
                placeholder={decision === 'issue-found' ? 'Describe the problem so the platform team can reproduce it.' : 'What did you test?'}
                onChange={(event) => setNote(event.target.value)}
              />
            </label>
            <div className="ex-actions">
              <button
                className={decision === 'accepted' ? 'primary-action ex-btn ok' : 'secondary-action ex-btn danger'}
                type="button"
                disabled={!formValid || state.deciding}
                onClick={submitDecision}
              >
                {decision === 'accepted' ? <UserCheck size={15} /> : <MessageSquareWarning size={15} />}
                {state.deciding ? 'Saving…' : decision === 'accepted' ? 'Confirm: tested — OK' : 'Report issue'}
              </button>
              <button className="secondary-action ex-btn" type="button" disabled={state.deciding} onClick={() => setDecision('')}>
                Cancel
              </button>
            </div>
          </div>
        ) : (
          onRecordConsumerDecision && (
            <div className="ex-actions">
              <button
                className="primary-action ex-btn ok"
                type="button"
                disabled={!permitAccept || !view.canAccept}
                title={!permitAccept ? REQUIRES_ACCEPT : view.canAccept ? undefined : 'The automatic candidate test must pass first.'}
                onClick={() => setDecision('accepted')}
              >
                <UserCheck size={15} />
                Mark tested — OK
              </button>
              <button
                className="secondary-action ex-btn danger"
                type="button"
                disabled={!permitAccept}
                title={permitAccept ? undefined : REQUIRES_ACCEPT}
                onClick={() => setDecision('issue-found')}
              >
                <MessageSquareWarning size={15} />
                Report issue
              </button>
            </div>
          )
        )}

        {view.history.length > 1 && (
          <ol className="ct-history" aria-label="Consumer decisions, newest first">
            {view.history.slice(0, 8).map((item) => (
              <li key={`${item.decidedAt}-${item.decidedBy}`}>
                {formatReportTime(item.decidedAt)} · {item.decision === 'accepted' ? 'Tested — OK' : 'Issue found'} ·{' '}
                {item.environment} · {item.decidedBy}
              </li>
            ))}
          </ol>
        )}
      </div>
    </section>
  );
}

function Detail({ label, value }) {
  return (
    <div className="detail">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Check({ label, ok }) {
  return (
    <div className={ok ? 'check ok' : 'check bad'}>
      {ok ? <CheckCircle2 size={17} /> : <AlertTriangle size={17} />}
      <span>{label}</span>
    </div>
  );
}

// Null-safe lower-casing for values that come from external data (scanners, registry).
function lower(value) {
  return String(value ?? '').toLowerCase();
}

function Badge({ status, label }) {
  const normalized = lower(status || 'unknown').replace(/\s+/g, '-');
  return <span className={`badge ${normalized}`}>{label || status || 'Unknown'}</span>;
}

function exportCsv(filename, header, rows) {
  const escape = (cell) => `"${String(cell ?? '').replace(/"/g, '""')}"`;
  const content = [header, ...rows].map((row) => row.map(escape).join(',')).join('\n');
  const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function downloadJson(filename, payload) {
  const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function exportInventory(images) {
  exportCsv(
    'ssi-inventory.csv',
    ['Image', 'Version', 'Source', 'Type', 'Runtime', 'Status', 'Critical', 'High', 'Medium', 'Low', 'Max CVSS', 'Owner', 'Last Scan'],
    images.map((image) => [
      image.name,
      image.version,
      image.source,
      image.type,
      image.runtime,
      image.status,
      image.critical,
      image.high,
      image.medium,
      image.low,
      image.maxCvss,
      image.owner,
      image.lastScanned,
    ]),
  );
}

function exportFindings(findings, report) {
  const name = (report && (report.image || report.id)) || 'scan';
  const slug = String(name).replace(/[^a-z0-9]+/gi, '-').replace(/^-+|-+$/g, '').toLowerCase();
  exportCsv(
    `ssi-scan-${slug || 'findings'}.csv`,
    ['CVE', 'Package', 'Installed', 'Fixed', 'Severity', 'CVSS', 'EPSS', 'Status'],
    findings.map((finding) => [
      finding.cve,
      finding.package,
      finding.installed,
      finding.fixed,
      finding.severity,
      finding.cvss,
      finding.epss == null ? '' : `${Math.round(finding.epss * 100)}%`,
      finding.status,
    ]),
  );
}

function exportRemediation(remediation) {
  exportCsv(
    'ssi-remediation-report.csv',
    ['Job', 'Image', 'Engine', 'CVEs Fixed', 'Before', 'After', 'Date', 'Status'],
    remediation.map((item) => [
      item.id,
      item.image,
      item.engine,
      item.cvesFixed,
      item.before,
      item.after,
      item.at,
      item.status,
    ]),
  );
}

// ISO-8601 week key (e.g. 2026-W37); mirrors isoWeek in server/remediationReporting.js.
function isoWeekKey(date) {
  const utc = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const day = utc.getUTCDay() || 7;
  utc.setUTCDate(utc.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(utc.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((utc - yearStart) / 86400000 + 1) / 7);
  return `${utc.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
}

const REPORT_TREND_WEEKS = 8;

// Weekly remediation throughput (CVEs fixed by verified jobs) for the last N ISO weeks,
// ending at the report date. Empty weeks are kept so the time axis stays continuous.
function weeklyRemediation(history, referenceDate, weeks = REPORT_TREND_WEEKS) {
  const end = Number.isNaN(referenceDate.getTime()) ? new Date() : referenceDate;
  const buckets = [];
  for (let offset = weeks - 1; offset >= 0; offset -= 1) {
    const key = isoWeekKey(new Date(end.getTime() - offset * 7 * 86400000));
    buckets.push({ week: key, label: key.slice(5), fixed: 0, jobs: 0 });
  }
  const byWeek = new Map(buckets.map((bucket) => [bucket.week, bucket]));
  for (const item of history) {
    if (String(item.status).toLowerCase() !== 'verified') continue;
    const at = new Date(item.at);
    if (Number.isNaN(at.getTime())) continue;
    const bucket = byWeek.get(isoWeekKey(at));
    if (!bucket) continue;
    bucket.fixed += Number(item.cvesFixed) || 0;
    bucket.jobs += 1;
  }
  return buckets;
}

function niceCeiling(value) {
  if (value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const step = [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].find((candidate) => candidate * magnitude >= value);
  return step * magnitude;
}

function RemediationThroughputChart({ data }) {
  const width = 600;
  const height = 200;
  const left = 40;
  const baseline = height - 30;
  const top = 18;
  const max = niceCeiling(Math.max(...data.map((point) => point.fixed)));
  const ticks = [0, max / 2, max];
  const groupWidth = (width - left) / data.length;
  const barWidth = Math.min(36, groupWidth * 0.46);
  const scale = (value) => (value / max) * (baseline - top);

  return (
    <svg className="rp-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="CVEs remediated per week">
      {ticks.map((tick) => (
        <g key={tick}>
          <line x1={left - 6} x2={width} y1={baseline - scale(tick)} y2={baseline - scale(tick)} className="rp-grid" />
          <text x={left - 12} y={baseline - scale(tick) + 4} textAnchor="end" className="rp-axis">
            {Number.isInteger(tick) ? tick : tick.toFixed(1)}
          </text>
        </g>
      ))}
      {data.map((point, index) => {
        const x = left + index * groupWidth + (groupWidth - barWidth) / 2;
        const barHeight = scale(point.fixed);
        const center = x + barWidth / 2;
        return (
          <g key={point.week}>
            <title>{`${point.week}: ${point.fixed} CVEs remediated (${point.jobs} verified job${point.jobs === 1 ? '' : 's'})`}</title>
            <rect x={left + index * groupWidth} y={top} width={groupWidth} height={baseline - top} className="rp-hit" />
            {point.fixed > 0 ? (
              <>
                <path
                  d={`M${x} ${baseline}V${baseline - barHeight + 4}a4 4 0 0 1 4 -4h${barWidth - 8}a4 4 0 0 1 4 4V${baseline}z`}
                  className="rp-bar"
                />
                <text x={center} y={baseline - barHeight - 7} textAnchor="middle" className="rp-value">
                  {point.fixed}
                </text>
              </>
            ) : (
              <rect x={x} y={baseline - 2} width={barWidth} height="2" rx="1" className="rp-bar-empty" />
            )}
            <text x={center} y={baseline + 19} textAnchor="middle" className="rp-axis">
              {point.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

const REPORT_STATUS_ORDER = ['Verified', 'Planned', 'Blocked'];
const REPORT_STATUS_LABELS = { ApprovalRequired: 'Approval required' };
const PUBLISH_STATUS_TONES = { Published: ' ok', Withdrawn: ' bad', Rejected: ' bad', Cancelled: ' bad' };

function reportStatusLabel(status) {
  return REPORT_STATUS_LABELS[status] || status;
}

// How a piece of evidence entered SSI: signed pipeline worker or manual upload.
function evidenceIntakeLabel(intake) {
  if (!intake?.channel) return 'Not recorded';
  return intake.channel === 'worker'
    ? `Signed worker · ${intake.workerId || 'unknown'}`
    : `Manual upload · ${intake.actor || 'unknown'}`;
}

function formatReportTime(value) {
  const date = new Date(value);
  if (!value || Number.isNaN(date.getTime())) return '-';
  const pad = (part) => String(part).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

// "project/repo/name:tag" → repo + tag + path; a registry port ("host:5000/…") is not a tag.
function splitImageReference(reference) {
  const value = String(reference || '');
  const slash = value.lastIndexOf('/');
  const colon = value.lastIndexOf(':');
  const hasTag = colon > slash;
  const name = hasTag ? value.slice(0, colon) : value;
  return { ...splitImageName(name), tag: hasTag ? value.slice(colon + 1) : '' };
}

function Reports({ images, report, state }) {
  const [historyFilter, setHistoryFilter] = useState('all');
  const [historyPage, setHistoryPage] = useState(1);
  const historyPageSize = 8;

  const remediation = report.history || [];
  const summary = report.summary || emptyRemediationReport.summary;
  const deployable = images.filter((image) => !isTechnicalArtifact(image));
  const hiddenArtifacts = images.length - deployable.length;
  const severityTotals = INVENTORY_SEVERITIES.reduce(
    (totals, severity) => ({
      ...totals,
      [severity.key]: deployable.reduce((sum, image) => sum + (Number(image[severity.key]) || 0), 0),
    }),
    {},
  );
  const openFindings = INVENTORY_SEVERITIES.reduce((sum, severity) => sum + severityTotals[severity.key], 0);
  const openCriticalHigh = severityTotals.critical + severityTotals.high;
  const verifiedJobs = Number(summary.verifiedJobs) || 0;
  const published = Number(summary.published) || 0;
  const publishRequests = Number(summary.publishRequests) || 0;
  const weekly = weeklyRemediation(remediation, new Date(report.generatedAt || Date.now()));
  const hasThroughput = weekly.some((point) => point.fixed > 0);
  const liveReport = !['mock', 'unavailable'].includes(String(state.source || ''));

  const statusKeys = [
    ...REPORT_STATUS_ORDER.filter((status) => remediation.some((item) => item.status === status)),
    ...[...new Set(remediation.map((item) => item.status))].filter((status) => !REPORT_STATUS_ORDER.includes(status)),
  ];
  const filteredHistory =
    historyFilter === 'all' ? remediation : remediation.filter((item) => item.status === historyFilter);
  const historyTotalPages = Math.max(1, Math.ceil(filteredHistory.length / historyPageSize));
  const historyCurrentPage = Math.min(historyPage, historyTotalPages);
  const pagedHistory = filteredHistory.slice(
    (historyCurrentPage - 1) * historyPageSize,
    historyCurrentPage * historyPageSize,
  );
  const pickHistoryFilter = (key) => {
    setHistoryFilter(key);
    setHistoryPage(1);
  };

  const kpis = [
    {
      label: 'Images',
      value: deployable.length,
      note: hiddenArtifacts > 0 ? `deployable · ${hiddenArtifacts} technical hidden` : 'deployable',
    },
    {
      label: 'Open Critical + High',
      value: openCriticalHigh,
      note: `${severityTotals.critical} critical · ${severityTotals.high} high`,
      tone: openCriticalHigh > 0 ? 'critical' : '',
    },
    {
      label: 'CVEs remediated',
      value: Number(summary.cvesRemediated) || 0,
      note: `${verifiedJobs} verified job${verifiedJobs === 1 ? '' : 's'}`,
      tone: 'good',
    },
    {
      label: 'Published',
      value: published,
      note: `of ${publishRequests} publish request${publishRequests === 1 ? '' : 's'}`,
    },
  ];

  return (
    // lang="en": the shell is lang="tr", which would upper-case English labels with a dotted İ.
    <div className="view-grid rp-view" lang="en">
      <section className="panel rp-head">
        <div className="rp-head-title">
          <h2>Security posture report</h2>
          <span>
            Inventory, vulnerability and remediation summary
            {report.generatedAt ? ` · Generated ${formatReportTime(report.generatedAt)}` : ''}
          </span>
        </div>
        <div className="rp-head-actions">
          <DataSourceBadge state={state} />
          <button className="secondary-action rp-btn" type="button" onClick={() => exportInventory(deployable)}>
            <Database size={15} />
            Inventory CSV
          </button>
          <button className="secondary-action rp-btn" type="button" onClick={() => exportRemediation(remediation)}>
            <Download size={15} />
            Remediation CSV
          </button>
          <button className="primary-action rp-btn" type="button" onClick={() => window.print()}>
            <Printer size={15} />
            Print
          </button>
        </div>
      </section>

      <section className="rp-kpis">
        {kpis.map((kpi) => (
          <div className={`panel rp-kpi${kpi.tone ? ` ${kpi.tone}` : ''}`} key={kpi.label}>
            <span>{kpi.label}</span>
            <strong>{kpi.value}</strong>
            <small>{kpi.note}</small>
          </div>
        ))}
      </section>

      <section className="rp-charts">
        <div className="panel rp-card">
          <div className="panel-header">
            <div>
              <BarChart3 size={19} />
              <h2>CVEs remediated per week</h2>
            </div>
            <span className="rp-range">Last {REPORT_TREND_WEEKS} weeks</span>
          </div>
          {hasThroughput ? (
            <RemediationThroughputChart data={weekly} />
          ) : (
            <div className="empty-table-state rp-chart-empty">No verified remediation in the last {REPORT_TREND_WEEKS} weeks.</div>
          )}
          <p className="rp-foot">Verified remediation jobs only · ISO weeks</p>
        </div>

        <div className="panel rp-card">
          <PanelHeader icon={PieChart} title="Open vulnerabilities by severity" />
          <div className="rp-severity">
            <SeverityDonut counts={severityTotals} total={openFindings} />
            <SeverityLegend counts={severityTotals} total={openFindings} />
          </div>
          <p className="rp-foot">
            Across {deployable.length} deployable image{deployable.length === 1 ? '' : 's'} · latest scan per image
          </p>
        </div>
      </section>

      <section className="panel rp-card">
        <PanelHeader icon={CalendarClock} title="Remediation history" />
        {remediation.length > 0 && (
          <div className="sev-filter rp-filter" role="group" aria-label="Status">
            {['all', ...statusKeys].map((key) => (
              <button
                key={key}
                type="button"
                className={`sev-pill${historyFilter === key ? ' active' : ''}`}
                aria-pressed={historyFilter === key}
                onClick={() => pickHistoryFilter(key)}
              >
                {key === 'all' ? 'All' : reportStatusLabel(key)}
                <em>{key === 'all' ? remediation.length : remediation.filter((item) => item.status === key).length}</em>
              </button>
            ))}
          </div>
        )}
        <div className="rp-scroll">
          <div className="rp-table">
            <div className="rp-row rp-row-head">
              <span>Job</span>
              <span>Image</span>
              <span>CVEs (before → after)</span>
              <span>Status</span>
              <span>Publish</span>
              <span>Date</span>
              <span aria-hidden="true" />
            </div>
            {remediation.length === 0 && <div className="empty-table-state">No remediation records yet.</div>}
            {pagedHistory.map((item) => {
              const image = splitImageReference(item.image);
              const fixed = Number(item.cvesFixed) || 0;
              const publishStatus = item.publishStatus || 'Not evaluated';
              return (
                <div className="rp-row" key={item.id}>
                  <span className="rp-job">{item.id}</span>
                  <span className="inv-img">
                    <strong title={item.image}>
                      {image.repo || item.image}
                      {image.tag && <em>:{image.tag}</em>}
                    </strong>
                    {image.path && <small>{image.path}</small>}
                  </span>
                  <span className="rp-cves">
                    <b>{item.before}</b> →{' '}
                    {lower(item.status) === 'verified' ? (
                      <b>{item.after}</b>
                    ) : (
                      // Plans and unfinished runs have no re-scan result yet.
                      <span className="inv-muted" title="No verified re-scan yet">
                        —
                      </span>
                    )}
                    {fixed > 0 && <em>−{fixed}</em>}
                  </span>
                  <span>
                    <Badge status={item.status} label={reportStatusLabel(item.status)} />
                  </span>
                  <span className={`rp-publish${PUBLISH_STATUS_TONES[publishStatus] || ''}`}>
                    {reportStatusLabel(publishStatus)}
                  </span>
                  <span className="inv-time">{formatReportTime(item.at)}</span>
                  <span className="rp-report">
                    {liveReport ? (
                      <a
                        className="rp-link"
                        href={remediationReportDocumentUrl(item.id)}
                        target="_blank"
                        rel="noopener noreferrer"
                        title={`${item.id} before/after report`}
                      >
                        <FileText size={14} />
                        Report
                      </a>
                    ) : (
                      <span className="inv-muted" title="Reports are generated from live API data only">
                        —
                      </span>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
        <PaginationBar
          page={historyCurrentPage}
          totalPages={historyTotalPages}
          totalItems={filteredHistory.length}
          pageSize={historyPageSize}
          onPage={setHistoryPage}
        />
      </section>
    </div>
  );
}

export default App;
