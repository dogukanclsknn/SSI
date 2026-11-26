// SSI — Teams (multi-tenancy): the team switcher, the Teams screen and the team memberships
// shown in Users. Rendered only while SSI_MULTI_TENANCY is on; every rule is enforced by the
// server (src/lib/tenancy.js, src/lib/tenantInventory.js) — this file only presents it.
import { useEffect, useState } from 'react';
import { Building2, CheckCircle2, FolderTree, Lock, Plus, Search, ShieldOff, Trash2, UserPlus } from 'lucide-react';
import {
  createTenant,
  listTenantMembers,
  listTenants,
  listUsers,
  removeTenantMembership,
  setTenantMembership,
  updateTenant,
} from './lib/api.js';

const TEAM_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$/;
const DEFAULT_TEAM = 'default';

export const TEAM_ROLE_OPTIONS = [
  { value: 'viewer', label: 'Viewer', summary: 'Sees the team’s images, jobs and reports' },
  { value: 'operator', label: 'Operator', summary: 'Onboards, plans remediation, requests publishes' },
  { value: 'approver', label: 'Approver', summary: 'Approves, rejects and withdraws the team’s publishes' },
];

const TEAM_FILTERS = [
  { key: 'all', label: 'All', match: () => true },
  { key: 'active', label: 'Active', match: (team) => team.status === 'active' },
  { key: 'disabled', label: 'Disabled', match: (team) => team.status !== 'active' },
];

const HARBOR_FIELDS = [
  { key: 'registry', label: 'Registry', effective: (target) => target.publish.registry },
  { key: 'project', label: 'Project', effective: (target) => target.publish.project },
  { key: 'onboardPrefix', label: 'Onboard folder', effective: (target) => target.onboarding.repositoryPrefix },
  { key: 'approvedPrefix', label: 'Approved folder', effective: (target) => target.publish.repositoryPrefix },
];

function folder(target) {
  return target ? `${target.project}/${target.repositoryPrefix}/` : '—';
}

function initials(text) {
  return String(text || '?')
    .split(/[\s._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0])
    .join('')
    .toUpperCase();
}

function formatTime(value) {
  const date = new Date(value);
  if (!value || Number.isNaN(date.getTime())) return '—';
  const pad = (part) => String(part).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function StatusBadge({ status }) {
  const active = status === 'active';
  return <span className={`badge ${active ? 'approved' : 'blocked'}`}>{active ? 'Active' : 'Disabled'}</span>;
}

function RoleSelect({ value, disabled, onChange, label = 'Team role' }) {
  return (
    <select className="tm-role-select" aria-label={label} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)}>
      {TEAM_ROLE_OPTIONS.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}

// Runs one change at a time and keeps its error for the panel.
function useAction(onDone) {
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  async function run(action, fallbackMessage) {
    setSaving(true);
    setError('');
    try {
      await action();
      if (onDone) await onDone();
      return true;
    } catch (err) {
      setError(err.message || fallbackMessage);
      return false;
    } finally {
      setSaving(false);
    }
  }
  return { saving, error, setError, run };
}

// ── Top bar: which team the console works in ──────────────────────────────────
// Shown to members of several teams and to platform administrators ("All teams").
export function TeamSwitcher({ tenancy, onSelect }) {
  const teams = Array.isArray(tenancy?.teams) ? tenancy.teams.filter((team) => team.status === 'active' || tenancy.platformAdmin) : [];
  if (!tenancy?.enabled || (!tenancy.platformAdmin && teams.length < 2)) return null;
  return (
    <label className="team-switcher" title="The team this console works in">
      <Building2 size={15} />
      <select aria-label="Team" value={tenancy.tenantId || ''} onChange={(event) => onSelect(event.target.value)}>
        {tenancy.platformAdmin && <option value="">All teams</option>}
        {teams.map((team) => (
          <option key={team.id} value={team.id}>
            {team.displayName}
            {team.status !== 'active' ? ' (disabled)' : ''}
          </option>
        ))}
      </select>
    </label>
  );
}

// ── Teams screen (platform administrators) ────────────────────────────────────
export function TeamManagement() {
  const [teams, setTeams] = useState([]);
  const [state, setState] = useState({ loading: true, error: '' });
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const [selected, setSelected] = useState('');
  const [creating, setCreating] = useState(false);

  async function refresh() {
    setState((current) => ({ ...current, loading: true }));
    try {
      const result = await listTenants();
      setTeams(Array.isArray(result.data) ? result.data : []);
      setState({ loading: false, error: '' });
    } catch (err) {
      setState({ loading: false, error: err.message || 'Teams could not be loaded.' });
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  const needle = query.trim().toLowerCase();
  const searched = needle
    ? teams.filter((team) => [team.id, team.displayName].some((value) => String(value || '').toLowerCase().includes(needle)))
    : teams;
  const activeFilter = TEAM_FILTERS.find((item) => item.key === filter) || TEAM_FILTERS[0];
  const visible = searched.filter(activeFilter.match);
  const selectedTeam = creating ? null : teams.find((team) => team.id === selected) || visible[0] || null;

  return (
    // lang="en": the shell is lang="tr", which would upper-case English labels with a dotted İ.
    <div className="catalog-layout inv-layout us-layout" lang="en">
      <section className="panel catalog-panel inv-panel">
        <div className="pub-stat-chips us-chips" role="group" aria-label="Filter">
          {TEAM_FILTERS.map((item) => (
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
            <input aria-label="Team search" placeholder="Search team name or id" value={query} onChange={(event) => setQuery(event.target.value)} />
          </div>
          <div className="inv-toolbar-spacer" />
          <button className="primary-action us-btn" type="button" onClick={() => setCreating(true)}>
            <Plus size={15} />
            Add team
          </button>
        </div>
        {state.error && <div className="inline-error">{state.error}</div>}

        <div className="us-table tm-table">
          <div className="us-row us-head">
            <span>Team</span>
            <span>Harbor folders</span>
            <span>Members</span>
            <span>Status</span>
          </div>
          {!state.loading && visible.length === 0 && (
            <div className="inv-empty">{teams.length === 0 ? 'No teams yet.' : 'No teams match the current filters.'}</div>
          )}
          {visible.map((team) => (
            <button
              key={team.id}
              type="button"
              className={`us-row${selectedTeam?.id === team.id ? ' selected' : ''}`}
              aria-pressed={selectedTeam?.id === team.id}
              onClick={() => {
                setCreating(false);
                setSelected(team.id);
              }}
            >
              <span className="us-user">
                <span className="us-avatar operator">{initials(team.displayName)}</span>
                <span className="us-id">
                  <strong>
                    {team.displayName}
                    {team.id === DEFAULT_TEAM && <em className="us-you">Default</em>}
                  </strong>
                  <small>{team.id}</small>
                </span>
              </span>
              <span className="tm-folders">
                <small title={folder(team.effectiveHarbor?.onboarding)}>{folder(team.effectiveHarbor?.onboarding)}</small>
                <small title={folder(team.effectiveHarbor?.publish)}>{folder(team.effectiveHarbor?.publish)}</small>
              </span>
              <span>{team.memberCount ?? 0}</span>
              <span>
                <StatusBadge status={team.status} />
              </span>
            </button>
          ))}
        </div>
      </section>

      {creating ? (
        <NewTeamPanel
          onCancel={() => setCreating(false)}
          onCreated={async (id) => {
            await refresh();
            setCreating(false);
            setSelected(id);
          }}
        />
      ) : (
        <TeamDetailPanel key={selectedTeam ? `${selectedTeam.id}:${selectedTeam.rowVersion}` : 'none'} team={selectedTeam} onChanged={refresh} />
      )}
    </div>
  );
}

function HarborFields({ values, effective, disabled, onChange }) {
  return (
    <div className="tm-harbor">
      {HARBOR_FIELDS.map((field) => (
        <label className="ab-field" key={field.key}>
          <span>{field.label}</span>
          <input
            value={values[field.key] || ''}
            disabled={disabled}
            placeholder={effective ? field.effective(effective) : 'Platform default'}
            onChange={(event) => onChange(field.key, event.target.value)}
          />
        </label>
      ))}
      <small className="hint">Empty fields use the platform default shown in grey.</small>
    </div>
  );
}

function TeamDetailPanel({ team, onChanged }) {
  const [name, setName] = useState(team?.displayName || '');
  const [harbor, setHarbor] = useState(team?.harbor || {});
  const [confirmId, setConfirmId] = useState('');
  const { saving, error, run } = useAction(onChanged);

  if (!team) {
    return (
      <aside className="panel inspector inv-insp us-rail" aria-label="Team detail">
        <div className="inv-empty">Select a team to manage it.</div>
      </aside>
    );
  }

  const isDefault = team.id === DEFAULT_TEAM;
  const harborChanged = HARBOR_FIELDS.some((field) => (harbor[field.key] || '') !== (team.harbor?.[field.key] || ''));
  const change = (changes, message) => run(() => updateTenant(team.id, { ...changes, rowVersion: team.rowVersion }), message);

  return (
    <aside className="panel inspector inv-insp us-rail" aria-label="Team detail">
      <div className="us-profile">
        <span className="us-avatar lg operator">{initials(team.displayName)}</span>
        <div>
          <h2>{team.displayName}</h2>
          <small>{team.id}</small>
        </div>
        <StatusBadge status={team.status} />
      </div>

      <div className="inv-facts">
        <div className="detail full">
          <span>Onboard folder</span>
          <strong className="tm-mono">{folder(team.effectiveHarbor?.onboarding)}</strong>
        </div>
        <div className="detail full">
          <span>Approved folder (publish boundary)</span>
          <strong className="tm-mono">{folder(team.effectiveHarbor?.publish)}</strong>
        </div>
        <div className="detail">
          <span>Members</span>
          <strong>{team.memberCount ?? 0}</strong>
        </div>
        <div className="detail">
          <span>Created</span>
          <strong>{formatTime(team.createdAt)}</strong>
        </div>
      </div>

      {isDefault && (
        <div className="us-note">
          <Lock size={14} />
          Every record from before multi-tenancy lives in the default team. It keeps the platform folders and cannot be
          disabled.
        </div>
      )}

      <div className="inv-section-title">Name</div>
      <div className="tm-inline">
        <input className="tm-input" aria-label="Team name" value={name} disabled={saving} onChange={(event) => setName(event.target.value)} />
        <button
          className="secondary-action us-btn"
          type="button"
          disabled={saving || !name.trim() || name.trim() === team.displayName}
          onClick={() => change({ displayName: name.trim() }, 'The name could not be saved.')}
        >
          Save
        </button>
      </div>

      <div className="inv-section-title">
        <FolderTree size={13} /> Harbor target
      </div>
      <HarborFields
        values={harbor}
        effective={team.effectiveHarbor}
        disabled={saving}
        onChange={(key, value) => setHarbor((current) => ({ ...current, [key]: value }))}
      />
      {harborChanged && (
        <div className="us-note">
          <ShieldOff size={14} />
          Images are assigned to teams by folder. Changing a folder changes which existing images this team sees and where it
          onboards and publishes.
        </div>
      )}
      <div className="us-actions">
        <button
          className="primary-action us-btn"
          type="button"
          disabled={saving || !harborChanged}
          onClick={() => change({ harbor }, 'The Harbor target could not be saved.')}
        >
          Save Harbor target
        </button>
      </div>

      {error && <div className="inline-error">{error}</div>}

      <TeamMembers team={team} onChanged={onChanged} />

      {!isDefault && (
        <div className="us-danger">
          <div>
            <strong>{team.status === 'active' ? 'Disable team' : 'Enable team'}</strong>
            <small>
              {team.status === 'active'
                ? 'Members lose access to this team at once. Its records are kept and come back when the team is enabled.'
                : 'Members get their access to this team back.'}
            </small>
          </div>
          {team.status === 'active' && (
            <label className="us-confirm">
              <span>Type {team.id} to confirm</span>
              <input value={confirmId} onChange={(event) => setConfirmId(event.target.value)} aria-label="Confirm team id" />
            </label>
          )}
          <button
            className={team.status === 'active' ? 'us-remove' : 'secondary-action us-btn'}
            type="button"
            disabled={saving || (team.status === 'active' && confirmId.trim() !== team.id)}
            onClick={() =>
              change({ status: team.status === 'active' ? 'disabled' : 'active' }, 'The team status could not be changed.')
            }
          >
            {team.status === 'active' ? 'Disable team' : 'Enable team'}
          </button>
        </div>
      )}
    </aside>
  );
}

function TeamMembers({ team, onChanged }) {
  const [members, setMembers] = useState([]);
  const [candidates, setCandidates] = useState([]);
  const [loadError, setLoadError] = useState('');
  const [newMember, setNewMember] = useState({ username: '', role: 'viewer' });

  async function load() {
    try {
      const [memberResult, userResult] = await Promise.all([listTenantMembers(team.id), listUsers()]);
      const list = Array.isArray(memberResult.data) ? memberResult.data : [];
      setMembers(list);
      const taken = new Set(list.map((member) => member.username));
      // Platform administrators act in every team; they are never members.
      setCandidates(
        (Array.isArray(userResult.data) ? userResult.data : []).filter(
          (user) => user.role !== 'admin' && !user.protected && !taken.has(user.username),
        ),
      );
      setLoadError('');
    } catch (err) {
      setLoadError(err.message || 'Members could not be loaded.');
    }
  }

  const { saving, error, run } = useAction(async () => {
    await load();
    await onChanged();
  });

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [team.id]);

  return (
    <>
      <div className="inv-section-title">Members</div>
      {(loadError || error) && <div className="inline-error">{loadError || error}</div>}
      <div className="tm-members">
        {members.length === 0 && <div className="inv-empty">No members yet.</div>}
        {members.map((member) => (
          <div className="tm-member" key={member.username}>
            <span className={`us-avatar ${member.role}`}>{initials(member.username)}</span>
            <span className="tm-member-name">
              <strong>{member.username}</strong>
              <small>since {formatTime(member.createdAt)}</small>
            </span>
            <RoleSelect
              value={member.role}
              disabled={saving}
              label={`Role of ${member.username}`}
              onChange={(role) => run(() => setTenantMembership(team.id, member.username, role), 'The role could not be changed.')}
            />
            <button
              className="tm-icon-button"
              type="button"
              title={`Remove ${member.username} from ${team.displayName}`}
              aria-label={`Remove ${member.username}`}
              disabled={saving}
              onClick={() => run(() => removeTenantMembership(team.id, member.username), 'The member could not be removed.')}
            >
              <Trash2 size={14} />
            </button>
          </div>
        ))}
      </div>
      <form
        className="tm-add"
        onSubmit={async (event) => {
          event.preventDefault();
          if (!newMember.username) return;
          const ok = await run(
            () => setTenantMembership(team.id, newMember.username, newMember.role),
            'The member could not be added.',
          );
          if (ok) setNewMember({ username: '', role: newMember.role });
        }}
      >
        <select
          aria-label="User to add"
          value={newMember.username}
          disabled={saving || candidates.length === 0}
          onChange={(event) => setNewMember((current) => ({ ...current, username: event.target.value }))}
        >
          <option value="">{candidates.length === 0 ? 'No users to add' : 'Add a user…'}</option>
          {candidates.map((user) => (
            <option key={user.username} value={user.username}>
              {user.displayName && user.displayName !== user.username ? `${user.displayName} (${user.username})` : user.username}
            </option>
          ))}
        </select>
        <RoleSelect value={newMember.role} disabled={saving} onChange={(role) => setNewMember((current) => ({ ...current, role }))} />
        <button className="secondary-action us-btn" type="submit" disabled={saving || !newMember.username}>
          <UserPlus size={14} />
          Add
        </button>
      </form>
    </>
  );
}

function NewTeamPanel({ onCancel, onCreated }) {
  const [form, setForm] = useState({ id: '', displayName: '', harbor: {} });
  const { saving, error, run } = useAction();
  const id = form.id.trim().toLowerCase();
  const idValid = TEAM_ID_PATTERN.test(id);

  return (
    <aside className="panel inspector inv-insp us-rail" aria-label="Add team">
      <div className="us-profile">
        <span className="us-avatar lg operator">
          <Plus size={18} />
        </span>
        <div>
          <h2>Add team</h2>
          <small>Members, roles and folders can be changed later</small>
        </div>
      </div>
      <form
        className="us-form"
        onSubmit={async (event) => {
          event.preventDefault();
          if (!idValid || !form.displayName.trim()) return;
          const ok = await run(
            () => createTenant({ id, displayName: form.displayName.trim(), harbor: form.harbor }),
            'The team could not be created.',
          );
          if (ok) await onCreated(id);
        }}
      >
        <label className="ab-field">
          <span>Team id</span>
          <input value={form.id} onChange={(event) => setForm((current) => ({ ...current, id: event.target.value }))} placeholder="payments" autoFocus />
          <small className={form.id && !idValid ? 'error' : ''}>
            {form.id && !idValid
              ? 'Lower-case letters, digits and "-" (2 to 40 characters).'
              : 'Permanent. Used in the Harbor folders (onboarded/<id>, approved/<id>).'}
          </small>
        </label>
        <label className="ab-field">
          <span>Name</span>
          <input
            value={form.displayName}
            onChange={(event) => setForm((current) => ({ ...current, displayName: event.target.value }))}
            placeholder="Payments Team"
          />
        </label>
        <div className="inv-section-title">
          <FolderTree size={13} /> Harbor target (optional)
        </div>
        <HarborFields
          values={form.harbor}
          effective={null}
          disabled={saving}
          onChange={(key, value) => setForm((current) => ({ ...current, harbor: { ...current.harbor, [key]: value } }))}
        />
        {error && <div className="inline-error">{error}</div>}
        <div className="us-actions">
          <button className="primary-action us-btn" type="submit" disabled={saving || !idValid || !form.displayName.trim()}>
            Add team
          </button>
          <button className="secondary-action us-btn" type="button" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </aside>
  );
}

// ── Users screen: the teams of one user ───────────────────────────────────────
export function UserTeamMemberships({ username, disabled }) {
  const [rows, setRows] = useState([]);
  const [loadError, setLoadError] = useState('');
  const [addition, setAddition] = useState({ tenantId: '', role: 'viewer' });

  async function load() {
    try {
      const teams = (await listTenants()).data || [];
      const memberships = await Promise.all(
        teams.map(async (team) => {
          const members = (await listTenantMembers(team.id)).data || [];
          return { team, membership: members.find((member) => member.username === username) || null };
        }),
      );
      setRows(memberships);
      setLoadError('');
    } catch (err) {
      setLoadError(err.message || 'Team memberships could not be loaded.');
    }
  }

  const { saving, error, run } = useAction(load);

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [username]);

  const memberOf = rows.filter((row) => row.membership);
  const available = rows.filter((row) => !row.membership && row.team.status === 'active');
  const busy = saving || disabled;

  return (
    <>
      <div className="inv-section-title">Teams</div>
      <small className="hint tm-hint">With multi-tenancy on, the team role replaces the role above inside that team.</small>
      {(loadError || error) && <div className="inline-error">{loadError || error}</div>}
      <div className="tm-members">
        {memberOf.length === 0 && <div className="inv-empty">Not a member of any team: this user cannot act in SSI.</div>}
        {memberOf.map(({ team, membership }) => (
          <div className="tm-member" key={team.id}>
            <span className="us-avatar operator">{initials(team.displayName)}</span>
            <span className="tm-member-name">
              <strong>{team.displayName}</strong>
              <small>
                {team.id}
                {team.status !== 'active' ? ' · disabled' : ''}
              </small>
            </span>
            <RoleSelect
              value={membership.role}
              disabled={busy}
              label={`Role in ${team.displayName}`}
              onChange={(role) => run(() => setTenantMembership(team.id, username, role), 'The role could not be changed.')}
            />
            <button
              className="tm-icon-button"
              type="button"
              title={`Remove from ${team.displayName}`}
              aria-label={`Remove from ${team.displayName}`}
              disabled={busy}
              onClick={() => run(() => removeTenantMembership(team.id, username), 'The membership could not be removed.')}
            >
              <Trash2 size={14} />
            </button>
          </div>
        ))}
      </div>
      {available.length > 0 && (
        <form
          className="tm-add"
          onSubmit={async (event) => {
            event.preventDefault();
            if (!addition.tenantId) return;
            const ok = await run(
              () => setTenantMembership(addition.tenantId, username, addition.role),
              'The membership could not be added.',
            );
            if (ok) setAddition({ tenantId: '', role: addition.role });
          }}
        >
          <select
            aria-label="Team to add"
            value={addition.tenantId}
            disabled={busy}
            onChange={(event) => setAddition((current) => ({ ...current, tenantId: event.target.value }))}
          >
            <option value="">Add to a team…</option>
            {available.map(({ team }) => (
              <option key={team.id} value={team.id}>
                {team.displayName}
              </option>
            ))}
          </select>
          <RoleSelect value={addition.role} disabled={busy} onChange={(role) => setAddition((current) => ({ ...current, role }))} />
          <button className="secondary-action us-btn" type="submit" disabled={busy || !addition.tenantId}>
            <CheckCircle2 size={14} />
            Add
          </button>
        </form>
      )}
    </>
  );
}
