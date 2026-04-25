import { useEffect, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getProfiles, deleteProfile, createProfile, updateProfile } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { CertificateProfile } from '../api/types';

function formatTTL(seconds: number): string {
  if (seconds === 0) return 'No limit';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

interface CreateProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  isLoading: boolean;
  error: string | null;
}

const AVAILABLE_ALGORITHMS = ['RSA', 'ECDSA', 'Ed25519'];
const ALGORITHM_MIN_SIZES: Record<string, number[]> = {
  RSA: [2048, 3072, 4096],
  ECDSA: [256, 384],
  Ed25519: [0],
};

const AVAILABLE_EKUS = [
  { value: 'serverAuth', label: 'Server Authentication (TLS)' },
  { value: 'clientAuth', label: 'Client Authentication' },
  { value: 'codeSigning', label: 'Code Signing' },
  { value: 'emailProtection', label: 'Email Protection (S/MIME)' },
  { value: 'timeStamping', label: 'Time Stamping' },
];

interface KeyAlgorithmEntry {
  algorithm: string;
  min_size: number;
}

function CreateProfileModal({ isOpen, onClose, onSuccess, isLoading, error }: CreateProfileModalProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [ttl, setTtl] = useState('86400');
  const [shortLived, setShortLived] = useState(false);
  const [keyAlgorithms, setKeyAlgorithms] = useState<KeyAlgorithmEntry[]>([
    { algorithm: 'ECDSA', min_size: 256 },
    { algorithm: 'RSA', min_size: 2048 },
  ]);
  const [selectedEkus, setSelectedEkus] = useState<string[]>(['serverAuth']);
  const [sanPatterns, setSanPatterns] = useState('');
  const [spiffePattern, setSpiffePattern] = useState('');

  const addAlgorithm = () => {
    const unused = AVAILABLE_ALGORITHMS.find(a => !keyAlgorithms.some(ka => ka.algorithm === a));
    if (unused) {
      setKeyAlgorithms([...keyAlgorithms, { algorithm: unused, min_size: ALGORITHM_MIN_SIZES[unused][0] }]);
    }
  };

  const removeAlgorithm = (idx: number) => {
    setKeyAlgorithms(keyAlgorithms.filter((_, i) => i !== idx));
  };

  const updateAlgorithm = (idx: number, field: 'algorithm' | 'min_size', value: string | number) => {
    const updated = [...keyAlgorithms];
    if (field === 'algorithm') {
      updated[idx] = { algorithm: value as string, min_size: ALGORITHM_MIN_SIZES[value as string]?.[0] || 0 };
    } else {
      updated[idx] = { ...updated[idx], min_size: value as number };
    }
    setKeyAlgorithms(updated);
  };

  const toggleEku = (eku: string) => {
    setSelectedEkus(prev => prev.includes(eku) ? prev.filter(e => e !== eku) : [...prev, eku]);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    await createProfile({
      name: name.trim(),
      description: description.trim(),
      max_ttl_seconds: parseInt(ttl) || 86400,
      allow_short_lived: shortLived,
      allowed_key_algorithms: keyAlgorithms,
      allowed_ekus: selectedEkus,
      required_san_patterns: sanPatterns.trim() ? sanPatterns.split(',').map(s => s.trim()).filter(Boolean) : [],
      spiffe_uri_pattern: spiffePattern.trim() || '',
      enabled: true,
    });
    setName('');
    setDescription('');
    setTtl('86400');
    setShortLived(false);
    setKeyAlgorithms([{ algorithm: 'ECDSA', min_size: 256 }, { algorithm: 'RSA', min_size: 2048 }]);
    setSelectedEkus(['serverAuth']);
    setSanPatterns('');
    setSpiffePattern('');
    onSuccess();
  };

  if (!isOpen) return null;

  const inputClass = 'w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400';
  const selectClass = 'bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400';

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-lg shadow-xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">Create Profile</h2>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              className={inputClass}
              placeholder="e.g., Web Server Certs"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Description</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              className={inputClass}
              placeholder="Optional description"
              rows={2}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Max TTL (seconds)</label>
            <input
              type="number"
              value={ttl}
              onChange={e => setTtl(e.target.value)}
              className={inputClass}
              placeholder="86400"
            />
            <p className="text-xs text-ink-muted mt-1">
              {shortLived
                ? 'Short-lived certs require TTL under 3600 (1 hour). e.g. 300 = 5m, 1800 = 30m'
                : 'e.g. 86400 = 1 day, 2592000 = 30 days'}
            </p>
            {shortLived && parseInt(ttl) >= 3600 && (
              <p className="text-xs text-amber-600 mt-1">TTL must be under 3600 for short-lived certs</p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="shortLived"
              checked={shortLived}
              onChange={e => {
                setShortLived(e.target.checked);
                if (e.target.checked && parseInt(ttl) >= 3600) {
                  setTtl('300');
                }
              }}
              className="w-4 h-4"
            />
            <label htmlFor="shortLived" className="text-sm text-ink">Allow short-lived certs</label>
          </div>

          {/* Allowed Key Algorithms */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="block text-sm font-medium text-ink">Allowed Key Algorithms</label>
              {keyAlgorithms.length < AVAILABLE_ALGORITHMS.length && (
                <button type="button" onClick={addAlgorithm} className="text-xs text-brand-600 hover:text-brand-700 font-medium">
                  + Add
                </button>
              )}
            </div>
            <div className="space-y-2">
              {keyAlgorithms.map((ka, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <select
                    value={ka.algorithm}
                    onChange={e => updateAlgorithm(idx, 'algorithm', e.target.value)}
                    className={selectClass + ' flex-1'}
                  >
                    {AVAILABLE_ALGORITHMS.map(a => (
                      <option key={a} value={a} disabled={a !== ka.algorithm && keyAlgorithms.some(k => k.algorithm === a)}>
                        {a}
                      </option>
                    ))}
                  </select>
                  {ka.algorithm !== 'Ed25519' ? (
                    <select
                      value={ka.min_size}
                      onChange={e => updateAlgorithm(idx, 'min_size', parseInt(e.target.value))}
                      className={selectClass + ' w-24'}
                    >
                      {(ALGORITHM_MIN_SIZES[ka.algorithm] || []).map(s => (
                        <option key={s} value={s}>{s}+</option>
                      ))}
                    </select>
                  ) : (
                    <span className="text-xs text-ink-muted w-24 text-center">fixed</span>
                  )}
                  <button type="button" onClick={() => removeAlgorithm(idx)} className="text-xs text-red-500 hover:text-red-600">
                    Remove
                  </button>
                </div>
              ))}
              {keyAlgorithms.length === 0 && (
                <p className="text-xs text-ink-faint">No algorithms configured. Click + Add to allow key types.</p>
              )}
            </div>
          </div>

          {/* Allowed EKUs */}
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Allowed Extended Key Usages</label>
            <div className="space-y-1.5">
              {AVAILABLE_EKUS.map(eku => (
                <label key={eku.value} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedEkus.includes(eku.value)}
                    onChange={() => toggleEku(eku.value)}
                    className="w-4 h-4"
                  />
                  <span className="text-sm text-ink">{eku.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Required SAN Patterns */}
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Required SAN Patterns</label>
            <input
              value={sanPatterns}
              onChange={e => setSanPatterns(e.target.value)}
              className={inputClass}
              placeholder="e.g., *.example.com, api.internal"
            />
            <p className="text-xs text-ink-muted mt-1">Comma-separated patterns. Leave empty for no constraints.</p>
          </div>

          {/* SPIFFE URI Pattern */}
          <div>
            <label className="block text-sm font-medium text-ink mb-1">SPIFFE URI Pattern</label>
            <input
              value={spiffePattern}
              onChange={e => setSpiffePattern(e.target.value)}
              className={inputClass}
              placeholder="e.g., spiffe://example.org/service/*"
            />
            <p className="text-xs text-ink-muted mt-1">Optional workload identity URI SAN pattern.</p>
          </div>

          <div className="flex gap-2 pt-4">
            <button
              type="submit"
              disabled={isLoading}
              className="flex-1 btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Creating...' : 'Create Profile'}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="flex-1 btn btn-ghost"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function ProfilesPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  // B-1 master closure (cat-b-7a34f893a8f9): rename + description Edit
  // affordance. Deeper policy fields (allowed_ekus, max_ttl_seconds,
  // allowed_key_algorithms, etc.) stay on the delete-and-recreate path
  // for v1 — closing the audit's destructive-rename complaint requires
  // only the simple metadata edit. Documented as a follow-up.
  const [editingProfile, setEditingProfile] = useState<CertificateProfile | null>(null);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['profiles'],
    queryFn: () => getProfiles(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteProfile,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['profiles'] }),
  });

  const createMutation = useMutation({
    mutationFn: createProfile,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['profiles'] });
      setShowCreate(false);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<CertificateProfile> }) => updateProfile(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['profiles'] });
      setEditingProfile(null);
    },
  });

  const columns: Column<CertificateProfile>[] = [
    {
      key: 'name',
      label: 'Profile',
      render: (p) => (
        <div>
          <div className="font-medium text-ink">{p.name}</div>
          <div className="text-xs text-ink-faint font-mono">{p.id}</div>
          {p.description && (
            <div className="text-xs text-ink-muted mt-0.5 max-w-xs truncate">{p.description}</div>
          )}
        </div>
      ),
    },
    {
      key: 'algorithms',
      label: 'Key Algorithms',
      render: (p) => (
        <div className="flex flex-wrap gap-1">
          {(p.allowed_key_algorithms || []).map((alg, i) => (
            <span key={i} className="badge badge-neutral text-xs">
              {alg.algorithm} {alg.min_size}+
            </span>
          ))}
        </div>
      ),
    },
    {
      key: 'ttl',
      label: 'Max TTL',
      render: (p) => (
        <div>
          <span className="text-ink">{formatTTL(p.max_ttl_seconds)}</span>
          {p.allow_short_lived && (
            <span className="ml-2 text-xs text-amber-700 bg-amber-100 px-1.5 py-0.5 rounded">
              short-lived
            </span>
          )}
        </div>
      ),
    },
    {
      key: 'ekus',
      label: 'EKUs',
      render: (p) => (
        <div className="flex flex-wrap gap-1">
          {(p.allowed_ekus || []).map((eku, i) => (
            <span key={i} className="text-xs text-ink-muted">{eku}</span>
          ))}
        </div>
      ),
    },
    {
      key: 'spiffe',
      label: 'SPIFFE',
      render: (p) => (
        p.spiffe_uri_pattern
          ? <span className="text-xs text-brand-400 font-mono">{p.spiffe_uri_pattern}</span>
          : <span className="text-ink-faint">&mdash;</span>
      ),
    },
    {
      key: 'enabled',
      label: 'Status',
      render: (p) => <StatusBadge status={p.enabled ? 'active' : 'disabled'} />,
    },
    {
      key: 'created',
      label: 'Created',
      render: (p) => <span className="text-xs text-ink-muted">{formatDateTime(p.created_at)}</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (p) => (
        <div className="flex gap-3 justify-end">
          <button
            onClick={(e) => { e.stopPropagation(); setEditingProfile(p); }}
            className="text-xs text-brand-400 hover:text-brand-500 transition-colors"
          >
            Edit
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); if (confirm(`Delete profile ${p.name}?`)) deleteMutation.mutate(p.id); }}
            className="text-xs text-red-600 hover:text-red-700 transition-colors"
          >
            Delete
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Certificate Profiles"
        subtitle={data ? `${data.total} profiles` : undefined}
        action={
          <button onClick={() => setShowCreate(true)} className="btn btn-primary">
            + New Profile
          </button>
        }
      />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No profiles configured" />
        )}
      </div>
      <CreateProfileModal
        isOpen={showCreate}
        onClose={() => setShowCreate(false)}
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ['profiles'] });
          setShowCreate(false);
        }}
        isLoading={createMutation.isPending}
        error={createMutation.error ? (createMutation.error as Error).message : null}
      />
      <EditProfileModal
        profile={editingProfile}
        onClose={() => setEditingProfile(null)}
        onSave={(data) => {
          if (!editingProfile) return;
          updateMutation.mutate({ id: editingProfile.id, data });
        }}
        isSaving={updateMutation.isPending}
        error={updateMutation.error ? (updateMutation.error as Error).message : null}
      />
    </>
  );
}

// EditProfileModal — B-1 closure (cat-b-7a34f893a8f9). Rename +
// description only. Deeper policy fields (allowed_ekus, max_ttl_seconds,
// allowed_key_algorithms, required_san_patterns, spiffe_uri_pattern,
// allow_short_lived) stay on delete-and-recreate for v1 — closing the
// audit's destructive-rename complaint requires only the simple
// metadata edit. The PUT contract takes a full Partial<CertificateProfile>
// so we forward the existing policy fields untouched.
interface EditProfileModalProps {
  profile: CertificateProfile | null;
  onClose: () => void;
  onSave: (data: Partial<CertificateProfile>) => void;
  isSaving: boolean;
  error: string | null;
}

function EditProfileModal({ profile, onClose, onSave, isSaving, error }: EditProfileModalProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');

  useEffect(() => {
    if (profile) {
      setName(profile.name);
      setDescription(profile.description || '');
    }
  }, [profile]);

  if (!profile) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    onSave({
      // Pass the full struct minus id/timestamps. Backend PUT needs the
      // policy fields preserved so we forward them from the editing target.
      name: name.trim(),
      description: description.trim(),
      allowed_key_algorithms: profile.allowed_key_algorithms,
      max_ttl_seconds: profile.max_ttl_seconds,
      allowed_ekus: profile.allowed_ekus,
      required_san_patterns: profile.required_san_patterns,
      spiffe_uri_pattern: profile.spiffe_uri_pattern,
      allow_short_lived: profile.allow_short_lived,
      enabled: profile.enabled,
    });
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">Edit Profile</h2>
        <p className="text-xs text-ink-muted mb-4 font-mono">{profile.id}</p>
        {error && <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name *</label>
            <input value={name} onChange={e => setName(e.target.value)} required
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400" />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Description</label>
            <textarea value={description} onChange={e => setDescription(e.target.value)} rows={2}
              className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400" />
          </div>
          <p className="text-xs text-ink-faint">
            Policy fields (TTL, EKUs, key algorithms, SAN patterns) stay on the
            create-recreate path for v1. See CHANGELOG B-1 known follow-ups.
          </p>
          <div className="flex gap-2 pt-4">
            <button type="submit" disabled={isSaving} className="flex-1 btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed">
              {isSaving ? 'Saving...' : 'Save Changes'}
            </button>
            <button type="button" onClick={onClose} className="flex-1 btn btn-ghost">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}
