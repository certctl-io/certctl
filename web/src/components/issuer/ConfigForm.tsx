/**
 * Renders config fields from an IssuerTypeConfig.configFields definition.
 * Handles sensitive field masking. M34 will reuse this directly for its
 * dynamic config wizard. M35 can reuse it for target config forms.
 */
import type { ConfigField } from '../../config/issuerTypes';

interface ConfigFormProps {
  fields: ConfigField[];
  values: Record<string, unknown>;
  onChange: (key: string, value: unknown) => void;
  /** When true, sensitive fields show as ******** with a "Change" button.
   *  Used in edit mode — empty value means "keep existing". */
  editMode?: boolean;
}

export default function ConfigForm({ fields, values, onChange, editMode }: ConfigFormProps) {
  return (
    <div className="space-y-5">
      {fields.map((field) => (
        <ConfigFieldInput
          key={field.key}
          field={field}
          value={values[field.key]}
          onChange={(v) => onChange(field.key, v)}
          editMode={editMode}
        />
      ))}
    </div>
  );
}

function ConfigFieldInput({
  field,
  value,
  onChange,
  editMode,
}: {
  field: ConfigField;
  value: unknown;
  onChange: (v: unknown) => void;
  editMode?: boolean;
}) {
  const inputCls =
    'w-full px-3 py-2 bg-surface border border-surface-border rounded text-ink placeholder-ink-faint focus:outline-none focus:border-brand-500 transition-colors';

  // In edit mode, sensitive fields that haven't been touched show as masked
  if (editMode && field.sensitive && value === undefined) {
    return (
      <div>
        <FieldLabel field={field} />
        <div className="flex items-center gap-2">
          <span className="text-sm text-ink-muted font-mono">********</span>
          <button
            type="button"
            onClick={() => onChange('')}
            className="text-xs text-brand-400 hover:text-brand-500"
          >
            Change
          </button>
        </div>
      </div>
    );
  }

  if (field.type === 'select') {
    return (
      <div>
        <FieldLabel field={field} />
        <select
          value={(value as string) || ''}
          onChange={(e) => onChange(e.target.value)}
          className={inputCls}
        >
          <option value="">Select {field.label}</option>
          {field.options?.map((opt) => (
            <option key={opt} value={opt}>{opt}</option>
          ))}
        </select>
      </div>
    );
  }

  if (field.type === 'textarea') {
    return (
      <div>
        <FieldLabel field={field} />
        <textarea
          value={(value as string) || ''}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          rows={4}
          className={`${inputCls} font-mono text-xs`}
        />
      </div>
    );
  }

  if (field.type === 'number') {
    return (
      <div>
        <FieldLabel field={field} />
        <input
          type="number"
          value={(value as number | string) ?? ''}
          onChange={(e) => onChange(e.target.value ? parseInt(e.target.value, 10) : '')}
          placeholder={field.placeholder}
          className={inputCls}
        />
      </div>
    );
  }

  // text or password
  return (
    <div>
      <FieldLabel field={field} />
      <input
        type={field.type === 'password' ? 'password' : 'text'}
        value={(value as string) || ''}
        onChange={(e) => onChange(e.target.value)}
        placeholder={field.placeholder}
        className={inputCls}
      />
    </div>
  );
}

function FieldLabel({ field }: { field: ConfigField }) {
  return (
    <label className="block text-sm font-medium text-ink mb-2">
      {field.label}
      {field.required && <span className="text-red-600 ml-1">*</span>}
      {field.sensitive && (
        <span className="ml-2 text-xs text-yellow-500 font-normal">sensitive</span>
      )}
    </label>
  );
}
