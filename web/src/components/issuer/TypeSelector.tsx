/**
 * Issuer type selector grid. Used in both the catalog view and create wizard.
 * M34 will reuse this for its 3-step wizard (Select Type step).
 */
import { issuerTypes, type IssuerTypeConfig } from '../../config/issuerTypes';

interface TypeSelectorProps {
  onSelect: (typeId: string) => void;
  /** Filter to only show these type IDs. If not provided, shows all non-comingSoon types. */
  filterIds?: string[];
}

export default function TypeSelector({ onSelect, filterIds }: TypeSelectorProps) {
  const types = filterIds
    ? issuerTypes.filter(t => filterIds.includes(t.id))
    : issuerTypes.filter(t => !t.comingSoon);

  return (
    <div className="grid grid-cols-2 gap-4">
      {types.map((type: IssuerTypeConfig) => (
        <button
          key={type.id}
          onClick={() => onSelect(type.id)}
          className="p-4 border border-surface-border rounded-lg hover:border-brand-500 hover:bg-opacity-5 transition-all text-left"
        >
          <div className="flex items-center gap-2">
            <span className="text-lg">{type.icon}</span>
            <span className="font-medium text-ink">{type.name}</span>
          </div>
          <div className="text-sm text-ink-muted mt-1">{type.description}</div>
        </button>
      ))}
    </div>
  );
}
