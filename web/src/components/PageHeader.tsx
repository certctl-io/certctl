interface PageHeaderProps {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
}

export default function PageHeader({ title, subtitle, action }: PageHeaderProps) {
  return (
    <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700 bg-slate-800">
      <div>
        <h2 className="text-lg font-semibold">{title}</h2>
        {subtitle && <p className="text-sm text-slate-400 mt-0.5">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}
