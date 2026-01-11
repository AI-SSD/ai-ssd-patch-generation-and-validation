import { AlertTriangle, XCircle, AlertCircle } from 'lucide-react';

function IssueCard({ issue }) {
  const issueMeta = {
    major: {
      icon: XCircle,
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/30',
      textColor: 'text-red-500',
      badge: 'bg-red-500'
    },
    warning: {
      icon: AlertTriangle,
      bgColor: 'bg-yellow-500/10',
      borderColor: 'border-yellow-500/30',
      textColor: 'text-yellow-500',
      badge: 'bg-yellow-500'
    },
    info: {
      icon: AlertCircle,
      bgColor: 'bg-blue-500/10',
      borderColor: 'border-blue-500/30',
      textColor: 'text-blue-500',
      badge: 'bg-blue-500'
    }
  };

  const meta = issueMeta[issue.type] || issueMeta.info;
  const Icon = meta.icon;

  return (
    <div className={`${meta.bgColor} ${meta.borderColor} border rounded-lg p-4`}>
      <div className="flex items-start gap-3">
        <Icon className={`w-5 h-5 ${meta.textColor} flex-shrink-0 mt-0.5`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`px-2 py-0.5 text-xs font-medium text-white rounded ${meta.badge}`}>
              {issue.type.toUpperCase()}
            </span>
            <span className="text-xs text-gray-500">{issue.category}</span>
          </div>
          <h4 className="text-white font-medium truncate">{issue.title}</h4>
          <p className="text-gray-400 text-sm mt-1 line-clamp-2">{issue.description}</p>
          <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
            {issue.cve && <span>CVE: {issue.cve}</span>}
            {issue.model && <span>Model: {issue.model}</span>}
            {issue.timestamp && (
              <span>{new Date(issue.timestamp).toLocaleString()}</span>
            )}
            {issue.attempts && <span>Attempts: {issue.attempts}</span>}
          </div>
        </div>
      </div>
    </div>
  );
}

export default IssueCard;
