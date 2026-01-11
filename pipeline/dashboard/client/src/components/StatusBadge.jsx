function StatusBadge({ status, type = 'default' }) {
  const statusStyles = {
    // General statuses
    success: 'bg-green-500/20 text-green-400 border-green-500/30',
    Success: 'bg-green-500/20 text-green-400 border-green-500/30',
    failed: 'bg-red-500/20 text-red-400 border-red-500/30',
    Failed: 'bg-red-500/20 text-red-400 border-red-500/30',
    warning: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    pending: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    
    // Specific statuses
    'PoC Still Works': 'bg-red-500/20 text-red-400 border-red-500/30',
    'PoC Blocked': 'bg-green-500/20 text-green-400 border-green-500/30',
    unpatchable: 'bg-red-500/20 text-red-400 border-red-500/30',
    patched: 'bg-green-500/20 text-green-400 border-green-500/30',
    
    // Boolean displays
    true: 'bg-green-500/20 text-green-400 border-green-500/30',
    false: 'bg-red-500/20 text-red-400 border-red-500/30',
    
    // Default
    default: 'bg-gray-500/20 text-gray-400 border-gray-500/30'
  };

  const style = statusStyles[status] || statusStyles.default;
  const displayText = typeof status === 'boolean' ? (status ? 'Yes' : 'No') : status;

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${style}`}>
      {displayText}
    </span>
  );
}

export default StatusBadge;
