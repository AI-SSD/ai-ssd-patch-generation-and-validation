function FilterBar({ filters, onFilterChange, options }) {
  return (
    <div className="flex flex-wrap gap-4 p-4 bg-dark-800 rounded-lg border border-dark-600">
      {options.cves && (
        <div className="flex flex-col gap-1">
          <label className="text-xs text-gray-500">CVE</label>
          <select
            value={filters.cve || ''}
            onChange={(e) => onFilterChange({ ...filters, cve: e.target.value })}
            className="bg-dark-700 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="">All CVEs</option>
            {options.cves.map((cve) => (
              <option key={cve} value={cve}>{cve}</option>
            ))}
          </select>
        </div>
      )}

      {options.models && (
        <div className="flex flex-col gap-1">
          <label className="text-xs text-gray-500">Model</label>
          <select
            value={filters.model || ''}
            onChange={(e) => onFilterChange({ ...filters, model: e.target.value })}
            className="bg-dark-700 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="">All Models</option>
            {options.models.map((model) => (
              <option key={model} value={model}>{model}</option>
            ))}
          </select>
        </div>
      )}

      {options.statuses && (
        <div className="flex flex-col gap-1">
          <label className="text-xs text-gray-500">Status</label>
          <select
            value={filters.status || ''}
            onChange={(e) => onFilterChange({ ...filters, status: e.target.value })}
            className="bg-dark-700 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="">All Statuses</option>
            {options.statuses.map((status) => (
              <option key={status} value={status}>{status}</option>
            ))}
          </select>
        </div>
      )}

      {options.showPocBlocked && (
        <div className="flex flex-col gap-1">
          <label className="text-xs text-gray-500">PoC Blocked</label>
          <select
            value={filters.pocBlocked === undefined ? '' : filters.pocBlocked.toString()}
            onChange={(e) => onFilterChange({ 
              ...filters, 
              pocBlocked: e.target.value === '' ? undefined : e.target.value === 'true' 
            })}
            className="bg-dark-700 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="">All</option>
            <option value="true">Blocked</option>
            <option value="false">Not Blocked</option>
          </select>
        </div>
      )}

      {options.showSastPassed && (
        <div className="flex flex-col gap-1">
          <label className="text-xs text-gray-500">SAST Passed</label>
          <select
            value={filters.sastPassed === undefined ? '' : filters.sastPassed.toString()}
            onChange={(e) => onFilterChange({ 
              ...filters, 
              sastPassed: e.target.value === '' ? undefined : e.target.value === 'true' 
            })}
            className="bg-dark-700 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="">All</option>
            <option value="true">Passed</option>
            <option value="false">Failed</option>
          </select>
        </div>
      )}

      <div className="flex flex-col gap-1">
        <label className="text-xs text-gray-500">&nbsp;</label>
        <button
          onClick={() => onFilterChange({})}
          className="px-4 py-2 text-sm text-gray-400 hover:text-white border border-dark-600 rounded-lg hover:border-gray-500 transition-colors"
        >
          Clear Filters
        </button>
      </div>
    </div>
  );
}

export default FilterBar;
