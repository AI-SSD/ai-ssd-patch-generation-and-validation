import { useState, useEffect } from 'react';
import { CheckCircle2, Search } from 'lucide-react';
import api from '../api';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import FilterBar from '../components/FilterBar';

function Validations() {
  const [validations, setValidations] = useState([]);
  const [filters, setFilters] = useState({});
  const [filterOptions, setFilterOptions] = useState({ cves: [], models: [], statuses: [] });
  const [loading, setLoading] = useState(true);
  const [selectedValidation, setSelectedValidation] = useState(null);

  useEffect(() => {
    fetchValidations();
    fetchFilterOptions();
  }, [filters]);

  const fetchValidations = async () => {
    setLoading(true);
    try {
      const response = await api.getValidations(filters);
      setValidations(response.data);
    } catch (error) {
      console.error('Error fetching validations:', error);
    }
    setLoading(false);
  };

  const fetchFilterOptions = async () => {
    try {
      const [cveRes, modelRes] = await Promise.all([
        api.getCVEs(),
        api.getModels()
      ]);
      setFilterOptions({
        cves: cveRes.data.map(c => c.cve_id),
        models: modelRes.data.map(m => m.model_name),
        statuses: ['Success', 'PoC Still Works']
      });
    } catch (error) {
      console.error('Error fetching filter options:', error);
    }
  };

  const columns = [
    { key: 'cve_id', label: 'CVE ID' },
    { key: 'model_name', label: 'Model' },
    { 
      key: 'status', 
      label: 'Status',
      render: (value) => <StatusBadge status={value} />
    },
    { 
      key: 'poc_blocked', 
      label: 'PoC Blocked',
      render: (value) => <StatusBadge status={value} />
    },
    { 
      key: 'build_success', 
      label: 'Build',
      render: (value) => <StatusBadge status={value} />
    },
    { 
      key: 'sast_passed', 
      label: 'SAST',
      render: (value) => <StatusBadge status={value} />
    },
    { 
      key: 'execution_time_seconds', 
      label: 'Duration',
      render: (value) => `${value?.toFixed(1)}s`
    },
    { 
      key: 'timestamp', 
      label: 'Timestamp',
      render: (value) => new Date(value).toLocaleString()
    }
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <CheckCircle2 className="w-6 h-6 text-blue-500" />
            Validation Results
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            {validations.length} validation records
          </p>
        </div>
      </div>

      <FilterBar
        filters={filters}
        onFilterChange={setFilters}
        options={{
          ...filterOptions,
          showPocBlocked: true,
          showSastPassed: true
        }}
      />

      <div className="bg-dark-800 rounded-xl border border-dark-600 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          </div>
        ) : (
          <DataTable
            columns={columns}
            data={validations}
            onRowClick={setSelectedValidation}
          />
        )}
      </div>

      {/* Detail Modal */}
      {selectedValidation && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-dark-800 rounded-xl border border-dark-600 p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-white">
                {selectedValidation.cve_id} - {selectedValidation.model_name}
              </h2>
              <button
                onClick={() => setSelectedValidation(null)}
                className="text-gray-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-gray-400">Status</label>
                  <div className="mt-1">
                    <StatusBadge status={selectedValidation.status} />
                  </div>
                </div>
                <div>
                  <label className="text-sm text-gray-400">PoC Blocked</label>
                  <div className="mt-1">
                    <StatusBadge status={selectedValidation.poc_blocked} />
                  </div>
                </div>
                <div>
                  <label className="text-sm text-gray-400">Build Success</label>
                  <div className="mt-1">
                    <StatusBadge status={selectedValidation.build_success} />
                  </div>
                </div>
                <div>
                  <label className="text-sm text-gray-400">SAST Passed</label>
                  <div className="mt-1">
                    <StatusBadge status={selectedValidation.sast_passed} />
                  </div>
                </div>
              </div>

              <div>
                <label className="text-sm text-gray-400">Execution Time</label>
                <p className="text-white">{selectedValidation.execution_time_seconds?.toFixed(2)}s</p>
              </div>

              <div>
                <label className="text-sm text-gray-400">Timestamp</label>
                <p className="text-white">{new Date(selectedValidation.timestamp).toLocaleString()}</p>
              </div>

              {selectedValidation.error_message && (
                <div>
                  <label className="text-sm text-gray-400">Error Message</label>
                  <p className="text-red-400 bg-red-500/10 p-3 rounded mt-1">
                    {selectedValidation.error_message}
                  </p>
                </div>
              )}

              {selectedValidation.poc_output && (
                <div>
                  <label className="text-sm text-gray-400">PoC Output</label>
                  <pre className="text-gray-300 bg-dark-900 p-3 rounded mt-1 text-xs overflow-x-auto">
                    {selectedValidation.poc_output}
                  </pre>
                </div>
              )}

              {selectedValidation.sast_findings && selectedValidation.sast_findings.length > 0 && (
                <div>
                  <label className="text-sm text-gray-400">SAST Findings ({selectedValidation.sast_findings.length})</label>
                  <div className="mt-2 space-y-2">
                    {selectedValidation.sast_findings.map((finding, idx) => (
                      <div key={idx} className="bg-dark-700 p-3 rounded text-sm">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-blue-400">{finding.tool}</span>
                          <span className={`text-xs px-2 py-0.5 rounded ${
                            finding.severity === 'error' ? 'bg-red-500/20 text-red-400' :
                            finding.severity === 'warning' ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-gray-500/20 text-gray-400'
                          }`}>
                            {finding.severity}
                          </span>
                        </div>
                        <p className="text-gray-300">{finding.message}</p>
                        {finding.line && (
                          <p className="text-gray-500 text-xs mt-1">Line: {finding.line}</p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Validations;
