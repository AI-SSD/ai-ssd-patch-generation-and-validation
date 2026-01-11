import { useState, useEffect } from 'react';
import { ShieldAlert } from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  Legend
} from 'recharts';
import api from '../api';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';

function CVEAnalysis() {
  const [cves, setCVEs] = useState([]);
  const [chartData, setChartData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCVE, setSelectedCVE] = useState(null);
  const [cveValidations, setCVEValidations] = useState([]);

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    if (selectedCVE) {
      fetchCVEValidations(selectedCVE);
    }
  }, [selectedCVE]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [cvesRes, chartRes] = await Promise.all([
        api.getCVEs(),
        api.getChartData('success-by-cve')
      ]);
      setCVEs(cvesRes.data);
      setChartData(chartRes.data);
    } catch (error) {
      console.error('Error fetching CVE data:', error);
    }
    setLoading(false);
  };

  const fetchCVEValidations = async (cveId) => {
    try {
      const response = await api.getValidations({ cve: cveId });
      setCVEValidations(response.data);
    } catch (error) {
      console.error('Error fetching CVE validations:', error);
    }
  };

  const columns = [
    { key: 'cve_id', label: 'CVE ID' },
    { key: 'total_validations', label: 'Total Tests' },
    { key: 'successful', label: 'Successful' },
    { key: 'failed', label: 'Failed' },
    { 
      key: 'success_rate', 
      label: 'Success Rate',
      render: (value) => (
        <span className={parseFloat(value) >= 70 ? 'text-green-400' : 'text-red-400'}>
          {value}%
        </span>
      )
    },
    { 
      key: 'avg_execution_time', 
      label: 'Avg Time',
      render: (value) => `${value}s`
    },
    { 
      key: 'models_tested', 
      label: 'Models',
      render: (value) => value?.length || 0
    }
  ];

  const validationColumns = [
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
      key: 'execution_time_seconds', 
      label: 'Duration',
      render: (value) => `${value?.toFixed(1)}s`
    }
  ];

  const radarData = cves.map(cve => ({
    cve: cve.cve_id.replace('CVE-', ''),
    successRate: parseFloat(cve.success_rate),
    tests: cve.total_validations * 10,
    models: cve.models_tested?.length * 25 || 0
  }));

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <ShieldAlert className="w-6 h-6 text-blue-500" />
          CVE Analysis
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          Analysis of patch effectiveness by vulnerability
        </p>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Bar Chart */}
        <div className="bg-dark-800 rounded-xl p-6 border border-dark-600">
          <h2 className="text-lg font-semibold text-white mb-4">Patch Results by CVE</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis dataKey="name" stroke="#666" tick={{ fontSize: 11 }} />
                <YAxis stroke="#666" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333' }}
                  labelStyle={{ color: '#fff' }}
                />
                <Legend />
                <Bar dataKey="successful" name="Blocked" fill="#22c55e" />
                <Bar dataKey="failed" name="Active" fill="#ef4444" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Radar Chart */}
        <div className="bg-dark-800 rounded-xl p-6 border border-dark-600">
          <h2 className="text-lg font-semibold text-white mb-4">CVE Comparison</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData}>
                <PolarGrid stroke="#333" />
                <PolarAngleAxis dataKey="cve" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#666' }} />
                <Radar
                  name="Success Rate %"
                  dataKey="successRate"
                  stroke="#22c55e"
                  fill="#22c55e"
                  fillOpacity={0.3}
                />
                <Legend />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* CVE Table */}
      <div className="bg-dark-800 rounded-xl border border-dark-600 overflow-hidden">
        <div className="p-4 border-b border-dark-600">
          <h2 className="text-lg font-semibold text-white">CVE Summary</h2>
        </div>
        <DataTable
          columns={columns}
          data={cves}
          onRowClick={(row) => setSelectedCVE(row.cve_id)}
        />
      </div>

      {/* CVE Detail Modal */}
      {selectedCVE && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-dark-800 rounded-xl border border-dark-600 p-6 max-w-4xl w-full mx-4 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-white">{selectedCVE} Validations</h2>
              <button
                onClick={() => setSelectedCVE(null)}
                className="text-gray-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <DataTable columns={validationColumns} data={cveValidations} />
          </div>
        </div>
      )}
    </div>
  );
}

export default CVEAnalysis;
