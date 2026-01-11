import { useState, useEffect } from 'react';
import { FileCode2 } from 'lucide-react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  ResponsiveContainer,
  Tooltip,
  Legend
} from 'recharts';
import api from '../api';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';

const COLORS = ['#22c55e', '#ef4444', '#f59e0b', '#3b82f6'];

function Patches() {
  const [patches, setPatches] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchPatches();
  }, []);

  const fetchPatches = async () => {
    setLoading(true);
    try {
      const response = await api.getPatches();
      setPatches(response.data);
    } catch (error) {
      console.error('Error fetching patches:', error);
    }
    setLoading(false);
  };

  const columns = [
    { key: 'cve_id', label: 'CVE ID' },
    { key: 'function_name', label: 'Function' },
    { key: 'model', label: 'Model' },
    { 
      key: 'success', 
      label: 'Generated',
      render: (value) => <StatusBadge status={value} />
    },
    { 
      key: 'syntax_valid', 
      label: 'Syntax Valid',
      render: (value) => <StatusBadge status={value} />
    },
    { 
      key: 'response_tokens', 
      label: 'Tokens',
      render: (value) => value || 'N/A'
    },
    { 
      key: 'total_duration', 
      label: 'Duration',
      render: (value) => value ? `${(value / 1e9).toFixed(2)}s` : 'N/A'
    }
  ];

  // Calculate summary stats
  const totalPatches = patches.length;
  const successfulGeneration = patches.filter(p => p.success).length;
  const syntaxValid = patches.filter(p => p.syntax_valid).length;
  const syntaxInvalid = patches.filter(p => p.success && !p.syntax_valid).length;

  const pieData = [
    { name: 'Valid Syntax', value: syntaxValid },
    { name: 'Invalid Syntax', value: syntaxInvalid },
    { name: 'Generation Failed', value: totalPatches - successfulGeneration }
  ].filter(d => d.value > 0);

  // Group by CVE
  const patchesByCVE = patches.reduce((acc, patch) => {
    const cve = patch.cve_id;
    if (!acc[cve]) acc[cve] = [];
    acc[cve].push(patch);
    return acc;
  }, {});

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
          <FileCode2 className="w-6 h-6 text-blue-500" />
          Patch Generation
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          LLM-generated patches for vulnerability remediation
        </p>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
          <p className="text-gray-400 text-sm">Total Patches</p>
          <p className="text-2xl font-bold text-white">{totalPatches}</p>
        </div>
        <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
          <p className="text-gray-400 text-sm">Successfully Generated</p>
          <p className="text-2xl font-bold text-green-400">{successfulGeneration}</p>
        </div>
        <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
          <p className="text-gray-400 text-sm">Syntax Valid</p>
          <p className="text-2xl font-bold text-blue-400">{syntaxValid}</p>
        </div>
        <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
          <p className="text-gray-400 text-sm">Syntax Invalid</p>
          <p className="text-2xl font-bold text-red-400">{syntaxInvalid}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Pie Chart */}
        <div className="bg-dark-800 rounded-xl p-6 border border-dark-600">
          <h2 className="text-lg font-semibold text-white mb-4">Generation Results</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                  label={({ name, percent }) => `${(percent * 100).toFixed(0)}%`}
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333' }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Patches by CVE */}
        <div className="lg:col-span-2 bg-dark-800 rounded-xl p-6 border border-dark-600">
          <h2 className="text-lg font-semibold text-white mb-4">Patches by CVE</h2>
          <div className="space-y-4">
            {Object.entries(patchesByCVE).map(([cve, cvePatches]) => (
              <div key={cve} className="bg-dark-700 rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-white font-medium">{cve}</h3>
                  <span className="text-sm text-gray-400">
                    {cvePatches.filter(p => p.syntax_valid).length}/{cvePatches.length} valid
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {cvePatches.map((patch, idx) => (
                    <span
                      key={idx}
                      className={`text-xs px-2 py-1 rounded ${
                        patch.syntax_valid
                          ? 'bg-green-500/20 text-green-400'
                          : 'bg-red-500/20 text-red-400'
                      }`}
                    >
                      {patch.model}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Patches Table */}
      <div className="bg-dark-800 rounded-xl border border-dark-600 overflow-hidden">
        <div className="p-4 border-b border-dark-600">
          <h2 className="text-lg font-semibold text-white">All Patches</h2>
        </div>
        <DataTable columns={columns} data={patches} />
      </div>
    </div>
  );
}

export default Patches;
