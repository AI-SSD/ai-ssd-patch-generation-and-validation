import { useState, useEffect } from 'react';
import { Bug } from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  Legend,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import api from '../api';
import DataTable from '../components/DataTable';

const COLORS = ['#22c55e', '#f59e0b', '#ef4444', '#3b82f6'];
const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#3b82f6',
  style: '#8b5cf6',
  information: '#6b7280'
};

function SastFindings() {
  const [sastData, setSastData] = useState([]);
  const [chartData, setChartData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [findingsRes, chartRes] = await Promise.all([
        api.getSastFindings(),
        api.getChartData('sast-by-tool')
      ]);
      setSastData(findingsRes.data);
      setChartData(chartRes.data);
    } catch (error) {
      console.error('Error fetching SAST data:', error);
    }
    setLoading(false);
  };

  // Calculate severity distribution
  const severityDist = {};
  sastData.forEach(item => {
    item.findings?.forEach(finding => {
      const sev = finding.severity || 'unknown';
      severityDist[sev] = (severityDist[sev] || 0) + 1;
    });
  });

  const severityPieData = Object.entries(severityDist).map(([name, value]) => ({
    name,
    value
  }));

  // Flatten findings for table
  const allFindings = sastData.flatMap(item => 
    (item.findings || []).map(f => ({
      ...f,
      cve_id: item.cve_id,
      model_name: item.model_name
    }))
  );

  const columns = [
    { key: 'cve_id', label: 'CVE' },
    { key: 'model_name', label: 'Model' },
    { key: 'tool', label: 'Tool' },
    { 
      key: 'severity', 
      label: 'Severity',
      render: (value) => (
        <span 
          className="px-2 py-0.5 rounded text-xs"
          style={{ 
            backgroundColor: `${SEVERITY_COLORS[value] || SEVERITY_COLORS.information}20`,
            color: SEVERITY_COLORS[value] || SEVERITY_COLORS.information
          }}
        >
          {value}
        </span>
      )
    },
    { 
      key: 'message', 
      label: 'Message',
      render: (value) => (
        <span className="text-sm truncate max-w-md block" title={value}>
          {value}
        </span>
      )
    },
    { 
      key: 'line', 
      label: 'Line',
      render: (value) => value || 'N/A'
    }
  ];

  const toolColumns = [
    { key: 'tool', label: 'Tool' },
    { key: 'total', label: 'Total Runs' },
    { key: 'passed', label: 'Passed' },
    { 
      key: 'passRate', 
      label: 'Pass Rate',
      render: (value) => `${value}%`
    },
    { key: 'critical', label: 'Critical' },
    { key: 'high', label: 'High' },
    { key: 'medium', label: 'Medium' },
    { key: 'low', label: 'Low' }
  ];

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
          <Bug className="w-6 h-6 text-blue-500" />
          SAST Findings
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          Static Application Security Testing results
        </p>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
          <p className="text-gray-400 text-sm">Total Findings</p>
          <p className="text-2xl font-bold text-white">{allFindings.length}</p>
        </div>
        <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
          <p className="text-gray-400 text-sm">Critical</p>
          <p className="text-2xl font-bold text-red-400">{severityDist.critical || 0}</p>
        </div>
        <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
          <p className="text-gray-400 text-sm">High</p>
          <p className="text-2xl font-bold text-orange-400">{severityDist.high || 0}</p>
        </div>
        <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
          <p className="text-gray-400 text-sm">Medium/Low</p>
          <p className="text-2xl font-bold text-yellow-400">
            {(severityDist.medium || 0) + (severityDist.low || 0)}
          </p>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Findings by Tool */}
        <div className="bg-dark-800 rounded-xl p-6 border border-dark-600">
          <h2 className="text-lg font-semibold text-white mb-4">Findings by Tool</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis dataKey="tool" stroke="#666" />
                <YAxis stroke="#666" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333' }}
                  labelStyle={{ color: '#fff' }}
                />
                <Legend />
                <Bar dataKey="critical" name="Critical" fill="#ef4444" stackId="a" />
                <Bar dataKey="high" name="High" fill="#f97316" stackId="a" />
                <Bar dataKey="medium" name="Medium" fill="#f59e0b" stackId="a" />
                <Bar dataKey="low" name="Low" fill="#3b82f6" stackId="a" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-dark-800 rounded-xl p-6 border border-dark-600">
          <h2 className="text-lg font-semibold text-white mb-4">Severity Distribution</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityPieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                >
                  {severityPieData.map((entry, index) => (
                    <Cell 
                      key={`cell-${index}`} 
                      fill={SEVERITY_COLORS[entry.name] || COLORS[index % COLORS.length]} 
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Tool Summary Table */}
      <div className="bg-dark-800 rounded-xl border border-dark-600 overflow-hidden">
        <div className="p-4 border-b border-dark-600">
          <h2 className="text-lg font-semibold text-white">Tool Summary</h2>
        </div>
        <DataTable columns={toolColumns} data={chartData} />
      </div>

      {/* All Findings Table */}
      <div className="bg-dark-800 rounded-xl border border-dark-600 overflow-hidden">
        <div className="p-4 border-b border-dark-600">
          <h2 className="text-lg font-semibold text-white">All Findings ({allFindings.length})</h2>
        </div>
        <DataTable columns={columns} data={allFindings} />
      </div>
    </div>
  );
}

export default SastFindings;
