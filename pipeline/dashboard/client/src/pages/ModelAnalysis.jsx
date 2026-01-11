import { useState, useEffect } from 'react';
import { Cpu } from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  Legend,
  ScatterChart,
  Scatter,
  ZAxis,
  Cell
} from 'recharts';
import api from '../api';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';

const COLORS = ['#22c55e', '#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#ec4899'];

function ModelAnalysis() {
  const [models, setModels] = useState([]);
  const [chartData, setChartData] = useState([]);
  const [executionData, setExecutionData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedModel, setSelectedModel] = useState(null);
  const [modelValidations, setModelValidations] = useState([]);

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    if (selectedModel) {
      fetchModelValidations(selectedModel);
    }
  }, [selectedModel]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [modelsRes, chartRes, execRes] = await Promise.all([
        api.getModels(),
        api.getChartData('success-by-model'),
        api.getChartData('execution-time')
      ]);
      setModels(modelsRes.data);
      setChartData(chartRes.data);
      setExecutionData(execRes.data);
    } catch (error) {
      console.error('Error fetching model data:', error);
    }
    setLoading(false);
  };

  const fetchModelValidations = async (modelName) => {
    try {
      const response = await api.getValidations({ model: modelName });
      setModelValidations(response.data);
    } catch (error) {
      console.error('Error fetching model validations:', error);
    }
  };

  const columns = [
    { key: 'model_name', label: 'Model' },
    { key: 'total_validations', label: 'Total Tests' },
    { key: 'successful', label: 'Successful' },
    { key: 'failed', label: 'Failed' },
    { 
      key: 'success_rate', 
      label: 'Success Rate',
      render: (value) => (
        <span className={parseFloat(value) >= 50 ? 'text-green-400' : 'text-red-400'}>
          {value}%
        </span>
      )
    },
    { 
      key: 'sast_pass_rate', 
      label: 'SAST Pass',
      render: (value) => `${value}%`
    },
    { 
      key: 'avg_execution_time', 
      label: 'Avg Time',
      render: (value) => `${value}s`
    },
    { 
      key: 'cves_tested', 
      label: 'CVEs',
      render: (value) => value?.length || 0
    }
  ];

  const validationColumns = [
    { key: 'cve_id', label: 'CVE' },
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
      key: 'sast_passed', 
      label: 'SAST',
      render: (value) => <StatusBadge status={value} />
    },
    { 
      key: 'execution_time_seconds', 
      label: 'Duration',
      render: (value) => `${value?.toFixed(1)}s`
    }
  ];

  // Prepare scatter data
  const scatterData = executionData.map((d, idx) => ({
    ...d,
    index: idx,
    statusValue: d.status === 'Success' ? 1 : 0
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
          <Cpu className="w-6 h-6 text-blue-500" />
          Model Analysis
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          Performance comparison across different LLM models
        </p>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Success by Model */}
        <div className="bg-dark-800 rounded-xl p-6 border border-dark-600">
          <h2 className="text-lg font-semibold text-white mb-4">Success Rate by Model</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis type="number" stroke="#666" />
                <YAxis 
                  dataKey="name" 
                  type="category" 
                  width={130} 
                  stroke="#666"
                  tick={{ fontSize: 11 }}
                />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333' }}
                  labelStyle={{ color: '#fff' }}
                />
                <Legend />
                <Bar dataKey="successful" name="Successful" fill="#22c55e" stackId="a" />
                <Bar dataKey="failed" name="Failed" fill="#ef4444" stackId="a" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Execution Time Distribution */}
        <div className="bg-dark-800 rounded-xl p-6 border border-dark-600">
          <h2 className="text-lg font-semibold text-white mb-4">Execution Time Distribution</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis 
                  dataKey="index" 
                  name="Test" 
                  stroke="#666" 
                  label={{ value: 'Test Index', position: 'bottom', fill: '#666' }}
                />
                <YAxis 
                  dataKey="executionTime" 
                  name="Time (s)" 
                  stroke="#666"
                  label={{ value: 'Seconds', angle: -90, position: 'insideLeft', fill: '#666' }}
                />
                <ZAxis dataKey="model" name="Model" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333' }}
                  labelStyle={{ color: '#fff' }}
                  formatter={(value, name) => {
                    if (name === 'Time (s)') return [`${value?.toFixed(1)}s`, 'Duration'];
                    return [value, name];
                  }}
                />
                <Scatter name="Validations" data={scatterData}>
                  {scatterData.map((entry, index) => (
                    <Cell 
                      key={`cell-${index}`} 
                      fill={entry.status === 'Success' ? '#22c55e' : '#ef4444'} 
                    />
                  ))}
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Model Comparison Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {models.map((model, idx) => (
          <div
            key={model.model_name}
            onClick={() => setSelectedModel(model.model_name)}
            className="bg-dark-800 rounded-xl p-4 border border-dark-600 cursor-pointer hover:border-blue-500 transition-colors"
          >
            <div className="flex items-center justify-between mb-3">
              <div 
                className="w-3 h-3 rounded-full" 
                style={{ backgroundColor: COLORS[idx % COLORS.length] }}
              />
              <span className={`text-xs px-2 py-1 rounded ${
                parseFloat(model.success_rate) >= 50 
                  ? 'bg-green-500/20 text-green-400' 
                  : 'bg-red-500/20 text-red-400'
              }`}>
                {model.success_rate}%
              </span>
            </div>
            <h3 className="text-white font-medium text-sm truncate">{model.model_name}</h3>
            <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-gray-500">Tests:</span>
                <span className="text-white ml-1">{model.total_validations}</span>
              </div>
              <div>
                <span className="text-gray-500">Avg:</span>
                <span className="text-white ml-1">{model.avg_execution_time}s</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Model Table */}
      <div className="bg-dark-800 rounded-xl border border-dark-600 overflow-hidden">
        <div className="p-4 border-b border-dark-600">
          <h2 className="text-lg font-semibold text-white">Model Summary</h2>
        </div>
        <DataTable
          columns={columns}
          data={models}
          onRowClick={(row) => setSelectedModel(row.model_name)}
        />
      </div>

      {/* Model Detail Modal */}
      {selectedModel && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-dark-800 rounded-xl border border-dark-600 p-6 max-w-4xl w-full mx-4 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-white">{selectedModel} Validations</h2>
              <button
                onClick={() => setSelectedModel(null)}
                className="text-gray-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <DataTable columns={validationColumns} data={modelValidations} />
          </div>
        </div>
      )}
    </div>
  );
}

export default ModelAnalysis;
