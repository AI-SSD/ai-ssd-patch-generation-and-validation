import { useState, useEffect } from 'react';
import { 
  Activity, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  ShieldCheck,
  RefreshCcw,
  Layers,
  Cpu
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
  LineChart,
  Line
} from 'recharts';
import api from '../api';
import StatCard from '../components/StatCard';
import IssueCard from '../components/IssueCard';

const COLORS = ['#22c55e', '#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6'];

function Dashboard() {
  const [overview, setOverview] = useState(null);
  const [issues, setIssues] = useState([]);
  const [successByModel, setSuccessByModel] = useState([]);
  const [successByCVE, setSuccessByCVE] = useState([]);
  const [phases, setPhases] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [overviewRes, issuesRes, modelChartRes, cveChartRes, phasesRes] = await Promise.all([
        api.getOverview(),
        api.getIssues(),
        api.getChartData('success-by-model'),
        api.getChartData('success-by-cve'),
        api.getPhases()
      ]);
      
      setOverview(overviewRes.data);
      setIssues(issuesRes.data);
      setSuccessByModel(modelChartRes.data);
      setSuccessByCVE(cveChartRes.data);
      setPhases(phasesRes.data);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    }
    setLoading(false);
  };

  const handleRefresh = async () => {
    try {
      await api.refreshData();
      fetchData();
    } catch (error) {
      console.error('Error refreshing data:', error);
    }
  };

  const formatDuration = (seconds) => {
    if (!seconds) return '0s';
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    if (hrs > 0) return `${hrs}h ${mins}m`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
  };

  const majorIssues = issues.filter(i => i.type === 'major');

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <RefreshCcw className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const pieData = [
    { name: 'PoC Blocked', value: parseInt(overview?.pocBlockedRate || 0) },
    { name: 'PoC Active', value: 100 - parseInt(overview?.pocBlockedRate || 0) }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard Overview</h1>
          <p className="text-gray-400 text-sm mt-1">
            Last run: {overview?.lastRunTimestamp ? new Date(overview.lastRunTimestamp).toLocaleString() : 'N/A'}
          </p>
        </div>
        <button
          onClick={handleRefresh}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
        >
          <RefreshCcw className="w-4 h-4" />
          Refresh Data
        </button>
      </div>

      {/* Major Issues Alert */}
      {majorIssues.length > 0 && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
          <h2 className="text-lg font-semibold text-red-400 mb-3 flex items-center gap-2">
            <XCircle className="w-5 h-5" />
            Major Issues ({majorIssues.length})
          </h2>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {majorIssues.slice(0, 5).map((issue, idx) => (
              <IssueCard key={idx} issue={issue} />
            ))}
            {majorIssues.length > 5 && (
              <p className="text-sm text-gray-400 text-center py-2">
                +{majorIssues.length - 5} more issues
              </p>
            )}
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Validations"
          value={overview?.totalValidations || 0}
          subtitle={`${overview?.totalCVEs || 0} CVEs, ${overview?.totalModels || 0} Models`}
          icon={Activity}
          color="blue"
        />
        <StatCard
          title="Success Rate"
          value={`${overview?.successRate || 0}%`}
          subtitle="PoC Blocked"
          icon={CheckCircle2}
          color={parseFloat(overview?.successRate) >= 70 ? 'green' : 'red'}
        />
        <StatCard
          title="SAST Pass Rate"
          value={`${overview?.sastPassRate || 0}%`}
          subtitle="Static Analysis"
          icon={ShieldCheck}
          color="purple"
        />
        <StatCard
          title="Total Duration"
          value={formatDuration(overview?.totalDuration)}
          subtitle={`${overview?.phasesCompleted || 0} phases completed`}
          icon={Clock}
          color="yellow"
        />
      </div>

      {/* Pipeline Phases */}
      <div className="bg-dark-800 rounded-xl p-6 border border-dark-600">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Layers className="w-5 h-5 text-blue-500" />
          Pipeline Phases
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {phases.map((phase, idx) => (
            <div
              key={idx}
              className={`p-4 rounded-lg border ${
                phase.status === 'success'
                  ? 'bg-green-500/10 border-green-500/30'
                  : 'bg-red-500/10 border-red-500/30'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-gray-400">Phase {phase.phase}</span>
                {phase.status === 'success' ? (
                  <CheckCircle2 className="w-4 h-4 text-green-500" />
                ) : (
                  <XCircle className="w-4 h-4 text-red-500" />
                )}
              </div>
              <h3 className="text-white font-medium">{phase.name}</h3>
              <p className="text-sm text-gray-400 mt-1">
                {formatDuration(phase.duration_seconds)}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Success by Model Chart */}
        <div className="bg-dark-800 rounded-xl p-6 border border-dark-600">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-blue-500" />
            Success Rate by Model
          </h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={successByModel} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis type="number" domain={[0, 'auto']} stroke="#666" />
                <YAxis 
                  dataKey="name" 
                  type="category" 
                  width={120} 
                  stroke="#666"
                  tick={{ fontSize: 12 }}
                />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333' }}
                  labelStyle={{ color: '#fff' }}
                />
                <Bar dataKey="successful" name="Successful" fill="#22c55e" stackId="a" />
                <Bar dataKey="failed" name="Failed" fill="#ef4444" stackId="a" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Success Rate Pie Chart */}
        <div className="bg-dark-800 rounded-xl p-6 border border-dark-600">
          <h2 className="text-lg font-semibold text-white mb-4">Overall PoC Blocking Rate</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}%`}
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
      </div>

      {/* Success by CVE Chart */}
      <div className="bg-dark-800 rounded-xl p-6 border border-dark-600">
        <h2 className="text-lg font-semibold text-white mb-4">Patch Results by CVE</h2>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={successByCVE}>
              <CartesianGrid strokeDasharray="3 3" stroke="#333" />
              <XAxis dataKey="name" stroke="#666" />
              <YAxis stroke="#666" />
              <Tooltip
                contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333' }}
                labelStyle={{ color: '#fff' }}
              />
              <Legend />
              <Bar dataKey="successful" name="PoC Blocked" fill="#22c55e" />
              <Bar dataKey="failed" name="PoC Active" fill="#ef4444" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
