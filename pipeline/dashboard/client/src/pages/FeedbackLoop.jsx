import { useState, useEffect } from 'react';
import { RefreshCcw, ChevronRight, ChevronDown } from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  Legend
} from 'recharts';
import api from '../api';
import StatusBadge from '../components/StatusBadge';

function FeedbackLoop() {
  const [feedbackData, setFeedbackData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expandedItems, setExpandedItems] = useState({});

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const response = await api.getFeedbackLoop();
      setFeedbackData(response.data);
    } catch (error) {
      console.error('Error fetching feedback loop data:', error);
    }
    setLoading(false);
  };

  const toggleExpand = (key) => {
    setExpandedItems(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!feedbackData) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-gray-400">No feedback loop data available</p>
      </div>
    );
  }

  const results = feedbackData.results || [];

  // Prepare chart data - showing attempts over time
  const chartData = results.flatMap(r => 
    r.validation_history?.map(h => ({
      attempt: `${r.cve_id.replace('CVE-', '')}-${r.model_name.split(':')[0]}-${h.attempt}`,
      pocBlocked: h.poc_blocked ? 1 : 0,
      sastPassed: h.sast_passed ? 1 : 0,
      cve: r.cve_id,
      model: r.model_name
    })) || []
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <RefreshCcw className="w-6 h-6 text-blue-500" />
          Feedback Loop Results
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          Iterative patch refinement through automated feedback
        </p>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
          <p className="text-gray-400 text-sm">Patches Processed</p>
          <p className="text-2xl font-bold text-white">{feedbackData.total_patches_processed}</p>
        </div>
        <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
          <p className="text-gray-400 text-sm">Successful</p>
          <p className="text-2xl font-bold text-green-400">{feedbackData.successful}</p>
        </div>
        <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
          <p className="text-gray-400 text-sm">Unpatchable</p>
          <p className="text-2xl font-bold text-red-400">{feedbackData.unpatchable}</p>
        </div>
        <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
          <p className="text-gray-400 text-sm">Total Retries</p>
          <p className="text-2xl font-bold text-yellow-400">{feedbackData.total_retry_attempts}</p>
        </div>
      </div>

      {/* Results by Attempt Chart */}
      {chartData.length > 0 && (
        <div className="bg-dark-800 rounded-xl p-6 border border-dark-600">
          <h2 className="text-lg font-semibold text-white mb-4">Retry Progress</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis 
                  dataKey="attempt" 
                  stroke="#666" 
                  tick={{ fontSize: 10 }}
                  angle={-45}
                  textAnchor="end"
                  height={60}
                />
                <YAxis stroke="#666" domain={[0, 1]} ticks={[0, 1]} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333' }}
                  labelStyle={{ color: '#fff' }}
                />
                <Legend />
                <Line 
                  type="stepAfter" 
                  dataKey="pocBlocked" 
                  name="PoC Blocked" 
                  stroke="#22c55e" 
                  strokeWidth={2}
                  dot={true}
                />
                <Line 
                  type="stepAfter" 
                  dataKey="sastPassed" 
                  name="SAST Passed" 
                  stroke="#3b82f6" 
                  strokeWidth={2}
                  dot={true}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Detailed Results */}
      <div className="bg-dark-800 rounded-xl border border-dark-600">
        <div className="p-4 border-b border-dark-600">
          <h2 className="text-lg font-semibold text-white">Detailed Retry History</h2>
        </div>
        <div className="divide-y divide-dark-600">
          {results.map((result, idx) => {
            const key = `${result.cve_id}-${result.model_name}`;
            const isExpanded = expandedItems[key];
            
            return (
              <div key={idx} className="p-4">
                <div 
                  className="flex items-center justify-between cursor-pointer"
                  onClick={() => toggleExpand(key)}
                >
                  <div className="flex items-center gap-3">
                    {isExpanded ? (
                      <ChevronDown className="w-5 h-5 text-gray-400" />
                    ) : (
                      <ChevronRight className="w-5 h-5 text-gray-400" />
                    )}
                    <div>
                      <h3 className="text-white font-medium">
                        {result.cve_id} - {result.model_name}
                      </h3>
                      <p className="text-sm text-gray-400">
                        {result.total_attempts} attempts • {(result.total_duration_seconds / 60).toFixed(1)} min
                      </p>
                    </div>
                  </div>
                  <StatusBadge status={result.final_status} />
                </div>

                {isExpanded && result.validation_history && (
                  <div className="mt-4 ml-8 space-y-3">
                    {result.validation_history.map((attempt, aIdx) => (
                      <div 
                        key={aIdx}
                        className={`p-3 rounded-lg border ${
                          attempt.poc_blocked 
                            ? 'bg-green-500/10 border-green-500/30' 
                            : 'bg-red-500/10 border-red-500/30'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-medium text-white">
                            Attempt {attempt.attempt} {attempt.is_retry && '(Retry)'}
                          </span>
                          <div className="flex items-center gap-2">
                            <StatusBadge status={attempt.poc_blocked} />
                            {attempt.sast_passed && (
                              <span className="text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded">
                                SAST OK
                              </span>
                            )}
                          </div>
                        </div>
                        <p className="text-sm text-gray-400">{attempt.status}</p>
                        {attempt.error_message && (
                          <p className="text-sm text-red-400 mt-1">{attempt.error_message}</p>
                        )}
                        <p className="text-xs text-gray-500 mt-2">
                          {new Date(attempt.timestamp).toLocaleString()}
                        </p>
                      </div>
                    ))}
                    
                    {result.failure_reason && (
                      <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                        <p className="text-sm text-red-400">
                          <strong>Failure Reason:</strong> {result.failure_reason}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default FeedbackLoop;
