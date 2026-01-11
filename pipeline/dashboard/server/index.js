const express = require('express');
const cors = require('cors');
const path = require('path');
const dataParser = require('./dataParser');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// Data directory - parent of dashboard folder
const DATA_DIR = path.join(__dirname, '..', '..');

// Cache for parsed data
let dataCache = null;
let lastCacheTime = null;
const CACHE_TTL = 60000; // 1 minute

// Helper to get fresh or cached data
async function getData() {
  const now = Date.now();
  if (!dataCache || !lastCacheTime || (now - lastCacheTime > CACHE_TTL)) {
    dataCache = await dataParser.parseAllData(DATA_DIR);
    lastCacheTime = now;
  }
  return dataCache;
}

// API Routes

// Get dashboard overview statistics
app.get('/api/overview', async (req, res) => {
  try {
    const data = await getData();
    
    // Count different failure types
    const executionErrors = data.validations.filter(v => v.status === 'Execution Error').length;
    const pocStillWorks = data.validations.filter(v => v.status === 'PoC Still Works').length;
    const invalidPatches = data.validations.filter(v => v.status === 'Invalid Patch').length;
    const buildErrors = data.validations.filter(v => v.status === 'Build Error').length;
    
    const overview = {
      totalRuns: data.pipelineRuns.length,
      totalCVEs: data.cves.length,
      totalModels: data.models.length,
      totalValidations: data.validations.length,
      successRate: calculateSuccessRate(data.validations),
      avgExecutionTime: calculateAvgExecutionTime(data.validations),
      phasesCompleted: data.pipelineRuns[0]?.phases_completed || 0,
      phasesFailed: data.pipelineRuns[0]?.phases_failed || 0,
      totalDuration: data.pipelineRuns[0]?.duration_seconds || 0,
      pocBlockedRate: calculatePocBlockedRate(data.validations),
      sastPassRate: calculateSastPassRate(data.validations),
      buildSuccessRate: calculateBuildSuccessRate(data.validations),
      lastRunTimestamp: data.pipelineRuns[0]?.start_time || null,
      // Failure breakdown for dashboard
      failureBreakdown: {
        executionErrors,
        pocStillWorks,
        invalidPatches,
        buildErrors,
        totalFailures: data.validations.filter(v => v.status !== 'Success').length
      }
    };
    res.json(overview);
  } catch (error) {
    console.error('Error fetching overview:', error);
    res.status(500).json({ error: 'Failed to fetch overview data' });
  }
});

// Get all issues (failed/problematic runs)
app.get('/api/issues', async (req, res) => {
  try {
    const data = await getData();
    const issues = identifyIssues(data);
    res.json(issues);
  } catch (error) {
    console.error('Error fetching issues:', error);
    res.status(500).json({ error: 'Failed to fetch issues' });
  }
});

// Get all validations with optional filters
app.get('/api/validations', async (req, res) => {
  try {
    const data = await getData();
    let validations = data.validations;

    // Apply filters
    const { cve, model, status, startDate, endDate, pocBlocked, sastPassed } = req.query;

    if (cve) {
      validations = validations.filter(v => v.cve_id === cve);
    }
    if (model) {
      validations = validations.filter(v => v.model_name.includes(model));
    }
    if (status) {
      validations = validations.filter(v => v.status === status);
    }
    if (startDate) {
      validations = validations.filter(v => new Date(v.timestamp) >= new Date(startDate));
    }
    if (endDate) {
      validations = validations.filter(v => new Date(v.timestamp) <= new Date(endDate));
    }
    if (pocBlocked !== undefined) {
      validations = validations.filter(v => v.poc_blocked === (pocBlocked === 'true'));
    }
    if (sastPassed !== undefined) {
      validations = validations.filter(v => v.sast_passed === (sastPassed === 'true'));
    }

    res.json(validations);
  } catch (error) {
    console.error('Error fetching validations:', error);
    res.status(500).json({ error: 'Failed to fetch validations' });
  }
});

// Get CVE-specific data
app.get('/api/cves', async (req, res) => {
  try {
    const data = await getData();
    const cveStats = data.cves.map(cve => {
      const cveValidations = data.validations.filter(v => v.cve_id === cve);
      return {
        cve_id: cve,
        total_validations: cveValidations.length,
        successful: cveValidations.filter(v => v.poc_blocked).length,
        failed: cveValidations.filter(v => !v.poc_blocked).length,
        success_rate: cveValidations.length > 0 
          ? ((cveValidations.filter(v => v.poc_blocked).length / cveValidations.length) * 100).toFixed(1)
          : 0,
        models_tested: [...new Set(cveValidations.map(v => v.model_name))],
        avg_execution_time: calculateAvgTime(cveValidations)
      };
    });
    res.json(cveStats);
  } catch (error) {
    console.error('Error fetching CVEs:', error);
    res.status(500).json({ error: 'Failed to fetch CVE data' });
  }
});

// Get model-specific data
app.get('/api/models', async (req, res) => {
  try {
    const data = await getData();
    const modelStats = data.models.map(model => {
      const modelValidations = data.validations.filter(v => v.model_name === model);
      return {
        model_name: model,
        total_validations: modelValidations.length,
        successful: modelValidations.filter(v => v.poc_blocked).length,
        failed: modelValidations.filter(v => !v.poc_blocked).length,
        success_rate: modelValidations.length > 0
          ? ((modelValidations.filter(v => v.poc_blocked).length / modelValidations.length) * 100).toFixed(1)
          : 0,
        sast_pass_rate: modelValidations.length > 0
          ? ((modelValidations.filter(v => v.sast_passed).length / modelValidations.length) * 100).toFixed(1)
          : 0,
        avg_execution_time: calculateAvgTime(modelValidations),
        cves_tested: [...new Set(modelValidations.map(v => v.cve_id))]
      };
    });
    res.json(modelStats);
  } catch (error) {
    console.error('Error fetching models:', error);
    res.status(500).json({ error: 'Failed to fetch model data' });
  }
});

// Get pipeline phases data
app.get('/api/phases', async (req, res) => {
  try {
    const data = await getData();
    const phases = data.pipelineRuns[0]?.results || [];
    res.json(phases);
  } catch (error) {
    console.error('Error fetching phases:', error);
    res.status(500).json({ error: 'Failed to fetch phase data' });
  }
});

// Get feedback loop results
app.get('/api/feedback-loop', async (req, res) => {
  try {
    const data = await getData();
    res.json(data.feedbackLoop);
  } catch (error) {
    console.error('Error fetching feedback loop:', error);
    res.status(500).json({ error: 'Failed to fetch feedback loop data' });
  }
});

// Get SAST findings
app.get('/api/sast-findings', async (req, res) => {
  try {
    const data = await getData();
    const sastFindings = data.validations
      .filter(v => v.sast_findings && v.sast_findings.length > 0)
      .map(v => ({
        cve_id: v.cve_id,
        model_name: v.model_name,
        findings: v.sast_findings
      }));
    res.json(sastFindings);
  } catch (error) {
    console.error('Error fetching SAST findings:', error);
    res.status(500).json({ error: 'Failed to fetch SAST findings' });
  }
});

// Get chart data for various visualizations
app.get('/api/charts/:type', async (req, res) => {
  try {
    const data = await getData();
    const { type } = req.params;

    let chartData;
    switch (type) {
      case 'success-by-model':
        chartData = getSuccessByModel(data);
        break;
      case 'success-by-cve':
        chartData = getSuccessByCVE(data);
        break;
      case 'execution-time':
        chartData = getExecutionTimeData(data);
        break;
      case 'sast-by-tool':
        chartData = getSastByTool(data);
        break;
      case 'timeline':
        chartData = getTimelineData(data);
        break;
      case 'retry-analysis':
        chartData = getRetryAnalysis(data);
        break;
      default:
        return res.status(400).json({ error: 'Invalid chart type' });
    }
    res.json(chartData);
  } catch (error) {
    console.error('Error fetching chart data:', error);
    res.status(500).json({ error: 'Failed to fetch chart data' });
  }
});

// Get patch generation data
app.get('/api/patches', async (req, res) => {
  try {
    const data = await getData();
    res.json(data.patchGeneration);
  } catch (error) {
    console.error('Error fetching patches:', error);
    res.status(500).json({ error: 'Failed to fetch patch data' });
  }
});

// Get vulnerability reproduction data
app.get('/api/reproductions', async (req, res) => {
  try {
    const data = await getData();
    res.json(data.reproductions);
  } catch (error) {
    console.error('Error fetching reproductions:', error);
    res.status(500).json({ error: 'Failed to fetch reproduction data' });
  }
});

// Refresh data cache
app.post('/api/refresh', async (req, res) => {
  try {
    dataCache = null;
    lastCacheTime = null;
    await getData();
    res.json({ success: true, message: 'Data cache refreshed' });
  } catch (error) {
    console.error('Error refreshing data:', error);
    res.status(500).json({ error: 'Failed to refresh data' });
  }
});

// Helper functions
function calculateSuccessRate(validations) {
  if (validations.length === 0) return 0;
  const successful = validations.filter(v => v.poc_blocked).length;
  return ((successful / validations.length) * 100).toFixed(1);
}

function calculatePocBlockedRate(validations) {
  if (validations.length === 0) return 0;
  const blocked = validations.filter(v => v.poc_blocked).length;
  return ((blocked / validations.length) * 100).toFixed(1);
}

function calculateSastPassRate(validations) {
  if (validations.length === 0) return 0;
  const passed = validations.filter(v => v.sast_passed).length;
  return ((passed / validations.length) * 100).toFixed(1);
}

function calculateBuildSuccessRate(validations) {
  if (validations.length === 0) return 0;
  const passed = validations.filter(v => v.build_success).length;
  return ((passed / validations.length) * 100).toFixed(1);
}

function calculateAvgExecutionTime(validations) {
  if (validations.length === 0) return 0;
  const total = validations.reduce((sum, v) => sum + (v.execution_time_seconds || 0), 0);
  return (total / validations.length).toFixed(1);
}

function calculateAvgTime(validations) {
  if (validations.length === 0) return 0;
  const total = validations.reduce((sum, v) => sum + (v.execution_time_seconds || 0), 0);
  return (total / validations.length).toFixed(1);
}

function identifyIssues(data) {
  const issues = [];

  // Check for failed phases
  const failedPhases = data.pipelineRuns[0]?.results?.filter(p => p.status === 'failed') || [];
  failedPhases.forEach(phase => {
    issues.push({
      type: 'major',
      category: 'Phase Failure',
      title: `Phase ${phase.phase}: ${phase.name} Failed`,
      description: phase.error_message || 'Unknown error',
      timestamp: phase.end_time,
      cve: null,
      model: null
    });
  });

  // Check for execution errors (environment failures)
  data.validations.filter(v => v.status === 'Execution Error').forEach(v => {
    issues.push({
      type: 'major',
      category: 'Execution Error',
      title: `${v.cve_id} - ${v.model_name}: Execution Error`,
      description: v.error_message || 'Environment or execution failure',
      timestamp: v.timestamp,
      cve: v.cve_id,
      model: v.model_name
    });
  });

  // Check for validations where PoC still works
  data.validations.filter(v => !v.poc_blocked && v.status === 'PoC Still Works').forEach(v => {
    issues.push({
      type: 'major',
      category: 'Patch Ineffective',
      title: `${v.cve_id} - ${v.model_name}: PoC Still Works`,
      description: v.error_message || 'The patch did not prevent the exploit',
      timestamp: v.timestamp,
      cve: v.cve_id,
      model: v.model_name
    });
  });

  // Check for build failures
  data.validations.filter(v => !v.build_success).forEach(v => {
    issues.push({
      type: 'major',
      category: 'Build Failure',
      title: `${v.cve_id} - ${v.model_name}: Build Failed`,
      description: v.error_message || 'The patched code failed to compile',
      timestamp: v.timestamp,
      cve: v.cve_id,
      model: v.model_name
    });
  });

  // Check for invalid patches (syntax errors)
  data.validations.filter(v => v.status === 'Invalid Patch').forEach(v => {
    issues.push({
      type: 'major',
      category: 'Invalid Patch',
      title: `${v.cve_id} - ${v.model_name}: Invalid Patch`,
      description: v.error_message || 'Patch has syntax errors',
      timestamp: v.timestamp,
      cve: v.cve_id,
      model: v.model_name
    });
  });

  // Check for SAST failures (only if not already an error status)
  data.validations.filter(v => !v.sast_passed && v.build_success && v.status !== 'Execution Error').forEach(v => {
    issues.push({
      type: 'warning',
      category: 'SAST Warning',
      title: `${v.cve_id} - ${v.model_name}: SAST Issues`,
      description: 'Static analysis found potential issues',
      timestamp: v.timestamp,
      cve: v.cve_id,
      model: v.model_name
    });
  });

  // Check for unpatchable items in feedback loop
  data.feedbackLoop?.results?.filter(r => r.final_status === 'unpatchable').forEach(r => {
    issues.push({
      type: 'major',
      category: 'Unpatchable',
      title: `${r.cve_id} - ${r.model_name}: Marked Unpatchable`,
      description: r.failure_reason || 'Failed after all retry attempts',
      timestamp: r.validation_history?.[r.validation_history.length - 1]?.timestamp,
      cve: r.cve_id,
      model: r.model_name,
      attempts: r.total_attempts
    });
  });

  // Sort by type (major first) and then by timestamp
  issues.sort((a, b) => {
    if (a.type === 'major' && b.type !== 'major') return -1;
    if (a.type !== 'major' && b.type === 'major') return 1;
    return new Date(b.timestamp) - new Date(a.timestamp);
  });

  return issues;
}

function getSuccessByModel(data) {
  const modelMap = {};
  data.validations.forEach(v => {
    if (!modelMap[v.model_name]) {
      modelMap[v.model_name] = { successful: 0, failed: 0 };
    }
    if (v.poc_blocked) {
      modelMap[v.model_name].successful++;
    } else {
      modelMap[v.model_name].failed++;
    }
  });

  return Object.entries(modelMap).map(([name, stats]) => ({
    name,
    successful: stats.successful,
    failed: stats.failed,
    total: stats.successful + stats.failed,
    successRate: ((stats.successful / (stats.successful + stats.failed)) * 100).toFixed(1)
  }));
}

function getSuccessByCVE(data) {
  const cveMap = {};
  data.validations.forEach(v => {
    if (!cveMap[v.cve_id]) {
      cveMap[v.cve_id] = { successful: 0, failed: 0 };
    }
    if (v.poc_blocked) {
      cveMap[v.cve_id].successful++;
    } else {
      cveMap[v.cve_id].failed++;
    }
  });

  return Object.entries(cveMap).map(([name, stats]) => ({
    name,
    successful: stats.successful,
    failed: stats.failed,
    total: stats.successful + stats.failed,
    successRate: ((stats.successful / (stats.successful + stats.failed)) * 100).toFixed(1)
  }));
}

function getExecutionTimeData(data) {
  return data.validations.map(v => ({
    cve: v.cve_id,
    model: v.model_name,
    executionTime: v.execution_time_seconds,
    timestamp: v.timestamp,
    status: v.poc_blocked ? 'Success' : 'Failed'
  }));
}

function getSastByTool(data) {
  const toolStats = {};
  
  data.validations.forEach(v => {
    if (v.sast_results) {
      v.sast_results.forEach(r => {
        if (!toolStats[r.tool]) {
          toolStats[r.tool] = {
            total: 0,
            passed: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
          };
        }
        toolStats[r.tool].total++;
        if (r.success) toolStats[r.tool].passed++;
        toolStats[r.tool].critical += r.critical_count || 0;
        toolStats[r.tool].high += r.high_count || 0;
        toolStats[r.tool].medium += r.medium_count || 0;
        toolStats[r.tool].low += r.low_count || 0;
      });
    }
  });

  return Object.entries(toolStats).map(([tool, stats]) => ({
    tool,
    ...stats,
    passRate: ((stats.passed / stats.total) * 100).toFixed(1)
  }));
}

function getTimelineData(data) {
  const timeline = [];
  
  // Add phase data
  data.pipelineRuns[0]?.results?.forEach(phase => {
    timeline.push({
      type: 'phase',
      name: phase.name,
      start: phase.start_time,
      end: phase.end_time,
      duration: phase.duration_seconds,
      status: phase.status
    });
  });

  // Add validation timestamps
  data.validations.forEach(v => {
    timeline.push({
      type: 'validation',
      name: `${v.cve_id} - ${v.model_name}`,
      start: v.timestamp,
      duration: v.execution_time_seconds,
      status: v.poc_blocked ? 'success' : 'failed'
    });
  });

  return timeline.sort((a, b) => new Date(a.start) - new Date(b.start));
}

function getRetryAnalysis(data) {
  if (!data.feedbackLoop?.results) return [];

  return data.feedbackLoop.results.map(r => ({
    cve: r.cve_id,
    model: r.model_name,
    totalAttempts: r.total_attempts,
    finalStatus: r.final_status,
    duration: r.total_duration_seconds,
    history: r.validation_history?.map(h => ({
      attempt: h.attempt,
      status: h.status,
      pocBlocked: h.poc_blocked,
      timestamp: h.timestamp
    }))
  }));
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Data directory: ${DATA_DIR}`);
});
