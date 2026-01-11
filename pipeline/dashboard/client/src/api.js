import axios from 'axios';

const API_BASE = '/api';

const api = {
  // Overview
  getOverview: () => axios.get(`${API_BASE}/overview`),
  
  // Issues
  getIssues: () => axios.get(`${API_BASE}/issues`),
  
  // Validations
  getValidations: (filters = {}) => {
    const params = new URLSearchParams(filters).toString();
    return axios.get(`${API_BASE}/validations${params ? `?${params}` : ''}`);
  },
  
  // CVEs
  getCVEs: () => axios.get(`${API_BASE}/cves`),
  
  // Models
  getModels: () => axios.get(`${API_BASE}/models`),
  
  // Phases
  getPhases: () => axios.get(`${API_BASE}/phases`),
  
  // Feedback Loop
  getFeedbackLoop: () => axios.get(`${API_BASE}/feedback-loop`),
  
  // SAST Findings
  getSastFindings: () => axios.get(`${API_BASE}/sast-findings`),
  
  // Charts
  getChartData: (type) => axios.get(`${API_BASE}/charts/${type}`),
  
  // Patches
  getPatches: () => axios.get(`${API_BASE}/patches`),
  
  // Reproductions
  getReproductions: () => axios.get(`${API_BASE}/reproductions`),
  
  // Refresh data
  refreshData: () => axios.post(`${API_BASE}/refresh`),
};

export default api;
