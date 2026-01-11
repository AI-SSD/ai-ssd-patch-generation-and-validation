import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Validations from './pages/Validations';
import CVEAnalysis from './pages/CVEAnalysis';
import ModelAnalysis from './pages/ModelAnalysis';
import Patches from './pages/Patches';
import FeedbackLoop from './pages/FeedbackLoop';
import SastFindings from './pages/SastFindings';

function App() {
  return (
    <Router>
      <div className="flex h-screen bg-dark-900">
        <Sidebar />
        <main className="flex-1 overflow-auto p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/validations" element={<Validations />} />
            <Route path="/cves" element={<CVEAnalysis />} />
            <Route path="/models" element={<ModelAnalysis />} />
            <Route path="/patches" element={<Patches />} />
            <Route path="/feedback-loop" element={<FeedbackLoop />} />
            <Route path="/sast" element={<SastFindings />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
