import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  CheckCircle2, 
  ShieldAlert, 
  Cpu, 
  FileCode2, 
  RefreshCcw,
  Bug,
  Activity
} from 'lucide-react';

const navItems = [
  { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/validations', icon: CheckCircle2, label: 'Validations' },
  { path: '/cves', icon: ShieldAlert, label: 'CVE Analysis' },
  { path: '/models', icon: Cpu, label: 'Model Analysis' },
  { path: '/patches', icon: FileCode2, label: 'Patches' },
  { path: '/feedback-loop', icon: RefreshCcw, label: 'Feedback Loop' },
  { path: '/sast', icon: Bug, label: 'SAST Findings' },
];

function Sidebar() {
  return (
    <aside className="w-64 bg-dark-800 border-r border-dark-600 flex flex-col">
      <div className="p-4 border-b border-dark-600">
        <div className="flex items-center gap-3">
          <Activity className="w-8 h-8 text-blue-500" />
          <div>
            <h1 className="text-lg font-bold text-white">CVE Pipeline</h1>
            <p className="text-xs text-gray-500">Analysis Dashboard</p>
          </div>
        </div>
      </div>
      
      <nav className="flex-1 p-4">
        <ul className="space-y-1">
          {navItems.map((item) => (
            <li key={item.path}>
              <NavLink
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                    isActive
                      ? 'bg-blue-600 text-white'
                      : 'text-gray-400 hover:text-white hover:bg-dark-700'
                  }`
                }
              >
                <item.icon className="w-5 h-5" />
                <span>{item.label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      
      <div className="p-4 border-t border-dark-600">
        <div className="text-xs text-gray-500">
          <p>AI-SSD Project</p>
          <p>Dissertation Research</p>
        </div>
      </div>
    </aside>
  );
}

export default Sidebar;
