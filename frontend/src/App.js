import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import './App.css';
import Home from './pages/Home';
import MainPage from './pages/MainPage';
import MikroTikDashboard from './pages/MikroTikDashboard';
import MikroTikAudit from './pages/MikroTikAudit';
import MikrotikAuditPage from './pages/MikrotikAuditPage';
import Navbar from './components/layout/Navbar';

function App() {
  return (
    <BrowserRouter>
      <Navbar />
      <div className="app-routes">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/diagnostic" element={<MainPage />} />
          <Route path="/mikrotik-dashboard" element={<MikroTikDashboard />} />
          <Route path="/mikrotik-audit" element={<MikroTikAudit />} />
          <Route path="/mikrotik/audit" element={<MikrotikAuditPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;