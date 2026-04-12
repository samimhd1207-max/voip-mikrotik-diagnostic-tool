import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import './App.css';
import Home from './pages/Home';
import MainPage from './pages/MainPage';
import MikroTikDashboard from './pages/MikroTikDashboard';
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
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;