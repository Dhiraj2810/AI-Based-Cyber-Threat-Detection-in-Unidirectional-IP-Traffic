import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import DiodeTopology from './components/DiodeTopology';
import AttackControlPanel from './components/AttackControlPanel';
import TelemetryCharts from './components/TelemetryCharts';
import RealtimeAlertFeed from './components/RealtimeAlertFeed';
import AlertLogTable from './components/AlertLogTable';
import AlertDetailModal from './components/AlertDetailModal';

export default function App() {
  const [status, setStatus] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [telemetry, setTelemetry] = useState({ current: {}, history: [] });
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);

  // Fetch initial status and alerts
  const fetchStatusAndAlerts = async () => {
    try {
      const resStatus = await fetch('/api/status');
      if (resStatus.ok) {
        const data = await resStatus.json();
        setStatus(data);
      }

      const resAlerts = await fetch('/api/alerts?limit=50');
      if (resAlerts.ok) {
        const data = await resAlerts.json();
        setAlerts(data);
      }

      const resTelem = await fetch('/api/telemetry');
      if (resTelem.ok) {
        const data = await resTelem.json();
        setTelemetry(data);
      }
    } catch (err) {
      console.error("Error fetching system status:", err);
    }
  };

  const alertBufferRef = React.useRef([]);
  const telemetryRef = React.useRef(null);

  useEffect(() => {
    fetchStatusAndAlerts();

    // Setup WebSockets connection
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/alerts`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      setWsConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);

        if (msg.type === 'telemetry') {
          telemetryRef.current = msg.data;
        } else if (msg.threat_class) {
          alertBufferRef.current.push(msg);
        }
      } catch (e) {
        console.error("WS message parse error:", e);
      }
    };

    ws.onclose = () => {
      setWsConnected(false);
    };

    // Smooth 300ms batched state flush interval (eliminates DOM re-render lag)
    const flushInterval = setInterval(() => {
      if (alertBufferRef.current.length > 0) {
        const newItems = alertBufferRef.current.splice(0, alertBufferRef.current.length);
        setAlerts((prev) => [...newItems.reverse(), ...prev].slice(0, 100));
      }
      if (telemetryRef.current) {
        const telemData = telemetryRef.current;
        telemetryRef.current = null;
        setTelemetry((prev) => ({
          current: telemData,
          history: [...prev.history.slice(-50), telemData]
        }));
      }
    }, 300);

    const pollInterval = setInterval(fetchStatusAndAlerts, 10000);

    return () => {
      ws.close();
      clearInterval(flushInterval);
      clearInterval(pollInterval);
    };
  }, []);

  const handleStartAttack = async (attackType) => {
    try {
      await fetch('/api/traffic/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: attackType })
      });
      fetchStatusAndAlerts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleStartAllAttacks = async () => {
    try {
      await fetch('/api/traffic/all', { method: 'POST' });
      fetchStatusAndAlerts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleStopAttack = async () => {
    try {
      await fetch('/api/traffic/stop', { method: 'POST' });
      fetchStatusAndAlerts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleRunBenchmark = async (simulateFail = false) => {
    const url = simulateFail
      ? '/api/benchmark?num_flows=10000&simulate_fail=true'
      : '/api/benchmark?num_flows=10000&use_live_state=true';
    const res = await fetch(url, { method: 'POST' });
    return await res.json();
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans pb-12">
      <Header status={status} telemetry={telemetry} />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 pt-6">
        <DiodeTopology />

        <AttackControlPanel
          activeAttack={status?.active_attack}
          activeAttacks={status?.active_attacks || []}
          onStartAttack={handleStartAttack}
          onStartAllAttacks={handleStartAllAttacks}
          onStopAttack={handleStopAttack}
          onRunBenchmark={handleRunBenchmark}
        />

        <TelemetryCharts
          telemetryHistory={telemetry.history}
          telemetryCurrent={telemetry.current}
        />

        <RealtimeAlertFeed
          alerts={alerts}
          onSelectAlert={(alert) => setSelectedAlert(alert)}
        />

        <AlertLogTable
          alerts={alerts}
          onSelectAlert={(alert) => setSelectedAlert(alert)}
        />
      </main>

      {/* SHAP & Alert Evidence Modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
        />
      )}
    </div>
  );
}
