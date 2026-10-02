import { useEffect, useState } from "react";
import "./App.css";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

const API_KEY = import.meta.env.VITE_AEGIS_API_KEY;

function App() {
  const [securityEvents, setSecurityEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState("");

  useEffect(() => {
    async function fetchAuditLogs() {
      try {
        setLoading(true);
        setApiError("");

        if (!API_KEY) {
          throw new Error(
            "API key is not loaded. Check frontend/.env.local and restart Vite."
          );
        }

        const response = await fetch(
          `${API_BASE_URL}/api/v1/audit-logs`,
          {
            method: "GET",
            headers: {
              "X-API-Key": API_KEY,
            },
          }
        );

        if (!response.ok) {
          const errorText = await response.text();

          throw new Error(
            `API request failed with status ${response.status}: ${errorText}`
          );
        }

        const data = await response.json();

        if (!Array.isArray(data)) {
          throw new Error("Invalid audit log response from backend.");
        }

        setSecurityEvents(data);
      } catch (error) {
        console.error("Failed to load audit logs:", error);
        setApiError(error.message);
      } finally {
        setLoading(false);
      }
    }

    fetchAuditLogs();
  }, []);

  const totalRequests = securityEvents.length;

  const threatsDetected = securityEvents.filter(
    (event) => event.threat_types && event.threat_types.trim() !== ""
  ).length;

  const requestsBlocked = securityEvents.filter(
    (event) => event.action === "block"
  ).length;

  const averageRisk =
    totalRequests > 0
      ? Math.round(
          securityEvents.reduce(
            (total, event) => total + Number(event.risk_score || 0),
            0
          ) / totalRequests
        )
      : 0;

  const lowRiskCount = securityEvents.filter(
    (event) => event.risk_score < 40
  ).length;

  const mediumRiskCount = securityEvents.filter(
    (event) =>
      event.risk_score >= 40 && event.risk_score < 70
  ).length;

  const highRiskCount = securityEvents.filter(
    (event) => event.risk_score >= 70
  ).length;

  const lowRiskPercentage =
    totalRequests > 0
      ? Math.round((lowRiskCount / totalRequests) * 100)
      : 0;

  const mediumRiskPercentage =
    totalRequests > 0
      ? Math.round((mediumRiskCount / totalRequests) * 100)
      : 0;

  const highRiskPercentage =
    totalRequests > 0
      ? Math.round((highRiskCount / totalRequests) * 100)
      : 0;

  return (
    <div className="dashboard">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">A</div>

          <div>
            <h1>AegisAI</h1>
            <p>Security Gateway</p>
          </div>
        </div>

        <nav className="navigation">
          <button className="nav-item active">
            <span>▣</span>
            Dashboard
          </button>

          <button className="nav-item">
            <span>◈</span>
            Security Events
          </button>

          <button className="nav-item">
            <span>◉</span>
            API Activity
          </button>

          <button className="nav-item">
            <span>⚙</span>
            Settings
          </button>
        </nav>

        <div className="system-status">
          <div className="status-dot"></div>

          <div>
            <strong>Gateway Online</strong>
            <span>Protection active</span>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY OVERVIEW</p>

            <h2>AegisAI Dashboard</h2>

            <p className="subtitle">
              Monitor and protect your AI applications.
            </p>
          </div>

          <div className="connection">
            <span className="online-dot"></span>
            API Connected
          </div>
        </header>

        {apiError && (
          <div className="api-error">
            Backend connection failed: {apiError}
          </div>
        )}

        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-header">
              <span>Total Requests</span>
              <span className="stat-icon">↗</span>
            </div>

            <strong>{loading ? "..." : totalRequests}</strong>

            <p>Requests scanned</p>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span>Threats Detected</span>
              <span className="stat-icon danger">!</span>
            </div>

            <strong>{loading ? "..." : threatsDetected}</strong>

            <p>Security findings</p>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span>Requests Blocked</span>
              <span className="stat-icon danger">×</span>
            </div>

            <strong>{loading ? "..." : requestsBlocked}</strong>

            <p>Blocked by policy</p>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span>Average Risk</span>
              <span className="stat-icon">◐</span>
            </div>

            <strong>{loading ? "..." : averageRisk}</strong>

            <p>Out of 100</p>
          </div>
        </section>

        <section className="content-grid">
          <div className="panel risk-panel">
            <div className="panel-header">
              <div>
                <p className="panel-label">RISK ANALYSIS</p>

                <h3>Security Risk Distribution</h3>
              </div>

              <span className="period">
                Based on recent audit logs
              </span>
            </div>

            <div className="risk-bars">
              <div className="risk-row">
                <div className="risk-name">
                  <span className="risk-indicator safe"></span>
                  Low Risk
                </div>

                <div className="bar">
                  <div
                    className="bar-fill safe-fill"
                    style={{
                      width: `${lowRiskPercentage}%`,
                    }}
                  ></div>
                </div>

                <strong>{lowRiskPercentage}%</strong>
              </div>

              <div className="risk-row">
                <div className="risk-name">
                  <span className="risk-indicator warning"></span>
                  Medium Risk
                </div>

                <div className="bar">
                  <div
                    className="bar-fill warning-fill"
                    style={{
                      width: `${mediumRiskPercentage}%`,
                    }}
                  ></div>
                </div>

                <strong>{mediumRiskPercentage}%</strong>
              </div>

              <div className="risk-row">
                <div className="risk-name">
                  <span className="risk-indicator danger"></span>
                  High Risk
                </div>

                <div className="bar">
                  <div
                    className="bar-fill danger-fill"
                    style={{
                      width: `${highRiskPercentage}%`,
                    }}
                  ></div>
                </div>

                <strong>{highRiskPercentage}%</strong>
              </div>
            </div>
          </div>

          <div className="panel detector-panel">
            <div className="panel-header">
              <div>
                <p className="panel-label">DETECTORS</p>

                <h3>Security Layers</h3>
              </div>
            </div>

            <div className="detector-list">
              <div className="detector">
                <div className="detector-icon">R</div>

                <div>
                  <strong>Rule Detector</strong>
                  <span>Active</span>
                </div>

                <b>✓</b>
              </div>

              <div className="detector">
                <div className="detector-icon">M</div>

                <div>
                  <strong>ML Detector</strong>
                  <span>Active</span>
                </div>

                <b>✓</b>
              </div>

              <div className="detector">
                <div className="detector-icon">P</div>

                <div>
                  <strong>PII Detector</strong>
                  <span>Active</span>
                </div>

                <b>✓</b>
              </div>

              <div className="detector">
                <div className="detector-icon">L</div>

                <div>
                  <strong>Policy Engine</strong>
                  <span>Active</span>
                </div>

                <b>✓</b>
              </div>
            </div>
          </div>
        </section>

        <section className="panel events-panel">
          <div className="panel-header">
            <div>
              <p className="panel-label">RECENT ACTIVITY</p>

              <h3>Security Events</h3>
            </div>

            <button className="view-button">
              Live API Data
            </button>
          </div>

          <div className="events-table">
            <div className="table-header">
              <span>Action</span>
              <span>Event</span>
              <span>Risk Score</span>
              <span>Status</span>
            </div>

            {loading ? (
              <div className="table-row">
                <span>...</span>
                <span>Loading audit logs...</span>
                <span>...</span>
                <span>...</span>
              </div>
            ) : securityEvents.length === 0 ? (
              <div className="table-row">
                <span>-</span>
                <span>No audit events found</span>
                <span>-</span>
                <span>-</span>
              </div>
            ) : (
              securityEvents.map((event) => {
                const action = event.action.toUpperCase();

                const status =
                  event.action === "allow"
                    ? "safe"
                    : "warning";

                return (
                  <div
                    className="table-row"
                    key={event.id}
                  >
                    <span>
                      <b className={`action ${status}`}>
                        {action}
                      </b>
                    </span>

                    <span>
                      {event.threat_types &&
                      event.threat_types.trim() !== ""
                        ? event.threat_types
                        : "Normal request"}
                    </span>

                    <span>
                      <strong>{event.risk_score}</strong>
                      <small>/100</small>
                    </span>

                    <span>
                      <span
                        className={`status-badge ${status}`}
                      >
                        {event.action === "allow"
                          ? "Safe"
                          : "Review"}
                      </span>
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </section>

        <footer className="footer">
          <span>AegisAI Security Gateway</span>
          <span>v0.1.0</span>
        </footer>
      </main>
    </div>
  );
}

export default App;