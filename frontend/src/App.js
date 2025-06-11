import React, { useState, useCallback, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Generate unique session ID
const getSessionId = () => {
  let sessionId = sessionStorage.getItem('rustproof_session_id');
  if (!sessionId) {
    sessionId = 'sess_' + Math.random().toString(36).substr(2, 9);
    sessionStorage.setItem('rustproof_session_id', sessionId);
  }
  return sessionId;
};

// Professional Security Score Component
const SecurityScore = ({ score, riskLevel, size = 'large' }) => {
  const radius = size === 'large' ? 85 : 50;
  const strokeWidth = size === 'large' ? 12 : 7;
  const normalizedRadius = radius - strokeWidth * 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const strokeDasharray = `${circumference} ${circumference}`;
  const strokeDashoffset = circumference - (score / 100) * circumference;
  
  const getScoreColor = (score) => {
    if (score >= 80) return '#10B981'; // Green
    if (score >= 60) return '#F59E0B'; // Yellow  
    if (score >= 40) return '#FF6B35'; // Orange
    return '#EF4444'; // Red
  };

  const getRiskBadgeColor = (risk) => {
    switch(risk) {
      case 'Low': return 'bg-green-900 text-green-200 border-green-500';
      case 'Medium': return 'bg-yellow-900 text-yellow-200 border-yellow-500';
      case 'High': return 'bg-orange-900 text-orange-200 border-orange-500';
      case 'Critical': return 'bg-red-900 text-red-200 border-red-500';
      default: return 'bg-gray-900 text-gray-200 border-gray-500';
    }
  };

  return (
    <div className="relative inline-flex flex-col items-center justify-center">
      <svg
        height={radius * 2}
        width={radius * 2}
        className="transform -rotate-90"
      >
        <circle
          stroke="#374151"
          fill="transparent"
          strokeWidth={strokeWidth}
          r={normalizedRadius}
          cx={radius}
          cy={radius}
        />
        <circle
          stroke={getScoreColor(score)}
          fill="transparent"
          strokeWidth={strokeWidth}
          strokeDasharray={strokeDasharray}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          r={normalizedRadius}
          cx={radius}
          cy={radius}
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="text-center">
          <div className={`font-bold ${size === 'large' ? 'text-3xl' : 'text-xl'} text-white`}>
            {score}
          </div>
          <div className={`text-gray-400 ${size === 'large' ? 'text-sm' : 'text-xs'}`}>
            Security Score
          </div>
        </div>
      </div>
      {riskLevel && size === 'large' && (
        <div className={`mt-4 px-4 py-2 rounded-full text-sm font-medium border ${getRiskBadgeColor(riskLevel)}`}>
          {riskLevel} Risk
        </div>
      )}
    </div>
  );
};

// Enhanced Vulnerability Card with RustProof branding
const VulnerabilityCard = ({ vulnerability }) => {
  const [showFix, setShowFix] = useState(false);
  const [showDetails, setShowDetails] = useState(false);
  
  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return 'bg-red-900 text-red-200 border-red-500';
      case 'High': return 'bg-orange-900 text-orange-200 border-orange-500';
      case 'Medium': return 'bg-yellow-900 text-yellow-200 border-yellow-500';
      case 'Low': return 'bg-blue-900 text-blue-200 border-blue-500';
      default: return 'bg-gray-900 text-gray-200 border-gray-500';
    }
  };

  const getCategoryIcon = (category) => {
    switch (category) {
      case 'Access Control': return '🔐';
      case 'Arithmetic': return '🔢';
      case 'DeFi': return '💰';
      case 'Oracle': return '📊';
      case 'Solana Specific': return '⚡';
      case 'Account Management': return '👤';
      case 'Cross Program': return '🔗';
      case 'Oracle/Time': return '⏰';
      case 'Governance': return '🗳️';
      case 'Performance': return '⚡';
      case 'Memory Safety': return '🛡️';
      case 'NFT/Token': return '🎨';
      case 'State Management': return '📊';
      case 'Error Handling': return '⚠️';
      default: return '🔒';
    }
  };

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-4 hover:border-orange-500/50 transition-all duration-200 hover:shadow-lg">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center space-x-3">
          <span className="text-2xl">{getCategoryIcon(vulnerability.category)}</span>
          <div>
            <h3 className="text-lg font-semibold text-white mb-1">{vulnerability.rule_id}</h3>
            <div className="flex items-center space-x-2">
              <span className={`inline-block px-3 py-1 rounded-full text-sm font-medium border ${getSeverityColor(vulnerability.severity)}`}>
                {vulnerability.severity}
              </span>
              <span className="text-sm text-gray-400">{vulnerability.category}</span>
              {vulnerability.cwe_id && (
                <span className="text-xs text-blue-400 bg-blue-900/30 px-2 py-1 rounded">
                  {vulnerability.cwe_id}
                </span>
              )}
            </div>
          </div>
        </div>
        <div className="text-right">
          <div className="text-sm text-gray-400">Line {vulnerability.line_number}</div>
          {vulnerability.impact_score && (
            <div className="text-xs text-orange-400">Impact: {vulnerability.impact_score}/100</div>
          )}
          {vulnerability.exploitability && (
            <div className="text-xs text-red-400">Risk: {vulnerability.exploitability}</div>
          )}
        </div>
      </div>
      
      <p className="text-gray-300 mb-4">{vulnerability.description}</p>
      
      <div className="mb-4">
        <h4 className="text-sm font-medium text-gray-400 mb-2">Vulnerable Code:</h4>
        <pre className="bg-gray-900 border border-gray-700 rounded p-3 text-sm text-gray-300 overflow-x-auto">
          <code>{vulnerability.code_snippet}</code>
        </pre>
      </div>
      
      <div className="flex space-x-4 mb-4">
        <button
          onClick={() => setShowFix(!showFix)}
          className="text-green-400 hover:text-green-300 text-sm font-medium flex items-center transition-colors"
        >
          <span className="mr-1">{showFix ? '🔽' : '▶️'}</span>
          {showFix ? 'Hide Fix' : 'Show Fix'}
        </button>
        
        <button
          onClick={() => setShowDetails(!showDetails)}
          className="text-orange-400 hover:text-orange-300 text-sm font-medium flex items-center transition-colors"
        >
          <span className="mr-1">{showDetails ? '🔽' : '▶️'}</span>
          {showDetails ? 'Hide Details' : 'Show Details'}
        </button>
      </div>
      
      {showFix && (
        <div className="mb-4 p-4 bg-green-900/20 border border-green-500/30 rounded">
          <h4 className="text-sm font-medium text-green-400 mb-2">✅ RustProof Fix Recommendation:</h4>
          <pre className="bg-gray-900 border border-gray-700 rounded p-3 text-sm text-green-300 overflow-x-auto">
            <code>{vulnerability.fix_example}</code>
          </pre>
          {vulnerability.real_world_example && (
            <div className="mt-3 p-3 bg-yellow-900/20 border border-yellow-500/30 rounded">
              <p className="text-sm text-yellow-300">
                <strong>⚠️ Real-world context:</strong> {vulnerability.real_world_example}
              </p>
            </div>
          )}
        </div>
      )}
      
      {showDetails && (
        <div className="p-4 bg-orange-900/20 border border-orange-500/30 rounded">
          <h4 className="text-sm font-medium text-orange-400 mb-2">📋 Detailed Analysis:</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-400">Category:</span>
              <span className="text-white ml-2">{vulnerability.category}</span>
            </div>
            <div>
              <span className="text-gray-400">Exploitability:</span>
              <span className="text-white ml-2">{vulnerability.exploitability}</span>
            </div>
            {vulnerability.cwe_id && (
              <div>
                <span className="text-gray-400">CWE ID:</span>
                <span className="text-white ml-2">{vulnerability.cwe_id}</span>
              </div>
            )}
            <div>
              <span className="text-gray-400">Impact Score:</span>
              <span className="text-white ml-2">{vulnerability.impact_score || 'N/A'}/100</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Professional Analytics Dashboard
const AnalyticsDashboard = ({ scanResult }) => {
  if (!scanResult) return null;

  const metrics = scanResult.security_metrics || {};
  const compliance = scanResult.compliance_report || {};

  return (
    <div className="space-y-6">
      {/* Security Metrics */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <h3 className="text-xl font-bold text-white mb-4">📊 Security Analysis</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center p-4 bg-blue-900/20 border border-blue-500/30 rounded">
            <div className="text-2xl font-bold text-blue-400">{metrics.total_lines_analyzed || 0}</div>
            <div className="text-sm text-gray-400">Lines Analyzed</div>
          </div>
          <div className="text-center p-4 bg-purple-900/20 border border-purple-500/30 rounded">
            <div className="text-2xl font-bold text-purple-400">{metrics.complexity_score || 0}</div>
            <div className="text-sm text-gray-400">Complexity Score</div>
          </div>
          <div className="text-center p-4 bg-orange-900/20 border border-orange-500/30 rounded">
            <div className="text-2xl font-bold text-orange-400">{metrics.attack_surface_score || 0}</div>
            <div className="text-sm text-gray-400">Attack Surface</div>
          </div>
          <div className="text-center p-4 bg-red-900/20 border border-red-500/30 rounded">
            <div className="text-2xl font-bold text-red-400">{metrics.defi_risk_score || 0}</div>
            <div className="text-sm text-gray-400">DeFi Risk</div>
          </div>
        </div>
      </div>

      {/* Professional Compliance Report */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <h3 className="text-xl font-bold text-white mb-4">📋 Compliance Assessment</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center">
            <div className="text-3xl font-bold text-green-400 mb-2">{compliance.soc2_score || 0}%</div>
            <div className="text-sm text-gray-400 mb-2">SOC 2 Compliance</div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div 
                className="bg-green-500 h-2 rounded-full transition-all duration-500"
                style={{ width: `${compliance.soc2_score || 0}%` }}
              ></div>
            </div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-blue-400 mb-2">{compliance.nist_score || 0}%</div>
            <div className="text-sm text-gray-400 mb-2">NIST Framework</div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div 
                className="bg-blue-500 h-2 rounded-full transition-all duration-500"
                style={{ width: `${compliance.nist_score || 0}%` }}
              ></div>
            </div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-purple-400 mb-2">{compliance.owasp_score || 0}%</div>
            <div className="text-sm text-gray-400 mb-2">OWASP Smart Contract</div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div 
                className="bg-purple-500 h-2 rounded-full transition-all duration-500"
                style={{ width: `${compliance.owasp_score || 0}%` }}
              ></div>
            </div>
          </div>
        </div>
        
        {compliance.missing_controls && compliance.missing_controls.length > 0 && (
          <div className="mt-6 p-4 bg-yellow-900/20 border border-yellow-500/30 rounded">
            <h4 className="text-yellow-400 font-medium mb-2">⚠️ Missing Controls:</h4>
            <ul className="text-sm text-yellow-300 list-disc list-inside space-y-1">
              {compliance.missing_controls.map((control, index) => (
                <li key={index}>{control}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Remediation Roadmap */}
      {scanResult.remediation_priority && scanResult.remediation_priority.length > 0 && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">🔧 Remediation Roadmap</h3>
          <div className="space-y-3">
            {scanResult.remediation_priority.slice(0, 5).map((item, index) => (
              <div key={index} className="flex items-center space-x-3 p-3 bg-gray-700 rounded hover:bg-gray-600 transition-colors">
                <div className="w-8 h-8 bg-orange-500 text-white rounded-full flex items-center justify-center text-sm font-bold">
                  {index + 1}
                </div>
                <div className="text-sm text-gray-300 flex-1">{item}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// Professional File Upload Component
const FileUpload = ({ onFileSelect, isScanning }) => {
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      onFileSelect(e.dataTransfer.files[0]);
    }
  }, [onFileSelect]);

  const handleChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      onFileSelect(e.target.files[0]);
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto">
      <div
        className={`relative border-2 border-dashed rounded-lg p-12 text-center transition-all duration-200 ${
          dragActive
            ? 'border-orange-400 bg-orange-500/10 scale-105'
            : 'border-gray-600 hover:border-gray-500'
        } ${isScanning ? 'opacity-50 pointer-events-none' : ''}`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <input
          type="file"
          accept=".rs,.rust"
          onChange={handleChange}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          disabled={isScanning}
        />
        
        <div className="space-y-4">
          <div className="flex justify-center">
            {isScanning ? (
              <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-orange-400"></div>
            ) : (
              <svg className="w-16 h-16 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
            )}
          </div>
          <div>
            <p className="text-xl font-medium text-gray-300">
              {isScanning ? 'RustProof is analyzing your code...' : 'Drop your Rust file here'}
            </p>
            <p className="text-gray-500 mt-2">
              or <span className="text-orange-400">browse</span> to choose a file
            </p>
            <p className="text-sm text-gray-600 mt-1">
              Supports .rs and .rust files • Max 10MB
            </p>
          </div>
          
          {isScanning && (
            <div className="mt-4">
              <div className="text-sm text-gray-400 mb-2">Professional Security Analysis in Progress...</div>
              <div className="bg-gray-700 rounded-full h-2 mx-8">
                <div className="bg-orange-400 h-2 rounded-full animate-pulse w-3/4"></div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// RustProof Header Component
const RustProofHeader = () => (
  <header className="bg-gray-900 border-b border-gray-800 sticky top-0 z-50">
    <div className="max-w-7xl mx-auto px-4 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-gradient-to-br from-orange-500 to-red-600 rounded-lg flex items-center justify-center">
            <span className="text-white font-bold text-lg">🛡️</span>
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">RustProof</h1>
            <p className="text-sm text-orange-400">Make Your Solana Code RustProof</p>
          </div>
        </div>
        <div className="text-sm text-gray-400">
          Professional Edition v1.0
        </div>
      </div>
    </div>
  </header>
);

// RustProof Footer Component
const RustProofFooter = () => (
  <footer className="bg-gray-900 border-t border-gray-800 mt-auto">
    <div className="max-w-7xl mx-auto px-4 py-8">
      <div className="flex flex-col md:flex-row justify-between items-center">
        {/* Left side: RustProof branding */}
        <div className="flex items-center space-x-2 mb-4 md:mb-0">
          <div className="w-6 h-6 bg-gradient-to-br from-orange-500 to-red-600 rounded flex items-center justify-center">
            <span className="text-white text-xs">🛡️</span>
          </div>
          <span className="text-white font-semibold">RustProof</span>
          <span className="text-gray-400">v1.0</span>
        </div>
        
        {/* Center: Developer attribution */}
        <div className="flex items-center space-x-2 text-gray-400 mb-4 md:mb-0">
          <span>Developed with</span>
          <span className="text-red-500">❤️</span>
          <span>by</span>
          <a href="https://akinator.sh" className="text-orange-400 hover:text-orange-300 font-medium transition-colors">
            Akinator
          </a>
        </div>
        
        {/* Right side: Social links */}
        <div className="flex items-center space-x-4">
          <a href="https://github.com/0xAkinator" 
             className="text-gray-400 hover:text-white transition-colors"
             target="_blank" rel="noopener noreferrer">
            <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>
          </a>
          <a href="https://x.com/0xAkinator" 
             className="text-gray-400 hover:text-white transition-colors"
             target="_blank" rel="noopener noreferrer">
            <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
              <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"/>
            </svg>
          </a>
          <a href="https://akinator.sh" 
             className="text-gray-400 hover:text-white transition-colors"
             target="_blank" rel="noopener noreferrer">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9v-9m0-9v9"/>
            </svg>
          </a>
        </div>
      </div>
      
      {/* Bottom copyright */}
      <div className="border-t border-gray-800 mt-6 pt-6 text-center text-gray-500 text-sm">
        <p>&copy; 2025 RustProof. Making Solana development safer, one scan at a time.</p>
      </div>
    </div>
  </footer>
);

// Platform Analytics Component (Session-based)
const PlatformAnalytics = ({ analytics }) => {
  if (!analytics) return null;

  return (
    <div className="mt-16">
      <h2 className="text-2xl font-bold text-white mb-6 text-center">📊 Platform Analytics</h2>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6 max-w-4xl mx-auto">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 text-center hover:border-orange-500/50 transition-colors">
          <div className="text-2xl font-bold text-blue-400 mb-1">🔍</div>
          <div className="text-2xl font-bold text-blue-400">{analytics.total_scans}</div>
          <div className="text-sm text-gray-400">Total Scans</div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 text-center hover:border-orange-500/50 transition-colors">
          <div className="text-2xl font-bold text-red-400 mb-1">📊</div>
          <div className="text-2xl font-bold text-red-400">{analytics.average_security_score}%</div>
          <div className="text-sm text-gray-400">Avg Security Score</div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 text-center hover:border-orange-500/50 transition-colors">
          <div className="text-2xl font-bold text-orange-400 mb-1">🐛</div>
          <div className="text-2xl font-bold text-orange-400">{analytics.total_vulnerabilities_found}</div>
          <div className="text-sm text-gray-400">Vulnerabilities Found</div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 text-center hover:border-orange-500/50 transition-colors">
          <div className="text-2xl font-bold text-green-400 mb-1">⚡</div>
          <div className="text-2xl font-bold text-green-400">{analytics.rule_types}</div>
          <div className="text-sm text-gray-400">Rule Categories</div>
        </div>
      </div>
    </div>
  );
};

// Main App Component
function App() {
  const [currentView, setCurrentView] = useState('upload');
  const [scanResult, setScanResult] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [sessionScans, setSessionScans] = useState([]);
  const [analytics, setAnalytics] = useState(null);

  useEffect(() => {
    loadPlatformAnalytics();
    loadSessionScans();
  }, []);

  const loadSessionScans = async () => {
    const sessionId = getSessionId();
    try {
      const response = await axios.get(`${API}/scans/session/${sessionId}`);
      setSessionScans(response.data.slice(0, 3)); // Show last 3 session scans
    } catch (error) {
      console.error('Failed to load session scans:', error);
    }
  };

  const loadPlatformAnalytics = async () => {
    try {
      const response = await axios.get(`${API}/analytics/platform`);
      setAnalytics(response.data);
    } catch (error) {
      console.error('Failed to load analytics:', error);
    }
  };

  const handleFileSelect = async (file) => {
    setIsScanning(true);
    setScanResult(null);
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await axios.post(`${API}/scan`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      setScanResult(response.data);
      setCurrentView('results');
      loadSessionScans(); // Refresh session scans
      loadPlatformAnalytics(); // Refresh analytics
    } catch (error) {
      console.error('Scan failed:', error);
      alert('Scan failed. Please try again.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleDemoScan = async () => {
    setIsScanning(true);
    setScanResult(null);
    
    try {
      const response = await axios.post(`${API}/demo-scan`);
      setScanResult(response.data);
      setCurrentView('results');
      loadSessionScans();
      loadPlatformAnalytics();
    } catch (error) {
      console.error('Demo scan failed:', error);
      alert('Demo scan failed. Please try again.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleExportJSON = async () => {
    if (!scanResult) return;
    
    try {
      const response = await axios.post(`${API}/export/json/${scanResult.id}`, {}, {
        responseType: 'blob'
      });
      
      const blob = new Blob([response.data], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `rustproof_scan_${scanResult.id.slice(0, 8)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('JSON export failed:', error);
      alert('JSON export failed. Please try again.');
    }
  };

  const handleExportPDF = async () => {
    if (!scanResult) return;
    
    try {
      const response = await axios.post(`${API}/export/pdf/${scanResult.id}`, {}, {
        responseType: 'blob'
      });
      
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `RustProof_Security_Report_${scanResult.id.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('PDF export failed:', error);
      alert('PDF export failed. Please try again.');
    }
  };

  const renderUploadView = () => (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <RustProofHeader />
      
      <div className="flex-1 py-12">
        <div className="max-w-7xl mx-auto px-4">
          {/* Enhanced Header */}
          <div className="text-center mb-12">
            <div className="flex justify-center mb-6">
              <div className="bg-gradient-to-br from-orange-500 to-red-600 p-4 rounded-full shadow-lg">
                <svg className="w-16 h-16 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
            </div>
            <h1 className="text-5xl font-bold text-white mb-4">
              Professional Solana Security Analysis
            </h1>
            <p className="text-xl text-gray-400 mb-8">
              Advanced vulnerability detection with enterprise-grade reporting and compliance
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto mb-8">
              <div className="bg-gray-800 px-4 py-3 rounded-lg border border-gray-700 hover:border-orange-500/50 transition-colors">
                <div className="text-2xl mb-1">🔐</div>
                <span className="text-sm font-medium text-green-400">Access Control</span>
              </div>
              <div className="bg-gray-800 px-4 py-3 rounded-lg border border-gray-700 hover:border-orange-500/50 transition-colors">
                <div className="text-2xl mb-1">💰</div>
                <span className="text-sm font-medium text-blue-400">DeFi Security</span>
              </div>
              <div className="bg-gray-800 px-4 py-3 rounded-lg border border-gray-700 hover:border-orange-500/50 transition-colors">
                <div className="text-2xl mb-1">⚡</div>
                <span className="text-sm font-medium text-purple-400">Solana Specific</span>
              </div>
              <div className="bg-gray-800 px-4 py-3 rounded-lg border border-gray-700 hover:border-orange-500/50 transition-colors">
                <div className="text-2xl mb-1">📊</div>
                <span className="text-sm font-medium text-yellow-400">Oracle Security</span>
              </div>
            </div>
          </div>

          {/* File Upload */}
          <FileUpload onFileSelect={handleFileSelect} isScanning={isScanning} />

          {/* Demo Button */}
          {!isScanning && (
            <div className="text-center mt-8">
              <button
                onClick={handleDemoScan}
                className="bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 text-white font-medium py-3 px-8 rounded-lg transition-all duration-200 transform hover:scale-105 shadow-lg"
              >
                🚀 Try Professional Demo Scan
              </button>
              <p className="text-gray-500 text-sm mt-2">
                Test with vulnerable DeFi contract examples
              </p>
            </div>
          )}

          {/* Platform Analytics */}
          <PlatformAnalytics analytics={analytics} />

          {/* Session Scans */}
          {sessionScans.length > 0 && (
            <div className="mt-16">
              <h2 className="text-2xl font-bold text-white mb-6">📈 Your Recent Scans</h2>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 max-w-4xl mx-auto">
                {sessionScans.map((scan) => (
                  <div
                    key={scan.id}
                    onClick={() => {
                      setScanResult(scan);
                      setCurrentView('results');
                    }}
                    className="bg-gray-800 border border-gray-700 rounded-lg p-4 cursor-pointer hover:border-orange-500/50 transition-all duration-200 hover:shadow-lg"
                  >
                    <div className="flex items-center justify-between mb-3">
                      <SecurityScore score={scan.security_score} riskLevel={scan.risk_assessment} size="small" />
                      <div className="text-right">
                        <div className="text-sm text-gray-400">
                          {new Date(scan.created_at).toLocaleDateString()}
                        </div>
                        <div className="text-xs text-gray-500">
                          {scan.total_vulnerabilities} issues found
                        </div>
                      </div>
                    </div>
                    <div className="flex space-x-2 text-xs">
                      {scan.critical_count > 0 && (
                        <span className="bg-red-900 text-red-200 px-2 py-1 rounded">
                          {scan.critical_count} Critical
                        </span>
                      )}
                      {scan.high_count > 0 && (
                        <span className="bg-orange-900 text-orange-200 px-2 py-1 rounded">
                          {scan.high_count} High
                        </span>
                      )}
                      {scan.medium_count > 0 && (
                        <span className="bg-yellow-900 text-yellow-200 px-2 py-1 rounded">
                          {scan.medium_count} Medium
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
      
      <RustProofFooter />
    </div>
  );

  const renderResultsView = () => (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <RustProofHeader />
      
      <div className="flex-1 py-12">
        <div className="max-w-7xl mx-auto px-4">
          {/* Enhanced Header with Navigation */}
          <div className="flex items-center justify-between mb-8">
            <button
              onClick={() => setCurrentView('upload')}
              className="text-orange-400 hover:text-orange-300 flex items-center space-x-2 transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
              <span>Back to Scanner</span>
            </button>
            <h1 className="text-3xl font-bold text-white">🔍 Professional Security Analysis</h1>
            <div className="flex space-x-2">
              <button 
                onClick={handleExportJSON}
                className="text-gray-400 hover:text-white p-2 rounded border border-gray-700 hover:border-orange-500 transition-colors"
              >
                💾 Export JSON
              </button>
              <button 
                onClick={handleExportPDF}
                className="text-gray-400 hover:text-white p-2 rounded border border-gray-700 hover:border-orange-500 transition-colors"
              >
                📄 Export PDF
              </button>
            </div>
          </div>

          {scanResult && (
            <>
              {/* Enhanced Security Score Overview */}
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 mb-8">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-2xl font-bold text-white mb-2">RustProof Analysis Results</h2>
                    <p className="text-gray-400">
                      Analyzed {scanResult.security_metrics?.total_lines_analyzed || 0} lines of code • 
                      Found {scanResult.total_vulnerabilities} security issues
                    </p>
                    <p className="text-orange-400 text-sm mt-1">
                      📁 File: {scanResult.file_name || 'Unknown'}
                    </p>
                  </div>
                  <SecurityScore 
                    score={scanResult.security_score} 
                    riskLevel={scanResult.risk_assessment}
                  />
                </div>
                
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8">
                  <div className="text-center p-4 bg-red-900/20 border border-red-500/30 rounded">
                    <div className="text-2xl font-bold text-red-400">{scanResult.critical_count}</div>
                    <div className="text-sm text-gray-400">Critical</div>
                  </div>
                  <div className="text-center p-4 bg-orange-900/20 border border-orange-500/30 rounded">
                    <div className="text-2xl font-bold text-orange-400">{scanResult.high_count}</div>
                    <div className="text-sm text-gray-400">High</div>
                  </div>
                  <div className="text-center p-4 bg-yellow-900/20 border border-yellow-500/30 rounded">
                    <div className="text-2xl font-bold text-yellow-400">{scanResult.medium_count}</div>
                    <div className="text-sm text-gray-400">Medium</div>
                  </div>
                  <div className="text-center p-4 bg-blue-900/20 border border-blue-500/30 rounded">
                    <div className="text-2xl font-bold text-blue-400">{scanResult.low_count}</div>
                    <div className="text-sm text-gray-400">Low</div>
                  </div>
                </div>
              </div>

              {/* Analytics Dashboard */}
              <AnalyticsDashboard scanResult={scanResult} />

              {/* Vulnerabilities List */}
              <div className="mt-8">
                <h2 className="text-2xl font-bold text-white mb-6">🐛 Detailed Vulnerability Report</h2>
                {scanResult.vulnerabilities.length > 0 ? (
                  <div className="space-y-4">
                    {scanResult.vulnerabilities.map((vulnerability) => (
                      <VulnerabilityCard key={vulnerability.id} vulnerability={vulnerability} />
                    ))}
                  </div>
                ) : (
                  <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-8 text-center">
                    <svg className="w-16 h-16 text-green-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 className="text-xl font-bold text-green-400 mb-2">🎉 Excellent Security!</h3>
                    <p className="text-green-300">Your Solana program passed RustProof analysis with no vulnerabilities detected.</p>
                    <p className="text-green-400 text-sm mt-2">Your code follows professional security best practices!</p>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
      
      <RustProofFooter />
    </div>
  );

  return (
    <div className="App">
      {currentView === 'upload' ? renderUploadView() : renderResultsView()}
    </div>
  );
}

export default App;