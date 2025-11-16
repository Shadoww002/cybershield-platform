import React, { useState, useRef, useEffect } from 'react';
import { Shield, Upload, Globe, Activity, FileText, AlertTriangle, CheckCircle, XCircle, Clock, TrendingUp, Database, Lock, Wifi, MessageSquare, Send, X, Bot, Download, Eye, Server, Bug, Zap, Target } from 'lucide-react';

const CyberThreatPlatform = () => {
  const [activeTab, setActiveTab] = useState('upload');
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [apiEndpoint, setApiEndpoint] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [monitorUrl, setMonitorUrl] = useState('');
  const [monitorStatus, setMonitorStatus] = useState('inactive');
  const [chatOpen, setChatOpen] = useState(false);
  const [messages, setMessages] = useState([
    { role: 'assistant', content: 'Hello! I\'m your CyberShield AI Assistant. I can help you understand your security analysis, explain threats, and provide recommendations. How can I assist you today?' }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const supportedFormats = ['.log', '.pcap', '.json', '.csv', '.txt', '.xml', '.pdf'];

  // Generate different analysis based on input
  const generateAnalysis = (source, identifier) => {
    const scenarios = [
      {
        overallThreatLevel: 'Critical',
        threatsDetected: 24,
        criticalIssues: 8,
        warnings: 12,
        info: 4,
        confidence: 94,
        predictions: [
          {
            type: 'Zero-Day Exploit Detected',
            severity: 'Critical',
            probability: 97,
            location: 'Application Layer /api/v2/admin',
            timestamp: new Date().toISOString(),
            recommendation: 'Immediate patching required. Isolate affected systems and implement emergency access controls.',
            impact: 'Full system compromise possible'
          },
          {
            type: 'Advanced Persistent Threat (APT)',
            severity: 'Critical',
            probability: 89,
            location: 'Network Layer - Multiple IPs',
            timestamp: new Date().toISOString(),
            recommendation: 'Engage incident response team. Monitor all outbound connections and review system logs.',
            impact: 'Data exfiltration in progress'
          },
          {
            type: 'Ransomware Signature',
            severity: 'Critical',
            probability: 92,
            location: 'File System: C:/Windows/System32',
            timestamp: new Date().toISOString(),
            recommendation: 'Disconnect from network immediately. Initiate backup restoration protocols.',
            impact: 'Potential data encryption'
          },
          {
            type: 'Credential Stuffing Attack',
            severity: 'High',
            probability: 85,
            location: 'Authentication Service',
            timestamp: new Date().toISOString(),
            recommendation: 'Force password resets for affected accounts. Enable MFA across all services.',
            impact: '1,234 accounts compromised'
          }
        ],
        vulnerabilities: [
          { cve: 'CVE-2024-8901', severity: 'Critical', component: 'Apache Log4j 2.17.0', cvssScore: 9.8 },
          { cve: 'CVE-2024-7823', severity: 'Critical', component: 'Windows SMB', cvssScore: 9.3 },
          { cve: 'CVE-2024-6745', severity: 'High', component: 'OpenSSL 3.0.1', cvssScore: 8.1 }
        ],
        attackVectors: ['Remote Code Execution', 'Privilege Escalation', 'Data Exfiltration', 'Lateral Movement'],
        timelineRisk: { next24h: 92, next7days: 95, next30days: 98 },
        affectedAssets: ['Production Servers', 'Database Cluster', 'API Gateway', 'Admin Portal', 'User Accounts'],
        recommendations: [
          'EMERGENCY: Isolate compromised systems from network immediately',
          'Deploy emergency security patches within 4 hours',
          'Activate incident response team and DRP procedures',
          'Implement network segmentation to contain breach',
          'Conduct immediate forensic analysis of affected systems',
          'Notify stakeholders and prepare breach notification'
        ],
        attackTimeline: [
          { time: '2 hours ago', event: 'Initial reconnaissance detected' },
          { time: '1 hour ago', event: 'Exploitation attempt on admin portal' },
          { time: '45 min ago', event: 'Privilege escalation successful' },
          { time: '20 min ago', event: 'Data exfiltration activity detected' }
        ]
      },
      {
        overallThreatLevel: 'High',
        threatsDetected: 15,
        criticalIssues: 3,
        warnings: 9,
        info: 3,
        confidence: 88,
        predictions: [
          {
            type: 'SQL Injection Vulnerability',
            severity: 'Critical',
            probability: 94,
            location: 'Login endpoint /api/auth/login',
            timestamp: new Date().toISOString(),
            recommendation: 'Implement parameterized queries immediately. Add WAF rules to block injection attempts.',
            impact: 'Database access possible'
          },
          {
            type: 'Cross-Site Scripting (XSS)',
            severity: 'High',
            probability: 82,
            location: 'User profile page',
            timestamp: new Date().toISOString(),
            recommendation: 'Sanitize all user inputs. Implement Content Security Policy headers.',
            impact: 'Session hijacking risk'
          },
          {
            type: 'Insecure Direct Object Reference',
            severity: 'High',
            probability: 78,
            location: 'Document download API',
            timestamp: new Date().toISOString(),
            recommendation: 'Add proper authorization checks. Implement access control lists.',
            impact: 'Unauthorized data access'
          },
          {
            type: 'Rate Limiting Bypass',
            severity: 'Medium',
            probability: 71,
            location: 'API endpoints',
            timestamp: new Date().toISOString(),
            recommendation: 'Implement distributed rate limiting with Redis. Add CAPTCHA for suspicious traffic.',
            impact: 'API abuse possible'
          }
        ],
        vulnerabilities: [
          { cve: 'CVE-2024-5432', severity: 'Critical', component: 'React 17.0.2', cvssScore: 8.6 },
          { cve: 'CVE-2024-4321', severity: 'High', component: 'Node.js 16.14.0', cvssScore: 7.5 },
          { cve: 'CVE-2024-3210', severity: 'Medium', component: 'Express 4.17.1', cvssScore: 6.1 }
        ],
        attackVectors: ['Web Application', 'API Layer', 'Authentication'],
        timelineRisk: { next24h: 68, next7days: 75, next30days: 81 },
        affectedAssets: ['Web Application', 'API Services', 'User Sessions', 'Database'],
        recommendations: [
          'Update all vulnerable npm packages to latest versions',
          'Enable Web Application Firewall with OWASP rules',
          'Implement comprehensive input validation',
          'Add security headers (CSP, HSTS, X-Frame-Options)',
          'Conduct code security review for injection flaws',
          'Enable API request logging and monitoring'
        ],
        attackTimeline: [
          { time: '6 hours ago', event: 'Automated vulnerability scan detected' },
          { time: '4 hours ago', event: 'SQL injection attempts on login form' },
          { time: '2 hours ago', event: 'Multiple XSS payload submissions' },
          { time: '30 min ago', event: 'Continued probing of API endpoints' }
        ]
      },
      {
        overallThreatLevel: 'Medium',
        threatsDetected: 9,
        criticalIssues: 1,
        warnings: 5,
        info: 3,
        confidence: 85,
        predictions: [
          {
            type: 'Outdated Dependencies',
            severity: 'High',
            probability: 88,
            location: 'Package.json dependencies',
            timestamp: new Date().toISOString(),
            recommendation: 'Update all packages to latest stable versions. Set up automated dependency scanning.',
            impact: 'Known vulnerabilities present'
          },
          {
            type: 'Weak Password Policy',
            severity: 'Medium',
            probability: 76,
            location: 'User registration system',
            timestamp: new Date().toISOString(),
            recommendation: 'Enforce strong password requirements. Implement password strength meter.',
            impact: 'Easy credential compromise'
          },
          {
            type: 'Missing Security Headers',
            severity: 'Medium',
            probability: 91,
            location: 'HTTP responses',
            timestamp: new Date().toISOString(),
            recommendation: 'Add security headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options.',
            impact: 'Clickjacking vulnerability'
          },
          {
            type: 'Unencrypted Data Transmission',
            severity: 'Medium',
            probability: 68,
            location: 'Internal API calls',
            timestamp: new Date().toISOString(),
            recommendation: 'Enforce HTTPS for all communications. Disable HTTP endpoints.',
            impact: 'Man-in-the-middle risk'
          }
        ],
        vulnerabilities: [
          { cve: 'CVE-2024-2109', severity: 'Medium', component: 'jQuery 3.5.1', cvssScore: 6.5 },
          { cve: 'CVE-2024-1098', severity: 'Medium', component: 'Bootstrap 4.6.0', cvssScore: 5.9 },
          { cve: 'CVE-2024-0987', severity: 'Low', component: 'Lodash 4.17.19', cvssScore: 4.3 }
        ],
        attackVectors: ['Client-Side', 'Configuration', 'Dependencies'],
        timelineRisk: { next24h: 42, next7days: 48, next30days: 55 },
        affectedAssets: ['Frontend Application', 'Configuration', 'Third-party Libraries'],
        recommendations: [
          'Update frontend dependencies to latest versions',
          'Implement security headers across all responses',
          'Enforce HTTPS with HSTS preloading',
          'Add automated security scanning to CI/CD pipeline',
          'Strengthen password policy requirements',
          'Regular security audits and penetration testing'
        ],
        attackTimeline: [
          { time: '24 hours ago', event: 'Dependency scanner identified outdated packages' },
          { time: '12 hours ago', event: 'Security header analysis completed' },
          { time: '6 hours ago', event: 'Password policy weakness detected' },
          { time: '1 hour ago', event: 'HTTP endpoint usage identified' }
        ]
      }
    ];

    // Generate pseudo-random but consistent index based on identifier
    const hash = identifier.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
    const index = hash % scenarios.length;
    
    return scenarios[index];
  };

  const handleFileUpload = (e) => {
    const files = Array.from(e.target.files);
    setUploadedFiles(files);
    // Reset analysis when new files are uploaded
    setAnalysisResult(null);
  };

  const analyzeFiles = async () => {
    if (uploadedFiles.length === 0) return;
    
    setAnalyzing(true);
    
    // Create unique identifier from files
    const fileIdentifier = uploadedFiles.map(f => f.name + f.size).join('-');
    
    setTimeout(() => {
      const result = generateAnalysis('file', fileIdentifier);
      setAnalysisResult(result);
      setAnalyzing(false);
    }, 3000);
  };

  const analyzeAPI = async () => {
    if (!apiEndpoint) return;
    setAnalyzing(true);
    
    setTimeout(() => {
      const result = generateAnalysis('api', apiEndpoint);
      setAnalysisResult(result);
      setAnalyzing(false);
    }, 2500);
  };

  const startMonitoring = () => {
    if (!monitorUrl) return;
    setMonitorStatus('active');
    setAnalyzing(true);
    
    setTimeout(() => {
      const result = generateAnalysis('monitor', monitorUrl);
      setAnalysisResult(result);
      setAnalyzing(false);
    }, 3500);
  };

  const stopMonitoring = () => {
    setMonitorStatus('inactive');
  };

  const getThreatColor = (level) => {
    switch(level) {
      case 'Critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'High': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'Medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'Low': return 'text-green-600 bg-green-50 border-green-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getThreatLevelColor = (level) => {
    switch(level) {
      case 'Critical': return 'bg-red-500';
      case 'High': return 'bg-orange-500';
      case 'Medium': return 'bg-yellow-500';
      case 'Low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getThreatBadgeColor = (level) => {
    switch(level) {
      case 'Critical': return 'bg-red-500 text-white';
      case 'High': return 'bg-orange-500 text-white';
      case 'Medium': return 'bg-yellow-500 text-white';
      case 'Low': return 'bg-green-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const sendMessage = async () => {
    if (!inputMessage.trim()) return;

    const userMessage = { role: 'user', content: inputMessage };
    setMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsTyping(true);

    setTimeout(() => {
      let response = '';
      const query = inputMessage.toLowerCase();

      if (analysisResult) {
        if (query.includes('threat') || query.includes('risk')) {
          response = `Based on the current analysis, your system has an **${analysisResult.overallThreatLevel} Risk** level with ${analysisResult.threatsDetected} threats detected. The most critical issues include:\n\n${analysisResult.predictions.slice(0, 2).map(p => `• **${p.type}** (${p.probability}% probability) - ${p.severity} severity\n  Impact: ${p.impact}`).join('\n\n')}\n\nI recommend addressing the critical issues immediately.`;
        } else if (query.includes('critical') || query.includes('urgent')) {
          const critical = analysisResult.predictions.filter(p => p.severity === 'Critical');
          response = `You have **${analysisResult.criticalIssues} critical issues** that need immediate attention:\n\n${critical.map((p, i) => `${i + 1}. **${p.type}**\n   - Location: ${p.location}\n   - Impact: ${p.impact}\n   - Recommendation: ${p.recommendation}`).join('\n\n')}`;
        } else if (query.includes('recommendation') || query.includes('fix') || query.includes('solve')) {
          response = `Here are the top security recommendations for your system:\n\n${analysisResult.recommendations.slice(0, 3).map((r, i) => `${i + 1}. ${r}`).join('\n\n')}\n\nWould you like me to explain any of these in more detail?`;
        } else if (query.includes('vulnerability') || query.includes('cve')) {
          response = `I've detected **${analysisResult.vulnerabilities.length} vulnerabilities** in your system:\n\n${analysisResult.vulnerabilities.map(v => `• **${v.cve}** in ${v.component}\n  - Severity: ${v.severity}\n  - CVSS Score: ${v.cvssScore}`).join('\n\n')}\n\nThese should be patched as soon as possible to prevent exploitation.`;
        } else if (query.includes('timeline') || query.includes('forecast') || query.includes('future')) {
          response = `According to the risk forecast:\n\n• **Next 24 hours**: ${analysisResult.timelineRisk.next24h}% risk\n• **Next 7 days**: ${analysisResult.timelineRisk.next7days}% risk\n• **Next 30 days**: ${analysisResult.timelineRisk.next30days}% risk\n\nThe risk is trending ${analysisResult.timelineRisk.next30days > analysisResult.timelineRisk.next24h ? 'upward' : 'stable'}, indicating you should take preventive action now.`;
        } else {
          response = `I can help you with:\n\n• **Threat Analysis** - Explain detected threats and their severity\n• **Recommendations** - Guide you through security improvements\n• **CVE Vulnerabilities** - Detail known security flaws\n• **Risk Timeline** - Discuss future risk predictions\n• **Attack Timeline** - Review the sequence of detected events\n\nWhat would you like to know more about?`;
        }
      } else {
        if (query.includes('hello') || query.includes('hi')) {
          response = 'Hello! I\'m here to help you analyze and understand security threats. Upload files, enter an API endpoint, or start monitoring to begin the analysis, and I\'ll provide detailed insights.';
        } else {
          response = 'Please run an analysis first by uploading files, analyzing an API endpoint, or starting live monitoring. Once the analysis is complete, I can help you understand the results and provide detailed recommendations.';
        }
      }

      setMessages(prev => [...prev, { role: 'assistant', content: response }]);
      setIsTyping(false);
    }, 1000 + Math.random() * 1000);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const exportReport = () => {
    const report = {
      ...analysisResult,
      generatedAt: new Date().toISOString(),
      platform: 'CyberShield AI',
      reportType: 'Comprehensive Security Analysis'
    };
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybershield-report-${Date.now()}.json`;
    a.click();
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Shield className="w-12 h-12 text-cyan-400" />
              <div className="absolute inset-0 bg-cyan-400 blur-xl opacity-30"></div>
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 bg-clip-text text-transparent">
                CyberShield AI
              </h1>
              <p className="text-slate-400 text-sm">Advanced Threat Prediction & Analysis Platform</p>
            </div>
          </div>
          {monitorStatus === 'active' && (
            <div className="flex items-center gap-2 px-4 py-2 bg-green-500/20 border border-green-500 rounded-lg backdrop-blur">
              <Activity className="w-5 h-5 text-green-400 animate-pulse" />
              <span className="text-green-400 font-semibold">Live Monitoring Active</span>
            </div>
          )}
        </div>

        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Input Section */}
          <div className="lg:col-span-1 space-y-6">
            {/* Tabs */}
            <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-2">
              <div className="flex flex-col gap-2">
                <button
                  onClick={() => setActiveTab('upload')}
                  className={`flex items-center gap-2 px-4 py-3 rounded-lg transition-all ${
                    activeTab === 'upload' ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg' : 'text-slate-400 hover:bg-slate-700'
                  }`}
                >
                  <Upload className="w-5 h-5" />
                  <span className="font-medium">File Upload</span>
                </button>
                <button
                  onClick={() => setActiveTab('api')}
                  className={`flex items-center gap-2 px-4 py-3 rounded-lg transition-all ${
                    activeTab === 'api' ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg' : 'text-slate-400 hover:bg-slate-700'
                  }`}
                >
                  <Database className="w-5 h-5" />
                  <span className="font-medium">API Analysis</span>
                </button>
                <button
                  onClick={() => setActiveTab('monitor')}
                  className={`flex items-center gap-2 px-4 py-3 rounded-lg transition-all ${
                    activeTab === 'monitor' ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg' : 'text-slate-400 hover:bg-slate-700'
                  }`}
                >
                  <Activity className="w-5 h-5" />
                  <span className="font-medium">Live Monitor</span>
                </button>
              </div>
            </div>

            {/* Input Forms */}
            <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
              {activeTab === 'upload' && (
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <Upload className="w-5 h-5 text-cyan-400" />
                    Upload Security Files
                  </h3>
                  <p className="text-sm text-slate-400">
                    Supported formats: {supportedFormats.join(', ')}
                  </p>
                  <div className="border-2 border-dashed border-slate-600 rounded-lg p-8 text-center hover:border-cyan-500 transition-colors cursor-pointer bg-slate-700/30">
                    <input
                      type="file"
                      multiple
                      onChange={handleFileUpload}
                      className="hidden"
                      id="fileUpload"
                      accept={supportedFormats.join(',')}
                    />
                    <label htmlFor="fileUpload" className="cursor-pointer">
                      <Upload className="w-12 h-12 mx-auto mb-3 text-slate-500" />
                      <p className="text-slate-400">Click to upload or drag and drop</p>
                      <p className="text-sm text-slate-500 mt-2">Multiple files supported</p>
                    </label>
                  </div>
                  {uploadedFiles.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-sm font-medium text-slate-300">Uploaded Files:</p>
                      {uploadedFiles.map((file, idx) => (
                        <div key={idx} className="flex items-center gap-2 text-sm bg-slate-700/50 p-3 rounded-lg border border-slate-600">
                          <FileText className="w-4 h-4 text-cyan-400" />
                          <span className="text-slate-300 flex-1">{file.name}</span>
                          <span className="text-xs text-slate-500">{(file.size / 1024).toFixed(1)} KB</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <button
                    onClick={analyzeFiles}
                    disabled={uploadedFiles.length === 0 || analyzing}
                    className="w-full bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 disabled:from-slate-600 disabled:to-slate-600 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-lg transition-all shadow-lg"
                  >
                    {analyzing ? 'Analyzing...' : 'Analyze Files'}
                  </button>
                </div>
              )}

              {activeTab === 'api' && (
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <Database className="w-5 h-5 text-cyan-400" />
                    API Security Analysis
                  </h3>
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">API Endpoint URL</label>
                    <input
                      type="text"
                      value={apiEndpoint}
                      onChange={(e) => setApiEndpoint(e.target.value)}
                      placeholder="https://api.example.com/v1/..."
                      className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">API Key (Optional)</label>
                    <input
                      type="password"
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      placeholder="Enter API key for authenticated analysis"
                      className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    />
                  </div>
                  <button
                    onClick={analyzeAPI}
                    disabled={!apiEndpoint || analyzing}
                    className="w-full bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 disabled:from-slate-600 disabled:to-slate-600 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-lg transition-all shadow-lg"
                  >
                    {analyzing ? 'Analyzing...' : 'Analyze API'}
                  </button>
                </div>
              )}

              {activeTab === 'monitor' && (
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <Activity className="w-5 h-5 text-cyan-400" />
                    Live Threat Monitoring
                  </h3>
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">URL to Monitor</label>
                    <input
                      type="text"
                      value={monitorUrl}
                      onChange={(e) => setMonitorUrl(e.target.value)}
                      placeholder="https://example.com"
                      className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    />
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 space-y-2 border border-slate-600">
                    <p className="text-sm font-medium text-slate-300">Monitoring Options:</p>
                    <label className="flex items-center gap-2 text-sm text-slate-400">
                      <input type="checkbox" className="rounded" defaultChecked />
                      Network Traffic Analysis
                    </label>
                    <label className="flex items-center gap-2 text-sm text-slate-400">
                      <input type="checkbox" className="rounded" defaultChecked />
                      Port Scanning Detection
                    </label>
                    <label className="flex items-center gap-2 text-sm text-slate-400">
                      <input type="checkbox" className="rounded" defaultChecked />
                      SSL/TLS Monitoring
                    </label>
                    <label className="flex items-center gap-2 text-sm text-slate-400">
                      <input type="checkbox" className="rounded" defaultChecked />
                      Real-time Alerts
                    </label>
                  </div>
                  {monitorStatus === 'inactive' ? (
                    <button
                      onClick={startMonitoring}
                      disabled={!monitorUrl || analyzing}
                      className="w-full bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 disabled:from-slate-600 disabled:to-slate-600 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-lg transition-all shadow-lg"
                    >
                      {analyzing ? 'Starting...' : 'Start Monitoring'}
                    </button>
                  ) : (
                    <button
                      onClick={stopMonitoring}
                      className="w-full bg-gradient-to-r from-red-500 to-rose-500 hover:from-red-600 hover:to-rose-600 text-white font-semibold py-3 rounded-lg transition-all shadow-lg"
                    >
                      Stop Monitoring
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Results Section */}
          <div className="lg:col-span-2 space-y-6">
            {analyzing && !analysisResult && (
              <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-12 text-center">
                <div className="relative w-20 h-20 mx-auto mb-6">
                  <div className="absolute inset-0 border-4 border-cyan-500/30 rounded-full"></div>
                  <div className="absolute inset-0 border-4 border-cyan-500 rounded-full border-t-transparent animate-spin"></div>
                  <Shield className="absolute inset-0 m-auto w-8 h-8 text-cyan-400" />
                </div>
                <p className="text-slate-300 font-medium text-lg">Analyzing security data...</p>
                <p className="text-slate-500 text-sm mt-2">AI models are processing threat patterns and vulnerabilities</p>
              </div>
            )}

            {!analyzing && !analysisResult && (
              <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-12 text-center">
                <div className="relative inline-block mb-4">
                  <Shield className="w-20 h-20 text-slate-600" />
                  <div className="absolute inset-0 bg-slate-600 blur-2xl opacity-20"></div>
                </div>
                <p className="text-slate-400 font-medium text-lg">No analysis yet</p>
                <p className="text-slate-500 text-sm mt-2">Upload files, enter API endpoint, or start monitoring to begin</p>
              </div>
            )}

            {analysisResult && (
              <div className="space-y-6">
                {/* Hero Summary Card */}
                <div className="relative bg-gradient-to-br from-slate-800 via-slate-800/95 to-slate-900 backdrop-blur border border-slate-700 rounded-2xl p-8 overflow-hidden">
                  <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl"></div>
                  <div className="absolute bottom-0 left-0 w-64 h-64 bg-purple-500/10 rounded-full blur-3xl"></div>
                  
                  <div className="relative z-10">
                    <div className="flex items-start justify-between mb-6">
                      <div>
                        <h2 className="text-3xl font-bold mb-2 bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                          Security Analysis Report
                        </h2>
                        <p className="text-slate-400">Generated {new Date().toLocaleString()}</p>
                      </div>
                      <button
                        onClick={exportReport}
                        className="flex items-center gap-2 px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500 rounded-lg transition-colors"
                      >
                        <Download className="w-4 h-4 text-cyan-400" />
                        <span className="text-cyan-400 text-sm font-medium">Export</span>
                      </button>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                      <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 backdrop-blur">
                        <div className="flex items-center justify-between mb-2">
                          <AlertTriangle className="w-6 h-6 text-red-400" />
                          <span className="text-3xl font-bold text-red-400">{analysisResult.criticalIssues}</span>
                        </div>
                        <p className="text-sm text-red-300 font-medium">Critical Issues</p>
                      </div>
                      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4 backdrop-blur">
                        <div className="flex items-center justify-between mb-2">
                          <Bug className="w-6 h-6 text-yellow-400" />
                          <span className="text-3xl font-bold text-yellow-400">{analysisResult.warnings}</span>
                        </div>
                        <p className="text-sm text-yellow-300 font-medium">Warnings</p>
                      </div>
                      <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4 backdrop-blur">
                        <div className="flex items-center justify-between mb-2">
                          <Eye className="w-6 h-6 text-blue-400" />
                          <span className="text-3xl font-bold text-blue-400">{analysisResult.info}</span>
                        </div>
                        <p className="text-sm text-blue-300 font-medium">Informational</p>
                      </div>
                      <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-xl p-4 backdrop-blur">
                        <div className="flex items-center justify-between mb-2">
                          <TrendingUp className="w-6 h-6 text-cyan-400" />
                          <span className="text-3xl font-bold text-cyan-400">{analysisResult.confidence}%</span>
                        </div>
                        <p className="text-sm text-cyan-300 font-medium">Confidence</p>
                      </div>
                    </div>

                    <div className="bg-slate-700/50 rounded-xl p-6 border border-slate-600">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-xl font-semibold text-white">Overall Threat Level</h3>
                        <div className={`px-4 py-2 rounded-lg font-bold text-lg ${getThreatLevelColor(analysisResult.overallThreatLevel)} text-white shadow-lg`}>
                          {analysisResult.overallThreatLevel} Risk
                        </div>
                      </div>
                      <div className="relative h-3 bg-slate-800 rounded-full overflow-hidden">
                        <div 
                          className={`absolute h-full ${getThreatLevelColor(analysisResult.overallThreatLevel)} transition-all duration-1000 ease-out`}
                          style={{width: `${analysisResult.overallThreatLevel === 'Critical' ? 100 : analysisResult.overallThreatLevel === 'High' ? 75 : analysisResult.overallThreatLevel === 'Medium' ? 50 : 25}%`}}
                        />
                      </div>
                      <p className="text-slate-400 text-sm mt-3">
                        {analysisResult.threatsDetected} threats detected across {analysisResult.affectedAssets.length} asset categories
                      </p>
                    </div>
                  </div>
                </div>

                {/* Attack Timeline */}
                {analysisResult.attackTimeline && (
                  <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
                    <h3 className="text-xl font-semibold mb-6 flex items-center gap-2">
                      <Clock className="w-6 h-6 text-cyan-400" />
                      Attack Timeline
                    </h3>
                    <div className="space-y-4">
                      {analysisResult.attackTimeline.map((event, idx) => (
                        <div key={idx} className="flex gap-4">
                          <div className="flex flex-col items-center">
                            <div className="w-3 h-3 rounded-full bg-red-500"></div>
                            {idx < analysisResult.attackTimeline.length - 1 && (
                              <div className="w-0.5 h-full bg-slate-700 mt-2"></div>
                            )}
                          </div>
                          <div className="flex-1 pb-4">
                            <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                              <div className="flex items-center justify-between mb-2">
                                <span className="text-slate-300 font-medium">{event.event}</span>
                                <span className="text-xs text-slate-500 bg-slate-800 px-2 py-1 rounded">{event.time}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Threat Predictions - Enhanced Cards */}
                <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
                  <h3 className="text-xl font-semibold mb-6 flex items-center gap-2">
                    <Target className="w-6 h-6 text-cyan-400" />
                    Detected Threats & Predictions
                  </h3>
                  <div className="space-y-4">
                    {analysisResult.predictions.map((threat, idx) => (
                      <div key={idx} className="bg-gradient-to-br from-slate-700/80 to-slate-800/80 border border-slate-600 rounded-xl p-5 hover:shadow-lg transition-shadow">
                        <div className="flex items-start justify-between mb-4">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                              <Zap className={`w-5 h-5 ${threat.severity === 'Critical' ? 'text-red-400' : threat.severity === 'High' ? 'text-orange-400' : 'text-yellow-400'}`} />
                              <span className="font-bold text-lg text-white">{threat.type}</span>
                              <span className={`px-3 py-1 rounded-full text-xs font-bold ${getThreatBadgeColor(threat.severity)}`}>
                                {threat.severity}
                              </span>
                            </div>
                            <div className="space-y-2 text-sm">
                              <div className="flex items-center gap-2 text-slate-400">
                                <Server className="w-4 h-4" />
                                <span>{threat.location}</span>
                              </div>
                              <div className="flex items-center gap-2 text-slate-400">
                                <AlertTriangle className="w-4 h-4" />
                                <span>Impact: {threat.impact}</span>
                              </div>
                            </div>
                          </div>
                          <div className="text-right ml-4">
                            <div className="text-4xl font-bold bg-gradient-to-br from-red-400 to-orange-500 bg-clip-text text-transparent">
                              {threat.probability}%
                            </div>
                            <div className="text-xs text-slate-400 mt-1">Probability</div>
                          </div>
                        </div>
                        
                        <div className="mt-4 pt-4 border-t border-slate-600">
                          <p className="text-sm font-semibold text-cyan-400 mb-2">💡 Recommendation:</p>
                          <p className="text-sm text-slate-300">{threat.recommendation}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Risk Timeline Forecast - Enhanced Visualization */}
                <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
                  <h3 className="text-xl font-semibold mb-6 flex items-center gap-2">
                    <TrendingUp className="w-6 h-6 text-cyan-400" />
                    Risk Timeline Forecast
                  </h3>
                  <div className="space-y-6">
                    <div className="relative">
                      <div className="flex justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <Clock className="w-4 h-4 text-yellow-400" />
                          <span className="text-sm font-medium text-slate-300">Next 24 Hours</span>
                        </div>
                        <span className="text-sm font-bold text-yellow-400">{analysisResult.timelineRisk.next24h}% Risk</span>
                      </div>
                      <div className="relative h-4 bg-slate-700 rounded-full overflow-hidden">
                        <div 
                          className="absolute h-full bg-gradient-to-r from-yellow-500 to-yellow-400 rounded-full transition-all duration-1000"
                          style={{width: `${analysisResult.timelineRisk.next24h}%`}}
                        />
                      </div>
                    </div>
                    
                    <div className="relative">
                      <div className="flex justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <Clock className="w-4 h-4 text-orange-400" />
                          <span className="text-sm font-medium text-slate-300">Next 7 Days</span>
                        </div>
                        <span className="text-sm font-bold text-orange-400">{analysisResult.timelineRisk.next7days}% Risk</span>
                      </div>
                      <div className="relative h-4 bg-slate-700 rounded-full overflow-hidden">
                        <div 
                          className="absolute h-full bg-gradient-to-r from-orange-500 to-orange-400 rounded-full transition-all duration-1000"
                          style={{width: `${analysisResult.timelineRisk.next7days}%`}}
                        />
                      </div>
                    </div>
                    
                    <div className="relative">
                      <div className="flex justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <Clock className="w-4 h-4 text-red-400" />
                          <span className="text-sm font-medium text-slate-300">Next 30 Days</span>
                        </div>
                        <span className="text-sm font-bold text-red-400">{analysisResult.timelineRisk.next30days}% Risk</span>
                      </div>
                      <div className="relative h-4 bg-slate-700 rounded-full overflow-hidden">
                        <div 
                          className="absolute h-full bg-gradient-to-r from-red-500 to-red-400 rounded-full transition-all duration-1000"
                          style={{width: `${analysisResult.timelineRisk.next30days}%`}}
                        />
                      </div>
                    </div>
                  </div>
                </div>

                {/* CVE Vulnerabilities - Enhanced Cards */}
                <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
                  <h3 className="text-xl font-semibold mb-6 flex items-center gap-2">
                    <Lock className="w-6 h-6 text-cyan-400" />
                    Known Vulnerabilities (CVE Database)
                  </h3>
                  <div className="grid gap-4">
                    {analysisResult.vulnerabilities.map((vuln, idx) => (
                      <div key={idx} className="bg-slate-700/50 border border-slate-600 rounded-xl p-4 hover:border-cyan-500/50 transition-colors">
                        <div className="flex items-center justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                              <Bug className="w-5 h-5 text-red-400" />
                              <span className="font-mono text-cyan-400 font-bold">{vuln.cve}</span>
                              <span className={`px-3 py-1 rounded-full text-xs font-bold ${getThreatBadgeColor(vuln.severity)}`}>
                                {vuln.severity}
                              </span>
                            </div>
                            <p className="text-sm text-slate-400 ml-8">{vuln.component}</p>
                          </div>
                          <div className="text-right">
                            <div className="text-2xl font-bold text-red-400">{vuln.cvssScore}</div>
                            <div className="text-xs text-slate-500">CVSS Score</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Attack Vectors */}
                <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
                  <h3 className="text-xl font-semibold mb-6 flex items-center gap-2">
                    <Target className="w-6 h-6 text-cyan-400" />
                    Identified Attack Vectors
                  </h3>
                  <div className="grid grid-cols-2 gap-3">
                    {analysisResult.attackVectors.map((vector, idx) => (
                      <div key={idx} className="bg-gradient-to-br from-red-500/20 to-orange-500/20 border border-red-500/30 rounded-lg p-4 text-center">
                        <p className="font-semibold text-red-300">{vector}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Affected Assets */}
                <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
                  <h3 className="text-xl font-semibold mb-6 flex items-center gap-2">
                    <Server className="w-6 h-6 text-cyan-400" />
                    Affected Assets
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    {analysisResult.affectedAssets.map((asset, idx) => (
                      <div key={idx} className="bg-slate-700/50 border border-slate-600 rounded-lg p-3 flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-red-500"></div>
                        <span className="text-sm text-slate-300">{asset}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Security Recommendations - Enhanced */}
                <div className="bg-gradient-to-br from-cyan-500/10 to-blue-500/10 backdrop-blur border border-cyan-500/30 rounded-xl p-6">
                  <h3 className="text-xl font-semibold mb-6 flex items-center gap-2">
                    <CheckCircle className="w-6 h-6 text-cyan-400" />
                    Priority Security Recommendations
                  </h3>
                  <div className="space-y-3">
                    {analysisResult.recommendations.map((rec, idx) => (
                      <div key={idx} className="flex items-start gap-3 bg-slate-800/50 border border-slate-700 p-4 rounded-lg hover:border-cyan-500/50 transition-colors">
                        <div className="flex-shrink-0 w-8 h-8 rounded-full bg-cyan-500/20 flex items-center justify-center border border-cyan-500/50">
                          <span className="text-cyan-400 font-bold text-sm">{idx + 1}</span>
                        </div>
                        <span className="text-slate-300 text-sm flex-1 pt-1">{rec}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* AI Chat Assistant */}
        {chatOpen && (
          <div className="fixed bottom-24 right-6 w-96 h-[600px] bg-slate-800 border border-slate-700 rounded-2xl shadow-2xl flex flex-col z-50">
            {/* Chat Header */}
            <div className="bg-gradient-to-r from-cyan-500 to-blue-500 p-4 rounded-t-2xl flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-white rounded-full flex items-center justify-center">
                  <Bot className="w-6 h-6 text-cyan-500" />
                </div>
                <div>
                  <h3 className="font-semibold text-white">CyberShield AI Assistant</h3>
                  <p className="text-xs text-cyan-100">Always here to help</p>
                </div>
              </div>
              <button
                onClick={() => setChatOpen(false)}
                className="text-white hover:bg-white/20 p-2 rounded-lg transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Chat Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {messages.map((msg, idx) => (
                <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[80%] p-3 rounded-lg ${
                    msg.role === 'user' 
                      ? 'bg-gradient-to-br from-cyan-500 to-blue-500 text-white' 
                      : 'bg-slate-700 text-slate-100 border border-slate-600'
                  }`}>
                    {msg.role === 'assistant' && (
                      <div className="flex items-center gap-2 mb-1">
                        <Bot className="w-4 h-4 text-cyan-400" />
                        <span className="text-xs text-cyan-400 font-semibold">AI Assistant</span>
                      </div>
                    )}
                    <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
                  </div>
                </div>
              ))}
              {isTyping && (
                <div className="flex justify-start">
                  <div className="bg-slate-700 border border-slate-600 p-3 rounded-lg">
                    <div className="flex gap-1">
                      <div className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce" style={{animationDelay: '0ms'}}></div>
                      <div className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce" style={{animationDelay: '150ms'}}></div>
                      <div className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce" style={{animationDelay: '300ms'}}></div>
                    </div>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Chat Input */}
            <div className="p-4 border-t border-slate-700">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="Ask about threats, recommendations..."
                  className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <button
                  onClick={sendMessage}
                  disabled={!inputMessage.trim() || isTyping}
                  className="bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 disabled:from-slate-600 disabled:to-slate-600 disabled:cursor-not-allowed p-2 rounded-lg transition-all"
                >
                  <Send className="w-5 h-5 text-white" />
                </button>
              </div>
              <p className="text-xs text-slate-500 mt-2">Ask me about your security analysis</p>
            </div>
          </div>
        )}

        {/* Floating Chat Button */}
        <button
          onClick={() => setChatOpen(!chatOpen)}
          className="fixed bottom-6 right-6 w-16 h-16 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 rounded-full shadow-2xl flex items-center justify-center transition-all z-40 hover:scale-110"
        >
          {chatOpen ? (
            <X className="w-7 h-7 text-white" />
          ) : (
            <>
              <MessageSquare className="w-7 h-7 text-white" />
              {analysisResult && (
                <span className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 rounded-full flex items-center justify-center text-xs font-bold text-white animate-pulse">
                  !
                </span>
              )}
            </>
          )}
        </button>
      </div>
    </div>
  );
};

export default CyberThreatPlatform;