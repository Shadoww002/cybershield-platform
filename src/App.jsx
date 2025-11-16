import React, { useState, useRef, useEffect } from 'react';
import { Shield, Upload, Globe, Activity, FileText, AlertTriangle, CheckCircle, XCircle, Clock, TrendingUp, Database, Lock, Wifi, MessageSquare, Send, X, Bot } from 'lucide-react';

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

  const handleFileUpload = (e) => {
    const files = Array.from(e.target.files);
    setUploadedFiles(files);
  };

  const analyzeFiles = async () => {
    setAnalyzing(true);
    
    // Simulate AI analysis
    setTimeout(() => {
      const result = {
        overallThreatLevel: 'Medium',
        threatsDetected: 12,
        criticalIssues: 3,
        warnings: 7,
        info: 2,
        confidence: 87,
        predictions: [
          {
            type: 'SQL Injection Attempt',
            severity: 'Critical',
            probability: 92,
            location: 'Login endpoint /api/auth',
            timestamp: new Date().toISOString(),
            recommendation: 'Implement parameterized queries and input validation'
          },
          {
            type: 'Unusual Traffic Pattern',
            severity: 'High',
            probability: 78,
            location: 'Multiple IPs: 45.xxx.xxx.xxx',
            timestamp: new Date().toISOString(),
            recommendation: 'Enable rate limiting and implement CAPTCHA'
          },
          {
            type: 'Suspicious File Upload',
            severity: 'Critical',
            probability: 95,
            location: 'Upload directory /var/www/uploads',
            timestamp: new Date().toISOString(),
            recommendation: 'Scan uploaded files and restrict executable permissions'
          },
          {
            type: 'Brute Force Attack',
            severity: 'High',
            probability: 85,
            location: 'SSH port 22',
            timestamp: new Date().toISOString(),
            recommendation: 'Implement fail2ban and use key-based authentication'
          }
        ],
        vulnerabilities: [
          { cve: 'CVE-2024-1234', severity: 'Critical', component: 'Apache 2.4.49' },
          { cve: 'CVE-2024-5678', severity: 'High', component: 'OpenSSL 1.1.1' },
          { cve: 'CVE-2024-9012', severity: 'Medium', component: 'PHP 7.4.3' }
        ],
        attackVectors: ['Web Application', 'Network Layer', 'Authentication'],
        timelineRisk: {
          next24h: 65,
          next7days: 78,
          next30days: 82
        },
        affectedAssets: ['Web Server', 'Database', 'API Gateway', 'User Accounts'],
        recommendations: [
          'Update all vulnerable components immediately',
          'Enable Web Application Firewall (WAF)',
          'Implement multi-factor authentication',
          'Regular security audits and penetration testing',
          'Employee security awareness training'
        ]
      };
      
      setAnalysisResult(result);
      setAnalyzing(false);
    }, 3000);
  };

  const analyzeAPI = async () => {
    if (!apiEndpoint) return;
    setAnalyzing(true);
    
    setTimeout(() => {
      const result = {
        overallThreatLevel: 'Low',
        threatsDetected: 5,
        criticalIssues: 1,
        warnings: 3,
        info: 1,
        confidence: 91,
        predictions: [
          {
            type: 'Missing Rate Limiting',
            severity: 'Medium',
            probability: 88,
            location: apiEndpoint,
            timestamp: new Date().toISOString(),
            recommendation: 'Implement API rate limiting to prevent abuse'
          },
          {
            type: 'Weak Authentication',
            severity: 'Critical',
            probability: 76,
            location: 'API Key Management',
            timestamp: new Date().toISOString(),
            recommendation: 'Implement OAuth 2.0 or JWT-based authentication'
          }
        ],
        vulnerabilities: [
          { cve: 'N/A', severity: 'Medium', component: 'API Gateway' }
        ],
        attackVectors: ['API Abuse', 'Data Exposure'],
        timelineRisk: {
          next24h: 45,
          next7days: 52,
          next30days: 58
        },
        affectedAssets: ['API Endpoints', 'Data Layer'],
        recommendations: [
          'Implement comprehensive API authentication',
          'Add request validation and sanitization',
          'Enable API monitoring and logging',
          'Use HTTPS for all communications'
        ]
      };
      
      setAnalysisResult(result);
      setAnalyzing(false);
    }, 2500);
  };

  const startMonitoring = () => {
    if (!monitorUrl) return;
    setMonitorStatus('active');
    setAnalyzing(true);
    
    setTimeout(() => {
      const result = {
        overallThreatLevel: 'High',
        threatsDetected: 18,
        criticalIssues: 5,
        warnings: 10,
        info: 3,
        confidence: 94,
        predictions: [
          {
            type: 'DDoS Attack Pattern',
            severity: 'Critical',
            probability: 94,
            location: monitorUrl,
            timestamp: new Date().toISOString(),
            recommendation: 'Enable DDoS protection and CDN services'
          },
          {
            type: 'Port Scanning Activity',
            severity: 'High',
            probability: 89,
            location: 'Multiple ports',
            timestamp: new Date().toISOString(),
            recommendation: 'Close unused ports and enable intrusion detection'
          },
          {
            type: 'SSL/TLS Vulnerability',
            severity: 'Critical',
            probability: 82,
            location: 'Certificate Configuration',
            timestamp: new Date().toISOString(),
            recommendation: 'Update SSL certificate and disable weak ciphers'
          }
        ],
        vulnerabilities: [
          { cve: 'CVE-2024-3456', severity: 'Critical', component: 'Nginx 1.18' },
          { cve: 'CVE-2024-7890', severity: 'High', component: 'SSL/TLS Config' }
        ],
        attackVectors: ['Network Infrastructure', 'Transport Layer', 'Application Layer'],
        timelineRisk: {
          next24h: 82,
          next7days: 88,
          next30days: 91
        },
        affectedAssets: ['Web Infrastructure', 'DNS', 'Load Balancer', 'Origin Servers'],
        recommendations: [
          'Implement DDoS mitigation immediately',
          'Update web server software',
          'Configure proper SSL/TLS settings',
          'Enable real-time threat monitoring',
          'Set up automated incident response'
        ]
      };
      
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

  const sendMessage = async () => {
    if (!inputMessage.trim()) return;

    const userMessage = { role: 'user', content: inputMessage };
    setMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsTyping(true);

    // Simulate AI response with context about the analysis
    setTimeout(() => {
      let response = '';
      const query = inputMessage.toLowerCase();

      if (analysisResult) {
        if (query.includes('threat') || query.includes('risk')) {
          response = `Based on the current analysis, your system has an **${analysisResult.overallThreatLevel} Risk** level with ${analysisResult.threatsDetected} threats detected. The most critical issues include:\n\n${analysisResult.predictions.slice(0, 2).map(p => `• **${p.type}** (${p.probability}% probability) - ${p.severity} severity`).join('\n')}\n\nI recommend addressing the critical issues immediately.`;
        } else if (query.includes('critical') || query.includes('urgent')) {
          const critical = analysisResult.predictions.filter(p => p.severity === 'Critical');
          response = `You have **${analysisResult.criticalIssues} critical issues** that need immediate attention:\n\n${critical.map((p, i) => `${i + 1}. **${p.type}**\n   - Location: ${p.location}\n   - Recommendation: ${p.recommendation}`).join('\n\n')}`;
        } else if (query.includes('recommendation') || query.includes('fix') || query.includes('solve')) {
          response = `Here are the top security recommendations for your system:\n\n${analysisResult.recommendations.slice(0, 3).map((r, i) => `${i + 1}. ${r}`).join('\n\n')}\n\nWould you like me to explain any of these in more detail?`;
        } else if (query.includes('vulnerability') || query.includes('cve')) {
          response = `I've detected **${analysisResult.vulnerabilities.length} vulnerabilities** in your system:\n\n${analysisResult.vulnerabilities.map(v => `• **${v.cve}** in ${v.component} (${v.severity} severity)`).join('\n')}\n\nThese should be patched as soon as possible to prevent exploitation.`;
        } else if (query.includes('timeline') || query.includes('forecast') || query.includes('future')) {
          response = `According to the risk forecast:\n\n• **Next 24 hours**: ${analysisResult.timelineRisk.next24h}% risk\n• **Next 7 days**: ${analysisResult.timelineRisk.next7days}% risk\n• **Next 30 days**: ${analysisResult.timelineRisk.next30days}% risk\n\nThe risk is trending ${analysisResult.timelineRisk.next30days > analysisResult.timelineRisk.next24h ? 'upward' : 'stable'}, indicating you should take preventive action now.`;
        } else if (query.includes('sql') || query.includes('injection')) {
          const sqlThreat = analysisResult.predictions.find(p => p.type.includes('SQL'));
          if (sqlThreat) {
            response = `**SQL Injection threat detected** with ${sqlThreat.probability}% probability at ${sqlThreat.location}.\n\n**Why this is critical:**\nSQL injection can allow attackers to:\n- Access sensitive database information\n- Modify or delete data\n- Execute administrative operations\n\n**Immediate actions:**\n${sqlThreat.recommendation}\n- Use prepared statements\n- Validate all user inputs\n- Apply principle of least privilege`;
          } else {
            response = 'No SQL injection threats were detected in your current analysis. However, it\'s always good practice to use parameterized queries and input validation.';
          }
        } else if (query.includes('ddos') || query.includes('attack')) {
          const ddosThreat = analysisResult.predictions.find(p => p.type.includes('DDoS'));
          if (ddosThreat) {
            response = `**DDoS Attack Pattern detected** with ${ddosThreat.probability}% probability.\n\n**Recommended mitigation:**\n- Enable DDoS protection services (Cloudflare, AWS Shield)\n- Implement rate limiting\n- Use a CDN to distribute traffic\n- Set up auto-scaling\n- Configure firewall rules`;
          } else {
            response = 'No active DDoS patterns detected, but it\'s good practice to have DDoS protection enabled proactively.';
          }
        } else if (query.includes('confidence') || query.includes('accuracy')) {
          response = `The AI analysis has a **${analysisResult.confidence}% confidence level**. This high confidence score means the predictions are based on strong pattern matching and historical threat data.\n\nFactors contributing to this confidence:\n- Clear attack signatures detected\n- Multiple corroborating indicators\n- Known vulnerability patterns\n- Historical threat intelligence`;
        } else {
          response = `I can help you with:\n\n• **Threat Analysis** - Explain detected threats and their severity\n• **Recommendations** - Guide you through security improvements\n• **CVE Vulnerabilities** - Detail known security flaws\n• **Risk Timeline** - Discuss future risk predictions\n• **Specific Threats** - Deep dive into SQL injection, DDoS, etc.\n\nWhat would you like to know more about?`;
        }
      } else {
        if (query.includes('hello') || query.includes('hi')) {
          response = 'Hello! I\'m here to help you analyze and understand security threats. Upload files, enter an API endpoint, or start monitoring to begin the analysis, and I\'ll provide detailed insights.';
        } else if (query.includes('help') || query.includes('what can you do')) {
          response = 'I can assist you with:\n\n• **File Analysis** - Upload security logs, PCAP files, or other formats\n• **API Security** - Test API endpoints for vulnerabilities\n• **Live Monitoring** - Real-time threat detection\n• **Threat Explanation** - Understand security risks\n• **Recommendations** - Get actionable security advice\n\nStart by uploading a file or entering a URL to analyze!';
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

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <Shield className="w-10 h-10 text-cyan-400" />
            <div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                CyberShield AI
              </h1>
              <p className="text-slate-400 text-sm">Advanced Threat Prediction & Analysis Platform</p>
            </div>
          </div>
          {monitorStatus === 'active' && (
            <div className="flex items-center gap-2 px-4 py-2 bg-green-500/20 border border-green-500 rounded-lg">
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
                    activeTab === 'upload' ? 'bg-cyan-500 text-white' : 'text-slate-400 hover:bg-slate-700'
                  }`}
                >
                  <Upload className="w-5 h-5" />
                  <span className="font-medium">File Upload</span>
                </button>
                <button
                  onClick={() => setActiveTab('api')}
                  className={`flex items-center gap-2 px-4 py-3 rounded-lg transition-all ${
                    activeTab === 'api' ? 'bg-cyan-500 text-white' : 'text-slate-400 hover:bg-slate-700'
                  }`}
                >
                  <Database className="w-5 h-5" />
                  <span className="font-medium">API Analysis</span>
                </button>
                <button
                  onClick={() => setActiveTab('monitor')}
                  className={`flex items-center gap-2 px-4 py-3 rounded-lg transition-all ${
                    activeTab === 'monitor' ? 'bg-cyan-500 text-white' : 'text-slate-400 hover:bg-slate-700'
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
                  <div className="border-2 border-dashed border-slate-600 rounded-lg p-8 text-center hover:border-cyan-500 transition-colors cursor-pointer">
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
                        <div key={idx} className="flex items-center gap-2 text-sm bg-slate-700/50 p-2 rounded">
                          <FileText className="w-4 h-4 text-cyan-400" />
                          <span className="text-slate-300">{file.name}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <button
                    onClick={analyzeFiles}
                    disabled={uploadedFiles.length === 0 || analyzing}
                    className="w-full bg-cyan-500 hover:bg-cyan-600 disabled:bg-slate-600 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-lg transition-colors"
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
                    className="w-full bg-cyan-500 hover:bg-cyan-600 disabled:bg-slate-600 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-lg transition-colors"
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
                  <div className="bg-slate-700/50 rounded-lg p-4 space-y-2">
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
                      className="w-full bg-green-500 hover:bg-green-600 disabled:bg-slate-600 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-lg transition-colors"
                    >
                      {analyzing ? 'Starting...' : 'Start Monitoring'}
                    </button>
                  ) : (
                    <button
                      onClick={stopMonitoring}
                      className="w-full bg-red-500 hover:bg-red-600 text-white font-semibold py-3 rounded-lg transition-colors"
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
                <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-cyan-400 mx-auto mb-4"></div>
                <p className="text-slate-300 font-medium">Analyzing security data...</p>
                <p className="text-slate-500 text-sm mt-2">AI models are processing threat patterns</p>
              </div>
            )}

            {!analyzing && !analysisResult && (
              <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-12 text-center">
                <Shield className="w-16 h-16 mx-auto mb-4 text-slate-600" />
                <p className="text-slate-400 font-medium">No analysis yet</p>
                <p className="text-slate-500 text-sm mt-2">Upload files, enter API endpoint, or start monitoring to begin</p>
              </div>
            )}

            {analysisResult && (
              <div className="space-y-6">
                {/* Summary Cards */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <AlertTriangle className="w-5 h-5 text-red-400" />
                      <span className="text-2xl font-bold text-red-400">{analysisResult.criticalIssues}</span>
                    </div>
                    <p className="text-sm text-slate-400">Critical</p>
                  </div>
                  <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <AlertTriangle className="w-5 h-5 text-yellow-400" />
                      <span className="text-2xl font-bold text-yellow-400">{analysisResult.warnings}</span>
                    </div>
                    <p className="text-sm text-slate-400">Warnings</p>
                  </div>
                  <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <CheckCircle className="w-5 h-5 text-blue-400" />
                      <span className="text-2xl font-bold text-blue-400">{analysisResult.info}</span>
                    </div>
                    <p className="text-sm text-slate-400">Info</p>
                  </div>
                  <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <TrendingUp className="w-5 h-5 text-cyan-400" />
                      <span className="text-2xl font-bold text-cyan-400">{analysisResult.confidence}%</span>
                    </div>
                    <p className="text-sm text-slate-400">Confidence</p>
                  </div>
                </div>

                {/* Overall Threat Level */}
                <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Shield className="w-5 h-5 text-cyan-400" />
                    Overall Threat Assessment
                  </h3>
                  <div className="flex items-center gap-4">
                    <div className={`px-4 py-2 rounded-lg font-bold ${getThreatLevelColor(analysisResult.overallThreatLevel)} text-white`}>
                      {analysisResult.overallThreatLevel} Risk
                    </div>
                    <div className="flex-1">
                      <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                        <div 
                          className={`h-full ${getThreatLevelColor(analysisResult.overallThreatLevel)}`}
                          style={{width: `${analysisResult.overallThreatLevel === 'Critical' ? 100 : analysisResult.overallThreatLevel === 'High' ? 75 : analysisResult.overallThreatLevel === 'Medium' ? 50 : 25}%`}}
                        />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Threat Predictions */}
                <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5 text-cyan-400" />
                    Detected Threats & Predictions
                  </h3>
                  <div className="space-y-3">
                    {analysisResult.predictions.map((threat, idx) => (
                      <div key={idx} className={`border rounded-lg p-4 ${getThreatColor(threat.severity)}`}>
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-semibold">{threat.type}</span>
                              <span className={`px-2 py-1 rounded text-xs font-bold ${getThreatLevelColor(threat.severity)} text-white`}>
                                {threat.severity}
                              </span>
                            </div>
                            <p className="text-sm opacity-80">{threat.location}</p>
                          </div>
                          <div className="text-right">
                            <div className="text-2xl font-bold">{threat.probability}%</div>
                            <div className="text-xs opacity-80">Probability</div>
                          </div>
                        </div>
                        <div className="mt-3 pt-3 border-t border-current opacity-50">
                          <p className="text-sm font-medium">Recommendation:</p>
                          <p className="text-sm opacity-80">{threat.recommendation}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Timeline Risk */}
                <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Clock className="w-5 h-5 text-cyan-400" />
                    Risk Timeline Forecast
                  </h3>
                  <div className="space-y-4">
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm text-slate-400">Next 24 Hours</span>
                        <span className="text-sm font-semibold text-yellow-400">{analysisResult.timelineRisk.next24h}% Risk</span>
                      </div>
                      <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                        <div className="h-full bg-yellow-500" style={{width: `${analysisResult.timelineRisk.next24h}%`}} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm text-slate-400">Next 7 Days</span>
                        <span className="text-sm font-semibold text-orange-400">{analysisResult.timelineRisk.next7days}% Risk</span>
                      </div>
                      <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                        <div className="h-full bg-orange-500" style={{width: `${analysisResult.timelineRisk.next7days}%`}} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm text-slate-400">Next 30 Days</span>
                        <span className="text-sm font-semibold text-red-400">{analysisResult.timelineRisk.next30days}% Risk</span>
                      </div>
                      <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                        <div className="h-full bg-red-500" style={{width: `${analysisResult.timelineRisk.next30days}%`}} />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Vulnerabilities */}
                <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Lock className="w-5 h-5 text-cyan-400" />
                    Known Vulnerabilities (CVE)
                  </h3>
                  <div className="space-y-2">
                    {analysisResult.vulnerabilities.map((vuln, idx) => (
                      <div key={idx} className="flex items-center justify-between bg-slate-700/50 p-3 rounded-lg">
                        <div>
                          <span className="font-mono text-cyan-400">{vuln.cve}</span>
                          <span className="text-slate-400 text-sm ml-3">{vuln.component}</span>
                        </div>
                        <span className={`px-3 py-1 rounded text-xs font-bold ${getThreatLevelColor(vuln.severity)} text-white`}>
                          {vuln.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recommendations */}
                <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-cyan-400" />
                    Security Recommendations
                  </h3>
                  <div className="space-y-2">
                    {analysisResult.recommendations.map((rec, idx) => (
                      <div key={idx} className="flex items-start gap-3 bg-slate-700/50 p-3 rounded-lg">
                        <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                        <span className="text-slate-300 text-sm">{rec}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Export Button */}
                <button 
                  onClick={() => {
                    const report = JSON.stringify(analysisResult, null, 2);
                    const blob = new Blob([report], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `cybershield-report-${Date.now()}.json`;
                    a.click();
                  }}
                  className="w-full bg-cyan-500 hover:bg-cyan-600 text-white font-semibold py-3 rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  <FileText className="w-5 h-5" />
                  Export Detailed Report (JSON)
                </button>
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
                      ? 'bg-cyan-500 text-white' 
                      : 'bg-slate-700 text-slate-100'
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
                  <div className="bg-slate-700 p-3 rounded-lg">
                    <div className="flex gap-1">
                      <div className="w-2 h-2 bg-slate-500 rounded-full animate-bounce" style={{animationDelay: '0ms'}}></div>
                      <div className="w-2 h-2 bg-slate-500 rounded-full animate-bounce" style={{animationDelay: '150ms'}}></div>
                      <div className="w-2 h-2 bg-slate-500 rounded-full animate-bounce" style={{animationDelay: '300ms'}}></div>
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
                  className="bg-cyan-500 hover:bg-cyan-600 disabled:bg-slate-600 disabled:cursor-not-allowed p-2 rounded-lg transition-colors"
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
          className="fixed bottom-6 right-6 w-16 h-16 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 rounded-full shadow-lg flex items-center justify-center transition-all z-40 group"
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