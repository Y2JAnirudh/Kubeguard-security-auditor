/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCode2,
  Terminal,
  Download,
  Copy,
  Check,
  Play,
  RotateCcw,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Sliders,
  Upload,
  RefreshCw,
  Server,
  Layers,
  ChevronDown,
  ChevronRight,
  FileText,
  ExternalLink
} from 'lucide-react';

interface Finding {
  rule_id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  file: string;
  resource: string;
  location?: string;
  evidence: string;
  impact: string;
  remediation: string;
  remediation_yaml?: string;
  references?: string[];
}

interface ScanResult {
  score: number;
  risk_level: string;
  files_scanned: string[];
  resources_scanned: number;
  total_findings: number;
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  category_counts: Record<string, number>;
  findings: Finding[];
  errors: string[];
}

interface HealthStatus {
  status: string;
  service: string;
  version: string;
  rules_loaded: {
    kubernetes_rules: number;
    docker_rules: number;
  };
}

interface TrivyStatus {
  available: boolean;
  version: string | null;
  message: string;
}

interface TrivyVuln {
  vulnerability_id: string;
  pkg_name: string;
  installed_version: string;
  fixed_version: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  title: string;
  primary_url?: string;
  target?: string;
}

interface TrivyResult {
  success: boolean;
  available: boolean;
  image?: string;
  version?: string;
  error?: string;
  notice?: string;
  counts?: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    UNKNOWN: number;
  };
  total_vulnerabilities?: number;
  vulnerabilities?: TrivyVuln[];
}

export default function App() {
  const [activeDatasetLabel, setActiveDatasetLabel] = useState<string>('Vulnerable Baseline (Demo)');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [apiHealth, setApiHealth] = useState<HealthStatus | null>(null);
  const [activeTab, setActiveTab] = useState<'findings' | 'charts' | 'trivy' | 'benchmark' | 'cli' | 'report' | 'presentation' | 'methodology'>('findings');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [uploadedFilesList, setUploadedFilesList] = useState<Array<{ filename: string; content: string }>>([]);
  const [pastedCode, setPastedCode] = useState<string>('');
  const [pastedType, setPastedType] = useState<string>('manifest.yaml');

  // Trivy integration state
  const [trivyStatus, setTrivyStatus] = useState<TrivyStatus | null>(null);
  const [trivyImage, setTrivyImage] = useState<string>('python:3.11-slim');
  const [trivyLoading, setTrivyLoading] = useState<boolean>(false);
  const [trivyScanResult, setTrivyScanResult] = useState<TrivyResult | null>(null);
  const [showSampleTrivy, setShowSampleTrivy] = useState<boolean>(false);

  // Check backend health and load initial vulnerable scan
  useEffect(() => {
    checkHealth();
    checkTrivyStatus();
    triggerDemoScan('vulnerable');
  }, []);

  const checkHealth = async (retries = 4) => {
    try {
      const res = await fetch('/api/health');
      const contentType = res.headers.get('content-type') || '';
      if (res.ok && contentType.includes('application/json')) {
        const data = await res.json();
        setApiHealth(data);
        return;
      }
    } catch (err) {
      // Backend is starting up
    }
    if (retries > 0) {
      setTimeout(() => checkHealth(retries - 1), 1000);
    }
  };

  const checkTrivyStatus = async () => {
    try {
      const res = await fetch('/api/trivy/status');
      const contentType = res.headers.get('content-type') || '';
      if (res.ok && contentType.includes('application/json')) {
        const data: TrivyStatus = await res.json();
        setTrivyStatus(data);
      }
    } catch (err) {
      console.warn('Trivy status probe offline:', err);
    }
  };

  const handleTrivyScan = async (imageTarget?: string) => {
    const target = (imageTarget || trivyImage).trim();
    if (!target) return;
    setTrivyLoading(true);
    try {
      const res = await fetch('/api/trivy/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image: target })
      });
      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const data: TrivyResult = await res.json();
        setTrivyScanResult(data);
      }
    } catch (err) {
      console.error('Error running Trivy scan:', err);
    } finally {
      setTrivyLoading(false);
    }
  };

  const triggerDemoScan = async (type: 'vulnerable' | 'secure', retries = 4) => {
    setLoading(true);
    try {
      const endpoint = type === 'vulnerable' ? '/api/scan/demo/vulnerable' : '/api/scan/demo/secure';
      const res = await fetch(endpoint, { method: 'POST' });
      const contentType = res.headers.get('content-type') || '';

      if (!contentType.includes('application/json')) {
        if (retries > 0) {
          setTimeout(() => triggerDemoScan(type, retries - 1), 1000);
          return;
        }
        throw new Error('FastAPI backend is warming up. Please click retry in a moment.');
      }

      if (!res.ok) {
        if (res.status === 503 && retries > 0) {
          setTimeout(() => triggerDemoScan(type, retries - 1), 1000);
          return;
        }
        throw new Error(`HTTP error ${res.status}`);
      }

      const data: ScanResult = await res.json();
      setScanResult(data);
      setActiveDatasetLabel(type === 'vulnerable' ? 'Vulnerable Baseline (Demo Scenario)' : 'Hardened Reference Architecture');
      
      // Expand top 2 findings
      const initialExp: Record<string, boolean> = {};
      if (data.findings && data.findings.length > 0) {
        initialExp[data.findings[0].rule_id + '-0'] = true;
        if (data.findings.length > 1) {
          initialExp[data.findings[1].rule_id + '-1'] = true;
        }
      }
      setExpandedFindings(initialExp);
      setLoading(false);
    } catch (err) {
      if (retries > 0) {
        setTimeout(() => triggerDemoScan(type, retries - 1), 1000);
      } else {
        console.error('Error running scan:', err);
        setLoading(false);
      }
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    const promises: Promise<{ filename: string; content: string }>[] = [];
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      promises.push(
        new Promise((resolve) => {
          const reader = new FileReader();
          reader.onload = (event) => {
            resolve({
              filename: file.name,
              content: (event.target?.result as string) || ''
            });
          };
          reader.readAsText(file);
        })
      );
    }

    Promise.all(promises).then((loadedFiles) => {
      setUploadedFilesList(loadedFiles);
      runCustomScan(loadedFiles);
    });
  };

  const runCustomScan = async (files: Array<{ filename: string; content: string }>) => {
    setLoading(true);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files })
      });
      const contentType = res.headers.get('content-type') || '';
      if (!res.ok || !contentType.includes('application/json')) {
        throw new Error(`Scan request failed (HTTP ${res.status})`);
      }
      const data: ScanResult = await res.json();
      setScanResult(data);
      setActiveDatasetLabel(`Uploaded (${files.length} custom file${files.length > 1 ? 's' : ''})`);
    } catch (err) {
      console.error('Error scanning uploaded files:', err);
    } finally {
      setLoading(false);
    }
  };

  const handlePastedAudit = async () => {
    if (!pastedCode.trim()) return;
    setLoading(true);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: pastedType,
          content: pastedCode
        })
      });
      const contentType = res.headers.get('content-type') || '';
      if (!res.ok || !contentType.includes('application/json')) {
        throw new Error(`Audit request failed (HTTP ${res.status})`);
      }
      const data: ScanResult = await res.json();
      setScanResult(data);
      setActiveDatasetLabel(`Pasted Code Snippet (${pastedType})`);
    } catch (err) {
      console.error('Error scanning pasted snippet:', err);
    } finally {
      setLoading(false);
    }
  };

  const downloadReportHtml = async () => {
    try {
      const res = await fetch('/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          uploadedFilesList.length > 0
            ? { files: uploadedFilesList }
            : pastedCode.trim()
            ? { content: pastedCode, filename: pastedType }
            : {}
        )
      });
      const htmlText = await res.text();
      const blob = new Blob([htmlText], { type: 'text/html' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `KubeGuard_Security_Audit_Report_${scanResult?.risk_level.replace(/\s+/g, '_') || 'Report'}.html`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Failed to download report:', err);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const toggleExpand = (key: string) => {
    setExpandedFindings(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const score = scanResult?.score ?? 0;
  const riskLevel = scanResult?.risk_level ?? 'CALCULATING...';
  const riskColor =
    score >= 90 ? '#22c55e' : score >= 70 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';

  const findings = scanResult?.findings ?? [];
  const categories = Array.from(new Set(findings.map(f => f.category)));

  // Filtered findings list
  const filteredFindings = findings.filter(f => {
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        f.rule_id.toLowerCase().includes(q) ||
        f.title.toLowerCase().includes(q) ||
        f.resource.toLowerCase().includes(q) ||
        f.evidence.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 font-sans antialiased selection:bg-cyan-500 selection:text-black">
      
      {/* Top Application Header */}
      <header className="border-b border-slate-800/80 bg-[#0b101d]/90 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-wrap items-center justify-between gap-4">
          
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 flex items-center justify-center shadow-lg shadow-cyan-500/20 border border-cyan-400/40">
              <ShieldAlert className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-black tracking-tight text-white">
                  Kube<span className="text-cyan-400">Guard</span>
                </span>
                <span className="px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider bg-cyan-950/80 text-cyan-400 border border-cyan-800 rounded">
                  React + FastAPI
                </span>
              </div>
              <p className="text-xs text-slate-400">Container &amp; Kubernetes Security Auditor &bull; Static Posture Assessment</p>
            </div>
          </div>

          {/* Backend Status & Demo Quick Switchers */}
          <div className="flex items-center flex-wrap gap-2">
            
            {/* FastAPI Engine Status Pill */}
            <div className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-300">
              <span className={`h-2 w-2 rounded-full ${apiHealth ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />
              <span className="font-semibold text-slate-300">FastAPI Backend:</span>
              <span className="text-cyan-400 font-mono">
                {apiHealth ? 'Connected (5050)' : 'Connecting...'}
              </span>
            </div>

            {/* Demo Buttons */}
            <div className="flex items-center gap-1.5 bg-slate-900/90 p-1.5 rounded-xl border border-slate-800">
              <button
                onClick={() => triggerDemoScan('vulnerable')}
                disabled={loading}
                className="px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 bg-red-500/20 text-red-300 border border-red-500/40 hover:bg-red-500/30 disabled:opacity-50"
              >
                <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
                Vulnerable App
              </button>
              <button
                onClick={() => triggerDemoScan('secure')}
                disabled={loading}
                className="px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30 disabled:opacity-50"
              >
                <span className="h-2 w-2 rounded-full bg-emerald-500" />
                Hardened App
              </button>
            </div>

            {/* Download Report Button */}
            <button
              onClick={downloadReportHtml}
              className="px-3.5 py-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition flex items-center gap-1.5 shadow-md shadow-cyan-600/20"
            >
              <Download className="h-3.5 w-3.5" />
              HTML Report
            </button>
          </div>

        </div>
      </header>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        
        {/* Upload & Snippet Input Bar */}
        <div className="bg-[#0e1526] border border-slate-800 rounded-2xl p-5 shadow-lg">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Upload className="h-4 w-4 text-cyan-400" />
                Audit Target Artifacts
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Upload Kubernetes YAML manifests (*.yaml, *.yml) or Dockerfiles for static vulnerability inspection.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <label className="cursor-pointer px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded-xl text-xs font-bold border border-slate-700 transition flex items-center gap-2">
                <FileCode2 className="h-4 w-4" />
                Upload YAML / Dockerfile
                <input
                  type="file"
                  multiple
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>

              <button
                onClick={() => triggerDemoScan('vulnerable')}
                className="px-3 py-2 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded-xl text-xs font-semibold border border-slate-800 transition flex items-center gap-1.5"
                title="Reset view to vulnerable demo"
              >
                <RotateCcw className="h-3.5 w-3.5" />
                Reset Demo
              </button>
            </div>
          </div>

          {/* Quick Raw Snippet Accordion */}
          <details className="mt-3 group">
            <summary className="cursor-pointer text-xs font-semibold text-slate-400 hover:text-cyan-400 transition select-none flex items-center gap-1.5">
              <span>Or paste raw YAML / Dockerfile snippet</span>
            </summary>
            <div className="mt-3 pt-3 border-t border-slate-800 space-y-2">
              <div className="flex items-center gap-3">
                <select
                  value={pastedType}
                  onChange={(e) => setPastedType(e.target.value)}
                  className="bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1 focus:outline-none"
                >
                  <option value="manifest.yaml">Kubernetes YAML Manifest</option>
                  <option value="Dockerfile">Dockerfile</option>
                </select>
                <button
                  onClick={handlePastedAudit}
                  disabled={loading || !pastedCode.trim()}
                  className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-bold transition disabled:opacity-50"
                >
                  Audit Snippet
                </button>
              </div>
              <textarea
                value={pastedCode}
                onChange={(e) => setPastedCode(e.target.value)}
                placeholder="apiVersion: apps/v1&#10;kind: Deployment&#10;metadata:&#10;  name: my-app..."
                className="w-full h-32 bg-[#090d18] border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-cyan-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </details>
        </div>

        {/* Executive Score & KPI Dashboard Bar */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
          
          {/* Main Security Score Card */}
          <div className="lg:col-span-2 bg-[#0f172a] border border-slate-800 rounded-2xl p-6 relative overflow-hidden flex flex-col justify-between shadow-xl">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Security Score</span>
              <span className="text-[11px] text-cyan-400 font-mono">Python Heuristic</span>
            </div>
            
            <div className="my-3 flex items-baseline gap-3">
              <span className="text-5xl font-black tracking-tight" style={{ color: riskColor }}>
                {loading ? '...' : score}
              </span>
              <span className="text-xl font-bold text-slate-400">/ 100</span>
              <span
                className="ml-auto px-3 py-1 rounded-full text-xs font-black tracking-wider uppercase"
                style={{
                  backgroundColor: `${riskColor}18`,
                  color: riskColor,
                  border: `1px solid ${riskColor}40`
                }}
              >
                {loading ? 'ANALYZING...' : riskLevel}
              </span>
            </div>

            <div className="text-xs text-slate-400 truncate">
              Auditing: <span className="font-semibold text-slate-200">{activeDatasetLabel}</span> ({scanResult?.resources_scanned ?? 0} resources, {scanResult?.files_scanned.length ?? 0} files)
            </div>
          </div>

          {/* Severity Badges KPI Grid */}
          <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs font-bold text-red-400">
              <span>CRITICAL</span>
              <span className="text-[10px] bg-red-950/80 px-2 py-0.5 rounded border border-red-900">-20 pts</span>
            </div>
            <div className="text-3xl font-black text-red-400 my-2">{scanResult?.counts.critical ?? 0}</div>
            <span className="text-[11px] text-slate-400">Privileged, root, secrets</span>
          </div>

          <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs font-bold text-orange-400">
              <span>HIGH</span>
              <span className="text-[10px] bg-orange-950/80 px-2 py-0.5 rounded border border-orange-900">-10 pts</span>
            </div>
            <div className="text-3xl font-black text-orange-400 my-2">{scanResult?.counts.high ?? 0}</div>
            <span className="text-[11px] text-slate-400">hostPID, hostPath, RBAC *</span>
          </div>

          <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs font-bold text-amber-400">
              <span>MEDIUM</span>
              <span className="text-[10px] bg-amber-950/80 px-2 py-0.5 rounded border border-amber-900">-5 pts</span>
            </div>
            <div className="text-3xl font-black text-amber-400 my-2">{scanResult?.counts.medium ?? 0}</div>
            <span className="text-[11px] text-slate-400">Limits, latest tag, NodePort</span>
          </div>

          <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs font-bold text-blue-400">
              <span>LOW</span>
              <span className="text-[10px] bg-blue-950/80 px-2 py-0.5 rounded border border-blue-900">-2 pts</span>
            </div>
            <div className="text-3xl font-black text-blue-400 my-2">{scanResult?.counts.low ?? 0}</div>
            <span className="text-[11px] text-slate-400">AppArmor, Requests</span>
          </div>

        </div>

        {/* Disclaimer Notice */}
        <div className="bg-slate-900/60 border-l-4 border-cyan-500 rounded-r-xl p-3.5 text-xs text-slate-400 flex flex-wrap items-center justify-between gap-2">
          <p>
            <strong className="text-slate-200">Static Policy Assessment:</strong> Score is a deterministic heuristic calculated by the Python FastAPI engine and should not be interpreted as a formal security certification.
          </p>
          <span className="text-[11px] bg-slate-800 px-2.5 py-1 rounded text-cyan-300 font-mono">
            {scanResult ? `${scanResult.total_findings} Weaknesses Detected` : 'Scanning...'}
          </span>
        </div>

        {/* Navigation Tabs */}
        <div className="border-b border-slate-800 flex gap-2 overflow-x-auto pb-1">
          <button
            onClick={() => setActiveTab('findings')}
            className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider rounded-t-lg transition flex items-center gap-2 ${
              activeTab === 'findings'
                ? 'bg-slate-800/90 text-cyan-400 border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <FileCode2 className="h-4 w-4" />
            Security Findings ({findings.length})
          </button>
          <button
            onClick={() => setActiveTab('charts')}
            className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider rounded-t-lg transition flex items-center gap-2 ${
              activeTab === 'charts'
                ? 'bg-slate-800/90 text-cyan-400 border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <Layers className="h-4 w-4" />
            Risk Breakdown &amp; Charts
          </button>
          <button
            onClick={() => setActiveTab('trivy')}
            className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider rounded-t-lg transition flex items-center gap-2 ${
              activeTab === 'trivy'
                ? 'bg-slate-800/90 text-cyan-400 border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <Search className="h-4 w-4" />
            Container Image Scan (Trivy)
            <span className={`h-2 w-2 rounded-full ${trivyStatus?.available ? 'bg-emerald-400' : 'bg-slate-600'}`} />
          </button>
          <button
            onClick={() => setActiveTab('benchmark')}
            className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider rounded-t-lg transition flex items-center gap-2 ${
              activeTab === 'benchmark'
                ? 'bg-slate-800/90 text-cyan-400 border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <ShieldCheck className="h-4 w-4" />
            Before vs After Demo
          </button>
          <button
            onClick={() => setActiveTab('cli')}
            className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider rounded-t-lg transition flex items-center gap-2 ${
              activeTab === 'cli'
                ? 'bg-slate-800/90 text-cyan-400 border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <Terminal className="h-4 w-4" />
            CLI &amp; Local Python Run
          </button>
          <button
            onClick={() => setActiveTab('report')}
            className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider rounded-t-lg transition flex items-center gap-2 ${
              activeTab === 'report'
                ? 'bg-slate-800/90 text-cyan-400 border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <FileText className="h-4 w-4" />
            HTML Report
          </button>
          <button
            onClick={() => setActiveTab('presentation')}
            className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider rounded-t-lg transition flex items-center gap-2 ${
              activeTab === 'presentation'
                ? 'bg-slate-800/90 text-cyan-400 border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <HelpCircle className="h-4 w-4" />
            2-Min Pitch &amp; Teacher Q&amp;A
          </button>
          <button
            onClick={() => setActiveTab('methodology')}
            className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider rounded-t-lg transition flex items-center gap-2 ${
              activeTab === 'methodology'
                ? 'bg-slate-800/90 text-cyan-400 border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <Sliders className="h-4 w-4" />
            Methodology &amp; Standards
          </button>
        </div>

        {/* TAB 1: DETAILED FILTERABLE FINDINGS */}
        {activeTab === 'findings' && (
          <div className="space-y-6">
            
            {/* Filter Bar */}
            <div className="bg-[#0f172a] p-4 rounded-xl border border-slate-800 flex flex-wrap gap-4 items-center justify-between">
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative">
                  <Search className="h-4 w-4 absolute left-3 top-2.5 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Search findings (e.g. K8S-001, root, privileged)..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-9 pr-3 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500 w-64"
                  />
                </div>

                <div className="flex items-center gap-1.5 bg-slate-900 px-2 py-1 rounded-lg border border-slate-700">
                  <Filter className="h-3.5 w-3.5 text-slate-400" />
                  <span className="text-xs text-slate-400">Severity:</span>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="bg-transparent text-xs text-slate-200 focus:outline-none cursor-pointer"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>

                {categories.length > 0 && (
                  <div className="flex items-center gap-1.5 bg-slate-900 px-2 py-1 rounded-lg border border-slate-700">
                    <span className="text-xs text-slate-400">Category:</span>
                    <select
                      value={categoryFilter}
                      onChange={(e) => setCategoryFilter(e.target.value)}
                      className="bg-transparent text-xs text-slate-200 focus:outline-none cursor-pointer"
                    >
                      <option value="ALL">All Categories</option>
                      {categories.map((c) => (
                        <option key={c} value={c}>{c}</option>
                      ))}
                    </select>
                  </div>
                )}
              </div>

              <div className="text-xs text-slate-400">
                Displaying <strong className="text-slate-200">{filteredFindings.length}</strong> of <strong className="text-slate-200">{findings.length}</strong> issues
              </div>
            </div>

            {/* Findings Accordion List */}
            {filteredFindings.length === 0 ? (
              <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-12 text-center space-y-3">
                <CheckCircle2 className="h-10 w-10 text-emerald-400 mx-auto" />
                <h4 className="text-base font-bold text-slate-200">No Security Issues Found</h4>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  The audited configuration complies with all evaluated security checks or no findings matched your active filters.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {filteredFindings.map((finding, idx) => {
                  const key = `${finding.rule_id}-${idx}`;
                  const isExpanded = !!expandedFindings[key];
                  const badgeStyle = {
                    CRITICAL: 'bg-red-950/80 text-red-400 border-red-800',
                    HIGH: 'bg-orange-950/80 text-orange-400 border-orange-800',
                    MEDIUM: 'bg-amber-950/80 text-amber-400 border-amber-800',
                    LOW: 'bg-blue-950/80 text-blue-400 border-blue-800',
                    INFO: 'bg-slate-900 text-slate-300 border-slate-700',
                  }[finding.severity];

                  return (
                    <div
                      key={key}
                      className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden transition-all hover:border-slate-700 shadow-md"
                    >
                      {/* Header Item */}
                      <div
                        onClick={() => toggleExpand(key)}
                        className="p-4 cursor-pointer flex items-center justify-between gap-4 select-none hover:bg-slate-800/40"
                      >
                        <div className="flex items-center gap-3">
                          <span className={`px-2.5 py-1 text-xs font-black uppercase tracking-wider rounded border ${badgeStyle}`}>
                            {finding.severity}
                          </span>
                          <span className="font-mono text-xs font-bold text-cyan-400">{finding.rule_id}</span>
                          <h4 className="font-semibold text-slate-200 text-sm">{finding.title}</h4>
                        </div>

                        <div className="flex items-center gap-4 text-xs text-slate-400">
                          <span className="hidden sm:inline-block bg-slate-800/90 px-2 py-0.5 rounded text-slate-300 font-mono text-[11px]">
                            {finding.resource}
                          </span>
                          {isExpanded ? <ChevronDown className="h-4 w-4 text-slate-400" /> : <ChevronRight className="h-4 w-4 text-slate-400" />}
                        </div>
                      </div>

                      {/* Expandable Body */}
                      {isExpanded && (
                        <div className="p-5 border-t border-slate-800 bg-[#090e1a] space-y-4 text-xs">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Affected Resource:</span>
                              <div className="mt-1 font-mono text-cyan-300 bg-slate-900/90 p-2 rounded border border-slate-800">
                                {finding.resource}
                              </div>
                            </div>
                            <div>
                              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Location:</span>
                              <div className="mt-1 font-mono text-slate-300 bg-slate-900/90 p-2 rounded border border-slate-800 truncate">
                                {finding.file} {finding.location ? `→ ${finding.location}` : ''}
                              </div>
                            </div>
                          </div>

                          {/* Evidence Box */}
                          <div>
                            <span className="text-[11px] font-bold text-red-400 uppercase tracking-wider flex items-center gap-1.5">
                              <AlertTriangle className="h-3.5 w-3.5" />
                              Evidence Detected by Rule Engine:
                            </span>
                            <pre className="mt-1.5 p-3 rounded-lg bg-red-950/20 border border-red-900/50 text-red-300 font-mono overflow-x-auto">
                              <code>{finding.evidence}</code>
                            </pre>
                          </div>

                          {/* Impact vs Remediation Columns */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="bg-red-950/15 border border-red-900/40 p-3.5 rounded-lg">
                              <span className="text-[11px] font-bold text-red-400 uppercase tracking-wider">🚨 Why It Matters &amp; Security Impact:</span>
                              <p className="mt-1.5 text-slate-300 leading-relaxed">{finding.impact}</p>
                            </div>
                            <div className="bg-emerald-950/15 border border-emerald-900/40 p-3.5 rounded-lg">
                              <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider">🛠️ Recommended Remediation:</span>
                              <p className="mt-1.5 text-slate-300 leading-relaxed">{finding.remediation}</p>
                            </div>
                          </div>

                          {/* Remediation Snippet */}
                          {finding.remediation_yaml && (
                            <div className="bg-slate-900/90 border border-slate-800 rounded-lg overflow-hidden">
                              <div className="bg-slate-800/80 px-3 py-1.5 flex items-center justify-between text-[11px] font-bold text-slate-300">
                                <span>Suggested YAML / Dockerfile Blueprint</span>
                                <button
                                  onClick={() => copyToClipboard(finding.remediation_yaml || '', key)}
                                  className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
                                >
                                  {copiedKey === key ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                                  {copiedKey === key ? 'Copied!' : 'Copy Code'}
                                </button>
                              </div>
                              <pre className="p-3 text-cyan-300 font-mono text-[11px] overflow-x-auto">
                                <code>{finding.remediation_yaml}</code>
                              </pre>
                            </div>
                          )}

                          {finding.references && finding.references.length > 0 && (
                            <div className="text-[11px] text-slate-500">
                              References: {finding.references.join(', ')}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* TAB 2: CHARTS & RISK BREAKDOWN */}
        {activeTab === 'charts' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              {/* Severity Distribution */}
              <div className="bg-[#0f172a] p-6 rounded-2xl border border-slate-800 space-y-4">
                <h3 className="text-sm font-bold text-slate-200">Findings by Severity</h3>
                <div className="space-y-3">
                  {[
                    { label: 'CRITICAL', count: scanResult?.counts.critical ?? 0, color: 'bg-red-500', text: 'text-red-400' },
                    { label: 'HIGH', count: scanResult?.counts.high ?? 0, color: 'bg-orange-500', text: 'text-orange-400' },
                    { label: 'MEDIUM', count: scanResult?.counts.medium ?? 0, color: 'bg-amber-500', text: 'text-amber-400' },
                    { label: 'LOW', count: scanResult?.counts.low ?? 0, color: 'bg-blue-500', text: 'text-blue-400' },
                  ].map((item) => {
                    const total = scanResult?.total_findings || 1;
                    const pct = Math.round((item.count / total) * 100);
                    return (
                      <div key={item.label} className="space-y-1">
                        <div className="flex justify-between text-xs font-semibold">
                          <span className={item.text}>{item.label}</span>
                          <span className="text-slate-400">{item.count} ({pct}%)</span>
                        </div>
                        <div className="h-2 bg-slate-900 rounded-full overflow-hidden">
                          <div className={`h-full ${item.color} rounded-full`} style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Category Distribution */}
              <div className="bg-[#0f172a] p-6 rounded-2xl border border-slate-800 space-y-4">
                <h3 className="text-sm font-bold text-slate-200">Findings by Security Category</h3>
                {scanResult?.category_counts && Object.keys(scanResult.category_counts).length > 0 ? (
                  <div className="space-y-2.5">
                    {Object.entries(scanResult.category_counts).map(([cat, count]) => (
                      <div key={cat} className="flex items-center justify-between p-2.5 bg-slate-900/80 rounded-lg border border-slate-800 text-xs">
                        <span className="text-slate-300 font-medium">{cat}</span>
                        <span className="px-2 py-0.5 bg-cyan-950 text-cyan-400 rounded font-mono font-bold">{count}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">No category data available.</p>
                )}
              </div>

            </div>

            {/* Score Deduction Table */}
            <div className="bg-[#0f172a] p-6 rounded-2xl border border-slate-800 space-y-4">
              <h3 className="text-sm font-bold text-slate-200">Transparent Scoring Deductions</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Severity Level</th>
                      <th className="py-2.5 px-3">Findings Count</th>
                      <th className="py-2.5 px-3">Penalty / Finding</th>
                      <th className="py-2.5 px-3">Total Subtraction</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    <tr>
                      <td className="py-2.5 px-3 text-red-400 font-bold">CRITICAL</td>
                      <td className="py-2.5 px-3 text-slate-200">{scanResult?.counts.critical ?? 0}</td>
                      <td className="py-2.5 px-3 text-slate-400">-20 pts</td>
                      <td className="py-2.5 px-3 text-red-400 font-mono font-bold">-{(scanResult?.counts.critical ?? 0) * 20} pts</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 px-3 text-orange-400 font-bold">HIGH</td>
                      <td className="py-2.5 px-3 text-slate-200">{scanResult?.counts.high ?? 0}</td>
                      <td className="py-2.5 px-3 text-slate-400">-10 pts</td>
                      <td className="py-2.5 px-3 text-orange-400 font-mono font-bold">-{(scanResult?.counts.high ?? 0) * 10} pts</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 px-3 text-amber-400 font-bold">MEDIUM</td>
                      <td className="py-2.5 px-3 text-slate-200">{scanResult?.counts.medium ?? 0}</td>
                      <td className="py-2.5 px-3 text-slate-400">-5 pts</td>
                      <td className="py-2.5 px-3 text-amber-400 font-mono font-bold">-{(scanResult?.counts.medium ?? 0) * 5} pts</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 px-3 text-blue-400 font-bold">LOW</td>
                      <td className="py-2.5 px-3 text-slate-200">{scanResult?.counts.low ?? 0}</td>
                      <td className="py-2.5 px-3 text-slate-400">-2 pts</td>
                      <td className="py-2.5 px-3 text-blue-400 font-mono font-bold">-{(scanResult?.counts.low ?? 0) * 2} pts</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB: CONTAINER IMAGE VULNERABILITY SCAN (TRIVY INTEGRATION) */}
        {activeTab === 'trivy' && (
          <div className="space-y-6">
            
            {/* Architectural Scope Distinction Banner */}
            <div className="bg-[#0f172a] p-6 rounded-2xl border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <Search className="h-5 w-5 text-cyan-400" />
                    Container Image Vulnerability Scan (Optional Trivy Integration)
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Extend KubeGuard's static manifest auditing with optional container image layer vulnerability (CVE) scanning.
                  </p>
                </div>
                <span className="px-3 py-1 rounded-full text-[11px] font-bold bg-slate-800 text-cyan-300 border border-slate-700">
                  Optional Security Tool
                </span>
              </div>

              {/* Distinction: KubeGuard vs Trivy */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                <div className="bg-[#090d18] p-4 rounded-xl border border-cyan-900/40">
                  <span className="text-[11px] font-bold text-cyan-400 uppercase tracking-wider">
                    🛡️ KubeGuard Configuration Findings
                  </span>
                  <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                    Evaluates <strong>Infrastructure-as-Code (IaC) configuration risks</strong> in Kubernetes YAMLs and Dockerfiles (e.g. root execution, privileged flags, shared namespaces, missing limits, wildcard RBAC). Operates 100% offline.
                  </p>
                  <div className="mt-2 text-[11px] text-cyan-300 font-mono">Metric: KubeGuard Security Score (0-100)</div>
                </div>

                <div className="bg-[#090d18] p-4 rounded-xl border border-purple-900/40">
                  <span className="text-[11px] font-bold text-purple-400 uppercase tracking-wider">
                    🔍 Trivy Image Vulnerability Findings
                  </span>
                  <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                    Inspects <strong>binary package dependencies inside image layers</strong> (e.g. libssl, glibc, runc) against known CVE vulnerability databases. Requires external Trivy CLI binary.
                  </p>
                  <div className="mt-2 text-[11px] text-purple-300 font-mono">Metric: CVE Flaw Counts by Severity</div>
                </div>
              </div>

              <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-xs text-slate-400">
                <strong className="text-slate-200">Scoring Separation Note:</strong> KubeGuard and Trivy scoring models remain strictly separated. KubeGuard evaluates deployment configuration hygiene, whereas Trivy queries CVE vulnerability feeds.
              </div>
            </div>

            {/* Trivy Tool Availability Banner */}
            <div className={`p-5 rounded-2xl border ${trivyStatus?.available ? 'bg-emerald-950/20 border-emerald-900/60' : 'bg-[#0f172a] border-slate-800'}`}>
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className={`h-9 w-9 rounded-xl flex items-center justify-center ${trivyStatus?.available ? 'bg-emerald-900/40 text-emerald-400' : 'bg-slate-800 text-slate-400'}`}>
                    {trivyStatus?.available ? <CheckCircle2 className="h-5 w-5" /> : <AlertTriangle className="h-5 w-5 text-amber-400" />}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="text-sm font-bold text-slate-200">Trivy Binary Status:</h4>
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${trivyStatus?.available ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-slate-800 text-amber-300 border border-slate-700'}`}>
                        {trivyStatus?.available ? 'Installed & Ready' : 'Unavailable (Optional)'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      {trivyStatus?.message || 'Checking Trivy binary availability in PATH...'}
                    </p>
                  </div>
                </div>

                {!trivyStatus?.available && (
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setShowSampleTrivy(!showSampleTrivy)}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded-lg text-xs font-semibold border border-slate-700 transition"
                    >
                      {showSampleTrivy ? 'Hide Demonstration CVEs' : 'Preview Sample Trivy CVEs'}
                    </button>
                  </div>
                )}
              </div>

              {!trivyStatus?.available && (
                <div className="mt-4 pt-3 border-t border-slate-800/80 text-xs text-slate-400 flex flex-wrap items-center justify-between gap-2">
                  <span>To enable live container image scanning locally: <code className="bg-slate-900 px-2 py-0.5 rounded text-cyan-300">brew install trivy</code> or <code className="bg-slate-900 px-2 py-0.5 rounded text-cyan-300">apt install trivy</code></span>
                  <span className="text-slate-500 text-[11px]">Core KubeGuard static analysis remains 100% operational</span>
                </div>
              )}
            </div>

            {/* Trivy Scan Input Controls */}
            <div className="bg-[#0f172a] p-6 rounded-2xl border border-slate-800 space-y-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Target Container Image</h4>
              
              <div className="flex flex-wrap gap-3 items-center">
                <input
                  type="text"
                  value={trivyImage}
                  onChange={(e) => setTrivyImage(e.target.value)}
                  placeholder="e.g. python:3.11-slim, alpine:3.19, payment-service:latest"
                  className="flex-1 min-w-[240px] bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                />

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleTrivyScan()}
                    disabled={trivyLoading || !trivyStatus?.available || !trivyImage.trim()}
                    className="px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:bg-slate-800 disabled:text-slate-600 text-white rounded-xl text-xs font-bold transition flex items-center gap-1.5 shadow"
                  >
                    {trivyLoading ? (
                      <>
                        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                        Scanning Image...
                      </>
                    ) : (
                      <>
                        <Search className="h-3.5 w-3.5" />
                        Scan with Trivy
                      </>
                    )}
                  </button>
                </div>
              </div>

              <div className="flex items-center gap-2 text-xs text-slate-400">
                <span className="text-[11px] font-semibold text-slate-500">Quick Presets:</span>
                {['python:3.11-slim', 'alpine:3.19', 'payment-service:latest', 'nginx:1.25'].map((img) => (
                  <button
                    key={img}
                    onClick={() => {
                      setTrivyImage(img);
                      if (trivyStatus?.available) handleTrivyScan(img);
                    }}
                    className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 font-mono text-[11px] border border-slate-800"
                  >
                    {img}
                  </button>
                ))}
              </div>
            </div>

            {/* Error Banner if Trivy Scan Failed */}
            {trivyScanResult && !trivyScanResult.success && (
              <div className="bg-red-950/20 border border-red-900/60 p-4 rounded-xl text-xs text-red-300 space-y-1">
                <strong>Scan Notice:</strong>
                <p>{trivyScanResult.error}</p>
                {trivyScanResult.notice && <p className="text-slate-400">{trivyScanResult.notice}</p>}
              </div>
            )}

            {/* Live Scan Results or Demonstration Benchmark */}
            {(trivyScanResult?.success || showSampleTrivy) && (
              <div className="space-y-4">
                
                {/* Result Summary Bar */}
                {(() => {
                  const data = trivyScanResult?.success
                    ? trivyScanResult
                    : {
                        image: 'python:3.11-slim (Demonstration CVE Output)',
                        counts: { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 1, UNKNOWN: 0 },
                        total_vulnerabilities: 7,
                        vulnerabilities: [
                          {
                            vulnerability_id: 'CVE-2024-21626',
                            pkg_name: 'runc',
                            installed_version: '1.1.10',
                            fixed_version: '1.1.11',
                            severity: 'CRITICAL',
                            title: 'runc process.cwd container breakout vulnerability via file descriptor leak',
                            primary_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21626',
                            target: 'runc (binary)'
                          },
                          {
                            vulnerability_id: 'CVE-2023-45853',
                            pkg_name: 'zlib1g',
                            installed_version: '1:1.2.13',
                            fixed_version: '1:1.2.14',
                            severity: 'HIGH',
                            title: 'Denial of service and potential memory corruption in MiniZip within zlib',
                            primary_url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-45853',
                            target: 'debian:12.5 (dpkg)'
                          },
                          {
                            vulnerability_id: 'CVE-2023-38545',
                            pkg_name: 'curl',
                            installed_version: '7.88.1-10+deb12u4',
                            fixed_version: '7.88.1-10+deb12u5',
                            severity: 'HIGH',
                            title: 'SOCKS5 heap buffer overflow during hostname resolution',
                            primary_url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-38545',
                            target: 'debian:12.5 (dpkg)'
                          },
                          {
                            vulnerability_id: 'CVE-2023-47038',
                            pkg_name: 'perl-base',
                            installed_version: '5.36.0-7+deb12u1',
                            fixed_version: 'None',
                            severity: 'MEDIUM',
                            title: 'Out-of-bounds write via regular expression engine Unicode match',
                            primary_url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-47038',
                            target: 'debian:12.5 (dpkg)'
                          }
                        ]
                      };

                  return (
                    <div className="space-y-4">
                      {/* Metric Header */}
                      <div className="bg-[#0f172a] p-5 rounded-2xl border border-slate-800 flex flex-wrap items-center justify-between gap-4">
                        <div>
                          <span className="text-xs text-slate-400 uppercase font-bold">Image Scanned:</span>
                          <div className="font-mono text-sm font-bold text-white mt-0.5">{data.image}</div>
                        </div>

                        <div className="flex items-center gap-3">
                          <div className="px-3 py-1 bg-red-950/80 border border-red-800 rounded-lg text-center">
                            <span className="text-[10px] text-red-400 font-bold uppercase block">Critical</span>
                            <span className="text-sm font-black text-red-300">{data.counts?.CRITICAL ?? 0}</span>
                          </div>
                          <div className="px-3 py-1 bg-orange-950/80 border border-orange-800 rounded-lg text-center">
                            <span className="text-[10px] text-orange-400 font-bold uppercase block">High</span>
                            <span className="text-sm font-black text-orange-300">{data.counts?.HIGH ?? 0}</span>
                          </div>
                          <div className="px-3 py-1 bg-amber-950/80 border border-amber-800 rounded-lg text-center">
                            <span className="text-[10px] text-amber-400 font-bold uppercase block">Medium</span>
                            <span className="text-sm font-black text-amber-300">{data.counts?.MEDIUM ?? 0}</span>
                          </div>
                          <div className="px-3 py-1 bg-blue-950/80 border border-blue-800 rounded-lg text-center">
                            <span className="text-[10px] text-blue-400 font-bold uppercase block">Low</span>
                            <span className="text-sm font-black text-blue-300">{data.counts?.LOW ?? 0}</span>
                          </div>
                        </div>
                      </div>

                      {/* Vulnerabilities Table */}
                      <div className="bg-[#0f172a] rounded-2xl border border-slate-800 overflow-hidden">
                        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                          <h5 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                            Discovered Image Vulnerabilities ({data.vulnerabilities?.length ?? 0})
                          </h5>
                          <span className="text-[11px] text-slate-500">Source: National Vulnerability Database (NVD)</span>
                        </div>

                        <div className="overflow-x-auto">
                          <table className="w-full text-xs text-left">
                            <thead className="bg-slate-900 text-slate-400 text-[10px] uppercase font-bold border-b border-slate-800">
                              <tr>
                                <th className="py-2.5 px-3">Severity</th>
                                <th className="py-2.5 px-3">Vulnerability ID</th>
                                <th className="py-2.5 px-3">Package</th>
                                <th className="py-2.5 px-3">Installed</th>
                                <th className="py-2.5 px-3">Fixed In</th>
                                <th className="py-2.5 px-3">Description</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/80">
                              {data.vulnerabilities?.map((v: any, i: number) => {
                                const sevStyle = {
                                  CRITICAL: 'bg-red-950 text-red-400 border-red-800',
                                  HIGH: 'bg-orange-950 text-orange-400 border-orange-800',
                                  MEDIUM: 'bg-amber-950 text-amber-400 border-amber-800',
                                  LOW: 'bg-blue-950 text-blue-400 border-blue-800',
                                  UNKNOWN: 'bg-slate-900 text-slate-400 border-slate-800',
                                }[v.severity as string] || 'bg-slate-900 text-slate-400';

                                return (
                                  <tr key={i} className="hover:bg-slate-900/40">
                                    <td className="py-2.5 px-3 whitespace-nowrap">
                                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${sevStyle}`}>
                                        {v.severity}
                                      </span>
                                    </td>
                                    <td className="py-2.5 px-3 font-mono font-bold text-cyan-400 whitespace-nowrap">
                                      {v.primary_url ? (
                                        <a href={v.primary_url} target="_blank" rel="noopener noreferrer" className="hover:underline flex items-center gap-1">
                                          {v.vulnerability_id}
                                          <ExternalLink className="h-3 w-3" />
                                        </a>
                                      ) : (
                                        v.vulnerability_id
                                      )}
                                    </td>
                                    <td className="py-2.5 px-3 font-mono text-slate-200">{v.pkg_name}</td>
                                    <td className="py-2.5 px-3 font-mono text-slate-400">{v.installed_version}</td>
                                    <td className="py-2.5 px-3 font-mono text-emerald-400">{v.fixed_version || 'None'}</td>
                                    <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate" title={v.title}>
                                      {v.title}
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    </div>
                  );
                })()}

              </div>
            )}

          </div>
        )}

        {/* TAB 3: BENCHMARK BEFORE VS AFTER */}
        {activeTab === 'benchmark' && (
          <div className="space-y-6">
            <div className="bg-[#0f172a] p-6 rounded-2xl border border-slate-800">
              <h3 className="text-base font-bold text-white mb-2">Defense-in-Depth Comparison Benchmark</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Demonstrate the tangible value of automated security auditing. Left side shows the unhardened deployment typical of initial developer setups. Right side illustrates the hardened posture conforming to Kubernetes Pod Security Standards (Restricted Profile).
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
                
                {/* Vulnerable Card */}
                <div className="border-2 border-red-500/50 bg-red-950/10 rounded-2xl p-6 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <span className="text-xs font-black uppercase text-red-400 tracking-wider">Baseline Setup</span>
                      <span className="px-2.5 py-0.5 rounded text-[11px] font-black uppercase bg-red-950 text-red-300 border border-red-800">
                        CRITICAL RISK
                      </span>
                    </div>

                    <h4 className="text-3xl font-black text-red-400 mb-1">0 / 100 Score</h4>
                    <p className="text-xs text-slate-400 mb-4">12 High-Severity Flaws Identified</p>

                    <ul className="space-y-2.5 text-xs text-slate-300">
                      <li className="flex items-center gap-2 text-red-400 font-medium">
                        <XCircle className="h-4 w-4 shrink-0 text-red-500" />
                        Privileged container enabled (securityContext.privileged: true)
                      </li>
                      <li className="flex items-center gap-2 text-red-400 font-medium">
                        <XCircle className="h-4 w-4 shrink-0 text-red-500" />
                        Root user UID 0 execution permitted
                      </li>
                      <li className="flex items-center gap-2 text-red-400 font-medium">
                        <XCircle className="h-4 w-4 shrink-0 text-red-500" />
                        Host root filesystem (/) and docker.sock mounted
                      </li>
                      <li className="flex items-center gap-2 text-red-400 font-medium">
                        <XCircle className="h-4 w-4 shrink-0 text-red-500" />
                        Host PID, network, and IPC namespaces shared
                      </li>
                      <li className="flex items-center gap-2 text-red-400 font-medium">
                        <XCircle className="h-4 w-4 shrink-0 text-red-500" />
                        Overly broad wildcard RBAC permissions (verbs: ["*"])
                      </li>
                      <li className="flex items-center gap-2 text-red-400 font-medium">
                        <XCircle className="h-4 w-4 shrink-0 text-red-500" />
                        Plaintext secrets hardcoded in environment variables
                      </li>
                    </ul>
                  </div>

                  <button
                    onClick={() => { triggerDemoScan('vulnerable'); setActiveTab('findings'); }}
                    className="mt-6 w-full py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-bold transition shadow"
                  >
                    Load &amp; Inspect Vulnerable App
                  </button>
                </div>

                {/* Hardened Card */}
                <div className="border-2 border-emerald-500/50 bg-emerald-950/10 rounded-2xl p-6 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <span className="text-xs font-black uppercase text-emerald-400 tracking-wider">Hardened Reference</span>
                      <span className="px-2.5 py-0.5 rounded text-[11px] font-black uppercase bg-emerald-950 text-emerald-300 border border-emerald-800">
                        LOW RISK
                      </span>
                    </div>

                    <h4 className="text-3xl font-black text-emerald-400 mb-1">96 / 100 Score</h4>
                    <p className="text-xs text-slate-400 mb-4">0 Critical, 0 High, 0 Medium Issues</p>

                    <ul className="space-y-2.5 text-xs text-slate-300">
                      <li className="flex items-center gap-2 text-emerald-400 font-medium">
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                        Enforces runAsNonRoot: true with dedicated UID 10001
                      </li>
                      <li className="flex items-center gap-2 text-emerald-400 font-medium">
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                        readOnlyRootFilesystem: true protects runtime container integrity
                      </li>
                      <li className="flex items-center gap-2 text-emerald-400 font-medium">
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                        Drops all POSIX kernel capabilities (drop: [ALL])
                      </li>
                      <li className="flex items-center gap-2 text-emerald-400 font-medium">
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                        RuntimeDefault seccomp profile applied
                      </li>
                      <li className="flex items-center gap-2 text-emerald-400 font-medium">
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                        Granular least-privilege Role and RoleBinding
                      </li>
                      <li className="flex items-center gap-2 text-emerald-400 font-medium">
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                        Secrets decoupled via valueFrom.secretKeyRef
                      </li>
                    </ul>
                  </div>

                  <button
                    onClick={() => { triggerDemoScan('secure'); setActiveTab('findings'); }}
                    className="mt-6 w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-bold transition shadow"
                  >
                    Load &amp; Inspect Hardened App
                  </button>
                </div>

              </div>
            </div>
          </div>
        )}

        {/* TAB 4: CLI & LOCAL COMMANDS */}
        {activeTab === 'cli' && (
          <div className="space-y-6">
            <div className="bg-[#0f172a] p-6 rounded-2xl border border-slate-800 space-y-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Terminal className="h-5 w-5 text-cyan-400" />
                How to Run KubeGuard Locally
              </h3>
              <p className="text-xs text-slate-400">
                You can run the FastAPI server + React frontend, or execute the CLI tool directly in terminal:
              </p>

              <div className="space-y-3">
                <div className="space-y-1">
                  <span className="text-xs font-bold text-slate-300">1. Run the Python CLI Tool:</span>
                  <div className="bg-[#090e1a] border border-slate-800 rounded-lg p-3 font-mono text-xs text-cyan-300 flex items-center justify-between">
                    <span>python3 cli.py examples/vulnerable-app/</span>
                    <button onClick={() => copyToClipboard('python3 cli.py examples/vulnerable-app/', 'c1')} className="text-slate-400 hover:text-cyan-300">
                      {copiedKey === 'c1' ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-xs font-bold text-slate-300">2. Run the FastAPI Backend Server:</span>
                  <div className="bg-[#090e1a] border border-slate-800 rounded-lg p-3 font-mono text-xs text-cyan-300 flex items-center justify-between">
                    <span>python3 server.py</span>
                    <button onClick={() => copyToClipboard('python3 server.py', 'c2')} className="text-slate-400 hover:text-cyan-300">
                      {copiedKey === 'c2' ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-xs font-bold text-slate-300">3. Run Pytest Test Suite:</span>
                  <div className="bg-[#090e1a] border border-slate-800 rounded-lg p-3 font-mono text-xs text-cyan-300 flex items-center justify-between">
                    <span>pytest</span>
                    <button onClick={() => copyToClipboard('pytest', 'c3')} className="text-slate-400 hover:text-cyan-300">
                      {copiedKey === 'c3' ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: HTML REPORT PREVIEW */}
        {activeTab === 'report' && (
          <div className="space-y-6">
            <div className="bg-[#0f172a] p-6 rounded-2xl border border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white">Standalone Executive HTML Audit Report</h3>
                <p className="text-xs text-slate-400 mt-1">
                  Generated directly by KubeGuard's Python report generator. Formatted for printing and PDF generation.
                </p>
              </div>

              <button
                onClick={downloadReportHtml}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-bold flex items-center gap-2 shadow"
              >
                <Download className="h-4 w-4" />
                Download Report (.html)
              </button>
            </div>

            <div className="bg-[#0b0f19] border border-slate-800 rounded-xl p-8 space-y-6 text-sm">
              <div className="border-b border-slate-800 pb-4 flex justify-between items-start">
                <div>
                  <h2 className="text-xl font-bold text-white">🛡️ KubeGuard Audit Report</h2>
                  <p className="text-xs text-slate-400">Target: {activeDatasetLabel}</p>
                </div>
                <div className="text-right text-xs text-slate-400">
                  <div>Date: {new Date().toISOString().split('T')[0]}</div>
                  <div>Engine: <span className="text-cyan-400 font-bold">FastAPI + Python</span></div>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
                <div className="bg-slate-900 p-4 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-400 uppercase font-bold">Score</span>
                  <div className="text-3xl font-black mt-1" style={{ color: riskColor }}>{score}</div>
                </div>
                <div className="bg-slate-900 p-4 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-400 uppercase font-bold">Risk Level</span>
                  <div className="text-sm font-black mt-2" style={{ color: riskColor }}>{riskLevel}</div>
                </div>
                <div className="bg-slate-900 p-4 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-400 uppercase font-bold">Issues</span>
                  <div className="text-2xl font-black mt-1 text-slate-200">{findings.length}</div>
                </div>
                <div className="bg-slate-900 p-4 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-400 uppercase font-bold">Resources</span>
                  <div className="text-2xl font-black mt-1 text-slate-200">{scanResult?.resources_scanned ?? 0}</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 6: 2-MINUTE PRESENTATION SCRIPT */}
        {activeTab === 'presentation' && (
          <div className="space-y-6">
            <div className="bg-[#0f172a] p-6 rounded-2xl border border-slate-800 space-y-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                🎤 2-Minute College Presentation Script
              </h3>
              <div className="space-y-4 text-xs text-slate-300 leading-relaxed border-l-2 border-cyan-500 pl-4 py-1">
                <div>
                  <strong className="text-cyan-400">1. Problem Statement (0:00 - 0:30):</strong>
                  <p className="mt-1">
                    "Good morning/afternoon. Today I am presenting <strong>KubeGuard</strong>, a container and Kubernetes static security auditor built with a React dashboard and Python FastAPI engine. In production cloud-native environments, developers deploy Kubernetes manifests and Dockerfiles daily. However, default configurations run containers as root, mount dangerous host filesystems, and grant wildcard RBAC privileges, exposing entire clusters to catastrophic compromise."
                  </p>
                </div>
                <div>
                  <strong className="text-cyan-400">2. Solution &amp; Live Demo (0:30 - 1:20):</strong>
                  <p className="mt-1">
                    "KubeGuard provides an automated, deterministic security gate. When I audit an unhardened application, KubeGuard's Python rule engine detects critical vulnerabilities—such as <code>securityContext.privileged: true</code> and hardcoded plaintext database secrets. It awards a <strong>0/100 CRITICAL RISK</strong> score and explains the exact host breakout impact."
                  </p>
                </div>
                <div>
                  <strong className="text-cyan-400">3. Remediation &amp; Hardening (1:20 - 2:00):</strong>
                  <p className="mt-1">
                    "For every issue, KubeGuard provides a ready-to-use YAML correction blueprint. When we apply these mitigations—enforcing <code>runAsNonRoot: true</code>, dropping all Linux capabilities, and isolating RBAC—and rescan, the security score jumps to <strong>96/100 LOW RISK</strong>. All analysis occurs in the Python backend, ensuring reliable CI/CD integration."
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-[#0f172a] p-6 rounded-2xl border border-slate-800 space-y-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                🎓 Likely Questions Your Teacher Will Ask &amp; Strong Answers
              </h3>

              <div className="space-y-4 text-xs">
                <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                  <strong className="text-slate-100 text-sm">Q1: "Does KubeGuard perform live penetration testing on a cluster?"</strong>
                  <p className="mt-2 text-slate-300 leading-relaxed">
                    <strong>Answer:</strong> "No, sir/ma'am. KubeGuard is explicitly a <em>static configuration auditor</em>. It shifts security left by inspecting YAML manifests and Dockerfiles before deployment. This prevents vulnerabilities from ever reaching runtime. For runtime monitoring, production stacks complement this with eBPF tools like Falco."
                  </p>
                </div>

                <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                  <strong className="text-slate-100 text-sm">Q2: "Why is running a container as root (UID 0) dangerous if it's already containerized?"</strong>
                  <p className="mt-2 text-slate-300 leading-relaxed">
                    <strong>Answer:</strong> "Containers share the host Linux kernel. If an attacker discovers a kernel exploit or container breakout vulnerability (like CVE-2024-21626 in runc), running as UID 0 allows them to escape directly with root authority on the physical host. Enforcing <code>runAsNonRoot: true</code> ensures defense-in-depth."
                  </p>
                </div>

                <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                  <strong className="text-slate-100 text-sm">Q3: "How is your architecture split between React and Python?"</strong>
                  <p className="mt-2 text-slate-300 leading-relaxed">
                    <strong>Answer:</strong> "The React frontend is responsible purely for user interaction, filtering, and cyber-themed visualizations. It does not duplicate security rules in JavaScript. All 24 Kubernetes rules, 10 Dockerfile rules, YAML parsing, and scoring algorithms execute in the Python FastAPI backend, which also powers the CLI."
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 7: METHODOLOGY */}
        {activeTab === 'methodology' && (
          <div className="bg-[#0f172a] p-6 rounded-2xl border border-slate-800 space-y-6 text-xs text-slate-300 leading-relaxed">
            <h3 className="text-base font-bold text-white">Security Methodology &amp; Scope Specification</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-3">
                <h4 className="font-bold text-cyan-400 uppercase text-xs">What KubeGuard Audits</h4>
                <p>
                  KubeGuard evaluates manifests against the <strong>Kubernetes Pod Security Standards (Restricted Profile)</strong>, the <strong>CIS Kubernetes Benchmark</strong>, and <strong>OWASP Container Security Guides</strong>:
                </p>
                <ul className="list-disc pl-4 space-y-1 text-slate-300">
                  <li><strong>Container Privilege Isolation:</strong> Privileged flags, root UID, capability drops.</li>
                  <li><strong>Host Namespace Leaks:</strong> hostPID, hostNetwork, hostIPC isolation.</li>
                  <li><strong>Storage Security:</strong> Host filesystem mounts (hostPath).</li>
                  <li><strong>RBAC Least Privilege:</strong> Wildcard permissions and cluster-admin role bindings.</li>
                  <li><strong>Secrets Hygiene:</strong> Detection of plaintext credentials in manifests and env vars.</li>
                  <li><strong>Dockerfile Standards:</strong> Missing USER, latest tags, unsafe remote execution.</li>
                </ul>
              </div>

              <div className="space-y-3">
                <h4 className="font-bold text-orange-400 uppercase text-xs">Honest Architecture Boundaries</h4>
                <p>
                  To maintain academic and professional integrity, KubeGuard clearly identifies what it does not do:
                </p>
                <ul className="list-disc pl-4 space-y-1 text-slate-300">
                  <li><strong>No Live Cluster Attacks:</strong> It does not exploit running Kubernetes clusters.</li>
                  <li><strong>No Image CVE Scanning:</strong> It checks configuration flags, not operating system package CVEs (Trivy should be used for CVEs).</li>
                  <li><strong>No Kernel Syscall Tracing:</strong> It operates statically, not via eBPF runtime probes (Falco).</li>
                </ul>
              </div>
            </div>
          </div>
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-6 mt-12 bg-[#070b14] text-center text-xs text-slate-500">
        <p>🛡️ <strong>KubeGuard</strong> &bull; Container &amp; Kubernetes Security Auditor &bull; College Cybersecurity Project</p>
        <p className="mt-1 text-[11px] text-slate-600">Architecture: React 19 Frontend + FastAPI Python 3.11 Backend. Licensed under MIT.</p>
      </footer>
    </div>
  );
}
