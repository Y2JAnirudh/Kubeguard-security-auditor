/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
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
  Upload,
  RefreshCw,
  Server,
  Layers,
  ChevronDown,
  ChevronRight,
  FileText,
  ExternalLink,
  Code,
  BarChart3,
  BookOpen,
  Info,
  X,
  FileCheck,
  ArrowRight,
  Sliders,
  Zap,
  Activity,
  Compass,
  Navigation,
  PieChart,
  Target,
  Radio,
  SlidersHorizontal,
  TrendingDown,
  Grid,
  Cpu,
  Crosshair,
  Sparkles
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
  integrations?: {
    trivy_available?: boolean;
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

// Preset Snippets for instant testing in the Interactive Editor
const PRESET_SNIPPETS: Record<string, { filename: string; code: string; label: string }> = {
  privileged: {
    filename: 'privileged-pod.yaml',
    label: 'Privileged Container (K8S-001)',
    code: `apiVersion: v1
kind: Pod
metadata:
  name: privileged-workload
  namespace: default
spec:
  containers:
    - name: worker
      image: alpine:3.19
      securityContext:
        privileged: true
        runAsUser: 0
        allowPrivilegeEscalation: true
`
  },
  secrets: {
    filename: 'secret-leak.yaml',
    label: 'Plaintext Credentials in Env (K8S-011)',
    code: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
  namespace: production
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: app
          image: mycompany/auth:latest
          env:
            - name: DB_PASSWORD
              value: "SuperSecretPassword123!"
            - name: AWS_SECRET_ACCESS_KEY
              value: "AKIAIOSFODNN7EXAMPLEKEY"
`
  },
  rbac: {
    filename: 'wildcard-rbac.yaml',
    label: 'Wildcard ClusterRole RBAC (K8S-013)',
    code: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-dev-role
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`
  },
  dockerfile: {
    filename: 'Dockerfile',
    label: 'Insecure Dockerfile (DOCK-001/002/004)',
    code: `FROM ubuntu:latest
# Runs as root by default
ENV API_KEY="sk_live_93819283918239"
RUN apt-get update && apt-get install -y curl
RUN curl -sSL https://install.example.com/script.sh | bash
CMD ["python3", "app.py"]
`
  },
  hardened: {
    filename: 'hardened-deployment.yaml',
    label: 'Hardened Workload (PSS Restricted Reference)',
    code: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-web
  namespace: production
spec:
  replicas: 3
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: web
          image: cgr.dev/chainguard/nginx:1.25.4@sha256:abc123
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
            requests:
              cpu: "100m"
              memory: "128Mi"
`
  }
};

type AppTab =
  | 'findings'
  | 'charts'
  | 'trivy'
  | 'benchmark'
  | 'cli'
  | 'report'
  | 'presentation'
  | 'methodology';

// Direct Column Navigation Targets Grouped by Page/Tab
const NAVIGATION_TARGETS = [
  {
    pageTitle: 'Security Findings',
    tab: 'findings' as AppTab,
    columns: [
      { id: 'section-score-overview', label: 'Security Posture Radial Gauge', desc: '0-100 baseline score & risk band' },
      { id: 'section-severity-overview', label: 'Severity KPI Analytics', desc: 'Critical, High, Medium, Low tiles' },
      { id: 'section-compliance-vectors', label: 'Security Pillar Compliance Strip', desc: '4-vector attack surface meters' },
      { id: 'section-spectrum-bar', label: 'Severity Distribution Spectrum', desc: 'Proportional multi-segment bar' },
      { id: 'section-audit-workspace', label: 'Audit Target Workspace', desc: 'Upload dropzone & live code editor' },
      { id: 'section-investigation-toolbar', label: 'Investigation Toolbar & Findings Table', desc: 'Keyword search, filters & rule cards' },
    ]
  },
  {
    pageTitle: 'Risk Breakdown & Charts',
    tab: 'charts' as AppTab,
    columns: [
      { id: 'column-radar-chart', label: 'Security Domain Radar Matrix', desc: '6-dimensional compliance spider chart' },
      { id: 'column-donut-chart', label: 'Interactive Severity Donut Chart', desc: 'Arc distribution & center telemetry' },
      { id: 'column-resource-heatmap', label: 'Resource Threat Topology Heatmap', desc: 'Workload risk density matrix' },
      { id: 'column-waterfall-chart', label: 'Heuristic Deduction Waterfall Graph', desc: 'Step-down mathematical penalty flow' },
      { id: 'column-severity-chart', label: 'Findings by Severity Breakdown', desc: 'Weighted point penalty bars' },
      { id: 'column-category-matrix', label: 'Findings by Security Category', desc: 'Policy pillars & risk counts' },
      { id: 'column-deduction-ledger', label: 'Transparent Scoring Deduction Ledger', desc: 'Heuristic deduction mathematical audit' },
    ]
  },
  {
    pageTitle: 'Container Image Scan (Trivy)',
    tab: 'trivy' as AppTab,
    columns: [
      { id: 'column-trivy-scope', label: 'IaC vs CVE Architecture Scope', desc: 'Configuration risks vs binary vulnerabilities' },
      { id: 'column-trivy-status', label: 'Trivy Binary Availability Status', desc: 'Local installation check & fallback' },
      { id: 'column-trivy-scanner', label: 'Target Image Vulnerability Scanner', desc: 'Image input & quick presets' },
      { id: 'column-trivy-donut', label: 'CVE Vulnerability Distribution Chart', desc: 'Interactive CVE severity breakdown' },
      { id: 'column-trivy-cve-table', label: 'Discovered Image Flaws (CVE Table)', desc: 'Parsed CVE IDs, packages & severity' },
    ]
  },
  {
    pageTitle: 'Before vs After Demo',
    tab: 'benchmark' as AppTab,
    columns: [
      { id: 'column-demo-delta', label: 'Security Posture Remediation Delta', desc: 'Baseline vs hardened comparison score' },
      { id: 'column-demo-vulnerable', label: 'Unchecked Baseline Column (Vulnerable)', desc: 'Root execution, hostPath & secret leaks' },
      { id: 'column-demo-hardened', label: 'Hardened Architecture Column (Secure)', desc: 'PSS Restricted profile & least privilege' },
    ]
  },
  {
    pageTitle: 'CLI & Local Python Run',
    tab: 'cli' as AppTab,
    columns: [
      { id: 'column-cli-audit', label: 'Manifest Directory Audit Command', desc: 'python3 cli.py scan command' },
      { id: 'column-cli-strict', label: 'Strict Mode CI/CD Gate Command', desc: 'Exit code 1 on critical findings' },
      { id: 'column-cli-pytest', label: 'Automated Pytest Suite (25 Tests)', desc: 'Run complete test suite' },
    ]
  },
  {
    pageTitle: 'HTML Report',
    tab: 'report' as AppTab,
    columns: [
      { id: 'column-report-actions', label: 'Executive Report Download Actions', desc: 'Generate & export standalone report' },
      { id: 'column-report-preview', label: 'Live Document Audit Report Preview', desc: 'Formatted report metrics' },
    ]
  },
  {
    pageTitle: '2-Min Pitch & Teacher Q&A',
    tab: 'presentation' as AppTab,
    columns: [
      { id: 'column-presentation-script', label: '2-Minute Presentation Walkthrough', desc: 'Problem, solution & demo speech' },
      { id: 'column-presentation-qa', label: 'Instructor Technical Q&A Cards', desc: 'Answers to top defense questions' },
    ]
  },
  {
    pageTitle: 'Methodology & Standards',
    tab: 'methodology' as AppTab,
    columns: [
      { id: 'column-methodology-frameworks', label: 'Evaluated Security Frameworks', desc: 'PSS Restricted & CIS Kubernetes' },
      { id: 'column-methodology-boundaries', label: 'Architectural Scope & Boundaries', desc: 'Static analysis scope guarantees' },
    ]
  }
];

export default function App() {
  const [activeDatasetLabel, setActiveDatasetLabel] = useState<string>('Vulnerable Baseline (Demo)');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [apiHealth, setApiHealth] = useState<HealthStatus | null>(null);
  
  // All 8 official tabs
  const [activeTab, setActiveTab] = useState<AppTab>('findings');
  
  // Navigation Dropdown & Element Highlighting State
  const [navDropdownOpen, setNavDropdownOpen] = useState<boolean>(false);
  const [highlightedElementId, setHighlightedElementId] = useState<string | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Cached baseline scan results for live Before vs After Delta comparison
  const [vulnerableCache, setVulnerableCache] = useState<ScanResult | null>(null);
  const [secureCache, setSecureCache] = useState<ScanResult | null>(null);

  // Filtering & Search
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [selectedResourceFilter, setSelectedResourceFilter] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Analytics Sub-View Switcher
  const [chartsViewMode, setChartsViewMode] = useState<'all' | 'radar_donut' | 'threat_matrix' | 'waterfall'>('all');
  const [hoveredRadarIndex, setHoveredRadarIndex] = useState<number | null>(null);
  const [hoveredSeveritySlice, setHoveredSeveritySlice] = useState<string | null>(null);
  const [hoveredWaterfallStep, setHoveredWaterfallStep] = useState<number | null>(null);
  
  // Custom Artifact Input Workspace
  const [inputMode, setInputMode] = useState<'upload' | 'snippet'>('upload');
  const [uploadedFilesList, setUploadedFilesList] = useState<Array<{ filename: string; content: string }>>([]);
  const [pastedCode, setPastedCode] = useState<string>('');
  const [pastedType, setPastedType] = useState<string>('manifest.yaml');

  // Trivy state
  const [trivyStatus, setTrivyStatus] = useState<TrivyStatus | null>(null);
  const [trivyImage, setTrivyImage] = useState<string>('python:3.11-slim');
  const [trivyLoading, setTrivyLoading] = useState<boolean>(false);
  const [trivyScanResult, setTrivyScanResult] = useState<TrivyResult | null>(null);
  const [showSampleTrivy, setShowSampleTrivy] = useState<boolean>(false);

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setNavDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Initial load
  useEffect(() => {
    checkHealth();
    checkTrivyStatus();
    initLoadDemos();
  }, []);

  const checkHealth = async () => {
    try {
      const res = await fetch('/api/health');
      const contentType = res.headers.get('content-type') || '';
      if (res.ok && contentType.includes('application/json')) {
        const data = await res.json();
        setApiHealth(data);
      }
    } catch (err) {
      console.warn('FastAPI health check pending:', err);
    }
  };

  const checkTrivyStatus = async () => {
    try {
      const res = await fetch('/api/trivy/status');
      if (res.ok) {
        const data: TrivyStatus = await res.json();
        setTrivyStatus(data);
      }
    } catch {
      setTrivyStatus({
        available: false,
        version: null,
        message: 'Trivy integration unavailable — core KubeGuard static analysis remains fully functional.'
      });
    }
  };

  // Preload both demo scans so Before vs After comparison has real data immediately
  const initLoadDemos = async () => {
    setLoading(true);
    try {
      const [vulnRes, secRes] = await Promise.all([
        fetch('/api/scan/demo/vulnerable', { method: 'POST' }).then(r => r.json()),
        fetch('/api/scan/demo/secure', { method: 'POST' }).then(r => r.json())
      ]);
      setVulnerableCache(vulnRes);
      setSecureCache(secRes);
      setScanResult(vulnRes);
      setActiveDatasetLabel('Vulnerable Baseline (Demo)');
    } catch (err) {
      console.error('Failed to load initial demo scans:', err);
    } finally {
      setLoading(false);
    }
  };

  const triggerDemoScan = async (type: 'vulnerable' | 'secure') => {
    setLoading(true);
    try {
      const endpoint = type === 'vulnerable' ? '/api/scan/demo/vulnerable' : '/api/scan/demo/secure';
      const res = await fetch(endpoint, { method: 'POST' });
      const contentType = res.headers.get('content-type') || '';
      if (!res.ok || !contentType.includes('application/json')) {
        throw new Error(`Demo scan failed (HTTP ${res.status})`);
      }
      const data: ScanResult = await res.json();
      setScanResult(data);
      if (type === 'vulnerable') setVulnerableCache(data);
      if (type === 'secure') setSecureCache(data);
      setActiveDatasetLabel(type === 'vulnerable' ? 'Vulnerable Baseline (Demo)' : 'Hardened Reference (Demo)');
      setUploadedFilesList([]);
      setPastedCode('');
      setExpandedFindings({});
    } catch (err) {
      console.error('Failed to trigger demo scan:', err);
    } finally {
      setLoading(false);
    }
  };

  // Core Dropdown Navigator: switches tab, scrolls smoothly to target column, highlights it
  const navigateToColumn = (tab: AppTab, elementId: string) => {
    setNavDropdownOpen(false);
    setActiveTab(tab);
    
    // Allow DOM to mount tab contents before scrolling
    setTimeout(() => {
      const el = document.getElementById(elementId);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        setHighlightedElementId(elementId);
        setTimeout(() => setHighlightedElementId(null), 2500);
      }
    }, 120);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    const fileList = Array.from(files);
    const promises = fileList.map((file) => {
      return new Promise<{ filename: string; content: string }>((resolve) => {
        const reader = new FileReader();
        reader.onload = (event) => {
          resolve({
            filename: file.name,
            content: (event.target?.result as string) || ''
          });
        };
        reader.readAsText(file);
      });
    });

    Promise.all(promises).then((loadedFiles) => {
      setUploadedFilesList(loadedFiles);
      runCustomScan(loadedFiles);
    });
  };

  const removeUploadedFile = (index: number) => {
    const next = [...uploadedFilesList];
    next.splice(index, 1);
    setUploadedFilesList(next);
    if (next.length > 0) {
      runCustomScan(next);
    } else {
      triggerDemoScan('vulnerable');
    }
  };

  const runCustomScan = async (files: Array<{ filename: string; content: string }>) => {
    setLoading(true);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files })
      });
      const data: ScanResult = await res.json();
      setScanResult(data);
      setActiveDatasetLabel(`Uploaded Manifests (${files.length} file${files.length > 1 ? 's' : ''})`);
      setExpandedFindings({});
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
      const data: ScanResult = await res.json();
      setScanResult(data);
      setActiveDatasetLabel(`Custom Snippet (${pastedType})`);
      setExpandedFindings({});
    } catch (err) {
      console.error('Error scanning pasted snippet:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadPresetSnippet = (key: string) => {
    const preset = PRESET_SNIPPETS[key];
    if (preset) {
      setPastedCode(preset.code);
      setPastedType(preset.filename);
      setInputMode('snippet');
    }
  };

  const handleTrivyScan = async (overrideImage?: string) => {
    const target = overrideImage || trivyImage;
    if (!target.trim()) return;
    setTrivyLoading(true);
    setTrivyScanResult(null);
    try {
      const res = await fetch('/api/trivy/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image: target.trim() })
      });
      const data: TrivyResult = await res.json();
      setTrivyScanResult(data);
    } catch (err) {
      setTrivyScanResult({
        success: false,
        available: false,
        error: `Network error reaching Trivy API: ${String(err)}`
      });
    } finally {
      setTrivyLoading(false);
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
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `kubeguard-security-report-${new Date().toISOString().slice(0, 10)}.html`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
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

  const expandAll = () => {
    const all: Record<string, boolean> = {};
    filteredFindings.forEach((f, idx) => {
      all[`${f.rule_id}-${idx}`] = true;
    });
    setExpandedFindings(all);
  };

  const collapseAll = () => {
    setExpandedFindings({});
  };

  // Score & Color calculations
  const score = scanResult?.score ?? 0;
  const riskLevel = scanResult?.risk_level ?? 'CALCULATING...';
  const riskColor =
    score >= 90 ? '#22c55e' : score >= 70 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';

  const findings = scanResult?.findings ?? [];
  const categories = useMemo(() => Array.from(new Set(findings.map(f => f.category))), [findings]);

  // Filtered findings list
  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
      if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false;
      if (selectedResourceFilter && f.resource !== selectedResourceFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          f.rule_id.toLowerCase().includes(q) ||
          f.title.toLowerCase().includes(q) ||
          f.resource.toLowerCase().includes(q) ||
          f.evidence.toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [findings, severityFilter, categoryFilter, selectedResourceFilter, searchQuery]);

  // SVG Radial Gauge calculations
  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  // Total findings count for proportional bar calculations
  const totalFindings = scanResult?.total_findings || 1;
  const critPct = Math.round(((scanResult?.counts.critical ?? 0) / totalFindings) * 100);
  const highPct = Math.round(((scanResult?.counts.high ?? 0) / totalFindings) * 100);
  const medPct = Math.round(((scanResult?.counts.medium ?? 0) / totalFindings) * 100);
  const lowPct = Math.round(((scanResult?.counts.low ?? 0) / totalFindings) * 100);

  // ─────────────────────────────────────────────────────────────
  // 6-DIMENSIONAL SECURITY DOMAIN RADAR MATRIX COMPUTATION
  // ─────────────────────────────────────────────────────────────
  const radarDimensions = useMemo(() => {
    const dims = [
      {
        key: 'pss',
        name: 'Pod Security Standards (PSS)',
        short: 'PSS Profile',
        rules: ['K8S-001', 'K8S-002', 'K8S-005', 'K8S-006', 'K8S-009', 'K8S-010', 'K8S-019'],
        categories: ['Privilege Escalation', 'Root Execution', 'Capabilities', 'Filesystem Security'],
      },
      {
        key: 'isolation',
        name: 'Privilege & Host Isolation',
        short: 'Host Isolation',
        rules: ['K8S-003', 'K8S-004', 'K8S-007', 'K8S-008', 'K8S-018', 'K8S-020'],
        categories: ['Host Isolation', 'Network Security'],
      },
      {
        key: 'rbac',
        name: 'RBAC & Identity Governance',
        short: 'RBAC / Auth',
        rules: ['K8S-013', 'K8S-014', 'K8S-015', 'K8S-021', 'K8S-022'],
        categories: ['RBAC & Authorization', 'Service Accounts', 'Identity'],
      },
      {
        key: 'secrets',
        name: 'Secrets & Sensitive Data',
        short: 'Secrets Mgmt',
        rules: ['K8S-011', 'K8S-012', 'DOCK-003'],
        categories: ['Sensitive Data', 'Credentials', 'Environment Secrets'],
      },
      {
        key: 'reliability',
        name: 'Resource Reliability & Quotas',
        short: 'Resource Quotas',
        rules: ['K8S-016', 'K8S-017', 'K8S-023'],
        categories: ['Resource Management', 'Health Probes', 'Availability'],
      },
      {
        key: 'supply_chain',
        name: 'Supply Chain & Container Hygiene',
        short: 'Supply Chain',
        rules: ['K8S-024', 'DOCK-001', 'DOCK-002', 'DOCK-004', 'DOCK-005', 'DOCK-006', 'DOCK-007', 'DOCK-008', 'DOCK-009', 'DOCK-010'],
        categories: ['Supply Chain & Provenance', 'Docker Security', 'Image Hygiene'],
      },
    ];

    const sevWeights: Record<string, number> = {
      CRITICAL: 20,
      HIGH: 10,
      MEDIUM: 5,
      LOW: 2,
      INFO: 0,
    };

    return dims.map((dim) => {
      const matched = findings.filter(
        (f) =>
          dim.rules.includes(f.rule_id) ||
          dim.categories.some((c) => f.category.toLowerCase().includes(c.toLowerCase()))
      );

      const penalty = matched.reduce((acc, f) => acc + (sevWeights[f.severity] || 0), 0);
      const scoreVal = Math.max(15, Math.min(100, 100 - penalty));

      return {
        ...dim,
        score: scoreVal,
        penalty,
        findingCount: matched.length,
        findings: matched,
      };
    });
  }, [findings]);

  // ─────────────────────────────────────────────────────────────
  // RESOURCE THREAT DENSITY TOPOLOGY
  // ─────────────────────────────────────────────────────────────
  const resourceThreatMatrix = useMemo(() => {
    const map = new Map<string, {
      resource: string;
      kind: string;
      name: string;
      findings: Finding[];
      counts: { critical: number; high: number; medium: number; low: number };
      penalty: number;
    }>();

    findings.forEach((f) => {
      const resKey = f.resource || 'Cluster / Manifest';
      let entry = map.get(resKey);
      if (!entry) {
        let kind = 'Resource';
        let name = resKey;
        if (resKey.includes('/')) {
          const parts = resKey.split('/');
          kind = parts[0];
          name = parts.slice(1).join('/');
        } else if (resKey.toLowerCase().includes('docker')) {
          kind = 'Dockerfile';
        }
        entry = {
          resource: resKey,
          kind,
          name,
          findings: [],
          counts: { critical: 0, high: 0, medium: 0, low: 0 },
          penalty: 0,
        };
        map.set(resKey, entry);
      }

      entry.findings.push(f);
      if (f.severity === 'CRITICAL') {
        entry.counts.critical++;
        entry.penalty += 20;
      } else if (f.severity === 'HIGH') {
        entry.counts.high++;
        entry.penalty += 10;
      } else if (f.severity === 'MEDIUM') {
        entry.counts.medium++;
        entry.penalty += 5;
      } else if (f.severity === 'LOW') {
        entry.counts.low++;
        entry.penalty += 2;
      }
    });

    return Array.from(map.values()).sort((a, b) => b.penalty - a.penalty);
  }, [findings]);

  // Donut Chart Segment Geometry
  const donutRadius = 66;
  const donutCircumference = 2 * Math.PI * donutRadius;
  const critFrac = (scanResult?.counts.critical ?? 0) / totalFindings;
  const highFrac = (scanResult?.counts.high ?? 0) / totalFindings;
  const medFrac = (scanResult?.counts.medium ?? 0) / totalFindings;
  const lowFrac = (scanResult?.counts.low ?? 0) / totalFindings;

  // Waterfall Steps
  const critPenalty = (scanResult?.counts.critical ?? 0) * 20;
  const highPenalty = (scanResult?.counts.high ?? 0) * 10;
  const medPenalty = (scanResult?.counts.medium ?? 0) * 5;
  const lowPenalty = (scanResult?.counts.low ?? 0) * 2;
  const totalDeductions = critPenalty + highPenalty + medPenalty + lowPenalty;

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 cyber-grid-bg font-sans antialiased selection:bg-cyan-500 selection:text-slate-950 flex flex-col">
      
      {/* ─────────────────────────────────────────────────────────────
          1. HEADER / ENTERPRISE SOC APPLICATION COMMAND BAR
      ────────────────────────────────────────────────────────────── */}
      <header className="border-b border-slate-800/80 bg-[#0a0f1d]/95 backdrop-blur-md sticky top-0 z-50 shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between gap-4">
          
          {/* Brand Identity & Engine Info */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="h-9 w-9 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-600/20 border border-cyan-400/30">
              <ShieldAlert className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-extrabold tracking-tight text-white">
                  Kube<span className="text-cyan-400">Guard</span>
                </span>
                <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold uppercase tracking-wider bg-slate-900 text-cyan-300 border border-slate-700/80 rounded">
                  React + FastAPI
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-medium">Container &amp; Kubernetes Security Auditor</p>
            </div>
          </div>

          {/* Interactive Actions, Drop-Down Column Navigator, Demo Switchers */}
          <div className="flex items-center gap-2.5 shrink-0">
            
            {/* Interactive Dropdown Navigator: Direct Page & Column Jump */}
            <div className="relative" ref={dropdownRef}>
              <button
                type="button"
                onClick={() => setNavDropdownOpen(!navDropdownOpen)}
                className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-850 border border-cyan-500/40 text-cyan-300 hover:text-cyan-200 text-xs font-semibold shadow-sm transition-all duration-200"
                aria-expanded={navDropdownOpen}
              >
                <Compass className="h-3.5 w-3.5 text-cyan-400 animate-pulse" />
                <span className="hidden sm:inline">Jump to Column</span>
                <ChevronDown className={`h-3 w-3 text-cyan-400 transition-transform duration-200 ${navDropdownOpen ? 'rotate-180' : ''}`} />
              </button>

              {/* Flyout Navigation Dropdown Menu */}
              <AnimatePresence>
                {navDropdownOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: -6, scale: 0.98 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -6, scale: 0.98 }}
                    transition={{ duration: 0.15, ease: 'easeOut' }}
                    className="absolute right-0 mt-2 w-80 max-h-[80vh] overflow-y-auto bg-[#0a0f1d] border border-cyan-500/40 rounded-2xl shadow-2xl shadow-cyan-950/60 p-2 z-50 divide-y divide-slate-800/80"
                  >
                    <div className="p-2 pb-1.5 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                      <span className="uppercase tracking-wider font-bold text-cyan-400 flex items-center gap-1.5">
                        <Navigation className="h-3 w-3" />
                        Target Column Navigator
                      </span>
                      <span>8 pages &bull; 28 columns</span>
                    </div>

                    {NAVIGATION_TARGETS.map((targetGroup) => (
                      <div key={targetGroup.tab} className="py-2 space-y-1">
                        <div className="px-2.5 py-1 text-[11px] font-bold text-slate-300 uppercase tracking-wide flex items-center justify-between">
                          <span>{targetGroup.pageTitle}</span>
                          {activeTab === targetGroup.tab && (
                            <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                              Active Page
                            </span>
                          )}
                        </div>
                        <div className="space-y-0.5">
                          {targetGroup.columns.map((col) => (
                            <button
                              key={col.id}
                              type="button"
                              onClick={() => navigateToColumn(targetGroup.tab, col.id)}
                              className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800/90 text-xs text-slate-300 hover:text-cyan-300 transition-colors flex flex-col group"
                            >
                              <span className="font-medium group-hover:text-cyan-300 flex items-center justify-between">
                                <span>{col.label}</span>
                                <ChevronRight className="h-3 w-3 text-slate-600 group-hover:text-cyan-400 transition-transform group-hover:translate-x-0.5" />
                              </span>
                              <span className="text-[10px] text-slate-500 group-hover:text-slate-400 truncate">
                                {col.desc}
                              </span>
                            </button>
                          ))}
                        </div>
                      </div>
                    ))}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Quick Demo Switchers */}
            <div className="hidden md:flex items-center gap-1.5 bg-slate-900/90 p-1 rounded-xl border border-slate-800">
              <button
                type="button"
                onClick={() => {
                  triggerDemoScan('vulnerable');
                  setActiveTab('findings');
                }}
                disabled={loading}
                className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all duration-200 flex items-center gap-1.5 ${
                  activeDatasetLabel.includes('Vulnerable')
                    ? 'bg-red-950/80 text-red-400 border border-red-800/80 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
                Vulnerable Demo
              </button>
              <button
                type="button"
                onClick={() => {
                  triggerDemoScan('secure');
                  setActiveTab('findings');
                }}
                disabled={loading}
                className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all duration-200 flex items-center gap-1.5 ${
                  activeDatasetLabel.includes('Hardened')
                    ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/80 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                Hardened Demo
              </button>
            </div>

            {/* HTML Report Action */}
            <button
              type="button"
              onClick={downloadReportHtml}
              className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-600/10 hover:bg-cyan-600/25 border border-cyan-500/30 text-cyan-300 hover:text-cyan-200 text-xs font-semibold transition-all duration-200"
            >
              <Download className="h-3.5 w-3.5" />
              <span>HTML Report</span>
            </button>

            {/* Live FastAPI Backend Connection Indicator */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs">
              <span className="relative flex h-2 w-2">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${apiHealth ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                <span className={`relative inline-flex rounded-full h-2 w-2 ${apiHealth ? 'bg-emerald-500' : 'bg-amber-500'}`} />
              </span>
              <span className={`text-[11px] font-bold ${apiHealth ? 'text-emerald-400' : 'text-amber-400'}`}>
                {apiHealth ? 'CONNECTED' : 'CONNECTING'}
              </span>
            </div>

          </div>
        </div>

        {/* ─────────────────────────────────────────────────────────────
            2. APPLICATION NAVIGATION TABS
        ────────────────────────────────────────────────────────────── */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center gap-1 overflow-x-auto scrollbar-none border-t border-slate-850/60 pt-1">
          {[
            { id: 'findings', label: 'Security Findings', icon: ShieldAlert, badge: findings.length },
            { id: 'charts', label: 'Risk Breakdown & Charts', icon: BarChart3, badge: 'Matrix' },
            { id: 'trivy', label: 'Container Image Scan', icon: Search, badge: 'Trivy' },
            { id: 'benchmark', label: 'Before vs After Demo', icon: ShieldCheck, badge: 'Delta' },
            { id: 'cli', label: 'CLI & Local Run', icon: Terminal, badge: '25 Tests' },
            { id: 'report', label: 'HTML Report', icon: FileText, badge: null },
            { id: 'presentation', label: '2-Min Pitch & Teacher Q&A', icon: HelpCircle, badge: 'Defense' },
            { id: 'methodology', label: 'Methodology & Standards', icon: BookOpen, badge: 'PSS' },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id as AppTab)}
                className={`flex items-center gap-2 px-3.5 py-2 border-b-2 text-xs font-semibold whitespace-nowrap transition-all duration-200 ${
                  isActive
                    ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <Icon className={`h-3.5 w-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
                {tab.badge !== null && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                    isActive ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </header>

      {/* ─────────────────────────────────────────────────────────────
          MAIN CONTENT AREA
      ────────────────────────────────────────────────────────────── */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 flex-1 w-full">
        
        {/* Real-time scanning indicator banner */}
        <AnimatePresence>
          {loading && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="bg-cyan-950/60 border border-cyan-800/80 rounded-xl p-3 flex items-center justify-between text-xs text-cyan-300 shadow-md"
            >
              <div className="flex items-center gap-2.5">
                <RefreshCw className="h-4 w-4 animate-spin text-cyan-400" />
                <span>Executing Python static rule engine across Kubernetes AST and Dockerfile tokens...</span>
              </div>
              <span className="font-mono text-[11px] text-cyan-400">FastAPI Engine</span>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ─────────────────────────────────────────────────────────────
            3. HERO / EXECUTIVE SECURITY OVERVIEW & RADIAL GAUGE
        ────────────────────────────────────────────────────────────── */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          
          {/* Radial Score Gauge Card (Visual Centerpiece) */}
          <div
            id="section-score-overview"
            className={`lg:col-span-5 bg-gradient-to-br from-[#0c1322] to-[#0f172a] border border-slate-800 rounded-2xl p-6 relative overflow-hidden flex flex-col justify-between shadow-xl transition-all duration-300 ${
              highlightedElementId === 'section-score-overview' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
            }`}
          >
            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Security Posture Score</span>
                <p className="text-[11px] text-slate-500 mt-0.5">Static Heuristic Deduction Model (100 Base)</p>
              </div>
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-slate-900 border border-slate-800 text-cyan-300">
                0 - 100 Posture
              </span>
            </div>

            {/* Radial Ring Visualization */}
            <div className="my-5 flex items-center gap-6">
              <div className="relative shrink-0 flex items-center justify-center">
                <svg className="w-34 h-34 -rotate-90 transform">
                  {/* Background Track */}
                  <circle
                    cx="68"
                    cy="68"
                    r={radius}
                    stroke="#1e293b"
                    strokeWidth="11"
                    fill="transparent"
                  />
                  {/* Dynamic Progress Ring */}
                  <circle
                    cx="68"
                    cy="68"
                    r={radius}
                    stroke={riskColor}
                    strokeWidth="11"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                    fill="transparent"
                    className="transition-all duration-700 ease-out"
                  />
                </svg>
                {/* Large Center Score */}
                <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                  <span className="text-4xl font-extrabold font-mono tabular-nums leading-none" style={{ color: riskColor }}>
                    {loading ? '...' : score}
                  </span>
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mt-1">/ 100</span>
                </div>
              </div>

              {/* Status & Classification */}
              <div className="space-y-2 flex-1">
                <span
                  className="inline-block px-3 py-1 rounded-md text-xs font-black tracking-wider uppercase"
                  style={{
                    backgroundColor: `${riskColor}15`,
                    color: riskColor,
                    border: `1px solid ${riskColor}40`
                  }}
                >
                  {loading ? 'ANALYZING...' : riskLevel}
                </span>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {score >= 90
                    ? 'Workload adheres to Kubernetes Pod Security Standards (PSS) Restricted Profile.'
                    : score >= 70
                    ? 'Baseline security controls active. Minor resource limits or unpinned tags present.'
                    : score >= 40
                    ? 'Significant privilege escalation or namespace leakage risks identified.'
                    : 'Critical compromise vectors detected: root execution, hostPath, or wildcard RBAC.'}
                </p>
              </div>
            </div>

            {/* Real Supporting Info Metadata Bar */}
            <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between text-xs text-slate-400 gap-2">
              <span className="truncate">
                Target: <strong className="text-slate-200">{activeDatasetLabel}</strong>
              </span>
              <span className="font-mono text-cyan-400 shrink-0">
                {scanResult?.resources_scanned ?? 0} resources &bull; {scanResult?.files_scanned.length ?? 0} files &bull; {scanResult?.total_findings ?? 0} issues
              </span>
            </div>
          </div>

          {/* Right: Polished Severity Analytics Tiles with Proportional Bars */}
          <div className="lg:col-span-7 flex flex-col justify-between gap-4">
            
            <div
              id="section-severity-overview"
              className={`grid grid-cols-2 sm:grid-cols-4 gap-3 p-1 rounded-2xl transition-all duration-300 ${
                highlightedElementId === 'section-severity-overview' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
              }`}
            >
              
              {/* Critical Card */}
              <button
                type="button"
                onClick={() => setSeverityFilter(severityFilter === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
                className={`p-4 rounded-2xl border text-left flex flex-col justify-between transition-all duration-200 ${
                  severityFilter === 'CRITICAL'
                    ? 'bg-red-950/40 border-red-500 ring-2 ring-red-500/30'
                    : 'bg-[#0c1322] border-slate-800 hover:border-red-900/60 hover:bg-red-950/20'
                }`}
              >
                <div className="flex items-center justify-between text-xs font-bold text-red-400">
                  <span className="flex items-center gap-1.5">
                    <AlertTriangle className="h-3.5 w-3.5" />
                    CRITICAL
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-950/80 border border-red-900 text-red-300">-20 pts</span>
                </div>
                <div className="my-2">
                  <span className="text-3xl font-black font-mono tabular-nums text-red-400">
                    {scanResult?.counts.critical ?? 0}
                  </span>
                  <span className="text-[11px] text-slate-500 block font-mono">{critPct}% of findings</span>
                </div>
                <div className="h-1 bg-slate-900 rounded-full overflow-hidden">
                  <div className="h-full bg-red-500 rounded-full" style={{ width: `${critPct}%` }} />
                </div>
              </button>

              {/* High Card */}
              <button
                type="button"
                onClick={() => setSeverityFilter(severityFilter === 'HIGH' ? 'ALL' : 'HIGH')}
                className={`p-4 rounded-2xl border text-left flex flex-col justify-between transition-all duration-200 ${
                  severityFilter === 'HIGH'
                    ? 'bg-orange-950/40 border-orange-500 ring-2 ring-orange-500/30'
                    : 'bg-[#0c1322] border-slate-800 hover:border-orange-900/60 hover:bg-orange-950/20'
                }`}
              >
                <div className="flex items-center justify-between text-xs font-bold text-orange-400">
                  <span className="flex items-center gap-1.5">
                    <ShieldAlert className="h-3.5 w-3.5" />
                    HIGH
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-orange-950/80 border border-orange-900 text-orange-300">-10 pts</span>
                </div>
                <div className="my-2">
                  <span className="text-3xl font-black font-mono tabular-nums text-orange-400">
                    {scanResult?.counts.high ?? 0}
                  </span>
                  <span className="text-[11px] text-slate-500 block font-mono">{highPct}% of findings</span>
                </div>
                <div className="h-1 bg-slate-900 rounded-full overflow-hidden">
                  <div className="h-full bg-orange-500 rounded-full" style={{ width: `${highPct}%` }} />
                </div>
              </button>

              {/* Medium Card */}
              <button
                type="button"
                onClick={() => setSeverityFilter(severityFilter === 'MEDIUM' ? 'ALL' : 'MEDIUM')}
                className={`p-4 rounded-2xl border text-left flex flex-col justify-between transition-all duration-200 ${
                  severityFilter === 'MEDIUM'
                    ? 'bg-amber-950/40 border-amber-500 ring-2 ring-amber-500/30'
                    : 'bg-[#0c1322] border-slate-800 hover:border-amber-900/60 hover:bg-amber-950/20'
                }`}
              >
                <div className="flex items-center justify-between text-xs font-bold text-amber-400">
                  <span className="flex items-center gap-1.5">
                    <Activity className="h-3.5 w-3.5" />
                    MEDIUM
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-950/80 border border-amber-900 text-amber-300">-5 pts</span>
                </div>
                <div className="my-2">
                  <span className="text-3xl font-black font-mono tabular-nums text-amber-400">
                    {scanResult?.counts.medium ?? 0}
                  </span>
                  <span className="text-[11px] text-slate-500 block font-mono">{medPct}% of findings</span>
                </div>
                <div className="h-1 bg-slate-900 rounded-full overflow-hidden">
                  <div className="h-full bg-amber-500 rounded-full" style={{ width: `${medPct}%` }} />
                </div>
              </button>

              {/* Low Card */}
              <button
                type="button"
                onClick={() => setSeverityFilter(severityFilter === 'LOW' ? 'ALL' : 'LOW')}
                className={`p-4 rounded-2xl border text-left flex flex-col justify-between transition-all duration-200 ${
                  severityFilter === 'LOW'
                    ? 'bg-blue-950/40 border-blue-500 ring-2 ring-blue-500/30'
                    : 'bg-[#0c1322] border-slate-800 hover:border-blue-900/60 hover:bg-blue-950/20'
                }`}
              >
                <div className="flex items-center justify-between text-xs font-bold text-blue-400">
                  <span className="flex items-center gap-1.5">
                    <Info className="h-3.5 w-3.5" />
                    LOW
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-950/80 border border-blue-900 text-blue-300">-2 pts</span>
                </div>
                <div className="my-2">
                  <span className="text-3xl font-black font-mono tabular-nums text-blue-400">
                    {scanResult?.counts.low ?? 0}
                  </span>
                  <span className="text-[11px] text-slate-500 block font-mono">{lowPct}% of findings</span>
                </div>
                <div className="h-1 bg-slate-900 rounded-full overflow-hidden">
                  <div className="h-full bg-blue-500 rounded-full" style={{ width: `${lowPct}%` }} />
                </div>
              </button>

            </div>

            {/* Compact Security Posture Multi-Segment Distribution Bar */}
            <div
              id="section-spectrum-bar"
              className={`bg-[#0c1322] border border-slate-800/90 rounded-2xl p-4 space-y-2 transition-all duration-300 ${
                highlightedElementId === 'section-spectrum-bar' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
              }`}
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-slate-300 flex items-center gap-1.5">
                  <Zap className="h-3.5 w-3.5 text-cyan-400" />
                  Severity Distribution Spectrum
                </span>
                <span className="font-mono text-slate-400 text-[11px]">
                  {scanResult?.total_findings ?? 0} total weaknesses detected
                </span>
              </div>

              {/* Multi-Segment Proportional Progress Bar */}
              <div className="h-3 bg-slate-900 rounded-full overflow-hidden flex p-0.5 border border-slate-800 gap-0.5">
                {critPct > 0 && (
                  <div className="h-full bg-red-500 rounded-l-full transition-all duration-700" style={{ width: `${critPct}%` }} title={`Critical: ${critPct}%`} />
                )}
                {highPct > 0 && (
                  <div className="h-full bg-orange-500 transition-all duration-700" style={{ width: `${highPct}%` }} title={`High: ${highPct}%`} />
                )}
                {medPct > 0 && (
                  <div className="h-full bg-amber-500 transition-all duration-700" style={{ width: `${medPct}%` }} title={`Medium: ${medPct}%`} />
                )}
                {lowPct > 0 && (
                  <div className="h-full bg-blue-500 rounded-r-full transition-all duration-700" style={{ width: `${lowPct}%` }} title={`Low: ${lowPct}%`} />
                )}
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-0.5">
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-red-500" /> Critical ({critPct}%)</span>
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-orange-500" /> High ({highPct}%)</span>
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-amber-500" /> Medium ({medPct}%)</span>
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-blue-500" /> Low ({lowPct}%)</span>
              </div>
            </div>

          </div>

        </section>

        {/* ─────────────────────────────────────────────────────────────
            3.5 INTERACTIVE SECURITY PILLAR COMPLIANCE VECTORS STRIP
        ────────────────────────────────────────────────────────────── */}
        <section
          id="section-compliance-vectors"
          className={`bg-[#0a0f1d] border border-slate-800/90 rounded-2xl p-4 shadow-lg transition-all duration-300 ${
            highlightedElementId === 'section-compliance-vectors' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
          }`}
        >
          <div className="flex items-center justify-between mb-3 text-xs">
            <div className="flex items-center gap-2">
              <Crosshair className="h-4 w-4 text-cyan-400" />
              <span className="font-bold text-slate-200">Attack Surface &amp; Policy Pillar Health</span>
            </div>
            <button
              type="button"
              onClick={() => setActiveTab('charts')}
              className="text-cyan-400 hover:text-cyan-300 text-[11px] font-mono flex items-center gap-1 transition"
            >
              <span>Explore Multi-Axis Radar Matrix</span>
              <ArrowRight className="h-3 w-3" />
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {radarDimensions.slice(0, 4).map((dim) => {
              const dimColor =
                dim.score >= 85 ? '#22c55e' : dim.score >= 60 ? '#eab308' : dim.score >= 40 ? '#f97316' : '#ef4444';
              return (
                <div
                  key={dim.key}
                  onClick={() => {
                    setActiveTab('charts');
                    navigateToColumn('charts', 'column-radar-chart');
                  }}
                  className="bg-[#0c1322] border border-slate-800 hover:border-cyan-500/50 p-3 rounded-xl cursor-pointer transition-all duration-200 group"
                >
                  <div className="flex items-center justify-between text-xs mb-1.5">
                    <span className="font-medium text-slate-300 group-hover:text-cyan-300 truncate text-[11px]">
                      {dim.short}
                    </span>
                    <span className="font-mono font-bold text-xs" style={{ color: dimColor }}>
                      {dim.score}%
                    </span>
                  </div>
                  <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${dim.score}%`, backgroundColor: dimColor }}
                    />
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono mt-2">
                    <span>{dim.findingCount} issue{dim.findingCount === 1 ? '' : 's'}</span>
                    <span className={dim.penalty > 0 ? 'text-red-400' : 'text-emerald-400'}>
                      {dim.penalty > 0 ? `-${dim.penalty} pts` : 'Nominal'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* ─────────────────────────────────────────────────────────────
            4. AUDIT TARGET WORKSPACE (Upload, Paste, or Quick Test)
        ────────────────────────────────────────────────────────────── */}
        <section
          id="section-audit-workspace"
          className={`bg-[#0c1322] border border-slate-800/80 rounded-2xl p-5 shadow-lg space-y-4 transition-all duration-300 ${
            highlightedElementId === 'section-audit-workspace' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
          }`}
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="h-8 w-8 rounded-lg bg-cyan-950/80 border border-cyan-800/50 flex items-center justify-center text-cyan-400">
                <Code className="h-4 w-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white">Audit Target Workspace</h3>
                <p className="text-xs text-slate-400">Upload Kubernetes YAML manifests or Dockerfiles for static vulnerability inspection.</p>
              </div>
            </div>

            {/* Input Mode Switcher */}
            <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-xl border border-slate-800">
              <button
                type="button"
                onClick={() => setInputMode('upload')}
                className={`px-3 py-1 rounded-lg text-xs font-semibold transition ${
                  inputMode === 'upload' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Upload Files
              </button>
              <button
                type="button"
                onClick={() => setInputMode('snippet')}
                className={`px-3 py-1 rounded-lg text-xs font-semibold transition ${
                  inputMode === 'snippet' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Paste / Test Snippet
              </button>
            </div>
          </div>

          {inputMode === 'upload' ? (
            <div className="space-y-3">
              <label className="border-2 border-dashed border-slate-700/80 hover:border-cyan-500/80 rounded-xl p-6 flex flex-col items-center justify-center text-center cursor-pointer bg-[#080d18] hover:bg-slate-900/40 transition group">
                <Upload className="h-7 w-7 text-cyan-400 group-hover:scale-110 transition-transform mb-2" />
                <span className="text-xs font-bold text-slate-200">
                  Drop Kubernetes YAMLs or Dockerfiles here, or <span className="text-cyan-400 underline">browse files</span>
                </span>
                <span className="text-[11px] text-slate-500 mt-1">Supports .yaml, .yml, and Dockerfile (multi-file batch audit)</span>
                <input
                  type="file"
                  multiple
                  accept=".yaml,.yml,Dockerfile,text/plain"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>

              {/* Uploaded Files Chips */}
              {uploadedFilesList.length > 0 && (
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <span className="text-xs text-slate-400 font-semibold">Loaded Files:</span>
                  {uploadedFilesList.map((file, idx) => (
                    <div
                      key={idx}
                      className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-cyan-300"
                    >
                      <FileCheck className="h-3.5 w-3.5 text-cyan-400" />
                      <span>{file.filename}</span>
                      <button
                        type="button"
                        onClick={() => removeUploadedFile(idx)}
                        className="text-slate-500 hover:text-red-400 ml-1 transition"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              {/* Preset Snippet Quick Loaders */}
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-slate-400 font-semibold">Test Presets:</span>
                {Object.entries(PRESET_SNIPPETS).map(([key, item]) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => loadPresetSnippet(key)}
                    className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 border border-slate-800 text-xs font-medium transition"
                  >
                    {item.label}
                  </button>
                ))}
              </div>

              {/* Code Snippet Editor */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">Target Type:</span>
                    <select
                      value={pastedType}
                      onChange={(e) => setPastedType(e.target.value)}
                      className="bg-slate-900 border border-slate-700 rounded-lg px-2 py-0.5 text-xs text-cyan-300 font-mono focus:outline-none"
                    >
                      <option value="deployment.yaml">Kubernetes Manifest (.yaml)</option>
                      <option value="Dockerfile">Containerfile / Dockerfile</option>
                    </select>
                  </div>
                  <span className="text-slate-500 font-mono text-[11px]">{pastedCode.split('\n').length} lines</span>
                </div>

                <textarea
                  value={pastedCode}
                  onChange={(e) => setPastedCode(e.target.value)}
                  placeholder="Paste raw Kubernetes YAML manifest or Dockerfile directives here to inspect..."
                  rows={7}
                  className="w-full bg-[#080d18] border border-slate-800 rounded-xl p-3 font-mono text-xs text-cyan-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 leading-relaxed"
                />

                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setPastedCode('')}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition"
                  >
                    Clear
                  </button>
                  <button
                    type="button"
                    onClick={handlePastedAudit}
                    disabled={!pastedCode.trim() || loading}
                    className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-slate-950 font-bold text-xs transition flex items-center gap-1.5 shadow"
                  >
                    <Play className="h-3.5 w-3.5" />
                    Audit Snippet
                  </button>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* ─────────────────────────────────────────────────────────────
            5. TAB 1: AUDIT FINDINGS (INVESTIGATION WORKSPACE)
        ────────────────────────────────────────────────────────────── */}
        {activeTab === 'findings' && (
          <section className="space-y-4">
            
            {/* Filter & Search Toolbar */}
            <div
              id="section-investigation-toolbar"
              className={`bg-[#0c1322] border border-slate-800 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-md transition-all duration-300 ${
                highlightedElementId === 'section-investigation-toolbar' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
              }`}
            >
              <div className="flex flex-wrap items-center gap-2.5 flex-1 min-w-[280px]">
                {/* Search Box */}
                <div className="relative flex-1 min-w-[200px] max-w-md">
                  <Search className="h-3.5 w-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search by Rule ID (e.g. K8S-001), keyword, resource..."
                    className="w-full bg-slate-900 border border-slate-700/80 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                  {searchQuery && (
                    <button
                      type="button"
                      onClick={() => setSearchQuery('')}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>

                {/* Severity Dropdown Filter */}
                <div className="flex items-center gap-1.5 bg-slate-900 px-2.5 py-1 rounded-lg border border-slate-800 text-xs">
                  <Filter className="h-3 w-3 text-slate-400" />
                  <span className="text-slate-400">Severity:</span>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="bg-transparent text-xs text-slate-200 font-semibold focus:outline-none cursor-pointer"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical (-20)</option>
                    <option value="HIGH">High (-10)</option>
                    <option value="MEDIUM">Medium (-5)</option>
                    <option value="LOW">Low (-2)</option>
                  </select>
                </div>

                {/* Category Dropdown Filter */}
                {categories.length > 0 && (
                  <div className="flex items-center gap-1.5 bg-slate-900 px-2.5 py-1 rounded-lg border border-slate-800 text-xs">
                    <span className="text-slate-400">Category:</span>
                    <select
                      value={categoryFilter}
                      onChange={(e) => setCategoryFilter(e.target.value)}
                      className="bg-transparent text-xs text-slate-200 font-semibold focus:outline-none cursor-pointer"
                    >
                      <option value="ALL">All Categories</option>
                      {categories.map((c) => (
                        <option key={c} value={c}>{c}</option>
                      ))}
                    </select>
                  </div>
                )}

                {/* Active Workload Filter Chip */}
                {selectedResourceFilter && (
                  <div className="flex items-center gap-1.5 bg-cyan-950/80 border border-cyan-800 px-2 py-0.5 rounded-lg text-xs font-mono text-cyan-300">
                    <span>Workload: {selectedResourceFilter}</span>
                    <button
                      type="button"
                      onClick={() => setSelectedResourceFilter(null)}
                      className="text-cyan-400 hover:text-cyan-200 ml-1"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                )}

                {/* Clear Filters Button if any active */}
                {(severityFilter !== 'ALL' || categoryFilter !== 'ALL' || selectedResourceFilter || searchQuery) && (
                  <button
                    type="button"
                    onClick={() => {
                      setSeverityFilter('ALL');
                      setCategoryFilter('ALL');
                      setSelectedResourceFilter(null);
                      setSearchQuery('');
                    }}
                    className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-semibold transition"
                  >
                    Reset Filters
                  </button>
                )}
              </div>

              {/* Expand / Collapse All & Match Counter */}
              <div className="flex items-center gap-3 text-xs text-slate-400 shrink-0">
                <button
                  type="button"
                  onClick={expandAll}
                  className="hover:text-cyan-400 transition-colors"
                >
                  Expand All
                </button>
                <span>&bull;</span>
                <button
                  type="button"
                  onClick={collapseAll}
                  className="hover:text-cyan-400 transition-colors"
                >
                  Collapse All
                </button>
                <span>&bull;</span>
                <span>
                  Showing <strong className="text-cyan-400 font-mono">{filteredFindings.length}</strong> of {findings.length}
                </span>
              </div>
            </div>

            {/* Findings List with Framer Motion hover elevation */}
            {filteredFindings.length === 0 ? (
              <div className="bg-[#0c1322] border border-slate-800 rounded-2xl p-12 text-center space-y-3">
                <CheckCircle2 className="h-10 w-10 text-emerald-400 mx-auto" />
                <h4 className="text-base font-bold text-slate-200">No Security Issues Found</h4>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  The audited configuration complies with all active policy checks, or no issues matched your current search filters.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredFindings.map((finding, idx) => {
                  const key = `${finding.rule_id}-${idx}`;
                  const isExpanded = !!expandedFindings[key];

                  const severityColorMap = {
                    CRITICAL: {
                      badge: 'bg-red-950/80 text-red-400 border-red-800/80',
                      indicator: 'bg-red-500',
                      borderHover: 'hover:border-red-900/60'
                    },
                    HIGH: {
                      badge: 'bg-orange-950/80 text-orange-400 border-orange-800/80',
                      indicator: 'bg-orange-500',
                      borderHover: 'hover:border-orange-900/60'
                    },
                    MEDIUM: {
                      badge: 'bg-amber-950/80 text-amber-400 border-amber-800/80',
                      indicator: 'bg-amber-500',
                      borderHover: 'hover:border-amber-900/60'
                    },
                    LOW: {
                      badge: 'bg-blue-950/80 text-blue-400 border-blue-800/80',
                      indicator: 'bg-blue-500',
                      borderHover: 'hover:border-blue-900/60'
                    },
                    INFO: {
                      badge: 'bg-slate-900 text-slate-400 border-slate-800',
                      indicator: 'bg-slate-400',
                      borderHover: 'hover:border-slate-700'
                    }
                  }[finding.severity];

                  return (
                    <motion.div
                      key={key}
                      whileHover={{ y: -2, transition: { duration: 0.18, ease: "easeOut" } }}
                      className={`bg-[#0c1322] border border-slate-800/90 rounded-xl overflow-hidden transition-colors duration-200 shadow-sm hover:shadow-lg hover:shadow-black/50 ${severityColorMap.borderHover}`}
                    >
                      {/* Summary Row */}
                      <div
                        onClick={() => toggleExpand(key)}
                        className="p-4 cursor-pointer flex items-center justify-between gap-4 select-none hover:bg-slate-850/40"
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <span className={`px-2 py-0.5 text-[11px] font-mono font-bold uppercase rounded border shrink-0 ${severityColorMap.badge}`}>
                            {finding.severity}
                          </span>
                          <span className="font-mono text-xs font-bold text-cyan-400 shrink-0">
                            {finding.rule_id}
                          </span>
                          <h4 className="font-semibold text-slate-200 text-sm truncate">
                            {finding.title}
                          </h4>
                        </div>

                        <div className="flex items-center gap-3 shrink-0">
                          <span className="hidden sm:inline-block bg-slate-900 px-2 py-0.5 rounded text-slate-400 font-mono text-[11px] border border-slate-800">
                            {finding.resource}
                          </span>
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4 text-slate-400" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-slate-400" />
                          )}
                        </div>
                      </div>

                      {/* Expandable Diagnostic Drawer with Framer Motion */}
                      <AnimatePresence>
                        {isExpanded && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            transition={{ duration: 0.2 }}
                            className="p-5 border-t border-slate-800/80 bg-[#080d18] space-y-4 text-xs"
                          >
                            {/* Metadata Grid */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                              <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Target Resource</span>
                                <span className="font-mono text-cyan-300 text-xs mt-0.5 block">{finding.resource}</span>
                              </div>
                              <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Manifest Location</span>
                                <span className="font-mono text-slate-300 text-xs mt-0.5 block truncate">
                                  {finding.file} {finding.location ? `→ ${finding.location}` : ''}
                                </span>
                              </div>
                            </div>

                            {/* Evidence Block */}
                            <div>
                              <span className="text-[11px] font-bold text-red-400 uppercase tracking-wider flex items-center gap-1.5 mb-1.5">
                                <AlertTriangle className="h-3.5 w-3.5" />
                                Evidence Detected in Configuration:
                              </span>
                              <pre className="p-3 rounded-lg bg-red-950/20 border border-red-900/50 text-red-300 font-mono text-xs overflow-x-auto">
                                <code>{finding.evidence}</code>
                              </pre>
                            </div>

                            {/* Impact vs Remediation Columns */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div className="bg-red-950/15 border border-red-900/40 p-4 rounded-xl">
                                <span className="text-[11px] font-bold text-red-400 uppercase tracking-wider block mb-1">
                                  🚨 Security Hazard &amp; Fallout
                                </span>
                                <p className="text-slate-300 leading-relaxed text-xs">{finding.impact}</p>
                              </div>
                              <div className="bg-emerald-950/15 border border-emerald-900/40 p-4 rounded-xl">
                                <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider block mb-1">
                                  🛠️ Recommended Remediation
                                </span>
                                <p className="text-slate-300 leading-relaxed text-xs">{finding.remediation}</p>
                              </div>
                            </div>

                            {/* Remediation Blueprint Snippet */}
                            {finding.remediation_yaml && (
                              <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden">
                                <div className="bg-slate-850 px-3.5 py-2 flex items-center justify-between text-[11px] font-bold text-slate-300 border-b border-slate-800">
                                  <span className="flex items-center gap-1.5">
                                    <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                                    Remediation Blueprint (Ready to Apply)
                                  </span>
                                  <button
                                    type="button"
                                    onClick={() => copyToClipboard(finding.remediation_yaml || '', key)}
                                    className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 transition-colors font-mono"
                                  >
                                    {copiedKey === key ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                                    {copiedKey === key ? 'Copied!' : 'Copy Snippet'}
                                  </button>
                                </div>
                                <pre className="p-3.5 text-cyan-300 font-mono text-xs overflow-x-auto">
                                  <code>{finding.remediation_yaml}</code>
                                </pre>
                              </div>
                            )}

                            {finding.references && finding.references.length > 0 && (
                              <div className="text-[11px] text-slate-500 pt-1 flex items-center gap-2">
                                <span>Official Guidance:</span>
                                {finding.references.map((ref, rIdx) => (
                                  <a
                                    key={rIdx}
                                    href={ref}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-cyan-400 hover:underline flex items-center gap-1"
                                  >
                                    {ref.replace(/^https?:\/\//, '').split('/')[0]}
                                    <ExternalLink className="h-3 w-3" />
                                  </a>
                                ))}
                              </div>
                            )}
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })}
              </div>
            )}
          </section>
        )}

        {/* ─────────────────────────────────────────────────────────────
            6. TAB 2: RISK BREAKDOWN & STATS CHARTS SUITE
        ────────────────────────────────────────────────────────────── */}
        {activeTab === 'charts' && (
          <section className="space-y-6">
            
            {/* View Mode Switcher Header */}
            <div className="flex flex-wrap items-center justify-between gap-3 bg-[#0a0f1d] border border-slate-800 p-3 rounded-2xl">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <BarChart3 className="h-4 w-4 text-cyan-400" />
                  Security Operations Center (SOC) Analytics Suite
                </h3>
                <p className="text-xs text-slate-400">Interactive multi-dimensional posture radar, threat density matrix &amp; penalty audit graphs.</p>
              </div>

              {/* Segmented Controls */}
              <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-xl border border-slate-800 text-xs">
                {[
                  { id: 'all', label: 'All Visualizations' },
                  { id: 'radar_donut', label: 'Radar & Donut' },
                  { id: 'threat_matrix', label: 'Workload Matrix' },
                  { id: 'waterfall', label: 'Waterfall Ledger' },
                ].map((mode) => (
                  <button
                    key={mode.id}
                    type="button"
                    onClick={() => setChartsViewMode(mode.id as any)}
                    className={`px-3 py-1 rounded-lg font-medium transition ${
                      chartsViewMode === mode.id
                        ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {mode.label}
                  </button>
                ))}
              </div>
            </div>

            {/* ROW 1: MULTI-AXIS SECURITY DOMAIN RADAR & INTERACTIVE SEVERITY DONUT */}
            {(chartsViewMode === 'all' || chartsViewMode === 'radar_donut') && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* 6-Axis Interactive Security Domain Radar */}
                <div
                  id="column-radar-chart"
                  className={`lg:col-span-7 bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-4 shadow-xl transition-all duration-300 ${
                    highlightedElementId === 'column-radar-chart' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-bold text-white flex items-center gap-2">
                        <Target className="h-4 w-4 text-cyan-400" />
                        6-Dimensional Security Domain Radar
                      </h4>
                      <p className="text-xs text-slate-400">Interactive polygon mapping posture compliance across key cloud-native domains.</p>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-400">
                      Hover Axis Points
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-center pt-2">
                    {/* SVG Radar Spider Web */}
                    <div className="md:col-span-7 flex justify-center relative">
                      {(() => {
                        const cx = 150;
                        const cy = 145;
                        const maxR = 98;
                        const numAxes = radarDimensions.length;

                        // Grid polygons at 25%, 50%, 75%, 100%
                        const rings = [0.25, 0.5, 0.75, 1.0];

                        // Data polygon points
                        const dataPoints = radarDimensions.map((dim, i) => {
                          const angle = (i * 2 * Math.PI) / numAxes - Math.PI / 2;
                          const r = (dim.score / 100) * maxR;
                          return {
                            x: cx + r * Math.cos(angle),
                            y: cy + r * Math.sin(angle),
                            dim,
                            angle,
                            i
                          };
                        });

                        const dataPolygonPath = dataPoints.map((p, idx) => `${idx === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ') + ' Z';

                        return (
                          <svg className="w-72 h-72 overflow-visible select-none" viewBox="0 0 300 290">
                            <defs>
                              <linearGradient id="radarAreaGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.45" />
                                <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.15" />
                              </linearGradient>
                              <filter id="radarGlow" x="-20%" y="-20%" width="140%" height="140%">
                                <feDropShadow dx="0" dy="0" stdDeviation="3" floodColor="#06b6d4" floodOpacity="0.6" />
                              </filter>
                            </defs>

                            {/* Concentric Polygon Web Rings */}
                            {rings.map((ringVal) => {
                              const ringPoints = Array.from({ length: numAxes }).map((_, i) => {
                                const angle = (i * 2 * Math.PI) / numAxes - Math.PI / 2;
                                const r = ringVal * maxR;
                                return `${cx + r * Math.cos(angle)},${cy + r * Math.sin(angle)}`;
                              }).join(' ');
                              return (
                                <g key={ringVal}>
                                  <polygon
                                    points={ringPoints}
                                    fill="none"
                                    stroke="#1e293b"
                                    strokeWidth="1.2"
                                    strokeDasharray={ringVal === 1.0 ? 'none' : '3 3'}
                                  />
                                  <text
                                    x={cx + 4}
                                    y={cy - ringVal * maxR + 9}
                                    fill="#475569"
                                    fontSize="8"
                                    fontFamily="monospace"
                                  >
                                    {Math.round(ringVal * 100)}%
                                  </text>
                                </g>
                              );
                            })}

                            {/* Spoke Lines */}
                            {Array.from({ length: numAxes }).map((_, i) => {
                              const angle = (i * 2 * Math.PI) / numAxes - Math.PI / 2;
                              const x = cx + maxR * Math.cos(angle);
                              const y = cy + maxR * Math.sin(angle);
                              const isHovered = hoveredRadarIndex === i;
                              return (
                                <line
                                  key={i}
                                  x1={cx}
                                  y1={cy}
                                  x2={x}
                                  y2={y}
                                  stroke={isHovered ? '#06b6d4' : '#1e293b'}
                                  strokeWidth={isHovered ? '2' : '1'}
                                  className="transition-colors duration-200"
                                />
                              );
                            })}

                            {/* Data Area Fill & Outline */}
                            <polygon
                              points={dataPoints.map((p) => `${p.x},${p.y}`).join(' ')}
                              fill="url(#radarAreaGradient)"
                              stroke="#06b6d4"
                              strokeWidth="2.5"
                              filter="url(#radarGlow)"
                              className="transition-all duration-500"
                            />

                            {/* Interactive Vertex Nodes */}
                            {dataPoints.map((p) => {
                              const isHovered = hoveredRadarIndex === p.i;
                              const nodeColor =
                                p.dim.score >= 85 ? '#22c55e' : p.dim.score >= 60 ? '#eab308' : '#ef4444';
                              return (
                                <g
                                  key={p.i}
                                  className="cursor-pointer"
                                  onMouseEnter={() => setHoveredRadarIndex(p.i)}
                                  onMouseLeave={() => setHoveredRadarIndex(null)}
                                  onClick={() => {
                                    setCategoryFilter(p.dim.categories[0] || 'ALL');
                                    setActiveTab('findings');
                                    navigateToColumn('findings', 'section-investigation-toolbar');
                                  }}
                                >
                                  {isHovered && (
                                    <circle
                                      cx={p.x}
                                      cy={p.y}
                                      r="11"
                                      fill="none"
                                      stroke="#06b6d4"
                                      strokeWidth="1.5"
                                      className="animate-ping opacity-75"
                                    />
                                  )}
                                  <circle
                                    cx={p.x}
                                    cy={p.y}
                                    r={isHovered ? '7' : '4.5'}
                                    fill={nodeColor}
                                    stroke="#070b14"
                                    strokeWidth="2"
                                    className="transition-all duration-200"
                                  />
                                </g>
                              );
                            })}

                            {/* Outer Axis Labels */}
                            {dataPoints.map((p) => {
                              const labelR = maxR + 24;
                              const lx = cx + labelR * Math.cos(p.angle);
                              const ly = cy + labelR * Math.sin(p.angle);
                              const isHovered = hoveredRadarIndex === p.i;
                              return (
                                <text
                                  key={`label-${p.i}`}
                                  x={lx}
                                  y={ly}
                                  textAnchor="middle"
                                  dominantBaseline="central"
                                  fill={isHovered ? '#38bdf8' : '#94a3b8'}
                                  fontSize="9.5"
                                  fontWeight={isHovered ? 'bold' : 'normal'}
                                  className="cursor-pointer transition-colors duration-150"
                                  onMouseEnter={() => setHoveredRadarIndex(p.i)}
                                  onMouseLeave={() => setHoveredRadarIndex(null)}
                                  onClick={() => {
                                    setCategoryFilter(p.dim.categories[0] || 'ALL');
                                    setActiveTab('findings');
                                  }}
                                >
                                  {p.dim.short}
                                </text>
                              );
                            })}
                          </svg>
                        );
                      })()}
                    </div>

                    {/* Interactive Telemetry Card beside Radar */}
                    <div className="md:col-span-5 space-y-3 bg-[#080d18] border border-slate-800/80 p-4 rounded-xl text-xs">
                      {(() => {
                        const activeDim =
                          hoveredRadarIndex !== null
                            ? radarDimensions[hoveredRadarIndex]
                            : radarDimensions[0];
                        const statusColor =
                          activeDim.score >= 85
                            ? 'text-emerald-400 bg-emerald-950/80 border-emerald-800'
                            : activeDim.score >= 60
                            ? 'text-amber-400 bg-amber-950/80 border-amber-800'
                            : 'text-red-400 bg-red-950/80 border-red-800';

                        return (
                          <div className="space-y-3">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider font-mono">
                                Domain Intelligence
                              </span>
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border font-mono ${statusColor}`}>
                                {activeDim.score}% COMPLIANT
                              </span>
                            </div>

                            <div>
                              <h5 className="font-bold text-slate-200 text-sm leading-snug">
                                {activeDim.name}
                              </h5>
                              <p className="text-[11px] text-slate-400 mt-1">
                                {activeDim.penalty > 0
                                  ? `${activeDim.findingCount} weakness${activeDim.findingCount === 1 ? '' : 'es'} identified triggering a -${activeDim.penalty} pts deduction.`
                                  : 'No policy violations identified. Standard security controls verified.'}
                              </p>
                            </div>

                            {activeDim.findings.length > 0 && (
                              <div className="space-y-1.5 pt-1">
                                <span className="text-[10px] font-mono text-slate-500 uppercase">Triggered Rules:</span>
                                <div className="flex flex-wrap gap-1">
                                  {activeDim.findings.slice(0, 4).map((f, fIdx) => (
                                    <span key={fIdx} className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-cyan-300">
                                      {f.rule_id}
                                    </span>
                                  ))}
                                  {activeDim.findings.length > 4 && (
                                    <span className="text-[10px] text-slate-500 font-mono">+{activeDim.findings.length - 4} more</span>
                                  )}
                                </div>
                              </div>
                            )}

                            <button
                              type="button"
                              onClick={() => {
                                setCategoryFilter(activeDim.categories[0] || 'ALL');
                                setActiveTab('findings');
                                navigateToColumn('findings', 'section-investigation-toolbar');
                              }}
                              className="w-full mt-2 py-1.5 rounded-lg bg-cyan-600/15 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 text-xs font-semibold flex items-center justify-center gap-1.5 transition"
                            >
                              <span>Inspect {activeDim.short} Findings</span>
                              <ArrowRight className="h-3 w-3" />
                            </button>
                          </div>
                        );
                      })()}
                    </div>
                  </div>
                </div>

                {/* Interactive SVG Donut Severity Distribution */}
                <div
                  id="column-donut-chart"
                  className={`lg:col-span-5 bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-4 shadow-xl flex flex-col justify-between transition-all duration-300 ${
                    highlightedElementId === 'column-donut-chart' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-bold text-white flex items-center gap-2">
                        <PieChart className="h-4 w-4 text-cyan-400" />
                        Severity Donut Distribution
                      </h4>
                      <p className="text-xs text-slate-400">Proportional arc weight by severity tier.</p>
                    </div>
                    <span className="text-xs font-mono text-slate-400">
                      {scanResult?.total_findings ?? 0} Total
                    </span>
                  </div>

                  {/* SVG Donut Centerpiece */}
                  <div className="my-2 flex items-center justify-center relative">
                    {(() => {
                      const critArc = critFrac * donutCircumference;
                      const highArc = highFrac * donutCircumference;
                      const medArc = medFrac * donutCircumference;
                      const lowArc = lowFrac * donutCircumference;

                      let currentOffset = 0;
                      const segments = [
                        { key: 'CRITICAL', arc: critArc, color: '#ef4444', count: scanResult?.counts.critical ?? 0, pts: '-20 pts' },
                        { key: 'HIGH', arc: highArc, color: '#f97316', count: scanResult?.counts.high ?? 0, pts: '-10 pts' },
                        { key: 'MEDIUM', arc: medArc, color: '#f59e0b', count: scanResult?.counts.medium ?? 0, pts: '-5 pts' },
                        { key: 'LOW', arc: lowArc, color: '#3b82f6', count: scanResult?.counts.low ?? 0, pts: '-2 pts' },
                      ];

                      const activeHover = hoveredSeveritySlice;
                      const hoveredData = segments.find(s => s.key === activeHover);

                      return (
                        <div className="relative flex items-center justify-center">
                          <svg className="w-52 h-52 -rotate-90 transform overflow-visible">
                            {/* Background Track */}
                            <circle
                              cx="104"
                              cy="104"
                              r={donutRadius}
                              stroke="#1e293b"
                              strokeWidth="18"
                              fill="transparent"
                            />

                            {/* Slices */}
                            {segments.map((seg) => {
                              const offset = currentOffset;
                              currentOffset += seg.arc;
                              if (seg.arc <= 0) return null;
                              const isHovered = activeHover === seg.key;
                              return (
                                <circle
                                  key={seg.key}
                                  cx="104"
                                  cy="104"
                                  r={donutRadius}
                                  stroke={seg.color}
                                  strokeWidth={isHovered ? 24 : 18}
                                  strokeDasharray={`${seg.arc} ${donutCircumference - seg.arc}`}
                                  strokeDashoffset={-offset}
                                  fill="transparent"
                                  className="transition-all duration-300 cursor-pointer"
                                  onMouseEnter={() => setHoveredSeveritySlice(seg.key)}
                                  onMouseLeave={() => setHoveredSeveritySlice(null)}
                                  onClick={() => {
                                    setSeverityFilter(severityFilter === seg.key ? 'ALL' : seg.key);
                                    setActiveTab('findings');
                                  }}
                                />
                              );
                            })}
                          </svg>

                          {/* Center Telemetry Readout */}
                          <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none">
                            <span className="text-3xl font-black font-mono tabular-nums leading-none text-white">
                              {hoveredData ? hoveredData.count : (scanResult?.total_findings ?? 0)}
                            </span>
                            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mt-1">
                              {hoveredData ? hoveredData.key : 'TOTAL FLAWS'}
                            </span>
                            <span className="text-[9px] font-mono text-cyan-400 mt-0.5">
                              {hoveredData ? `${hoveredData.pts} penalty` : `${score}/100 score`}
                            </span>
                          </div>
                        </div>
                      );
                    })()}
                  </div>

                  {/* Interactive Severity Legend Strip */}
                  <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80">
                    {[
                      { key: 'CRITICAL', label: 'Critical', count: scanResult?.counts.critical ?? 0, color: 'text-red-400', bg: 'hover:bg-red-950/30' },
                      { key: 'HIGH', label: 'High', count: scanResult?.counts.high ?? 0, color: 'text-orange-400', bg: 'hover:bg-orange-950/30' },
                      { key: 'MEDIUM', label: 'Medium', count: scanResult?.counts.medium ?? 0, color: 'text-amber-400', bg: 'hover:bg-amber-950/30' },
                      { key: 'LOW', label: 'Low', count: scanResult?.counts.low ?? 0, color: 'text-blue-400', bg: 'hover:bg-blue-950/30' },
                    ].map((item) => (
                      <button
                        key={item.key}
                        type="button"
                        onClick={() => {
                          setSeverityFilter(severityFilter === item.key ? 'ALL' : item.key);
                          setActiveTab('findings');
                        }}
                        onMouseEnter={() => setHoveredSeveritySlice(item.key)}
                        onMouseLeave={() => setHoveredSeveritySlice(null)}
                        className={`p-2 rounded-xl border border-slate-800 text-left transition-colors flex items-center justify-between text-xs ${item.bg}`}
                      >
                        <span className={`font-semibold ${item.color}`}>{item.label}</span>
                        <span className="font-mono font-bold text-slate-300">{item.count}</span>
                      </button>
                    ))}
                  </div>

                </div>

              </div>
            )}

            {/* ROW 2: WORKLOAD RISK TOPOLOGY GRID (HEATMAP) */}
            {(chartsViewMode === 'all' || chartsViewMode === 'threat_matrix') && (
              <div
                id="column-resource-heatmap"
                className={`bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-4 shadow-xl transition-all duration-300 ${
                  highlightedElementId === 'column-resource-heatmap' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h4 className="text-sm font-bold text-white flex items-center gap-2">
                      <Grid className="h-4 w-4 text-cyan-400" />
                      Workload Risk Topology &amp; Attack Density Matrix
                    </h4>
                    <p className="text-xs text-slate-400">Scanned Kubernetes objects and Dockerfiles ranked by accumulated penalty points.</p>
                  </div>
                  <span className="text-xs font-mono text-cyan-400">
                    {resourceThreatMatrix.length} Workloads Audited
                  </span>
                </div>

                {resourceThreatMatrix.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500 border border-slate-800 rounded-xl">
                    No workload resources detected in current audit target.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 pt-2">
                    {resourceThreatMatrix.map((item, idx) => {
                      const tierColor =
                        item.counts.critical > 0
                          ? 'border-red-900/60 bg-red-950/15 hover:border-red-500'
                          : item.counts.high > 0
                          ? 'border-orange-900/60 bg-orange-950/15 hover:border-orange-500'
                          : item.counts.medium > 0
                          ? 'border-amber-900/60 bg-amber-950/15 hover:border-amber-500'
                          : 'border-blue-900/60 bg-blue-950/15 hover:border-blue-500';

                      const badgeText =
                        item.counts.critical > 0
                          ? 'CRITICAL COMPROMISE'
                          : item.counts.high > 0
                          ? 'HIGH RISK'
                          : item.counts.medium > 0
                          ? 'MODERATE RISK'
                          : 'LOW EXPOSURE';

                      return (
                        <div
                          key={idx}
                          onClick={() => {
                            setSelectedResourceFilter(item.resource);
                            setActiveTab('findings');
                            navigateToColumn('findings', 'section-investigation-toolbar');
                          }}
                          className={`p-4 rounded-xl border ${tierColor} space-y-3 cursor-pointer transition-all duration-200 hover:-translate-y-0.5 shadow-sm group`}
                        >
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-slate-900/90 text-cyan-300 border border-slate-700 truncate max-w-[140px]">
                              {item.kind}
                            </span>
                            <span className="font-mono text-[10px] font-bold text-red-400">
                              -{item.penalty} pts
                            </span>
                          </div>

                          <div>
                            <h5 className="font-bold text-sm text-slate-100 group-hover:text-cyan-300 truncate">
                              {item.name}
                            </h5>
                            <span className="text-[10px] font-bold uppercase tracking-wider block mt-0.5 text-slate-400">
                              {badgeText}
                            </span>
                          </div>

                          {/* Mini Severity Count Pill Strip */}
                          <div className="flex items-center gap-1.5 pt-1 border-t border-slate-800/80 text-[11px] font-mono">
                            {item.counts.critical > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-red-950 text-red-300 border border-red-800">
                                {item.counts.critical} crit
                              </span>
                            )}
                            {item.counts.high > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-orange-950 text-orange-300 border border-orange-800">
                                {item.counts.high} high
                              </span>
                            )}
                            {item.counts.medium > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                                {item.counts.medium} med
                              </span>
                            )}
                            {item.counts.low > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                                {item.counts.low} low
                              </span>
                            )}
                            <span className="text-slate-500 text-[10px] ml-auto">
                              {item.findings.length} findings &rarr;
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* ROW 3: HEURISTIC DEDUCTION WATERFALL GRAPH */}
            {(chartsViewMode === 'all' || chartsViewMode === 'waterfall') && (
              <div
                id="column-waterfall-chart"
                className={`bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-5 shadow-xl transition-all duration-300 ${
                  highlightedElementId === 'column-waterfall-chart' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
                }`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-bold text-white flex items-center gap-2">
                      <TrendingDown className="h-4 w-4 text-cyan-400" />
                      Deterministic Posture Deduction Waterfall Graph
                    </h4>
                    <p className="text-xs text-slate-400">Step-by-step mathematical flow from 100 Base Posture to current score.</p>
                  </div>
                  <span className="text-xs font-mono text-cyan-400">
                    Mathematical Ledger
                  </span>
                </div>

                {/* Waterfall Stepped Chart */}
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-2">
                  {[
                    { title: 'Baseline Score', value: '+100', color: 'text-emerald-400', border: 'border-emerald-700/60', bg: 'bg-emerald-950/20', note: 'Uncompromised Base' },
                    { title: 'Critical Penalty', value: `-${critPenalty}`, color: 'text-red-400', border: 'border-red-700/60', bg: 'bg-red-950/20', note: `${scanResult?.counts.critical ?? 0} × 20 pts` },
                    { title: 'High Penalty', value: `-${highPenalty}`, color: 'text-orange-400', border: 'border-orange-700/60', bg: 'bg-orange-950/20', note: `${scanResult?.counts.high ?? 0} × 10 pts` },
                    { title: 'Medium Penalty', value: `-${medPenalty}`, color: 'text-amber-400', border: 'border-amber-700/60', bg: 'bg-amber-950/20', note: `${scanResult?.counts.medium ?? 0} × 5 pts` },
                    { title: 'Low Penalty', value: `-${lowPenalty}`, color: 'text-blue-400', border: 'border-blue-700/60', bg: 'bg-blue-950/20', note: `${scanResult?.counts.low ?? 0} × 2 pts` },
                    { title: 'Net Posture Score', value: `${score}`, color: riskColor, border: 'border-cyan-500/60', bg: 'bg-cyan-950/30', note: `${riskLevel}` },
                  ].map((step, sIdx) => (
                    <div
                      key={sIdx}
                      className={`p-4 rounded-xl border ${step.border} ${step.bg} flex flex-col justify-between space-y-2`}
                    >
                      <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                        {step.title}
                      </div>
                      <div className="text-2xl font-black font-mono" style={{ color: step.color }}>
                        {step.value}
                      </div>
                      <div className="text-[10px] font-mono text-slate-500 pt-1 border-t border-slate-800">
                        {step.note}
                      </div>
                    </div>
                  ))}
                </div>

                <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-400 flex flex-wrap items-center justify-between gap-2">
                  <span>Formula: <code className="text-cyan-300 font-mono">max(0, 100 - (20×Crit + 10×High + 5×Med + 2×Low))</code></span>
                  <span className="font-mono text-cyan-400">Total Deductions: -{totalDeductions} points</span>
                </div>
              </div>
            )}

            {/* ROW 4: POLICY PILLARS MATRIX & AUDIT LEDGER */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              {/* Severity Breakdown Card */}
              <div
                id="column-severity-chart"
                className={`bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-4 transition-all duration-300 ${
                  highlightedElementId === 'column-severity-chart' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
                }`}
              >
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <BarChart3 className="h-4 w-4 text-cyan-400" />
                    Severity Breakdown
                  </h4>
                  <span className="text-xs text-slate-500 font-mono">Deduction-weighted</span>
                </div>

                <div className="space-y-3 pt-2">
                  {[
                    { label: 'CRITICAL', count: scanResult?.counts.critical ?? 0, color: 'bg-red-500', text: 'text-red-400', pts: '-20 pts' },
                    { label: 'HIGH', count: scanResult?.counts.high ?? 0, color: 'bg-orange-500', text: 'text-orange-400', pts: '-10 pts' },
                    { label: 'MEDIUM', count: scanResult?.counts.medium ?? 0, color: 'bg-amber-500', text: 'text-amber-400', pts: '-5 pts' },
                    { label: 'LOW', count: scanResult?.counts.low ?? 0, color: 'bg-blue-500', text: 'text-blue-400', pts: '-2 pts' },
                  ].map((item) => {
                    const total = scanResult?.total_findings || 1;
                    const pct = Math.round((item.count / total) * 100);
                    return (
                      <div key={item.label} className="space-y-1.5">
                        <div className="flex justify-between text-xs font-semibold">
                          <span className={item.text}>{item.label} ({item.pts})</span>
                          <span className="text-slate-400 font-mono">{item.count} issues ({pct}%)</span>
                        </div>
                        <div className="h-2.5 bg-slate-900 rounded-full overflow-hidden p-0.5 border border-slate-800">
                          <div
                            className={`h-full ${item.color} rounded-full transition-all duration-700`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Category Breakdown Card */}
              <div
                id="column-category-matrix"
                className={`bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-4 transition-all duration-300 ${
                  highlightedElementId === 'column-category-matrix' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
                }`}
              >
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <Layers className="h-4 w-4 text-cyan-400" />
                    Findings by Security Category
                  </h4>
                  <span className="text-xs text-slate-500 font-mono">Policy Pillars</span>
                </div>

                {scanResult?.category_counts && Object.keys(scanResult.category_counts).length > 0 ? (
                  <div className="space-y-2.5 pt-2">
                    {Object.entries(scanResult.category_counts).map(([cat, count]) => {
                      const maxCount = Math.max(...Object.values(scanResult.category_counts), 1);
                      const barWidth = Math.round((count / maxCount) * 100);
                      return (
                        <div
                          key={cat}
                          onClick={() => {
                            setCategoryFilter(cat);
                            setActiveTab('findings');
                            navigateToColumn('findings', 'section-investigation-toolbar');
                          }}
                          className="space-y-1 cursor-pointer group"
                        >
                          <div className="flex items-center justify-between text-xs">
                            <span className="text-slate-300 group-hover:text-cyan-300 font-medium transition-colors">{cat}</span>
                            <span className="font-mono font-bold text-cyan-400">{count}</span>
                          </div>
                          <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-gradient-to-r from-cyan-500 to-blue-600 rounded-full transition-all duration-500"
                              style={{ width: `${barWidth}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">No categories identified.</p>
                )}
              </div>

            </div>

            {/* Transparent Scoring Deduction Audit Ledger */}
            <div
              id="column-deduction-ledger"
              className={`bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-4 transition-all duration-300 ${
                highlightedElementId === 'column-deduction-ledger' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
              }`}
            >
              <h4 className="text-sm font-bold text-white">Transparent Security Posture Ledger</h4>
              <p className="text-xs text-slate-400">
                KubeGuard starts at a baseline of 100 points and computes deductions deterministically based on severity weights:
              </p>

              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Severity Level</th>
                      <th className="py-2.5 px-3">Detected Count</th>
                      <th className="py-2.5 px-3">Deduction Weight</th>
                      <th className="py-2.5 px-3">Subtotal Penalty</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80 font-mono">
                    <tr>
                      <td className="py-2.5 px-3 text-red-400 font-bold">CRITICAL</td>
                      <td className="py-2.5 px-3 text-slate-200">{scanResult?.counts.critical ?? 0}</td>
                      <td className="py-2.5 px-3 text-slate-400">-20 pts</td>
                      <td className="py-2.5 px-3 text-red-400 font-bold">-{(scanResult?.counts.critical ?? 0) * 20} pts</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 px-3 text-orange-400 font-bold">HIGH</td>
                      <td className="py-2.5 px-3 text-slate-200">{scanResult?.counts.high ?? 0}</td>
                      <td className="py-2.5 px-3 text-slate-400">-10 pts</td>
                      <td className="py-2.5 px-3 text-orange-400 font-bold">-{(scanResult?.counts.high ?? 0) * 10} pts</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 px-3 text-amber-400 font-bold">MEDIUM</td>
                      <td className="py-2.5 px-3 text-slate-200">{scanResult?.counts.medium ?? 0}</td>
                      <td className="py-2.5 px-3 text-slate-400">-5 pts</td>
                      <td className="py-2.5 px-3 text-amber-400 font-bold">-{(scanResult?.counts.medium ?? 0) * 5} pts</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 px-3 text-blue-400 font-bold">LOW</td>
                      <td className="py-2.5 px-3 text-slate-200">{scanResult?.counts.low ?? 0}</td>
                      <td className="py-2.5 px-3 text-slate-400">-2 pts</td>
                      <td className="py-2.5 px-3 text-blue-400 font-bold">-{(scanResult?.counts.low ?? 0) * 2} pts</td>
                    </tr>
                  </tbody>
                  <tfoot className="border-t border-slate-700 bg-slate-900/60 font-bold text-xs">
                    <tr>
                      <td colSpan={3} className="py-2.5 px-3 text-slate-300">Final Security Posture Score</td>
                      <td className="py-2.5 px-3 font-mono" style={{ color: riskColor }}>
                        {score} / 100 ({riskLevel})
                      </td>
                    </tr>
                  </tfoot>
                </table>
              </div>
            </div>
          </section>
        )}

        {/* ─────────────────────────────────────────────────────────────
            7. TAB 3: CONTAINER IMAGE SCAN (TRIVY INTEGRATION)
        ────────────────────────────────────────────────────────────── */}
        {activeTab === 'trivy' && (
          <section className="space-y-6">
            
            {/* Scope Distinction Header */}
            <div
              id="column-trivy-scope"
              className={`bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-4 transition-all duration-300 ${
                highlightedElementId === 'column-trivy-scope' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
              }`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <Search className="h-5 w-5 text-cyan-400" />
                    Container Image Vulnerability Scan (Optional Trivy Integration)
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Defense-in-depth external security integration for container image layer CVE analysis.
                  </p>
                </div>
                <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-purple-950 text-purple-300 border border-purple-800">
                  Tool Integration
                </span>
              </div>

              {/* Distinction Columns */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
                <div className="bg-[#080d18] p-4 rounded-xl border border-cyan-900/40">
                  <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider block">
                    🛡️ KubeGuard Configuration Findings
                  </span>
                  <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                    Audits <strong>Infrastructure-as-Code (IaC) configuration risks</strong> in Kubernetes YAMLs and Dockerfiles (e.g. root execution, privileged flags, shared host namespaces, missing limits, wildcard RBAC). <strong>Runs 100% offline.</strong>
                  </p>
                  <div className="mt-2 text-[11px] text-cyan-300 font-mono">Output: 0-100 Security Posture Score</div>
                </div>

                <div className="bg-[#080d18] p-4 rounded-xl border border-purple-900/40">
                  <span className="text-xs font-bold text-purple-400 uppercase tracking-wider block">
                    🔍 Trivy Image Package Findings
                  </span>
                  <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                    Inspects <strong>binary packages inside image layers</strong> (e.g. runc, libssl, glibc) against published CVE vulnerability advisories. Requires external Trivy CLI binary.
                  </p>
                  <div className="mt-2 text-[11px] text-purple-300 font-mono">Output: CVE Vulnerability Flaw Counts</div>
                </div>
              </div>
            </div>

            {/* Trivy Tool Status Banner */}
            <div
              id="column-trivy-status"
              className={`p-5 rounded-2xl border transition-all duration-300 ${
                trivyStatus?.available ? 'bg-emerald-950/20 border-emerald-900/60' : 'bg-[#0c1322] border-slate-800'
              } ${highlightedElementId === 'column-trivy-status' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''}`}
            >
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className={`h-10 w-10 rounded-xl flex items-center justify-center ${trivyStatus?.available ? 'bg-emerald-900/40 text-emerald-400' : 'bg-slate-900 text-amber-400 border border-slate-800'}`}>
                    {trivyStatus?.available ? <CheckCircle2 className="h-5 w-5" /> : <AlertTriangle className="h-5 w-5" />}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="text-sm font-bold text-white">Trivy Binary Availability:</h4>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${trivyStatus?.available ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-amber-950 text-amber-300 border border-amber-800'}`}>
                        {trivyStatus?.available ? 'Installed & Ready' : 'Unavailable (Optional)'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      {trivyStatus?.message || 'Inspecting system PATH for trivy executable...'}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setShowSampleTrivy(!showSampleTrivy)}
                    className="px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-cyan-300 rounded-lg text-xs font-semibold border border-slate-700 transition"
                  >
                    {showSampleTrivy ? 'Hide Demonstration CVEs' : 'Preview Sample Trivy CVEs'}
                  </button>
                </div>
              </div>

              {!trivyStatus?.available && (
                <div className="mt-4 pt-3 border-t border-slate-800 text-xs text-slate-400 flex flex-wrap items-center justify-between gap-2">
                  <span>To enable live container scanning on your host machine: <code className="bg-slate-900 px-2 py-0.5 rounded text-cyan-300 font-mono">brew install trivy</code> or <code className="bg-slate-900 px-2 py-0.5 rounded text-cyan-300 font-mono">apt install trivy</code></span>
                  <span className="text-slate-500 text-[11px]">Core KubeGuard static analysis remains 100% operational</span>
                </div>
              )}
            </div>

            {/* Target Image Input */}
            <div
              id="column-trivy-scanner"
              className={`bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-4 transition-all duration-300 ${
                highlightedElementId === 'column-trivy-scanner' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
              }`}
            >
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Target Container Image</h4>
              
              <div className="flex flex-wrap gap-3 items-center">
                <input
                  type="text"
                  value={trivyImage}
                  onChange={(e) => setTrivyImage(e.target.value)}
                  placeholder="e.g. alpine:3.19, python:3.11-slim, nginx:1.25"
                  className="flex-1 min-w-[240px] bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                />

                <button
                  type="button"
                  onClick={() => handleTrivyScan()}
                  disabled={trivyLoading || !trivyStatus?.available || !trivyImage.trim()}
                  className="px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:bg-slate-800 disabled:text-slate-600 text-white rounded-xl text-xs font-bold transition flex items-center gap-1.5 shadow"
                >
                  {trivyLoading ? (
                    <>
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Search className="h-3.5 w-3.5" />
                      Scan Image
                    </>
                  )}
                </button>
              </div>

              {/* Presets */}
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <span className="text-slate-500 font-semibold text-[11px]">Quick Presets:</span>
                {['python:3.11-slim', 'alpine:3.19', 'nginx:1.25', 'node:20-bookworm-slim'].map((img) => (
                  <button
                    key={img}
                    type="button"
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

            {/* Error Notification */}
            {trivyScanResult && !trivyScanResult.success && (
              <div className="bg-red-950/20 border border-red-900/60 p-4 rounded-xl text-xs text-red-300 space-y-1">
                <strong>Scan Notice:</strong>
                <p>{trivyScanResult.error}</p>
                {trivyScanResult.notice && <p className="text-slate-400">{trivyScanResult.notice}</p>}
              </div>
            )}

            {/* Results Display */}
            {(trivyScanResult?.success || showSampleTrivy) && (
              <div
                id="column-trivy-cve-table"
                className={`space-y-4 transition-all duration-300 ${
                  highlightedElementId === 'column-trivy-cve-table' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 p-2 rounded-2xl shadow-cyan-500/20' : ''
                }`}
              >
                {(() => {
                  const data = trivyScanResult?.success
                    ? trivyScanResult
                    : {
                        image: 'python:3.11-slim (Demonstration CVE Telemetry)',
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
                      {/* KPI & CVE Donut Row */}
                      <div
                        id="column-trivy-donut"
                        className="bg-[#0c1322] p-5 rounded-2xl border border-slate-800 flex flex-wrap items-center justify-between gap-4"
                      >
                        <div>
                          <span className="text-[11px] text-slate-400 uppercase font-bold">Image Scanned</span>
                          <div className="font-mono text-sm font-bold text-white mt-0.5">{data.image}</div>
                          <span className="text-xs text-slate-500 font-mono mt-1 block">
                            {data.total_vulnerabilities ?? 0} CVE advisories recorded
                          </span>
                        </div>

                        <div className="flex items-center gap-2">
                          <div className="px-3 py-1 bg-red-950/80 border border-red-800 rounded-lg text-center">
                            <span className="text-[10px] text-red-400 font-bold uppercase block">Critical</span>
                            <span className="text-sm font-black font-mono text-red-300">{data.counts?.CRITICAL ?? 0}</span>
                          </div>
                          <div className="px-3 py-1 bg-orange-950/80 border border-orange-800 rounded-lg text-center">
                            <span className="text-[10px] text-orange-400 font-bold uppercase block">High</span>
                            <span className="text-sm font-black font-mono text-orange-300">{data.counts?.HIGH ?? 0}</span>
                          </div>
                          <div className="px-3 py-1 bg-amber-950/80 border border-amber-800 rounded-lg text-center">
                            <span className="text-[10px] text-amber-400 font-bold uppercase block">Medium</span>
                            <span className="text-sm font-black font-mono text-amber-300">{data.counts?.MEDIUM ?? 0}</span>
                          </div>
                          <div className="px-3 py-1 bg-blue-950/80 border border-blue-800 rounded-lg text-center">
                            <span className="text-[10px] text-blue-400 font-bold uppercase block">Low</span>
                            <span className="text-sm font-black font-mono text-blue-300">{data.counts?.LOW ?? 0}</span>
                          </div>
                        </div>
                      </div>

                      {/* CVE Table */}
                      <div className="bg-[#0c1322] rounded-2xl border border-slate-800 overflow-hidden">
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
                                <th className="py-2.5 px-3">CVE ID</th>
                                <th className="py-2.5 px-3">Package</th>
                                <th className="py-2.5 px-3">Installed</th>
                                <th className="py-2.5 px-3">Fixed In</th>
                                <th className="py-2.5 px-3">Advisory Summary</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800 font-mono">
                              {data.vulnerabilities?.map((v, i) => (
                                <tr key={i} className="hover:bg-slate-850/40">
                                  <td className="py-2.5 px-3 whitespace-nowrap">
                                    <span className="px-2 py-0.5 rounded text-[10px] font-bold border bg-red-950 text-red-400 border-red-800">
                                      {v.severity}
                                    </span>
                                  </td>
                                  <td className="py-2.5 px-3 font-bold text-cyan-400 whitespace-nowrap">
                                    {v.primary_url ? (
                                      <a href={v.primary_url} target="_blank" rel="noopener noreferrer" className="hover:underline flex items-center gap-1">
                                        {v.vulnerability_id}
                                        <ExternalLink className="h-3 w-3" />
                                      </a>
                                    ) : (
                                      v.vulnerability_id
                                    )}
                                  </td>
                                  <td className="py-2.5 px-3 text-slate-200">{v.pkg_name}</td>
                                  <td className="py-2.5 px-3 text-slate-400">{v.installed_version}</td>
                                  <td className="py-2.5 px-3 text-emerald-400">{v.fixed_version || 'None'}</td>
                                  <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate font-sans text-xs">
                                    {v.title}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    </div>
                  );
                })()}
              </div>
            )}
          </section>
        )}

        {/* ─────────────────────────────────────────────────────────────
            8. TAB 4: BEFORE VS AFTER DEMO (POSTURE COMPARISON)
        ────────────────────────────────────────────────────────────── */}
        {activeTab === 'benchmark' && (
          <section className="space-y-6">
            
            {/* Posture Delta Summary Header */}
            <div
              id="column-demo-delta"
              className={`bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-4 transition-all duration-300 ${
                highlightedElementId === 'column-demo-delta' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <ShieldCheck className="h-5 w-5 text-cyan-400" />
                    Security Posture Remediation Delta
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Direct comparison of the default developer configuration against the hardened reference architecture.
                  </p>
                </div>
                
                {/* Dynamic Real Delta Pill */}
                {vulnerableCache && secureCache && (
                  <div className="flex items-center gap-3 px-3.5 py-1.5 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono">
                    <span className="text-red-400 font-bold">{vulnerableCache.score}/100</span>
                    <ArrowRight className="h-3.5 w-3.5 text-cyan-400" />
                    <span className="text-emerald-400 font-bold">{secureCache.score}/100</span>
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[11px] font-bold">
                      +{secureCache.score - vulnerableCache.score} pts Posture Gain
                    </span>
                  </div>
                )}
              </div>

              {/* Side-by-Side Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-3">
                
                {/* Vulnerable Baseline */}
                <div
                  id="column-demo-vulnerable"
                  className={`border border-red-500/40 bg-red-950/10 rounded-2xl p-6 flex flex-col justify-between space-y-5 transition-all duration-300 ${
                    highlightedElementId === 'column-demo-vulnerable' ? 'ring-2 ring-cyan-400 bg-red-950/30 shadow-cyan-500/20' : ''
                  }`}
                >
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-red-400 uppercase tracking-wider">Unchecked Baseline</span>
                      <span className="px-2.5 py-0.5 rounded text-[11px] font-bold bg-red-950 text-red-300 border border-red-800">
                        {vulnerableCache?.risk_level || 'CRITICAL RISK'}
                      </span>
                    </div>

                    <div className="flex items-baseline gap-2">
                      <span className="text-4xl font-black font-mono text-red-400">
                        {vulnerableCache?.score ?? 0}
                      </span>
                      <span className="text-slate-500 font-bold">/ 100</span>
                      <span className="text-xs text-slate-400 ml-2">
                        ({vulnerableCache?.total_findings ?? 34} weaknesses detected)
                      </span>
                    </div>

                    <div className="space-y-2 text-xs text-slate-300 pt-2 border-t border-red-900/30">
                      <div className="flex items-center gap-2 text-red-400">
                        <XCircle className="h-4 w-4 shrink-0 text-red-500" />
                        <span>Privileged container enabled (<code className="text-red-300">privileged: true</code>)</span>
                      </div>
                      <div className="flex items-center gap-2 text-red-400">
                        <XCircle className="h-4 w-4 shrink-0 text-red-500" />
                        <span>Runs as root (<code className="text-red-300">runAsUser: 0</code>)</span>
                      </div>
                      <div className="flex items-center gap-2 text-red-400">
                        <XCircle className="h-4 w-4 shrink-0 text-red-500" />
                        <span>Host filesystems (/) &amp; docker.sock mounted</span>
                      </div>
                      <div className="flex items-center gap-2 text-red-400">
                        <XCircle className="h-4 w-4 shrink-0 text-red-500" />
                        <span>Plaintext secrets in environment variables</span>
                      </div>
                      <div className="flex items-center gap-2 text-red-400">
                        <XCircle className="h-4 w-4 shrink-0 text-red-500" />
                        <span>Wildcard RBAC permissions (<code className="text-red-300">verbs: ["*"]</code>)</span>
                      </div>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => {
                      triggerDemoScan('vulnerable');
                      setActiveTab('findings');
                    }}
                    className="w-full py-2 bg-red-600 hover:bg-red-500 text-white rounded-xl text-xs font-bold transition shadow"
                  >
                    Load &amp; Inspect Vulnerable Baseline
                  </button>
                </div>

                {/* Hardened Architecture */}
                <div
                  id="column-demo-hardened"
                  className={`border border-emerald-500/40 bg-emerald-950/10 rounded-2xl p-6 flex flex-col justify-between space-y-5 transition-all duration-300 ${
                    highlightedElementId === 'column-demo-hardened' ? 'ring-2 ring-cyan-400 bg-emerald-950/30 shadow-cyan-500/20' : ''
                  }`}
                >
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">Hardened Reference</span>
                      <span className="px-2.5 py-0.5 rounded text-[11px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                        {secureCache?.risk_level || 'LOW RISK'}
                      </span>
                    </div>

                    <div className="flex items-baseline gap-2">
                      <span className="text-4xl font-black font-mono text-emerald-400">
                        {secureCache?.score ?? 96}
                      </span>
                      <span className="text-slate-500 font-bold">/ 100</span>
                      <span className="text-xs text-slate-400 ml-2">
                        ({secureCache?.total_findings ?? 2} minor policy notes)
                      </span>
                    </div>

                    <div className="space-y-2 text-xs text-slate-300 pt-2 border-t border-emerald-900/30">
                      <div className="flex items-center gap-2 text-emerald-400">
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                        <span>Enforces <code className="text-emerald-300">runAsNonRoot: true</code> with UID 10001</span>
                      </div>
                      <div className="flex items-center gap-2 text-emerald-400">
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                        <span><code className="text-emerald-300">readOnlyRootFilesystem: true</code> protects integrity</span>
                      </div>
                      <div className="flex items-center gap-2 text-emerald-400">
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                        <span>Drops all Linux capabilities (<code className="text-emerald-300">drop: [ALL]</code>)</span>
                      </div>
                      <div className="flex items-center gap-2 text-emerald-400">
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                        <span>Applies <code className="text-emerald-300">RuntimeDefault</code> seccomp profile</span>
                      </div>
                      <div className="flex items-center gap-2 text-emerald-400">
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                        <span>Granular least-privilege Role and RoleBinding</span>
                      </div>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => {
                      triggerDemoScan('secure');
                      setActiveTab('findings');
                    }}
                    className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold transition shadow"
                  >
                    Load &amp; Inspect Hardened App
                  </button>
                </div>

              </div>
            </div>
          </section>
        )}

        {/* ─────────────────────────────────────────────────────────────
            9. TAB 5: CLI & LOCAL COMMANDS
        ────────────────────────────────────────────────────────────── */}
        {activeTab === 'cli' && (
          <section className="space-y-6">
            <div className="bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Terminal className="h-5 w-5 text-cyan-400" />
                Local Terminal &amp; CI/CD Pipeline Commands
              </h3>
              <p className="text-xs text-slate-400">
                KubeGuard functions autonomously from the command line for pre-commit hooks and CI/CD pipelines:
              </p>

              <div className="space-y-3 pt-2">
                <div
                  id="column-cli-audit"
                  className={`space-y-1 p-2 rounded-xl transition-all duration-300 ${
                    highlightedElementId === 'column-cli-audit' ? 'ring-2 ring-cyan-400 bg-cyan-950/20' : ''
                  }`}
                >
                  <span className="text-xs font-bold text-slate-300">Audit Directory of Manifests:</span>
                  <div className="bg-[#080d18] border border-slate-800 rounded-lg p-3 font-mono text-xs text-cyan-300 flex items-center justify-between">
                    <span>python3 cli.py examples/vulnerable-app/</span>
                    <button type="button" onClick={() => copyToClipboard('python3 cli.py examples/vulnerable-app/', 'c1')} className="text-slate-500 hover:text-cyan-300">
                      {copiedKey === 'c1' ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                <div
                  id="column-cli-strict"
                  className={`space-y-1 p-2 rounded-xl transition-all duration-300 ${
                    highlightedElementId === 'column-cli-strict' ? 'ring-2 ring-cyan-400 bg-cyan-950/20' : ''
                  }`}
                >
                  <span className="text-xs font-bold text-slate-300">Strict CI/CD Enforcement (Exit code 1 if score &lt; 70):</span>
                  <div className="bg-[#080d18] border border-slate-800 rounded-lg p-3 font-mono text-xs text-cyan-300 flex items-center justify-between">
                    <span>python3 cli.py examples/vulnerable-app/ --strict</span>
                    <button type="button" onClick={() => copyToClipboard('python3 cli.py examples/vulnerable-app/ --strict', 'c2')} className="text-slate-500 hover:text-cyan-300">
                      {copiedKey === 'c2' ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                <div
                  id="column-cli-pytest"
                  className={`space-y-1 p-2 rounded-xl transition-all duration-300 ${
                    highlightedElementId === 'column-cli-pytest' ? 'ring-2 ring-cyan-400 bg-cyan-950/20' : ''
                  }`}
                >
                  <span className="text-xs font-bold text-slate-300">Run Automated Pytest Suite (25 Tests):</span>
                  <div className="bg-[#080d18] border border-slate-800 rounded-lg p-3 font-mono text-xs text-cyan-300 flex items-center justify-between">
                    <span>pytest -v</span>
                    <button type="button" onClick={() => copyToClipboard('pytest -v', 'c3')} className="text-slate-500 hover:text-cyan-300">
                      {copiedKey === 'c3' ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* ─────────────────────────────────────────────────────────────
            10. TAB 6: HTML REPORT PREVIEW
        ────────────────────────────────────────────────────────────── */}
        {activeTab === 'report' && (
          <section className="space-y-6">
            <div
              id="column-report-actions"
              className={`bg-[#0c1322] p-6 rounded-2xl border border-slate-800 flex flex-wrap items-center justify-between gap-4 transition-all duration-300 ${
                highlightedElementId === 'column-report-actions' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
              }`}
            >
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <FileText className="h-5 w-5 text-cyan-400" />
                  Standalone Executive HTML Audit Report
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Self-contained, styled HTML audit report generated server-side by KubeGuard's Python report generator.
                </p>
              </div>

              <button
                type="button"
                onClick={downloadReportHtml}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 rounded-xl text-xs font-bold flex items-center gap-2 shadow"
              >
                <Download className="h-4 w-4" />
                Download Report (.html)
              </button>
            </div>

            {/* Simulated Report Preview */}
            <div
              id="column-report-preview"
              className={`bg-[#080d18] border border-slate-800 rounded-2xl p-8 space-y-6 text-sm transition-all duration-300 ${
                highlightedElementId === 'column-report-preview' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
              }`}
            >
              <div className="border-b border-slate-800 pb-4 flex justify-between items-start">
                <div>
                  <h2 className="text-xl font-bold text-white">🛡️ KubeGuard Security Audit Report</h2>
                  <p className="text-xs text-slate-400">Target Workload: {activeDatasetLabel}</p>
                </div>
                <div className="text-right text-xs text-slate-400">
                  <div>Date: {new Date().toISOString().split('T')[0]}</div>
                  <div>Engine: <span className="text-cyan-400 font-bold">FastAPI + Python</span></div>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
                <div className="bg-slate-900/90 p-4 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400 uppercase font-bold">Posture Score</span>
                  <div className="text-3xl font-black mt-1 font-mono" style={{ color: riskColor }}>{score}</div>
                </div>
                <div className="bg-slate-900/90 p-4 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400 uppercase font-bold">Risk Level</span>
                  <div className="text-xs font-black mt-2 font-mono uppercase" style={{ color: riskColor }}>{riskLevel}</div>
                </div>
                <div className="bg-slate-900/90 p-4 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400 uppercase font-bold">Total Issues</span>
                  <div className="text-2xl font-black mt-1 font-mono text-slate-200">{findings.length}</div>
                </div>
                <div className="bg-slate-900/90 p-4 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400 uppercase font-bold">Resources</span>
                  <div className="text-2xl font-black mt-1 font-mono text-slate-200">{scanResult?.resources_scanned ?? 0}</div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* ─────────────────────────────────────────────────────────────
            11. TAB 7: 2-MINUTE PITCH & TEACHER Q&A
        ────────────────────────────────────────────────────────────── */}
        {activeTab === 'presentation' && (
          <section className="space-y-6">
            <div
              id="column-presentation-script"
              className={`bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-4 transition-all duration-300 ${
                highlightedElementId === 'column-presentation-script' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
              }`}
            >
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <HelpCircle className="h-5 w-5 text-cyan-400" />
                2-Minute College Presentation Walkthrough
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

            {/* Instructor Defense Q&A Cards */}
            <div
              id="column-presentation-qa"
              className={`bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-4 transition-all duration-300 ${
                highlightedElementId === 'column-presentation-qa' ? 'ring-2 ring-cyan-400 bg-cyan-950/20 shadow-cyan-500/20' : ''
              }`}
            >
              <h3 className="text-base font-bold text-white">
                🎓 Likely Questions Your Teacher Will Ask &amp; Technical Answers
              </h3>

              <div className="space-y-3 text-xs">
                <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                  <strong className="text-slate-100 text-sm block mb-1">Q1: "Does KubeGuard perform live penetration testing on a cluster?"</strong>
                  <p className="text-slate-300 leading-relaxed">
                    <strong>Answer:</strong> "No. KubeGuard is explicitly a <em>static configuration auditor</em>. It shifts security left by inspecting YAML manifests and Dockerfiles before deployment. This prevents vulnerabilities from ever reaching runtime. For runtime monitoring, production stacks complement this with eBPF tools like Falco."
                  </p>
                </div>

                <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                  <strong className="text-slate-100 text-sm block mb-1">Q2: "Why is running a container as root (UID 0) dangerous if it's already containerized?"</strong>
                  <p className="text-slate-300 leading-relaxed">
                    <strong>Answer:</strong> "Containers share the host Linux kernel. If an attacker discovers a kernel exploit or container breakout vulnerability (like CVE-2024-21626 in runc), running as UID 0 allows them to escape directly with root authority on the physical host. Enforcing <code>runAsNonRoot: true</code> ensures defense-in-depth."
                  </p>
                </div>

                <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                  <strong className="text-slate-100 text-sm block mb-1">Q3: "How is your architecture split between React and Python?"</strong>
                  <p className="text-slate-300 leading-relaxed">
                    <strong>Answer:</strong> "The React frontend is responsible purely for user interaction, filtering, and cyber-themed visualizations. It does not duplicate security rules in JavaScript. All 24 Kubernetes rules, 10 Dockerfile rules, YAML parsing, and scoring algorithms execute in the Python FastAPI backend, which also powers the CLI."
                  </p>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* ─────────────────────────────────────────────────────────────
            12. TAB 8: METHODOLOGY & STANDARDS
        ────────────────────────────────────────────────────────────── */}
        {activeTab === 'methodology' && (
          <section className="space-y-6">
            <div className="bg-[#0c1322] p-6 rounded-2xl border border-slate-800 space-y-6 text-xs text-slate-300 leading-relaxed">
              <h3 className="text-base font-bold text-white">Security Methodology &amp; Scope Specification</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div
                  id="column-methodology-frameworks"
                  className={`space-y-3 p-3 rounded-2xl transition-all duration-300 ${
                    highlightedElementId === 'column-methodology-frameworks' ? 'ring-2 ring-cyan-400 bg-cyan-950/20' : ''
                  }`}
                >
                  <h4 className="font-bold text-cyan-400 uppercase text-xs">Evaluated Security Frameworks</h4>
                  <p>
                    KubeGuard evaluates manifests against the <strong>Kubernetes Pod Security Standards (Restricted Profile)</strong>, the <strong>CIS Kubernetes Benchmark</strong>, and <strong>OWASP Container Security Guides</strong>:
                  </p>
                  <ul className="list-disc pl-4 space-y-1.5 text-slate-300">
                    <li><strong>Container Privilege Isolation:</strong> Privileged flags, root UID, capability drops.</li>
                    <li><strong>Host Namespace Leaks:</strong> hostPID, hostNetwork, hostIPC isolation.</li>
                    <li><strong>Storage Security:</strong> Host filesystem mounts (hostPath).</li>
                    <li><strong>RBAC Least Privilege:</strong> Wildcard permissions and cluster-admin role bindings.</li>
                    <li><strong>Secrets Hygiene:</strong> Detection of plaintext credentials in manifests and env vars.</li>
                    <li><strong>Dockerfile Standards:</strong> Missing USER, latest tags, unsafe remote execution.</li>
                  </ul>
                </div>

                <div
                  id="column-methodology-boundaries"
                  className={`space-y-3 p-3 rounded-2xl transition-all duration-300 ${
                    highlightedElementId === 'column-methodology-boundaries' ? 'ring-2 ring-cyan-400 bg-cyan-950/20' : ''
                  }`}
                >
                  <h4 className="font-bold text-orange-400 uppercase text-xs">Honest Architecture Boundaries</h4>
                  <p>
                    To maintain academic and professional integrity, KubeGuard clearly identifies what it does not do:
                  </p>
                  <ul className="list-disc pl-4 space-y-1.5 text-slate-300">
                    <li><strong>No Live Cluster Attacks:</strong> It does not exploit running Kubernetes clusters.</li>
                    <li><strong>No Image CVE Scanning:</strong> It checks configuration flags, not operating system package CVEs (Trivy should be used for CVEs).</li>
                    <li><strong>No Kernel Syscall Tracing:</strong> It operates statically, not via eBPF runtime probes (Falco).</li>
                  </ul>
                </div>
              </div>
            </div>
          </section>
        )}

      </main>

      {/* ─────────────────────────────────────────────────────────────
          13. FOOTER
      ────────────────────────────────────────────────────────────── */}
      <footer className="border-t border-slate-800/80 py-5 bg-[#0a0f1d] text-center text-xs text-slate-500 mt-12">
        <div className="max-w-7xl mx-auto px-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-extrabold text-slate-300">KubeGuard</span>
            <span>&bull;</span>
            <span>Container &amp; Kubernetes Security Posture Management</span>
          </div>
          <div className="flex items-center gap-3 text-[11px] text-slate-500 font-mono">
            <span>React 19 + FastAPI</span>
            <span>&bull;</span>
            <span>24 K8s Rules</span>
            <span>&bull;</span>
            <span>10 Docker Rules</span>
            <span>&bull;</span>
            <span>MIT License</span>
          </div>
        </div>
      </footer>

    </div>
  );
}
