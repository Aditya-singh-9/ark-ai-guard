/**
 * Central API client for DevScops Guard backend.
 * Reads VITE_API_URL from env. Attaches JWT Bearer token automatically.
 */

const configUrl = import.meta.env.VITE_API_URL;
const API_BASE = configUrl 
  ? (configUrl.endsWith("/api/v1") ? configUrl : `${configUrl.replace(/\/$/, "")}/api/v1`)
  : "http://localhost:8000/api/v1";

// ── Token helpers ─────────────────────────────────────────────────────────────

const TOKEN_KEY = "ark_jwt";

export const getToken = (): string | null => localStorage.getItem(TOKEN_KEY);
export const setToken = (token: string): void => localStorage.setItem(TOKEN_KEY, token);
export const removeToken = (): void => localStorage.removeItem(TOKEN_KEY);

// ── GitHub OAuth URL ──────────────────────────────────────────────────────────

const GITHUB_CLIENT_ID = import.meta.env.VITE_GITHUB_CLIENT_ID ?? "Ov23li7v3bY1iFPfBHxp";

// Dynamically use the current domain — works on localhost, Vercel, and custom domains
const getRedirectUri = () => `${window.location.origin}/auth/callback`;

export const githubOAuthUrl = () =>
  `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(getRedirectUri())}&scope=repo,user:email`;

// ── Fetch wrapper ─────────────────────────────────────────────────────────────

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  if (res.status === 204) return undefined as unknown as T;

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    // Auto-logout on 401 Unauthorized (e.g., token expired or database wiped)
    if (res.status === 401) {
      removeToken();
      window.location.href = "/";
      return Promise.reject("Session expired. Please log in again.");
    }
    const msg =
      data?.detail ??
      data?.message ??
      `HTTP ${res.status}: ${res.statusText}`;
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }

  return data as T;
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface User {
  id: number;
  github_id: number;
  username: string;
  email: string | null;
  display_name: string | null;
  avatar_url: string | null;
  created_at: string;
}

export interface Repository {
  id: number;
  name: string;
  owner: string;
  full_name: string;
  url: string;
  language: string | null;
  description: string | null;
  is_private: boolean;
  total_scans: number;
  last_scanned_at: string | null;
  security_score: number | null;
  scan_status: string | null;
  latest_scan_id?: number | null;
}

export interface ScanStatus {
  scan_id: number;
  repository_id: number;
  status: "pending" | "cloning" | "scanning" | "analysing" | "finalising" | "running" | "completed" | "failed";
  security_score: number | null;
  nexus_score: number | null;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  detected_language: string | null;
  scan_time: string;
  completed_at: string | null;
  duration_seconds: number | null;
  error_message: string | null;
  scan_phase_detail: string | null;
  layers_completed: number[] | null;
}

export interface VulnerabilityItem {
  id: number;
  file: string | null;
  line: number | null;
  issue: string;
  description: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  scanner: string;
  rule_id: string | null;
  cve_id: string | null;
  cwe_id: string | null;
  code_snippet: string | null;
  suggested_fix: string | null;
  package_name: string | null;
  package_version: string | null;
  fixed_version: string | null;
  layer_id?: number | null;
  confidence?: number | null;
  exploitability?: number | null;
  blast_radius?: number | null;
  false_positive_probability?: number | null;
  ai_summary?: string | null;
}

export interface VulnerabilityReport {
  scan_id: number;
  repository_name: string;
  repository_url: string;
  scan_time: string;
  completed_at: string | null;
  status: string;
  security_score: number | null;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  detected_language: string | null;
  detected_frameworks: string[];
  ai_recommendations: Record<string, unknown> | null;
  architecture_summary: string | null;
  vulnerabilities: VulnerabilityItem[];
  cicd_yaml: string | null;
}

export interface DashboardStats {
  total_repositories: number;
  total_scans: number;
  average_security_score: number | null;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  repositories: Array<{
    id: number;
    name: string;
    url: string;
    language: string | null;
    last_scanned_at: string | null;
    security_score: number | null;
    total_vulnerabilities: number;
    scan_status: string;
  }>;
}

export interface CICDResponse {
  repository: string;
  language: string;
  frameworks: string[];
  yaml: string;
}

// ── API Functions ─────────────────────────────────────────────────────────────

/** Exchange GitHub OAuth code for JWT. */
export async function authGithub(code: string): Promise<{ access_token: string; user: User }> {
  return request("/auth/github", {
    method: "POST",
    body: JSON.stringify({ code }),
  });
}

/** Get current authenticated user. */
export async function getMe(): Promise<User> {
  return request("/auth/me");
}

/** Get all repositories connected by current user. */
export async function getRepositories(): Promise<Repository[]> {
  return request("/repositories");
}

/** Connect a new GitHub repository by URL. */
export async function connectRepository(url: string): Promise<Repository> {
  return request("/connect-repository", {
    method: "POST",
    body: JSON.stringify({ repository_url: url }),
  });
}

/** Remove a repository. */
export async function deleteRepository(id: number): Promise<void> {
  return request(`/repositories/${id}`, { method: "DELETE" });
}

/** Initiate a scan for a repository. Returns scan_id to poll. */
export async function scanRepository(repoId: number): Promise<{ scan_id: number; status: string; message: string }> {
  return request("/scan-repository", {
    method: "POST",
    body: JSON.stringify({ repository_id: repoId }),
  });
}

/** Poll scan status. */
export async function getScanStatus(scanId: number): Promise<ScanStatus> {
  return request(`/scans/${scanId}/status`);
}

/** Get granular live status for Deep Scan. */
export interface LiveScanStatus {
  scan_id: number;
  status: string;
  scan_phase_detail: string;
  layers_completed: number[];
  nexus_score: number | null;
  total_vulnerabilities: number;
  is_complete: boolean;
}

export async function getLiveScanStatus(scanId: number): Promise<LiveScanStatus> {
  return request(`/scans/${scanId}/live-status`);
}

/** Get the latest scan result for a repository. */
export async function getLatestScanResult(repoId: number): Promise<ScanStatus> {
  return request(`/scan-results/${repoId}`);
}

/** Get all scans for a repository. */
export async function getRepoScans(repoId: number, limit = 10): Promise<ScanStatus[]> {
  return request(`/repositories/${repoId}/scans?limit=${limit}`);
}

/** Get full vulnerability report for a scan. */
export async function getVulnerabilityReport(scanId: number, severity?: string): Promise<VulnerabilityReport> {
  const qs = severity ? `?severity=${severity}` : "";
  return request(`/vulnerability-report/${scanId}${qs}`);
}

/** Get aggregated dashboard statistics. */
export async function getDashboardStats(): Promise<DashboardStats> {
  return request("/dashboard/stats");
}

/** Generate an AI CI/CD pipeline for a repository. */
export async function generateCicd(repoId: number): Promise<CICDResponse> {
  return request("/generate-cicd", {
    method: "POST",
    body: JSON.stringify({ repository_id: repoId }),
  });
}

/** List all GitHub repos accessible to the current user (for auto-import). */
export interface GithubRepoItem {
  id: number;
  full_name: string;
  description: string | null;
  language: string | null;
  is_private: boolean;
  html_url: string;
  updated_at: string | null;
}

export async function listGithubRepos(): Promise<GithubRepoItem[]> {
  return request("/github/repos");
}

// ── New endpoints ─────────────────────────────────────────────────────────────

export interface TrendPoint {
  scan_id: number;
  date: string;
  security_score: number | null;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  duration_seconds: number | null;
}

export interface ScanTrends {
  repository_id: number;
  repository_name: string;
  total_scans: number;
  trend: TrendPoint[];
}

/** Get scan score history / trend for a repo. */
export async function getRepoTrends(repoId: number): Promise<ScanTrends> {
  return request(`/repositories/${repoId}/trends`);
}

/** Return the base API URL for direct download links (SBOM, report). */
export function getApiBase(): string {
  return API_BASE;
}

/** Download the SBOM for a repo (returns a direct download URL). */
export function getSbomUrl(repoId: number, format = "cyclonedx"): string {
  return `${getApiBase()}/repositories/${repoId}/sbom?format=${format}`;
}

/** Download an HTML vulnerability report for a scan. */
export function getReportDownloadUrl(scanId: number): string {
  return `${getApiBase()}/vulnerability-report/${scanId}/download`;
}

/** Helper to download files securely using JWT Bearer token */
export async function downloadSecureFile(url: string, filename: string): Promise<void> {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error("File download failed. Status " + res.status);

  const blob = await res.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = downloadUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(downloadUrl);
}

/** Get the badge SVG URL for a repo. */
export function getBadgeUrl(repoId: number): string {
  return `${getApiBase()}/repositories/${repoId}/badge`;
}

/** Test a Slack webhook URL. */
export async function testSlackWebhook(webhookUrl: string): Promise<{ status: string; message: string }> {
  return request("/notifications/test-slack", {
    method: "POST",
    body: JSON.stringify({ webhook_url: webhookUrl }),
  });
}

/** Create Auto-Fix Pull Request on GitHub */
export async function createAutofixPr(scanId: number): Promise<{ status: string; message: string; pr_url?: string }> {
  return request(`/scans/${scanId}/create-pr`, {
    method: "POST",
  });
}

// ── Mythos AI & Policy Data Endpoints ────────────────────────────────────────

/** Get compliance framework analysis */
export async function getScanCompliance(scanId: number): Promise<any> {
  return request(`/scans/${scanId}/compliance`);
}

/** Get OWASP Top 10 coverage analysis */
export async function getScanOwasp(scanId: number): Promise<any> {
  return request(`/scans/${scanId}/owasp`);
}

/** Get policy-as-code gate status and violations */
export async function getScanPolicy(scanId: number): Promise<any> {
  return request(`/scans/${scanId}/policy`);
}

/** Get AI auto-fix suggestions for vulnerabilities */
export async function getScanAutofixes(scanId: number): Promise<any> {
  return request(`/scans/${scanId}/autofixes`);
}

/** Get AI threat analysis including STRIDE and risk level */
export async function getScanThreatAnalysis(scanId: number): Promise<any> {
  return request(`/scans/${scanId}/threat-analysis`);
}

/** Call backend logout endpoint to revoke the JWT token server-side. */
export async function logoutApi(): Promise<{ message: string }> {
  return request("/auth/logout", { method: "POST" });
}

/** Backend health check — used to verify connectivity */
export async function healthCheck(): Promise<{ status: string; version?: string }> {
  const res = await fetch(`${API_BASE.replace("/api/v1", "")}/health`);
  if (!res.ok) throw new Error("Backend unreachable");
  return res.json();
}
