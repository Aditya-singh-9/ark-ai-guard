/**
 * Central API client for ARK DevSecOps AI backend.
 * Reads VITE_API_URL from env. Attaches JWT Bearer token automatically.
 */

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000/api/v1";

// ── Token helpers ─────────────────────────────────────────────────────────────

const TOKEN_KEY = "ark_jwt";

export const getToken = (): string | null => localStorage.getItem(TOKEN_KEY);
export const setToken = (token: string): void => localStorage.setItem(TOKEN_KEY, token);
export const removeToken = (): void => localStorage.removeItem(TOKEN_KEY);

// ── GitHub OAuth URL ──────────────────────────────────────────────────────────

const GITHUB_CLIENT_ID = "Ov23li7v3bY1iFPfBHxp";
const GITHUB_REDIRECT_URI = "http://localhost:8080/auth/callback";

export const githubOAuthUrl = () =>
  `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(GITHUB_REDIRECT_URI)}&scope=repo,user:email`;

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
}

export interface ScanStatus {
  scan_id: number;
  repository_id: number;
  status: "pending" | "running" | "completed" | "failed";
  security_score: number | null;
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
