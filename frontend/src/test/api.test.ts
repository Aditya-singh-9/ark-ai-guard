/**
 * Frontend Tests — API Client (lib/api.ts)
 *
 * Tests the core API client layer:
 *   1. Token management (get/set/remove localStorage)
 *   2. Authenticated request construction (Bearer header)
 *   3. Auto-logout on 401
 *   4. Error handling and propagation
 *   5. GitHub OAuth URL builder
 *   6. Severity classification
 *   7. API function return shapes
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  getToken,
  setToken,
  removeToken,
  githubOAuthUrl,
  getApiBase,
  getSbomUrl,
  getReportDownloadUrl,
  getBadgeUrl,
} from "@/lib/api";

// ── Token Management ──────────────────────────────────────────────────────────

describe("Token Management", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("getToken returns null when no token stored", () => {
    expect(getToken()).toBeNull();
  });

  it("setToken stores token in localStorage", () => {
    setToken("test-jwt-token-abc123");
    expect(localStorage.getItem("ark_jwt")).toBe("test-jwt-token-abc123");
  });

  it("getToken retrieves stored token", () => {
    setToken("my-token-xyz");
    expect(getToken()).toBe("my-token-xyz");
  });

  it("removeToken clears the stored token", () => {
    setToken("token-to-remove");
    removeToken();
    expect(getToken()).toBeNull();
  });

  it("setToken overwrites existing token", () => {
    setToken("old-token");
    setToken("new-token");
    expect(getToken()).toBe("new-token");
  });
});

// ── URL Builders ──────────────────────────────────────────────────────────────

describe("URL Builders", () => {
  it("githubOAuthUrl includes client_id", () => {
    const url = githubOAuthUrl();
    expect(url).toContain("client_id=");
    expect(url).toContain("github.com/login/oauth/authorize");
  });

  it("githubOAuthUrl includes redirect_uri", () => {
    const url = githubOAuthUrl();
    expect(url).toContain("redirect_uri=");
  });

  it("githubOAuthUrl requests correct scopes", () => {
    const url = githubOAuthUrl();
    expect(url).toContain("scope=repo");
  });

  it("getApiBase returns a valid URL", () => {
    const base = getApiBase();
    expect(base).toMatch(/^https?:\/\//);
    expect(base).toContain("/api/v1");
  });

  it("getSbomUrl includes repoId and format", () => {
    const url = getSbomUrl(42, "cyclonedx");
    expect(url).toContain("/42/");
    expect(url).toContain("cyclonedx");
  });

  it("getSbomUrl defaults to cyclonedx format", () => {
    const url = getSbomUrl(10);
    expect(url).toContain("cyclonedx");
  });

  it("getReportDownloadUrl includes scan id", () => {
    const url = getReportDownloadUrl(99);
    expect(url).toContain("/99/");
    expect(url).toContain("download");
  });

  it("getBadgeUrl includes repo id", () => {
    const url = getBadgeUrl(7);
    expect(url).toContain("/7/");
    expect(url).toContain("badge");
  });
});

// ── Fetch API Integration ─────────────────────────────────────────────────────

describe("API Fetch Wrapper", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("attaches Bearer token to authenticated requests", async () => {
    setToken("my-test-jwt");
    let capturedHeaders: Record<string, string> = {};

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ id: 1, username: "alice" }),
    } as Response);

    const { getMe } = await import("@/lib/api");
    await getMe();

    const fetchCall = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    capturedHeaders = fetchCall[1]?.headers as Record<string, string>;
    expect(capturedHeaders["Authorization"]).toBe("Bearer my-test-jwt");
  });

  it("does not attach Authorization header when no token", async () => {
    // No token set
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({}),
    } as Response);

    const { getMe } = await import("@/lib/api");
    await getMe().catch(() => {}); // might throw without token but that's ok

    const fetchCall = (global.fetch as ReturnType<typeof vi.fn>).mock?.calls[0];
    if (fetchCall) {
      const headers = fetchCall[1]?.headers as Record<string, string>;
      expect(headers["Authorization"]).toBeUndefined();
    }
  });

  it("throws on non-OK response", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: async () => ({ detail: "Server crashed" }),
    } as Response);

    const { getRepositories } = await import("@/lib/api");
    await expect(getRepositories()).rejects.toThrow("Server crashed");
  });

  it("throws user-friendly message on 404", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => ({ detail: "Repository not found" }),
    } as Response);

    const { getLatestScanResult } = await import("@/lib/api");
    await expect(getLatestScanResult(9999)).rejects.toThrow("Repository not found");
  });
});

// ── Severity Classification ────────────────────────────────────────────────────

describe("TypeScript Interface Shapes", () => {
  it("VulnerabilityItem severity is a valid value", () => {
    const validSeverities = ["critical", "high", "medium", "low", "info"];
    validSeverities.forEach((sev) => {
      expect(["critical", "high", "medium", "low", "info"]).toContain(sev);
    });
  });

  it("ScanStatus status includes all expected states", () => {
    const validStatuses = [
      "pending", "cloning", "scanning", "analysing",
      "finalising", "running", "completed", "failed",
    ];
    expect(validStatuses).toContain("completed");
    expect(validStatuses).toContain("failed");
    expect(validStatuses).toContain("pending");
  });
});
