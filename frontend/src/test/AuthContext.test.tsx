/**
 * Frontend Tests — AuthContext
 *
 * Tests the global authentication state management:
 *   1. Initial state (unauthenticated)
 *   2. Login sets user + token in localStorage
 *   3. Logout clears user + token
 *   4. Session restore from localStorage on mount
 *   5. Auto-clear on expired / invalid token
 *   6. isLoggedIn derived state
 *   7. isLoading transitions
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import { setToken, removeToken, getToken } from "@/lib/api";
import type { ReactNode } from "react";

// ── Mock the API module ───────────────────────────────────────────────────────

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    getMe: vi.fn(),
  };
});

const mockUser = {
  id: 1,
  github_id: 12345,
  username: "alice",
  email: "alice@example.com",
  display_name: "Alice",
  avatar_url: "https://github.com/alice.png",
  created_at: "2024-01-01T00:00:00Z",
};

function wrapper({ children }: { children: ReactNode }) {
  return <AuthProvider>{children}</AuthProvider>;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("AuthContext — Initial State", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
  });

  it("starts unauthenticated with user=null", async () => {
    const { getMe } = await import("@/lib/api");
    (getMe as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("No token"));

    const { result } = renderHook(() => useAuth(), { wrapper });

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.user).toBeNull();
    expect(result.current.isLoggedIn).toBe(false);
  });

  it("isLoading resolves to false after mount completes", async () => {
    const { getMe } = await import("@/lib/api");
    (getMe as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("No token"));

    const { result } = renderHook(() => useAuth(), { wrapper });

    // isLoading starts true, then resolves to false once the session check completes
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    // After loading, user is null (no valid token)
    expect(result.current.user).toBeNull();
  });
});

describe("AuthContext — Login", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
  });

  it("login() sets user and stores token", async () => {
    const { getMe } = await import("@/lib/api");
    (getMe as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("No token"));

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    act(() => {
      result.current.login("test-jwt-token", mockUser);
    });

    expect(result.current.user).toEqual(mockUser);
    expect(result.current.isLoggedIn).toBe(true);
    expect(getToken()).toBe("test-jwt-token");
  });

  it("login() makes isLoggedIn true", async () => {
    const { getMe } = await import("@/lib/api");
    (getMe as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("No token"));

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expect(result.current.isLoggedIn).toBe(false);
    act(() => result.current.login("token", mockUser));
    expect(result.current.isLoggedIn).toBe(true);
  });
});

describe("AuthContext — Logout", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
  });

  it("logout() clears user and removes token from localStorage", async () => {
    const { getMe } = await import("@/lib/api");
    (getMe as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("No token"));

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    // First log in
    act(() => result.current.login("test-token", mockUser));
    expect(result.current.isLoggedIn).toBe(true);

    // Then log out
    act(() => result.current.logout());
    expect(result.current.user).toBeNull();
    expect(result.current.isLoggedIn).toBe(false);
    expect(getToken()).toBeNull();
  });

  it("logout() is safe to call when already unauthenticated", async () => {
    const { getMe } = await import("@/lib/api");
    (getMe as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("No token"));

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    // Should not throw
    expect(() => act(() => result.current.logout())).not.toThrow();
  });
});

describe("AuthContext — Session Restore", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
  });

  it("restores user session if valid token exists in localStorage", async () => {
    setToken("stored-valid-token");

    const { getMe } = await import("@/lib/api");
    (getMe as ReturnType<typeof vi.fn>).mockResolvedValue(mockUser);

    const { result } = renderHook(() => useAuth(), { wrapper });

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.user).toEqual(mockUser);
    expect(result.current.isLoggedIn).toBe(true);
  });

  it("clears token if getMe fails during session restore", async () => {
    setToken("expired-token");

    const { getMe } = await import("@/lib/api");
    (getMe as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("401 Unauthorized"));

    const { result } = renderHook(() => useAuth(), { wrapper });

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.user).toBeNull();
    expect(getToken()).toBeNull(); // Token should have been purged
  });

  it("skips getMe call when no token in localStorage", async () => {
    // No token set
    const { getMe } = await import("@/lib/api");

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expect(getMe).not.toHaveBeenCalled();
    expect(result.current.user).toBeNull();
  });
});
