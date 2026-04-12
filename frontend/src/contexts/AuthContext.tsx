/**
 * AuthContext — provides current user state across the app.
 * On mount, restores session from localStorage JWT via GET /auth/me.
 */
import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { getMe, removeToken, setToken, getToken, User, logoutApi } from "@/lib/api";

interface AuthState {
  user: User | null;
  isLoading: boolean;
  isLoggedIn: boolean;
  login: (token: string, user: User) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthState>({
  user: null,
  isLoading: true,
  isLoggedIn: false,
  login: () => {},
  logout: () => {},
});

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Restore session on mount
  useEffect(() => {
    const token = getToken();
    if (!token) {
      setIsLoading(false);
      return;
    }
    getMe()
      .then(setUser)
      .catch(() => removeToken()) // token expired/invalid — clear it
      .finally(() => setIsLoading(false));
  }, []);

  const login = (token: string, userData: User) => {
    setToken(token);
    setUser(userData);
  };

  const logout = () => {
    // Fire-and-forget server-side revocation (non-blocking)
    logoutApi().catch(() => {/* best-effort */});
    removeToken();
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{ user, isLoading, isLoggedIn: !!user, login, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
};
