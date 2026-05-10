import { useState, useEffect } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Shield, Lock, Eye, EyeOff, Loader2, CheckCircle, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { API_BASE } from "@/lib/api";

export default function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const token = searchParams.get("token") || "";

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [strength, setStrength] = useState(0); // 0-4

  // Token validation
  const hasToken = token.length > 0;

  // Password strength calculator
  useEffect(() => {
    let score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9!@#$%^&*]/.test(password)) score++;
    setStrength(score);
  }, [password]);

  const strengthLabel = ["", "Weak", "Fair", "Good", "Strong"][strength];
  const strengthColor = ["", "text-red-400", "text-yellow-400", "text-blue-400", "text-green-400"][strength];
  const strengthBarColor = ["", "bg-red-500", "bg-yellow-500", "bg-blue-500", "bg-green-500"][strength];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (password.length < 8) {
      toast.error("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirmPassword) {
      toast.error("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, new_password: password }),
      });

      const data = await res.json().catch(() => ({}));

      if (res.ok) {
        setDone(true);
        setTimeout(() => navigate("/login"), 3000);
      } else {
        toast.error(data.detail || "Reset failed. The link may have expired.");
      }
    } catch {
      toast.error("Network error. Please check your connection.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0d1117] flex items-center justify-center p-4">
      {/* Background glow */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-blue-600/10 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-md">
        {/* Card */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-2xl overflow-hidden shadow-2xl">
          {/* Header strip */}
          <div className="h-1 bg-gradient-to-r from-blue-500 via-cyan-400 to-blue-600" />

          <div className="p-8">
            {/* Logo */}
            <div className="flex items-center gap-3 mb-8">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center shadow-lg shadow-blue-500/25">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <p className="text-xs text-gray-500 leading-none">ARK</p>
                <p className="text-sm font-semibold text-gray-200 leading-tight">DevScops Guard</p>
              </div>
            </div>

            {/* No token */}
            {!hasToken && (
              <div className="text-center py-4">
                <div className="w-14 h-14 rounded-full bg-yellow-500/10 border border-yellow-500/30 flex items-center justify-center mx-auto mb-4">
                  <AlertTriangle className="w-7 h-7 text-yellow-400" />
                </div>
                <h2 className="text-xl font-bold text-white mb-2">Invalid reset link</h2>
                <p className="text-gray-400 text-sm mb-6">
                  This link is missing a reset token. Please use the link from your email,
                  or request a new one.
                </p>
                <Link
                  to="/forgot-password"
                  className="inline-block py-2.5 px-6 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold transition-colors"
                >
                  Request new link
                </Link>
              </div>
            )}

            {/* Success */}
            {hasToken && done && (
              <div className="text-center py-4">
                <div className="w-16 h-16 rounded-full bg-green-500/10 border border-green-500/30 flex items-center justify-center mx-auto mb-5">
                  <CheckCircle className="w-8 h-8 text-green-400" />
                </div>
                <h2 className="text-xl font-bold text-white mb-3">Password updated!</h2>
                <p className="text-gray-400 text-sm mb-6">
                  Your password has been changed successfully.
                  Redirecting you to login in a moment…
                </p>
                <Link
                  to="/login"
                  className="inline-block py-2.5 px-6 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold transition-colors"
                >
                  Go to Login
                </Link>
              </div>
            )}

            {/* Form */}
            {hasToken && !done && (
              <>
                <h2 className="text-2xl font-bold text-white mb-2">Set new password</h2>
                <p className="text-gray-400 text-sm mb-8">
                  Choose a strong password for your account.
                </p>

                <form onSubmit={handleSubmit} className="space-y-5">
                  {/* New password */}
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1.5">
                      New Password
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                      <input
                        type={showPassword ? "text" : "password"}
                        id="reset-new-password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="At least 8 characters"
                        autoComplete="new-password"
                        className="w-full bg-[#0d1117] border border-[#30363d] text-white
                                   rounded-xl pl-10 pr-10 py-3 text-sm
                                   focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50
                                   placeholder:text-gray-600 transition-colors"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                        tabIndex={-1}
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                    {/* Strength bar */}
                    {password && (
                      <div className="mt-2">
                        <div className="flex gap-1">
                          {[1, 2, 3, 4].map((i) => (
                            <div
                              key={i}
                              className={`h-1 flex-1 rounded-full transition-all duration-300 ${
                                i <= strength ? strengthBarColor : "bg-[#30363d]"
                              }`}
                            />
                          ))}
                        </div>
                        <p className={`text-xs mt-1 ${strengthColor}`}>{strengthLabel}</p>
                      </div>
                    )}
                  </div>

                  {/* Confirm password */}
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1.5">
                      Confirm Password
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                      <input
                        type={showConfirm ? "text" : "password"}
                        id="reset-confirm-password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Repeat your password"
                        autoComplete="new-password"
                        className={`w-full bg-[#0d1117] border text-white
                                   rounded-xl pl-10 pr-10 py-3 text-sm
                                   focus:outline-none focus:ring-2 focus:ring-blue-500/50
                                   placeholder:text-gray-600 transition-colors
                                   ${confirmPassword && confirmPassword !== password
                                     ? "border-red-500/50 focus:border-red-500/50"
                                     : confirmPassword && confirmPassword === password
                                     ? "border-green-500/50 focus:border-green-500/50"
                                     : "border-[#30363d] focus:border-blue-500/50"}`}
                      />
                      <button
                        type="button"
                        onClick={() => setShowConfirm(!showConfirm)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                        tabIndex={-1}
                      >
                        {showConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                    {confirmPassword && confirmPassword !== password && (
                      <p className="text-xs text-red-400 mt-1">Passwords don't match</p>
                    )}
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full py-3 rounded-xl font-semibold text-white text-sm
                               bg-gradient-to-r from-blue-600 to-blue-500
                               hover:from-blue-500 hover:to-blue-400
                               disabled:opacity-60 disabled:cursor-not-allowed
                               flex items-center justify-center gap-2 transition-all
                               shadow-lg shadow-blue-500/20 hover:shadow-blue-500/30"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Updating password…
                      </>
                    ) : (
                      "Update Password"
                    )}
                  </button>
                </form>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
