import { useState } from "react";
import { Link } from "react-router-dom";
import { Shield, Mail, ArrowLeft, Loader2, CheckCircle } from "lucide-react";
import { toast } from "sonner";
import { API_BASE } from "@/lib/api";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) {
      toast.error("Please enter your email address.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
      });

      if (res.ok) {
        setSent(true);
      } else {
        const data = await res.json().catch(() => ({}));
        toast.error(data.detail || "Something went wrong. Please try again.");
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

            {sent ? (
              /* Success state */
              <div className="text-center py-4">
                <div className="w-16 h-16 rounded-full bg-green-500/10 border border-green-500/30 flex items-center justify-center mx-auto mb-5">
                  <CheckCircle className="w-8 h-8 text-green-400" />
                </div>
                <h2 className="text-xl font-bold text-white mb-3">Check your inbox</h2>
                <p className="text-gray-400 text-sm leading-relaxed mb-6">
                  If <span className="text-blue-400 font-medium">{email}</span> is registered,
                  you'll receive a password reset link shortly.
                  <br /><br />
                  The link expires in <strong className="text-gray-300">30 minutes</strong>.
                </p>
                <p className="text-xs text-gray-500 mb-6">
                  Didn't get the email? Check your spam folder, or{" "}
                  <button
                    onClick={() => setSent(false)}
                    className="text-blue-400 hover:text-blue-300 underline"
                  >
                    try again
                  </button>.
                </p>
                <Link
                  to="/login"
                  className="inline-flex items-center gap-2 text-sm text-blue-400 hover:text-blue-300 transition-colors"
                >
                  <ArrowLeft className="w-4 h-4" />
                  Back to login
                </Link>
              </div>
            ) : (
              /* Form state */
              <>
                <h2 className="text-2xl font-bold text-white mb-2">Forgot password?</h2>
                <p className="text-gray-400 text-sm mb-8 leading-relaxed">
                  Enter the email address linked to your account and we'll send you a reset link.
                </p>

                <form onSubmit={handleSubmit} className="space-y-5">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1.5">
                      Email address
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                      <input
                        type="email"
                        id="forgot-email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="you@example.com"
                        autoComplete="email"
                        className="w-full bg-[#0d1117] border border-[#30363d] text-white
                                   rounded-xl pl-10 pr-4 py-3 text-sm
                                   focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50
                                   placeholder:text-gray-600 transition-colors"
                      />
                    </div>
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
                        Sending reset link…
                      </>
                    ) : (
                      "Send Reset Link"
                    )}
                  </button>
                </form>

                <p className="text-center text-sm text-gray-500 mt-6">
                  Remember your password?{" "}
                  <Link to="/login" className="text-blue-400 hover:text-blue-300 font-medium transition-colors">
                    Sign in
                  </Link>
                </p>
              </>
            )}
          </div>
        </div>

        {/* Back link */}
        {!sent && (
          <div className="text-center mt-4">
            <Link
              to="/login"
              className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300 transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              Back to login
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
