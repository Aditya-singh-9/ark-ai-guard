import { useState, useRef, useEffect, useCallback } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Shield, Mail, RotateCcw, ArrowRight, Loader2, CheckCircle2 } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { verifyEmail, resendOtp } from "@/lib/api";
import { toast } from "sonner";

const OTP_LENGTH = 6;
const RESEND_COOLDOWN = 60; // seconds
const OTP_EXPIRY = 10 * 60; // 10 minutes in seconds

export default function VerifyEmailPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { login } = useAuth();

  const email = searchParams.get("email") ?? "";

  const [digits, setDigits] = useState<string[]>(Array(OTP_LENGTH).fill(""));
  const [loading, setLoading] = useState(false);
  const [shake, setShake] = useState(false);
  const [verified, setVerified] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(RESEND_COOLDOWN);
  const [expiryLeft, setExpiryLeft] = useState(OTP_EXPIRY);
  const [resending, setResending] = useState(false);

  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // Countdown for resend cooldown
  useEffect(() => {
    if (resendCooldown <= 0) return;
    const t = setTimeout(() => setResendCooldown(c => c - 1), 1000);
    return () => clearTimeout(t);
  }, [resendCooldown]);

  // Countdown for OTP expiry
  useEffect(() => {
    if (expiryLeft <= 0) return;
    const t = setTimeout(() => setExpiryLeft(s => s - 1), 1000);
    return () => clearTimeout(t);
  }, [expiryLeft]);

  const formatTime = (s: number) =>
    `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  const triggerShake = () => {
    setShake(true);
    setTimeout(() => setShake(false), 600);
  };

  const focusNext = (index: number) => {
    const next = inputRefs.current[index + 1];
    if (next) next.focus();
  };

  const focusPrev = (index: number) => {
    const prev = inputRefs.current[index - 1];
    if (prev) prev.focus();
  };

  const handleChange = (index: number, value: string) => {
    const char = value.replace(/\D/g, "").slice(-1);
    const newDigits = [...digits];
    newDigits[index] = char;
    setDigits(newDigits);
    if (char) focusNext(index);

    // Auto-submit when all 6 filled
    if (char && newDigits.every(d => d !== "")) {
      handleSubmit(newDigits.join(""));
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace") {
      if (digits[index]) {
        const newDigits = [...digits];
        newDigits[index] = "";
        setDigits(newDigits);
      } else {
        focusPrev(index);
      }
    } else if (e.key === "ArrowLeft") {
      focusPrev(index);
    } else if (e.key === "ArrowRight") {
      focusNext(index);
    }
  };

  const handlePaste = (e: React.ClipboardEvent) => {
    e.preventDefault();
    const text = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, OTP_LENGTH);
    if (!text) return;
    const newDigits = Array(OTP_LENGTH).fill("");
    text.split("").forEach((c, i) => { if (i < OTP_LENGTH) newDigits[i] = c; });
    setDigits(newDigits);
    const lastFilled = Math.min(text.length, OTP_LENGTH - 1);
    inputRefs.current[lastFilled]?.focus();
    if (text.length === OTP_LENGTH) {
      handleSubmit(newDigits.join(""));
    }
  };

  const handleSubmit = useCallback(async (otp?: string) => {
    const code = (otp ?? digits.join("")).trim();
    if (code.length < OTP_LENGTH) {
      toast.error("Please enter all 6 digits.");
      triggerShake();
      return;
    }
    if (!email) {
      toast.error("Email address not found. Please register again.");
      return;
    }
    setLoading(true);
    try {
      const data = await verifyEmail(email, code);
      setVerified(true);
      login(data.access_token, data.user);
      toast.success("Email verified! Welcome to ARK DevScops Guard 🎉");
      setTimeout(() => navigate("/dashboard"), 1200);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Verification failed.";
      toast.error(msg);
      triggerShake();
      setDigits(Array(OTP_LENGTH).fill(""));
      inputRefs.current[0]?.focus();
    } finally {
      setLoading(false);
    }
  }, [digits, email, login, navigate]);

  const handleResend = async () => {
    if (resendCooldown > 0 || !email) return;
    setResending(true);
    try {
      await resendOtp(email);
      setResendCooldown(RESEND_COOLDOWN);
      setExpiryLeft(OTP_EXPIRY);
      setDigits(Array(OTP_LENGTH).fill(""));
      inputRefs.current[0]?.focus();
      toast.success("A new code has been sent to your email.");
    } catch {
      toast.error("Failed to resend code. Please try again.");
    } finally {
      setResending(false);
    }
  };

  const expiryPct = (expiryLeft / OTP_EXPIRY) * 100;
  const expiryColor =
    expiryLeft > 300 ? "#22c55e" : expiryLeft > 120 ? "#eab308" : "#ef4444";

  return (
    <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center p-4">
      {/* Background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[500px] h-[500px] bg-purple-600/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-[300px] h-[300px] bg-cyan-600/8 rounded-full blur-3xl" />
      </div>

      <style>{`
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          20%, 60% { transform: translateX(-8px); }
          40%, 80% { transform: translateX(8px); }
        }
        .shake { animation: shake 0.5s ease-in-out; }

        @keyframes pop-in {
          0% { transform: scale(0.8); opacity: 0; }
          100% { transform: scale(1); opacity: 1; }
        }
        .pop-in { animation: pop-in 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) forwards; }

        @keyframes draw-check {
          to { stroke-dashoffset: 0; }
        }
      `}</style>

      <div className="relative w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-purple-500/30">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold text-white">DevScops Guard</span>
          </Link>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-2xl p-8 backdrop-blur-sm shadow-2xl">
          {verified ? (
            /* ── Success state ── */
            <div className="text-center py-4 pop-in">
              <div className="w-20 h-20 rounded-full bg-green-500/15 border-2 border-green-500/40 flex items-center justify-center mx-auto mb-6">
                <CheckCircle2 className="w-10 h-10 text-green-400" />
              </div>
              <h1 className="text-2xl font-bold text-white mb-2">Email Verified!</h1>
              <p className="text-gray-400 text-sm">Redirecting you to the dashboard…</p>
            </div>
          ) : (
            <>
              {/* Header */}
              <div className="text-center mb-8">
                <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-purple-500/20 to-cyan-500/20 border border-purple-500/30 flex items-center justify-center mx-auto mb-4">
                  <Mail className="w-8 h-8 text-purple-400" />
                </div>
                <h1 className="text-2xl font-bold text-white">Check your email</h1>
                <p className="mt-2 text-sm text-gray-400">
                  We sent a 6-digit code to
                </p>
                <p className="mt-1 text-sm font-semibold text-purple-300 truncate">
                  {email || "your email"}
                </p>
              </div>

              {/* Expiry Timer */}
              <div className="mb-6">
                <div className="flex items-center justify-between text-xs text-gray-500 mb-1.5">
                  <span>Code expires in</span>
                  <span
                    className="font-mono font-semibold tabular-nums transition-colors"
                    style={{ color: expiryColor }}
                  >
                    {formatTime(expiryLeft)}
                  </span>
                </div>
                <div className="h-1 bg-white/10 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-1000"
                    style={{ width: `${expiryPct}%`, backgroundColor: expiryColor }}
                  />
                </div>
              </div>

              {/* OTP Inputs */}
              <div
                className={`flex gap-2.5 justify-center mb-6 ${shake ? "shake" : ""}`}
                onPaste={handlePaste}
              >
                {digits.map((d, i) => (
                  <input
                    key={i}
                    ref={el => { inputRefs.current[i] = el; }}
                    id={`otp-digit-${i}`}
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]"
                    maxLength={1}
                    value={d}
                    autoFocus={i === 0}
                    onChange={e => handleChange(i, e.target.value)}
                    onKeyDown={e => handleKeyDown(i, e)}
                    disabled={loading || verified}
                    className={`
                      w-12 h-14 text-center text-xl font-bold rounded-xl
                      bg-white/5 border-2 text-white
                      focus:outline-none transition-all duration-200
                      disabled:opacity-50 disabled:cursor-not-allowed
                      ${d
                        ? "border-purple-500 bg-purple-500/10 shadow-lg shadow-purple-500/20"
                        : "border-white/10 focus:border-purple-500 focus:bg-purple-500/5"
                      }
                    `}
                  />
                ))}
              </div>

              {/* Submit button */}
              <button
                id="verify-otp-btn"
                onClick={() => handleSubmit()}
                disabled={loading || digits.join("").length < OTP_LENGTH}
                className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl
                           bg-gradient-to-r from-purple-600 to-cyan-600 text-white font-semibold text-sm
                           hover:from-purple-500 hover:to-cyan-500 transition-all duration-200
                           shadow-lg shadow-purple-500/20 hover:shadow-purple-500/40
                           disabled:opacity-50 disabled:cursor-not-allowed
                           hover:scale-[1.02] active:scale-[0.98]"
              >
                {loading
                  ? <><Loader2 className="w-4 h-4 animate-spin" /> Verifying…</>
                  : <><ArrowRight className="w-4 h-4" /> Verify Email</>
                }
              </button>

              {/* Resend */}
              <div className="mt-6 text-center">
                <p className="text-sm text-gray-500 mb-2">Didn't receive the code?</p>
                <button
                  id="resend-otp-btn"
                  onClick={handleResend}
                  disabled={resendCooldown > 0 || resending}
                  className="inline-flex items-center gap-1.5 text-sm font-medium
                             transition-colors disabled:cursor-not-allowed
                             text-purple-400 hover:text-purple-300
                             disabled:text-gray-600"
                >
                  {resending
                    ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Sending…</>
                    : <><RotateCcw className="w-3.5 h-3.5" />
                        {resendCooldown > 0
                          ? `Resend in ${resendCooldown}s`
                          : "Resend code"
                        }
                      </>
                  }
                </button>
              </div>

              <div className="mt-6 border-t border-white/8 pt-4 text-center">
                <p className="text-xs text-gray-600">
                  Wrong email?{" "}
                  <Link
                    to="/register"
                    className="text-purple-400 hover:text-purple-300 transition-colors"
                  >
                    Start over
                  </Link>
                </p>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
