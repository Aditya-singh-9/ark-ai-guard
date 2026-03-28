/**
 * AuthCallback page — handles GitHub OAuth redirect.
 * Reads ?code= from URL, exchanges it for JWT, then redirects to /dashboard.
 */
import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { authGithub } from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import { Shield, Loader2 } from "lucide-react";
import { toast } from "sonner";

const AuthCallback = () => {
  const navigate = useNavigate();
  const { login } = useAuth();
  const handledRef = useRef(false);

  useEffect(() => {
    if (handledRef.current) return; // prevent double-call in StrictMode
    handledRef.current = true;

    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const error = params.get("error");

    if (error) {
      toast.error(`GitHub authorization denied: ${error}`);
      navigate("/");
      return;
    }

    if (!code) {
      toast.error("No authorization code found. Please try again.");
      navigate("/");
      return;
    }

    authGithub(code)
      .then(({ access_token, user }) => {
        login(access_token, user);
        toast.success(`Welcome, ${user.display_name ?? user.username}! 🎉`);
        navigate("/dashboard");
      })
      .catch((err: Error) => {
        toast.error(`Login failed: ${err.message}`);
        navigate("/");
      });
  }, []);

  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="flex flex-col items-center gap-4 text-center">
        <div className="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center">
          <Shield className="w-6 h-6 text-primary" />
        </div>
        <div>
          <h2 className="text-lg font-semibold">Authenticating with GitHub</h2>
          <p className="text-sm text-muted-foreground mt-1">
            Please wait while we verify your credentials…
          </p>
        </div>
        <Loader2 className="w-5 h-5 animate-spin text-primary" />
      </div>
    </div>
  );
};

export default AuthCallback;
