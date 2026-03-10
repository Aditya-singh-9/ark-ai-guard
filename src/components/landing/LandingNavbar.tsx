import { Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";

const LandingNavbar = () => (
  <nav className="fixed top-0 left-0 right-0 z-50 glass border-b border-border/50">
    <div className="max-w-6xl mx-auto flex items-center justify-between h-16 px-4">
      <Link to="/" className="flex items-center gap-2">
        <Shield className="w-6 h-6 text-primary" />
        <span className="font-bold text-lg">ARK DevSecOps AI</span>
      </Link>
      <div className="hidden md:flex items-center gap-6 text-sm text-muted-foreground">
        <a href="#features" className="hover:text-foreground transition-colors">Features</a>
        <a href="#how-it-works" className="hover:text-foreground transition-colors">How It Works</a>
        <a href="#preview" className="hover:text-foreground transition-colors">Preview</a>
      </div>
      <Link to="/dashboard">
        <Button size="sm" className="bg-primary text-primary-foreground hover:bg-primary/90">
          Dashboard
        </Button>
      </Link>
    </div>
  </nav>
);

export default LandingNavbar;
