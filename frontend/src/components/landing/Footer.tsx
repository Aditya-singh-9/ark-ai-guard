import { Shield, Github, ExternalLink } from "lucide-react";
import { Link } from "react-router-dom";

const Footer = () => (
  <footer className="border-t border-border/50 py-16 px-4">
    <div className="max-w-6xl mx-auto">
      <div className="grid md:grid-cols-5 gap-8 mb-12">
        {/* Brand */}
        <div className="md:col-span-2">
          <Link to="/" className="flex items-center gap-2 mb-4 w-fit">
            <div className="w-8 h-8 rounded-lg bg-primary/20 flex items-center justify-center">
              <Shield className="w-4 h-4 text-primary" />
            </div>
            <span className="font-bold text-lg">DevScops Guard</span>
          </Link>
          <p className="text-sm text-muted-foreground leading-relaxed max-w-xs">
            Open-source DevSecOps platform powered by AI. Secure your code, automatically.
          </p>
          <div className="flex items-center gap-3 mt-4">
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <Github className="w-4 h-4" /> GitHub
            </a>
            <span className="text-border">·</span>
            <span className="text-xs text-muted-foreground">Apache 2.0 License</span>
          </div>
        </div>

        {/* Product */}
        <div>
          <h4 className="font-semibold mb-4 text-sm">Product</h4>
          <ul className="space-y-2.5 text-sm text-muted-foreground">
            {["Features", "Pricing", "Security", "Changelog", "Roadmap"].map((item) => (
              <li key={item} className="hover:text-foreground transition-colors cursor-pointer">{item}</li>
            ))}
          </ul>
        </div>

        {/* Resources */}
        <div>
          <h4 className="font-semibold mb-4 text-sm">Resources</h4>
          <ul className="space-y-2.5 text-sm text-muted-foreground">
            {[
              { label: "Documentation", icon: true },
              { label: "API Reference", icon: true },
              { label: "GitHub Repository", icon: true },
              { label: "Community", icon: false },
              { label: "Blog", icon: false },
            ].map((item) => (
              <li key={item.label} className="hover:text-foreground transition-colors cursor-pointer flex items-center gap-1">
                {item.label}
                {item.icon && <ExternalLink className="w-3 h-3 opacity-50" />}
              </li>
            ))}
          </ul>
        </div>

        {/* Company */}
        <div>
          <h4 className="font-semibold mb-4 text-sm">Company</h4>
          <ul className="space-y-2.5 text-sm text-muted-foreground">
            {["About", "Contact", "Privacy Policy", "Terms of Service", "Security"].map((item) => (
              <li key={item} className="hover:text-foreground transition-colors cursor-pointer">{item}</li>
            ))}
          </ul>
        </div>
      </div>

      {/* Bottom bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between pt-8 border-t border-border/40 gap-4 text-xs text-muted-foreground">
        <span>© 2026 DevScops Guard. Built with ♥ for the developer community.</span>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-primary/5 border border-primary/10">
          <Shield className="w-3 h-3 text-primary" />
          <span className="text-primary font-medium font-mono">Open Source · Free to Use</span>
        </div>
      </div>
    </div>
  </footer>
);

export default Footer;
