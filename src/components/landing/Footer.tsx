import { Shield } from "lucide-react";

const Footer = () => (
  <footer className="border-t border-border py-12 px-4">
    <div className="max-w-6xl mx-auto grid md:grid-cols-4 gap-8">
      <div>
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-6 h-6 text-primary" />
          <span className="font-bold text-lg">ARK DevSecOps AI</span>
        </div>
        <p className="text-sm text-muted-foreground">
          Open-source DevSecOps platform powered by AI.
        </p>
      </div>
      <div>
        <h4 className="font-semibold mb-3 text-sm">Product</h4>
        <ul className="space-y-2 text-sm text-muted-foreground">
          <li className="hover:text-foreground transition-colors cursor-pointer">Features</li>
          <li className="hover:text-foreground transition-colors cursor-pointer">Pricing</li>
          <li className="hover:text-foreground transition-colors cursor-pointer">Changelog</li>
        </ul>
      </div>
      <div>
        <h4 className="font-semibold mb-3 text-sm">Resources</h4>
        <ul className="space-y-2 text-sm text-muted-foreground">
          <li className="hover:text-foreground transition-colors cursor-pointer">Documentation</li>
          <li className="hover:text-foreground transition-colors cursor-pointer">API Reference</li>
          <li className="hover:text-foreground transition-colors cursor-pointer">GitHub</li>
        </ul>
      </div>
      <div>
        <h4 className="font-semibold mb-3 text-sm">Company</h4>
        <ul className="space-y-2 text-sm text-muted-foreground">
          <li className="hover:text-foreground transition-colors cursor-pointer">About</li>
          <li className="hover:text-foreground transition-colors cursor-pointer">Contact</li>
          <li className="hover:text-foreground transition-colors cursor-pointer">Privacy</li>
        </ul>
      </div>
    </div>
    <div className="max-w-6xl mx-auto mt-8 pt-8 border-t border-border text-center text-xs text-muted-foreground">
      © 2026 ARK DevSecOps AI. Open-source security for developers.
    </div>
  </footer>
);

export default Footer;
