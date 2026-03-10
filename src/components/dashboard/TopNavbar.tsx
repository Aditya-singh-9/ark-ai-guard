import { Search, Bell, GitBranch } from "lucide-react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";

const TopNavbar = () => (
  <header className="h-14 border-b border-border bg-card/50 backdrop-blur-md flex items-center justify-between px-6">
    <div className="relative w-80">
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
      <input
        placeholder="Search repositories, scans..."
        className="w-full bg-muted rounded-lg pl-9 pr-4 py-2 text-sm outline-none focus:ring-1 focus:ring-primary"
      />
    </div>
    <div className="flex items-center gap-4">
      <div className="flex items-center gap-2 text-xs text-neon-green">
        <GitBranch className="w-4 h-4" />
        <span>Connected</span>
      </div>
      <button className="relative p-2 hover:bg-muted rounded-lg transition-colors">
        <Bell className="w-5 h-5 text-muted-foreground" />
        <span className="absolute top-1 right-1 w-2 h-2 bg-primary rounded-full" />
      </button>
      <Avatar className="w-8 h-8">
        <AvatarFallback className="bg-primary/20 text-primary text-xs">DV</AvatarFallback>
      </Avatar>
    </div>
  </header>
);

export default TopNavbar;
