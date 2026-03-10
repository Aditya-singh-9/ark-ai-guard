import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Index from "./pages/Index.tsx";
import NotFound from "./pages/NotFound.tsx";
import DashboardLayout from "./pages/DashboardLayout.tsx";
import DashboardOverview from "./pages/DashboardOverview.tsx";
import RepositoriesPage from "./pages/RepositoriesPage.tsx";
import VulnerabilitiesPage from "./pages/VulnerabilitiesPage.tsx";
import CICDGeneratorPage from "./pages/CICDGeneratorPage.tsx";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/dashboard" element={<DashboardLayout />}>
            <Route index element={<DashboardOverview />} />
            <Route path="repos" element={<RepositoriesPage />} />
            <Route path="scans" element={<DashboardOverview />} />
            <Route path="vulns" element={<VulnerabilitiesPage />} />
            <Route path="cicd" element={<CICDGeneratorPage />} />
            <Route path="settings" element={<DashboardOverview />} />
            <Route path="profile" element={<DashboardOverview />} />
          </Route>
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
