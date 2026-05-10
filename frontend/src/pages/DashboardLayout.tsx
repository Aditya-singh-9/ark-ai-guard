import { Outlet, Navigate } from "react-router-dom";
import DashboardSidebar from "@/components/dashboard/DashboardSidebar";
import TopNavbar from "@/components/dashboard/TopNavbar";
import { useAuth } from "@/contexts/AuthContext";

const DashboardLayout = () => {
  const { isLoggedIn, isLoading } = useAuth();

  // While JWT is being validated, show a blank screen to avoid flash
  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="w-8 h-8 rounded-full border-2 border-primary border-t-transparent animate-spin" />
      </div>
    );
  }

  // Not authenticated — redirect to login, preserving the intended path
  if (!isLoggedIn) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="flex min-h-screen w-full bg-background">
      <DashboardSidebar />
      <div className="flex-1 flex flex-col">
        <TopNavbar />
        <main className="flex-1 p-6 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;
