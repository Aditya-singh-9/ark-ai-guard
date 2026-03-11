import { Outlet } from "react-router-dom";
import DashboardSidebar from "@/components/dashboard/DashboardSidebar";
import TopNavbar from "@/components/dashboard/TopNavbar";

const DashboardLayout = () => (
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

export default DashboardLayout;
