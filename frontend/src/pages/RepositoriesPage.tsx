import RepositoryTable from "@/components/dashboard/RepositoryTable";

const RepositoriesPage = () => (
  <div className="space-y-6">
    <div>
      <h1 className="text-2xl font-bold mb-1">Repositories</h1>
      <p className="text-sm text-muted-foreground">Manage and scan your connected repositories.</p>
    </div>
    <RepositoryTable />
  </div>
);

export default RepositoriesPage;
