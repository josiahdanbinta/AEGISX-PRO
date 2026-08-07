import { useState, useEffect, useCallback } from "react";
import {
  Users, UserPlus, Search, Shield, Building, Key,
  ChevronDown, Filter, X, Edit2, Trash2, Ban, Unlock,
  AlertTriangle, AlertCircle, Clock, CheckCircle, XCircle,
  Plus, Eye, EyeOff, ChevronRight, FolderTree,
} from "lucide-react";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Input } from "@/components/ui/Input";
import { Table } from "@/components/ui/Table";
import { Loading } from "@/components/ui/Loading";
import { Modal } from "@/components/ui/Modal";
import { StatCard } from "@/components/dashboards/StatCard";
import { api } from "@/services/api";

interface UserItem {
  id: string;
  email: string;
  full_name: string;
  roles: string[];
  department?: string;
  status: string;
  last_login_at?: string;
  created_at: string;
}

interface Role {
  id: string;
  name: string;
  description: string;
  permissions_count: number;
  is_system: boolean;
}

interface Department {
  id: string;
  name: string;
  parent_id?: string;
  user_count: number;
  children: Department[];
}

interface UserStats {
  total: number;
  active: number;
  suspended: number;
  locked: number;
}

type AdminTab = "users" | "roles" | "departments";

const statusBadgeVariant: Record<string, "success" | "danger" | "warning" | "info" | "default"> = {
  active: "success",
  suspended: "danger",
  locked: "warning",
  inactive: "default",
};

const roleOptions = ["", "admin", "analyst", "operator", "viewer", "auditor"];
const statusOptions = ["", "active", "suspended", "locked", "inactive"];
const departmentsList = ["", "SOC", "Engineering", "Compliance", "IT", "Management", "DevOps"];

export function UsersPage() {
  const [activeTab, setActiveTab] = useState<AdminTab>("users");
  const [stats, setStats] = useState<UserStats>({ total: 0, active: 0, suspended: 0, locked: 0 });

  const [users, setUsers] = useState<UserItem[]>([]);
  const [usersLoading, setUsersLoading] = useState(true);
  const [usersError, setUsersError] = useState<string | null>(null);
  const [usersPage, setUsersPage] = useState(1);
  const [usersTotal, setUsersTotal] = useState(0);

  const [searchQuery, setSearchQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [departmentFilter, setDepartmentFilter] = useState("");

  const [roles, setRoles] = useState<Role[]>([]);
  const [rolesLoading, setRolesLoading] = useState(true);
  const [departments, setDepartments] = useState<Department[]>([]);
  const [departmentsLoading, setDepartmentsLoading] = useState(true);

  const [showAddUser, setShowAddUser] = useState(false);
  const [showEditUser, setShowEditUser] = useState(false);
  const [showAddRole, setShowAddRole] = useState(false);
  const [showAddDepartment, setShowAddDepartment] = useState(false);

  const [editingUser, setEditingUser] = useState<UserItem | null>(null);
  const [newUser, setNewUser] = useState({ full_name: "", email: "", password: "", roles: [] as string[], department: "" });
  const [newRole, setNewRole] = useState({ name: "", description: "" });
  const [newDepartment, setNewDepartment] = useState({ name: "", parent_id: "" });

  useEffect(() => {
    api.get<UserStats>("/users/stats")
      .then((res) => setStats(res))
      .catch(() => {});
  }, []);

  const fetchUsers = useCallback(() => {
    setUsersLoading(true);
    setUsersError(null);
    const params: Record<string, string> = { page: String(usersPage) };
    if (searchQuery) params.search = searchQuery;
    if (roleFilter) params.role = roleFilter;
    if (statusFilter) params.status = statusFilter;
    if (departmentFilter) params.department = departmentFilter;
    api.get<{ data: UserItem[]; total: number }>("/users", { params })
      .then((res) => { setUsers(res.data); setUsersTotal(res.total); })
      .catch((err) => setUsersError(err?.error?.message || "Failed to load users"))
      .finally(() => setUsersLoading(false));
  }, [usersPage, searchQuery, roleFilter, statusFilter, departmentFilter]);

  useEffect(() => {
    if (activeTab === "users") fetchUsers();
  }, [activeTab, fetchUsers]);

  useEffect(() => {
    if (activeTab === "roles") {
      setRolesLoading(true);
      api.get<Role[]>("/users/roles")
        .then((res) => setRoles(res))
        .catch(() => {})
        .finally(() => setRolesLoading(false));
    }
  }, [activeTab]);

  useEffect(() => {
    if (activeTab === "departments") {
      setDepartmentsLoading(true);
      api.get<Department[]>("/users/departments")
        .then((res) => setDepartments(res))
        .catch(() => {})
        .finally(() => setDepartmentsLoading(false));
    }
  }, [activeTab]);

  const createUser = async () => {
    if (!newUser.email || !newUser.full_name || !newUser.password) return;
    try {
      await api.post("/users", newUser);
      setShowAddUser(false);
      setNewUser({ full_name: "", email: "", password: "", roles: [], department: "" });
      fetchUsers();
    } catch (_) {}
  };

  const updateUser = async () => {
    if (!editingUser) return;
    try {
      await api.put("/users/" + editingUser.id, {
        full_name: editingUser.full_name,
        email: editingUser.email,
        roles: editingUser.roles,
        department: editingUser.department,
        status: editingUser.status,
      });
      setShowEditUser(false);
      setEditingUser(null);
      fetchUsers();
    } catch (_) {}
  };

  const deleteUser = async (id: string) => {
    if (!window.confirm("Are you sure you want to delete this user?")) return;
    try {
      await api.delete("/users/" + id);
      fetchUsers();
    } catch (_) {}
  };

  const suspendUser = async (id: string) => {
    try {
      await api.patch("/users/" + id, { status: "suspended" });
      fetchUsers();
    } catch (_) {}
  };

  const createRole = async () => {
    if (!newRole.name) return;
    try {
      await api.post("/users/roles", newRole);
      setShowAddRole(false);
      setNewRole({ name: "", description: "" });
      setRolesLoading(true);
      api.get<Role[]>("/users/roles").then((res) => setRoles(res)).catch(() => {}).finally(() => setRolesLoading(false));
    } catch (_) {}
  };

  const createDepartment = async () => {
    if (!newDepartment.name) return;
    try {
      await api.post("/users/departments", newDepartment);
      setShowAddDepartment(false);
      setNewDepartment({ name: "", parent_id: "" });
      setDepartmentsLoading(true);
      api.get<Department[]>("/users/departments").then((res) => setDepartments(res)).catch(() => {}).finally(() => setDepartmentsLoading(false));
    } catch (_) {}
  };

  const toggleRole = (role: string) => {
    if (!editingUser) {
      setNewUser((prev) => ({
        ...prev,
        roles: prev.roles.includes(role) ? prev.roles.filter((r) => r !== role) : [...prev.roles, role],
      }));
    } else {
      setEditingUser((prev) => ({
        ...prev!,
        roles: prev!.roles.includes(role) ? prev!.roles.filter((r) => r !== role) : [...prev!.roles, role],
      }));
    }
  };

  const renderDepartmentTree = (deps: Department[], depth: number = 0): React.ReactNode => {
    return deps.map((dep) => (
      <div key={dep.id}>
        <div className="flex items-center justify-between p-3 rounded-lg hover:bg-slate-50 transition-colors" style={{ paddingLeft: 16 + depth * 20 + "px" }}>
          <div className="flex items-center gap-2">
            <ChevronRight className="w-4 h-4 text-slate-400" />
            <FolderTree className="w-4 h-4 text-brand-600" />
            <span className="text-sm font-medium text-slate-900">{dep.name}</span>
            <Badge variant="default" size="sm">{dep.user_count} users</Badge>
          </div>
          <div className="flex items-center gap-1">
            <button className="p-1.5 rounded-lg text-slate-400 hover:text-blue-600 hover:bg-blue-50 transition-colors">
              <Edit2 className="w-3.5 h-3.5" />
            </button>
            <button className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors">
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
        {dep.children.length > 0 && renderDepartmentTree(dep.children, depth + 1)}
      </div>
    ));
  };

  const tabs: { key: AdminTab; label: string }[] = [
    { key: "users", label: "Users" },
    { key: "roles", label: "Roles" },
    { key: "departments", label: "Departments" },
  ];

  const columns = [
    {
      key: "full_name",
      header: "Name",
      width: "180px",
      render: (row: UserItem) => (
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-brand-100 flex items-center justify-center text-brand-700 font-semibold text-xs">
            {row.full_name.split(" ").map((n) => n[0]).join("").toUpperCase().slice(0, 2)}
          </div>
          <div>
            <p className="text-sm font-medium text-slate-900">{row.full_name}</p>
          </div>
        </div>
      ),
    },
    {
      key: "email",
      header: "Email",
      render: (row: UserItem) => (
        <span className="text-sm text-slate-600">{row.email}</span>
      ),
    },
    {
      key: "roles",
      header: "Roles",
      width: "180px",
      render: (row: UserItem) => (
        <div className="flex flex-wrap gap-1">
          {row.roles.map((r) => (
            <Badge key={r} variant="info" size="sm">{r}</Badge>
          ))}
          {row.roles.length === 0 && <span className="text-xs text-slate-400">--</span>}
        </div>
      ),
    },
    {
      key: "department",
      header: "Department",
      width: "130px",
      render: (row: UserItem) => (
        <span className="text-sm text-slate-600">{row.department || "--"}</span>
      ),
    },
    {
      key: "status",
      header: "Status",
      width: "100px",
      render: (row: UserItem) => (
        <Badge variant={statusBadgeVariant[row.status] || "default"} size="sm">
          {row.status}
        </Badge>
      ),
    },
    {
      key: "last_login_at",
      header: "Last Login",
      width: "150px",
      render: (row: UserItem) => (
        <span className="text-xs text-slate-500">
          {row.last_login_at
            ? new Date(row.last_login_at).toLocaleDateString("en-US", {
                month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
              })
            : "Never"}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "120px",
      render: (row: UserItem) => (
        <div className="flex items-center gap-1">
          <button
            onClick={() => { setEditingUser({ ...row }); setShowEditUser(true); }}
            className="p-1.5 rounded-lg text-slate-400 hover:text-blue-600 hover:bg-blue-50 transition-colors"
            title="Edit"
          >
            <Edit2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => suspendUser(row.id)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-amber-600 hover:bg-amber-50 transition-colors"
            title="Suspend"
          >
            <Ban className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => deleteUser(row.id)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors"
            title="Delete"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">User Management</h1>
          <p className="text-sm text-slate-500 mt-1">
            {stats.total} total user{stats.total !== 1 ? "s" : ""} | {stats.active} active
          </p>
        </div>
        {activeTab === "users" && (
          <Button size="md" onClick={() => setShowAddUser(true)}>
            <UserPlus className="w-4 h-4" />
            Add User
          </Button>
        )}
        {activeTab === "roles" && (
          <Button size="md" onClick={() => setShowAddRole(true)}>
            <Plus className="w-4 h-4" />
            Add Role
          </Button>
        )}
        {activeTab === "departments" && (
          <Button size="md" onClick={() => setShowAddDepartment(true)}>
            <Plus className="w-4 h-4" />
            Add Department
          </Button>
        )}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Users" value={String(stats.total)} icon={Users} />
        <StatCard label="Active" value={String(stats.active)} icon={CheckCircle} />
        <StatCard label="Suspended" value={String(stats.suspended)} icon={Ban} />
        <StatCard label="Locked" value={String(stats.locked)} icon={Unlock} />
      </div>

      <div className="flex border-b border-slate-200 gap-1">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={
              "px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px " +
              (activeTab === tab.key
                ? "border-brand-600 text-brand-700"
                : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300")
            }
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "users" && (
        <div className="space-y-4">
          <Card padding="none">
            <div className="p-4 border-b border-slate-100">
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex-1 min-w-[200px] max-w-xs">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <Input
                    placeholder="Search by name or email..."
                    value={searchQuery}
                    onChange={(e) => { setSearchQuery(e.target.value); setUsersPage(1); }}
                    className="pl-9"
                  />
                </div>
                <div className="relative">
                  <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                  <select
                    value={roleFilter}
                    onChange={(e) => { setRoleFilter(e.target.value); setUsersPage(1); }}
                    className="appearance-none bg-white border border-slate-200 rounded-lg pl-9 pr-8 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer"
                  >
                    <option value="">All Roles</option>
                    {roleOptions.filter(Boolean).map((r) => (
                      <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>
                    ))}
                  </select>
                  <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
                </div>
                <div className="relative">
                  <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                  <select
                    value={statusFilter}
                    onChange={(e) => { setStatusFilter(e.target.value); setUsersPage(1); }}
                    className="appearance-none bg-white border border-slate-200 rounded-lg pl-9 pr-8 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer"
                  >
                    <option value="">All Statuses</option>
                    {statusOptions.filter(Boolean).map((s) => (
                      <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                    ))}
                  </select>
                  <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
                </div>
                <div className="relative">
                  <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                  <select
                    value={departmentFilter}
                    onChange={(e) => { setDepartmentFilter(e.target.value); setUsersPage(1); }}
                    className="appearance-none bg-white border border-slate-200 rounded-lg pl-9 pr-8 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer"
                  >
                    <option value="">All Departments</option>
                    {departmentsList.filter(Boolean).map((d) => (
                      <option key={d} value={d}>{d}</option>
                    ))}
                  </select>
                  <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
                </div>
                {(searchQuery || roleFilter || statusFilter || departmentFilter) && (
                  <Button variant="ghost" size="sm" onClick={() => { setSearchQuery(""); setRoleFilter(""); setStatusFilter(""); setDepartmentFilter(""); setUsersPage(1); }}>
                    <X className="w-3.5 h-3.5" />
                    Clear
                  </Button>
                )}
              </div>
            </div>

            {usersError && (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <AlertCircle className="w-10 h-10 text-red-400" />
                <p className="text-red-600 font-medium">{usersError}</p>
                <Button variant="secondary" size="sm" onClick={fetchUsers}>Retry</Button>
              </div>
            )}

            {!usersError && (
              <Table
                columns={columns}
                data={users}
                keyExtractor={(row) => String(row.id)}
                page={usersPage}
                pageSize={20}
                total={usersTotal}
                onPageChange={setUsersPage}
                loading={usersLoading}
              />
            )}
          </Card>
        </div>
      )}

      {activeTab === "roles" && (
        <div className="space-y-4">
          {rolesLoading && (
            <div className="flex items-center justify-center py-20">
              <Loading size="lg" text="Loading roles..." />
            </div>
          )}
          {!rolesLoading && roles.length === 0 && (
            <Card>
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <Shield className="w-10 h-10 text-slate-300" />
                <p className="text-slate-500 font-medium">No roles defined</p>
                <Button variant="secondary" size="sm" onClick={() => setShowAddRole(true)}>
                  <Plus className="w-4 h-4" />
                  Add Role
                </Button>
              </div>
            </Card>
          )}
          {!rolesLoading && roles.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {roles.map((role) => (
                <Card key={role.id} hover>
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-brand-50">
                        <Shield className="w-4 h-4 text-brand-600" />
                      </div>
                      <div>
                        <h3 className="font-medium text-slate-900">{role.name}</h3>
                        {role.is_system && (
                          <Badge variant="default" size="sm">System</Badge>
                        )}
                      </div>
                    </div>
                  </div>
                  {role.description && (
                    <p className="text-sm text-slate-500 mb-3">{role.description}</p>
                  )}
                  <div className="flex items-center justify-between mt-3 pt-3 border-t border-slate-100">
                    <span className="text-xs text-slate-500">
                      <Key className="w-3.5 h-3.5 inline mr-1" />
                      {role.permissions_count} permission{role.permissions_count !== 1 ? "s" : ""}
                    </span>
                    <div className="flex items-center gap-1">
                      <button className="p-1.5 rounded-lg text-slate-400 hover:text-blue-600 hover:bg-blue-50 transition-colors">
                        <Edit2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === "departments" && (
        <div className="space-y-4">
          {departmentsLoading && (
            <div className="flex items-center justify-center py-20">
              <Loading size="lg" text="Loading departments..." />
            </div>
          )}
          {!departmentsLoading && departments.length === 0 && (
            <Card>
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <Building className="w-10 h-10 text-slate-300" />
                <p className="text-slate-500 font-medium">No departments defined</p>
                <Button variant="secondary" size="sm" onClick={() => setShowAddDepartment(true)}>
                  <Plus className="w-4 h-4" />
                  Add Department
                </Button>
              </div>
            </Card>
          )}
          {!departmentsLoading && departments.length > 0 && (
            <Card>
              <div className="divide-y divide-slate-100">
                {renderDepartmentTree(departments)}
              </div>
            </Card>
          )}
        </div>
      )}

      <Modal open={showAddUser} onClose={() => setShowAddUser(false)} title="Add User" size="md">
        <div className="space-y-4">
          <Input label="Full Name" value={newUser.full_name} onChange={(e) => setNewUser((p) => ({ ...p, full_name: e.target.value }))} placeholder="John Doe" />
          <Input label="Email" type="email" value={newUser.email} onChange={(e) => setNewUser((p) => ({ ...p, email: e.target.value }))} placeholder="john@org.com" />
          <Input label="Password" type="password" value={newUser.password} onChange={(e) => setNewUser((p) => ({ ...p, password: e.target.value }))} placeholder="Minimum 8 characters" />
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Department</label>
            <select value={newUser.department} onChange={(e) => setNewUser((p) => ({ ...p, department: e.target.value }))} className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer">
              <option value="">-- Select --</option>
              {departmentsList.filter(Boolean).map((d) => (<option key={d} value={d}>{d}</option>))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Roles</label>
            <div className="flex flex-wrap gap-2">
              {roleOptions.filter(Boolean).map((role) => (
                <button
                  key={role}
                  onClick={() => toggleRole(role)}
                  className={
                    "px-3 py-1.5 text-xs font-medium rounded-full border transition-colors " +
                    (newUser.roles.includes(role)
                      ? "bg-brand-50 border-brand-300 text-brand-700"
                      : "bg-white border-slate-200 text-slate-600 hover:border-slate-300")
                  }
                >
                  {role.charAt(0).toUpperCase() + role.slice(1)}
                </button>
              ))}
            </div>
          </div>
          <div className="flex items-center justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => { setShowAddUser(false); setNewUser({ full_name: "", email: "", password: "", roles: [], department: "" }); }}>
              Cancel
            </Button>
            <Button onClick={createUser} disabled={!newUser.email || !newUser.full_name || !newUser.password}>
              <UserPlus className="w-4 h-4" />
              Add User
            </Button>
          </div>
        </div>
      </Modal>

      <Modal open={showEditUser} onClose={() => { setShowEditUser(false); setEditingUser(null); }} title="Edit User" size="md">
        {editingUser && (
          <div className="space-y-4">
            <Input label="Full Name" value={editingUser.full_name} onChange={(e) => setEditingUser((p) => ({ ...p!, full_name: e.target.value }))} />
            <Input label="Email" type="email" value={editingUser.email} onChange={(e) => setEditingUser((p) => ({ ...p!, email: e.target.value }))} />
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Department</label>
              <select value={editingUser.department || ""} onChange={(e) => setEditingUser((p) => ({ ...p!, department: e.target.value }))} className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer">
                <option value="">-- Select --</option>
                {departmentsList.filter(Boolean).map((d) => (<option key={d} value={d}>{d}</option>))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Roles</label>
              <div className="flex flex-wrap gap-2">
                {roleOptions.filter(Boolean).map((role) => (
                  <button
                    key={role}
                    onClick={() => toggleRole(role)}
                    className={
                      "px-3 py-1.5 text-xs font-medium rounded-full border transition-colors " +
                      (editingUser.roles.includes(role)
                        ? "bg-brand-50 border-brand-300 text-brand-700"
                        : "bg-white border-slate-200 text-slate-600 hover:border-slate-300")
                    }
                  >
                    {role.charAt(0).toUpperCase() + role.slice(1)}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Status</label>
              <select value={editingUser.status} onChange={(e) => setEditingUser((p) => ({ ...p!, status: e.target.value }))} className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer">
                {statusOptions.filter(Boolean).map((s) => (<option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>))}
              </select>
            </div>
            <div className="flex items-center justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => { setShowEditUser(false); setEditingUser(null); }}>Cancel</Button>
              <Button onClick={updateUser}>Save Changes</Button>
            </div>
          </div>
        )}
      </Modal>

      <Modal open={showAddRole} onClose={() => setShowAddRole(false)} title="Add Role" size="sm">
        <div className="space-y-4">
          <Input label="Role Name" value={newRole.name} onChange={(e) => setNewRole((p) => ({ ...p, name: e.target.value }))} placeholder="e.g. soc_manager" />
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Description</label>
            <textarea value={newRole.description} onChange={(e) => setNewRole((p) => ({ ...p, description: e.target.value }))} placeholder="Describe the role..." className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 resize-none" rows={2} />
          </div>
          <div className="flex items-center justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => { setShowAddRole(false); setNewRole({ name: "", description: "" }); }}>Cancel</Button>
            <Button onClick={createRole} disabled={!newRole.name}>
              <Plus className="w-4 h-4" />
              Add Role
            </Button>
          </div>
        </div>
      </Modal>

      <Modal open={showAddDepartment} onClose={() => setShowAddDepartment(false)} title="Add Department" size="sm">
        <div className="space-y-4">
          <Input label="Department Name" value={newDepartment.name} onChange={(e) => setNewDepartment((p) => ({ ...p, name: e.target.value }))} placeholder="e.g. Security Operations" />
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Parent Department</label>
            <select value={newDepartment.parent_id} onChange={(e) => setNewDepartment((p) => ({ ...p, parent_id: e.target.value }))} className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer">
              <option value="">-- Root (no parent) --</option>
            </select>
          </div>
          <div className="flex items-center justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => { setShowAddDepartment(false); setNewDepartment({ name: "", parent_id: "" }); }}>Cancel</Button>
            <Button onClick={createDepartment} disabled={!newDepartment.name}>
              <Plus className="w-4 h-4" />
              Add Department
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
