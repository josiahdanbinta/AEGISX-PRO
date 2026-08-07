"""
AEGIS â€” First-Run Setup Script
Creates initial tenant, admin user, and displays all credentials.
"""
import asyncio
import uuid

async def setup():
    from app.core.database import async_session_factory, engine
    from app.core.security import hash_password
    from app.models.user import User
    from app.models.tenant import Tenant
    from app.models.base import Base

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as db:
        # Check if tenant already exists
        from sqlalchemy import select
        existing = await db.scalar(select(Tenant).limit(1))
        if existing:
            print("\n  Database already initialized.")
            print(f"  Tenant ID: {existing.id}")
            return

        # Create tenant
        tenant_id = uuid.uuid4()
        tenant = Tenant(
            id=tenant_id,
            name="default",
            display_name="AEGIS Enterprise",
            subscription_tier="enterprise",
            status="active",
            quota_assets=10000,
            quota_users=1000,
            quota_storage_gb=500,
        )
        db.add(tenant)
        await db.flush()

        # Create super admin
        admin_id = uuid.uuid4()
        admin = User(
            id=admin_id,
            tenant_id=tenant_id,
            username="admin",
            email="admin@AEGIS.com",
            hashed_password=hash_password("Admin123!@#"),
            full_name="Super Admin",
            roles=[{"role_name": "super_admin"}],
            status="active",
            must_change_password=True,
        )
        db.add(admin)

        # Create sample roles
        from app.models.user import Role
        roles = [
            Role(tenant_id=tenant_id, name="tenant_admin", display_name="Tenant Administrator", is_system=True,
                 permissions=["users:create","users:delete","users:suspend","users:read","users:update","roles:read","roles:manage","departments:manage","audit:read"]),
            Role(tenant_id=tenant_id, name="soc_manager", display_name="SOC Manager", is_system=True,
                 permissions=["incidents:manage","alerts:manage","assets:read","detection:manage","soar:manage","dashboards:read"]),
            Role(tenant_id=tenant_id, name="soc_analyst_l2", display_name="SOC Analyst L2", is_system=True,
                 permissions=["incidents:manage","alerts:manage","assets:read","detection:read","dashboards:read"]),
            Role(tenant_id=tenant_id, name="soc_analyst_l1", display_name="SOC Analyst L1", is_system=True,
                 permissions=["incidents:read","alerts:acknowledge","assets:read","dashboards:read"]),
            Role(tenant_id=tenant_id, name="threat_hunter", display_name="Threat Hunter", is_system=True,
                 permissions=["threat_intel:manage","detection:manage","incidents:read","alerts:read"]),
            Role(tenant_id=tenant_id, name="incident_responder", display_name="Incident Responder", is_system=True,
                 permissions=["incidents:manage","soar:execute","evidence:manage"]),
            Role(tenant_id=tenant_id, name="compliance_officer", display_name="Compliance Officer", is_system=True,
                 permissions=["compliance:manage","vulnerabilities:manage","reports:generate","audit:read"]),
            Role(tenant_id=tenant_id, name="auditor", display_name="Auditor", is_system=True,
                 permissions=["audit:read","reports:read","compliance:read"]),
        ]
        for role in roles:
            db.add(role)

        await db.commit()

        print("""
  â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
  â•‘           AEGIS â€” Setup Complete                       â•‘
  â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

  â”Œâ”€ Database â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚ Tables created successfully                              â”‚
  â”‚ Tenant + Admin + 8 roles initialized                     â”‚
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

  â”Œâ”€ Login Credentials â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚ Dashboard  : http://YOUR_IP:80                           â”‚
  â”‚ Email      : admin@AEGIS.com                            â”‚
  â”‚ Password   : Admin123!@#                                  â”‚
  â”‚ Tenant ID  : {tenant_id}             â”‚
  â”‚ Role       : super_admin                                â”‚
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

  â”Œâ”€ Agent Enrollment â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚ Registration Key : (set in backend/.env)                â”‚
  â”‚ Tenant ID        : {tenant_id}          â”‚
  â”‚                                                         â”‚
  â”‚ Linux/macOS:                                            â”‚
  â”‚   curl -sSL http://YOUR_IP:8000/deploy/install.sh | \   â”‚
  â”‚   bash -s -- --server http://YOUR_IP:8000 \              â”‚
  â”‚   --key YOUR_KEY --tenant {tenant_id} â”‚
  â”‚                                                         â”‚
  â”‚ Windows:                                                â”‚
  â”‚   .\\install.ps1 -Server http://YOUR_IP:8000 \           â”‚
  â”‚   -Key YOUR_KEY -Tenant {tenant_id}   â”‚
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

  âš   Change the admin password on first login!
""".format(tenant_id=tenant_id))


if __name__ == "__main__":
    asyncio.run(setup())
