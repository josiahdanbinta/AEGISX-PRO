#!/usr/bin/env python3
"""AEGISX Startup Diagnostic — logs exact import failures."""
import sys, traceback

print("=== AEGISX Startup Diagnostic ===")

modules = [
    ("config", "app.core.config"),
    ("security", "app.core.security"),
    ("database", "app.core.database"),
    ("cache", "app.core.cache"),
    ("exceptions", "app.core.exceptions"),
    ("exception_handlers", "app.core.exception_handlers"),
    ("middleware", "app.middleware"),
    ("models", "app.models"),
    ("deps", "app.api.deps"),
    ("router", "app.api.v1.router"),
    ("ai-llm", "app.ai.llm"),
    ("ai-services", "app.ai.services"),
]

failed = []
for name, module in modules:
    try:
        __import__(module)
        print(f"  ✓ {name}")
    except Exception as e:
        print(f"  ✗ {name}: {e}")
        failed.append((name, str(e)))

if failed:
    print(f"\n=== {len(failed)} IMPORT FAILURES ===")
    for name, err in failed:
        print(f"  {name}: {err}")
    sys.exit(1)

# Try creating the app
print("\n=== Creating FastAPI app ===")
try:
    from app.main import app
    print("  ✓ App created successfully")
except Exception as e:
    print(f"  ✗ App creation failed: {e}")
    traceback.print_exc()
    sys.exit(1)

print("\n=== ALL CHECKS PASSED ===")
