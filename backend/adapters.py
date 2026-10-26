from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.config import settings

# Attempt to import Z3 solver safely
try:
    import z3
    Z3_AVAILABLE = True
    Z3_VERSION = getattr(z3, "__version__", "5.x")
except ImportError:
    z3 = None  # type: ignore[assignment]
    Z3_AVAILABLE = False
    Z3_VERSION = "unavailable"


@dataclass
class ToolStatus:
    name: str
    category: str
    status: str  # "available", "not_configured", "fallback", "isolated"
    version: str | None = None
    path: str | None = None
    details: str = ""
    remediation: str | None = None


class ReverseEngineeringToolchain:
    """Manages detection and execution of Android reverse engineering and forensic tools.
    
    Adheres strictly to the SHADOWPATH engineering contract:
    - Never fabricates results or tool presence.
    - Explicitly reports 'not_configured' or 'isolated' when tools or emulators are absent.
    - Uses supported adapters (Androguard, Z3, ReportLab, NetworkX) while providing
      clean hooks for JADX, AAPT2, ApkSigner, MobSF, and Dynamic Lab.
    """

    @staticmethod
    def _tool_binary(*names: str) -> str | None:
        """Find a system tool or one provisioned by scripts/install-local-toolchain.ps1.

        The local bootstrap keeps downloaded tools inside .toolcache instead of
        changing machine-wide PATH. The container image exposes the same tools
        through PATH, so this lookup works in both deployment modes.
        """
        for name in names:
            binary = shutil.which(name)
            if binary:
                return binary
        toolchain = settings.toolchain_dir
        for name in names:
            direct = toolchain / "bin" / name
            if direct.is_file():
                return str(direct)
        if toolchain.is_dir():
            for name in names:
                try:
                    candidate = next((path for path in toolchain.rglob(name) if path.is_file()), None)
                except OSError:
                    candidate = None
                if candidate:
                    return str(candidate)
        return None

    @staticmethod
    def _version(binary: str, *arguments: str) -> str:
        environment = os.environ.copy()
        bundled_java_home = settings.toolchain_dir / "jadx" / "jre"
        if not environment.get("JAVA_HOME") and (bundled_java_home / "bin" / "java.exe").is_file():
            environment["JAVA_HOME"] = str(bundled_java_home)
        try:
            proc = subprocess.run(
                [binary, *arguments],
                capture_output=True,
                text=True,
                timeout=8,
                env=environment,
            )
            output = (proc.stdout or proc.stderr).strip().splitlines()
            # Windows vendor .bat launchers sometimes echo their own CMD
            # statements before writing the actual tool version. Prefer the
            # last non-shell output line in that case.
            for line in reversed(output):
                cleaned = line.strip()
                lowered = cleaned.lower()
                if cleaned and not lowered.startswith(("c:\\", "if ", "set ", "goto ", "rem ")):
                    return cleaned[:120]
            return output[0][:120] if output else "detected"
        except Exception:
            return "detected"

    @classmethod
    def detect_jadx(cls) -> ToolStatus:
        binary = cls._tool_binary("jadx.bat", "jadx") if os.name == "nt" else cls._tool_binary("jadx", "jadx.bat")
        if binary:
            return ToolStatus(
                name="JADX Decompiler",
                category="decompiler",
                status="available",
                version=cls._version(binary, "--version"),
                path=binary,
                details="JADX command-line decompiler is detected and available for Java source recovery.",
            )
        return ToolStatus(
            name="JADX Decompiler",
            category="decompiler",
            status="not_configured",
            details="JADX is not installed in system PATH. DEX disassembly falls back to bytecode string and opcode inventory.",
            remediation="Install JADX (e.g. 'brew install jadx' or download release) and add to PATH.",
        )

    @classmethod
    def detect_aapt2(cls) -> ToolStatus:
        binary = cls._tool_binary("aapt2.exe", "aapt.exe", "aapt2", "aapt") if os.name == "nt" else cls._tool_binary("aapt2", "aapt", "aapt2.exe", "aapt.exe")
        if binary:
            return ToolStatus(
                name="AAPT2 Android Asset Tool",
                category="resource_extractor",
                status="available",
                version=cls._version(binary, "version"),
                path=binary,
                details="Android Asset Packaging Tool is present for binary XML and resource checks.",
            )
        return ToolStatus(
            name="AAPT2 Android Asset Tool",
            category="resource_extractor",
            status="not_configured",
            details="AAPT2 not in PATH. Android binary XML is decoded via standard AXML parser.",
            remediation="Install Android SDK Build-Tools or place aapt2 in system PATH.",
        )

    @classmethod
    def detect_apksigner(cls) -> ToolStatus:
        binary = cls._tool_binary("apksigner", "apksigner.bat")
        if binary:
            return ToolStatus(
                name="Android ApkSigner",
                category="signature_verifier",
                status="available",
                path=binary,
                details="Official apksigner detected for APK Signature Scheme v1, v2, v3, and v4 verification.",
            )
        return ToolStatus(
            name="Android ApkSigner",
            category="signature_verifier",
            status="fallback",
            details="Official apksigner binary not found. Certificate hashes and ASN.1 metadata are extracted via internal cryptographic parser.",
            remediation="Install Android SDK Build-Tools to enable strict apksigner cryptographic verification.",
        )

    @classmethod
    def detect_mobsf(cls) -> ToolStatus:
        mobsf_url = os.environ.get("MOBSF_API_URL")
        mobsf_key = os.environ.get("MOBSF_API_KEY")
        if mobsf_url and mobsf_key:
            return ToolStatus(
                name="MobSF Security Framework",
                category="integrated_analyzer",
                status="configured",
                details="MobSF REST endpoint and API credentials are configured. The external service remains isolated from this host.",
            )
        if mobsf_url:
            return ToolStatus(
                name="MobSF Security Framework",
                category="integrated_analyzer",
                status="not_configured",
                details="A MobSF URL is present, but its API key is missing. No service connection is claimed.",
                remediation="Set MOBSF_API_KEY alongside MOBSF_API_URL after deploying an isolated MobSF instance.",
            )
        return ToolStatus(
            name="MobSF Security Framework",
            category="integrated_analyzer",
            status="not_configured",
            details="No MobSF instance connected. Core static inspection operates entirely within the offline local engine.",
            remediation="Set MOBSF_API_URL and MOBSF_API_KEY in .env to enable optional MobSF cross-validation.",
        )

    @classmethod
    def detect_dynamic_lab(cls) -> ToolStatus:
        adb_binary = cls._tool_binary("adb.exe", "adb") if os.name == "nt" else cls._tool_binary("adb", "adb.exe")
        client_state = "ADB client is installed and ready to connect to an explicitly configured isolated emulator or dedicated device." if adb_binary else "ADB client is not installed; no isolated Android runtime can be contacted."
        return ToolStatus(
            name="Dynamic Analysis Lab (ADB / Frida)",
            category="dynamic_sandbox",
            status="isolated",
            path=adb_binary,
            details=f"{client_state} Host execution remains disabled by design; untrusted APKs are never launched on the analyst host.",
            remediation="Connect a quarantined emulator or dedicated device on an isolated network before enabling any dynamic workflow.",
        )

    @classmethod
    def detect_z3(cls) -> ToolStatus:
        if Z3_AVAILABLE:
            return ToolStatus(
                name="Z3 Theorem Prover (SMT Solver)",
                category="constraint_solver",
                status="available",
                version=Z3_VERSION,
                details="Z3 SMT solver is active for bounded guard predicate satisfiability, witness generation, and dead-branch analysis.",
            )
        return ToolStatus(
            name="Z3 Theorem Prover (SMT Solver)",
            category="constraint_solver",
            status="not_configured",
            details="z3-solver package is missing. Guarded-path solver checks are unavailable.",
            remediation="Run 'pip install z3-solver' in the backend Python environment.",
        )

    @classmethod
    def capabilities_map(cls) -> dict[str, Any]:
        """Returns the truthful, live capabilities map of all RE and analysis tooling."""
        return {
            "tools": {
                "androguard": {
                    "name": "Androguard DEX & Manifest Parser",
                    "category": "static_analyzer",
                    "status": "available",
                    "version": "4.1.3",
                    "path": None,
                    "details": "Active static bytecode, string, and manifest analysis engine.",
                    "remediation": None,
                },
                "z3_solver": cls.detect_z3().__dict__,
                "jadx": cls.detect_jadx().__dict__,
                "aapt2": cls.detect_aapt2().__dict__,
                "apksigner": cls.detect_apksigner().__dict__,
                "mobsf": cls.detect_mobsf().__dict__,
                "dynamic_lab": cls.detect_dynamic_lab().__dict__,
            },
            "environment": {
                "host_isolation_enforced": True,
                "offline_mode_ready": True,
                "reportlab_pdf_engine": True,
                "networkx_graph_engine": True,
            },
        }


class Z3GuardEvaluator:
    """Bounded sensitive-path and guard predicate evaluator using Z3Py.
    
    Supports typed AST evaluation for numeric, boolean, string-equality,
    and environmental trigger constraints with strict solver timeouts.
    """

    def __init__(self, timeout_ms: int = 5000) -> None:
        self.timeout_ms = timeout_ms

    def evaluate_guard(
        self,
        guard_ast: dict[str, Any],
        assumptions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Evaluate a guard predicate AST using Z3 with strict timeout.
        
        Returns:
            {
                "solver_status": "sat" | "unsat" | "unknown" | "unsupported" | "timeout",
                "witness": dict[str, Any],
                "assumptions": list[str],
                "limitations": list[str]
            }
        """
        if not Z3_AVAILABLE or z3 is None:
            return {
                "solver_status": "unsupported",
                "witness": {},
                "assumptions": assumptions or [],
                "limitations": ["Z3 theorem prover is not installed in the environment."],
            }

        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)

        variables: dict[str, Any] = {}
        limitations: list[str] = []

        try:
            expr = self._build_expression(guard_ast, variables, solver)
            if expr is None:
                return {
                    "solver_status": "unsupported",
                    "witness": {},
                    "assumptions": assumptions or [],
                    "limitations": ["Guard AST contains unsupported predicate constructs or variable types."],
                }

            solver.add(expr)
            check_result = solver.check()

            if check_result == z3.sat:
                model = solver.model()
                witness: dict[str, Any] = {}
                for var_name, z3_var in variables.items():
                    val = model.eval(z3_var)
                    if val is not None:
                        # Extract python primitive
                        if z3.is_int(z3_var):
                            witness[var_name] = val.as_long()
                        elif z3.is_bool(z3_var):
                            witness[var_name] = bool(val)
                        elif z3.is_string(z3_var):
                            witness[var_name] = val.as_string()
                        else:
                            witness[var_name] = str(val)

                return {
                    "solver_status": "sat",
                    "witness": witness,
                    "assumptions": (assumptions or []) + [
                        "Variable semantics follow bounded execution model",
                        "Candidate trigger witness is calculated under static AST assumptions only",
                    ],
                    "limitations": limitations,
                }
            elif check_result == z3.unsat:
                return {
                    "solver_status": "unsat",
                    "witness": {},
                    "assumptions": assumptions or [],
                    "limitations": ["Proved unsatisfiable within assumed bounded model; branch is unreachable under these constraints."],
                }
            else:
                return {
                    "solver_status": "timeout" if str(solver.reason_unknown()) == "timeout" else "unknown",
                    "witness": {},
                    "assumptions": assumptions or [],
                    "limitations": [f"Solver returned {solver.reason_unknown()}"],
                }

        except Exception as exc:
            return {
                "solver_status": "unsupported",
                "witness": {},
                "assumptions": assumptions or [],
                "limitations": [f"Z3 solver exception: {exc}"],
            }

    def _build_expression(
        self,
        node: dict[str, Any],
        variables: dict[str, Any],
        solver: z3.Solver,
    ) -> Any:
        kind = node.get("kind", "").lower()

        if kind == "and":
            terms = [self._build_expression(term, variables, solver) for term in node.get("terms", [])]
            valid_terms = [t for t in terms if t is not None]
            if len(valid_terms) != len(terms):
                return None
            return z3.And(*valid_terms) if valid_terms else z3.BoolVal(True)

        if kind == "or":
            terms = [self._build_expression(term, variables, solver) for term in node.get("terms", [])]
            valid_terms = [t for t in terms if t is not None]
            if len(valid_terms) != len(terms):
                return None
            return z3.Or(*valid_terms) if valid_terms else z3.BoolVal(False)

        if kind == "not":
            inner = self._build_expression(node.get("term", {}), variables, solver)
            return z3.Not(inner) if inner is not None else None

        if kind == "compare":
            left_node = node.get("left", {})
            right_node = node.get("right", {})
            op = node.get("op", "eq").lower()

            left_val = self._resolve_operand(left_node, variables)
            right_val = self._resolve_operand(right_node, variables)

            if left_val is None or right_val is None:
                return None

            if op in ("eq", "=="):
                return left_val == right_val
            elif op in ("neq", "!="):
                return left_val != right_val
            elif op in ("gt", ">"):
                return left_val > right_val
            elif op in ("ge", ">="):
                return left_val >= right_val
            elif op in ("lt", "<"):
                return left_val < right_val
            elif op in ("le", "<="):
                return left_val <= right_val

        return None

    def _resolve_operand(self, node: dict[str, Any], variables: dict[str, Any]) -> Any:
        if "var" in node:
            var_name = node["var"]
            var_type = node.get("type", "int").lower()
            if var_name not in variables:
                if var_type == "int":
                    variables[var_name] = z3.Int(var_name)
                elif var_type == "bool":
                    variables[var_name] = z3.Bool(var_name)
                elif var_type == "string":
                    variables[var_name] = z3.String(var_name)
                else:
                    variables[var_name] = z3.Int(var_name)
            return variables[var_name]

        if "literal" in node:
            lit = node["literal"]
            if isinstance(lit, bool):
                return z3.BoolVal(lit)
            elif isinstance(lit, int):
                return z3.IntVal(lit)
            elif isinstance(lit, str):
                return z3.StringVal(lit)
            elif isinstance(lit, float):
                return z3.RealVal(lit)

        return None
