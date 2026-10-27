"""RedScout CLI - full entry point."""
import concurrent.futures
import typer
from rich.console import Console
import yaml
import datetime
import os
from pathlib import Path

from .scope_guard import ScopeGuard, ScopeError
from .audit import AuditLog
from .plugins.registry import discover
from .workflow import WorkflowEngine
from .graph_engine import AttackGraph
from .vault import EvidenceVault
from .pdf_report import generate
from .ai_copilot import AICopilot

app = typer.Typer(help="RedScout - Ethical Red Team Orchestration")
console = Console()


def run_scan(scope: str, target: str, workflow: str = None, report: str = "report.pdf", notify: bool = False, ports: str = "1-1000", only: str = None):
    audit = AuditLog("audit.log")
    vault = EvidenceVault("vault")
    plugins = discover()

    if only:
        selected = [p.strip() for p in only.split(",")]
        plugins = {k: v for k, v in plugins.items() if k in selected}
        console.print(f"[yellow]⚡ Fast Mode: Running only {', '.join(plugins.keys())}[/yellow]")

    try:
        guard = ScopeGuard(scope)
        guard.check_target(target)
        audit.log("scan_start", target=target)
        console.print(f"[green]✓[/green] Scope OK → {target}")
        console.print(f"[cyan]Plugins:[/cyan] {', '.join(plugins.keys())}")

        if workflow:
            engine = WorkflowEngine(plugins)
            results = engine.run(workflow, target, guard, audit, vault)
        else:
            results = []
            # --- අලුත් කොටස: Parallel Execution (Multithreading) ---
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_plugin = {}
                for name, plugin in plugins.items():
                    if guard.is_technique_allowed(plugin.technique):
                        # Nmap එකට විතරක් ports pass කරනවා
                        if name == "nmap":
                            future = executor.submit(plugin.run, target, ports=ports)
                        else:
                            future = executor.submit(plugin.run, target)
                        future_to_plugin[future] = name
                
                for future in concurrent.futures.as_completed(future_to_plugin):
                    name = future_to_plugin[future]
                    try:
                        r = future.result()
                        results.append({"plugin": name, **r})
                        vault.add("finding", target, r.get("findings", []))
                    except Exception as exc:
                        console.print(f"[red]✗ Plugin {name} generated an exception: {exc}[/red]")
            # --------------------------------------------------------

        all_findings = [f for r in results for f in r.get("findings", [])]

        graph = AttackGraph()
        graph.add_host(target)
        for r in results:
            for f in r.get("findings", []):
                if "service" in f:
                    graph.add_service(target, f["service"], f.get("port", "?"))
                
                # --- : Findings ටික Graph එකට දාමු ---
                if "name" in f and f["name"] != "Information Gathered":
                    # හැම finding එකක්ම වගේ vulnerability එකක් විදියට count කරමු
                    vuln_name = f.get("name", "Unknown Finding")
                    sev = f.get("severity", "Info")
                    graph.add_vulnerability(f"{target}:{f.get('target', 'web')}", vuln_name, sev)
                # ------------------------------------------------
        all_findings = [f for r in results for f in r.get("findings", [])]

        # --- අලුත් කොටස: Graph එක හදමු ---
        graph = AttackGraph()
        graph.add_host(target)
        for r in results:
            for f in r.get("findings", []):
                if "service" in f:
                    graph.add_service(target, f["service"], f.get("port", "?"))
                
                # Findings ටික Graph එකට Vulnerability විදියට දාමු
                if "name" in f and f["name"] != "Information Gathered":
                    vuln_name = f.get("name", "Unknown Finding")
                    sev = f.get("severity", "Info")
                    graph.add_vulnerability(f"{target}:{f.get('target', 'web')}", vuln_name, sev)

        summary = graph.summary()
        summary["techniques"] = [
            plugins[r["plugin"]].technique for r in results if r["plugin"] in plugins
        ]
        # ------------------------------------

        ai = AICopilot()
        exec_summary = ai.write_executive_summary(summary, all_findings)
        ai = AICopilot()
        exec_summary = ai.write_executive_summary(summary, all_findings)

        path = generate(report, summary, all_findings, exec_summary)
        console.print(f"[green]✓[/green] Report: {path}")
        console.print(f"[green]✓[/green] Vault chain valid: {vault.verify_chain()}")

        audit.log("scan_done", findings=len(all_findings))

        return path

    except ScopeError as e:
        audit.log("scope_violation", target=target, error=str(e))
        console.print(f"[red]✗ Scope violation:[/red] {e}")
        raise


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t"),
    scope: str = typer.Option(None, "--scope", "-s"),
    workflow: str = typer.Option(None, "--workflow", "-w"),
    report: str = typer.Option(None, "--report", "-r"), 
    notify: bool = typer.Option(False, "--notify", "-n"),
    ports: str = typer.Option("1-1000", "--ports", "-p"),
    only: str = typer.Option(None, "--only"),
):
    # Report නම හදාගන්න (Unique file names)
    # Report නම හදාගන්න (Safe file names)
    if not report:
        import re
        import urllib.parse
        
        # Target එකෙන් Domain එක විතරක් වෙන් කරගන්න (උදා: https://www.gov.lk/... -> www.gov.lk)
        parsed = urllib.parse.urlparse(target if target.startswith('http') else f'http://{target}')
        domain = parsed.netloc if parsed.netloc else target
        
        # Domain එකේ තියෙන අමුතු අකුරු ඔක්කොම _ කරන්න
        safe_target = re.sub(r'[^a-zA-Z0-9_-]', '_', domain)
        
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report = f"reports/report_{safe_target}_{now}.pdf"
        os.makedirs("reports", exist_ok=True)
    
    # Auto-Scope feature
    if not scope:
        now = datetime.datetime.now(datetime.timezone.utc)
        scope_data = {
            "authorized_by": "CLI Auto-Scope",
            "valid_from": (now - datetime.timedelta(hours=1)).isoformat(),
            "valid_until": (now + datetime.timedelta(hours=1)).isoformat(),
            "targets": [target],
            "allowed_techniques": ["port_scan", "web_vuln_scan", "subdomain_enum", "dns_enum", "whois_lookup", "web_fuzzing"]
        }
        temp_dir = Path("scopes")
        temp_dir.mkdir(exist_ok=True)
        import re
        safe_target_name = re.sub(r'[^a-zA-Z0-9]', '_', target)
        temp_scope_path = temp_dir / f"temp_{safe_target_name}.yaml"
        with open(temp_scope_path, "w") as f:
            yaml.dump(scope_data, f, default_flow_style=False)
        scope = str(temp_scope_path)
        console.print(f"[yellow]⚠ Auto-scope generated for {target}[/yellow]")

    try:
        run_scan(scope, target, workflow, report, notify, ports, only)
    except ScopeError:
        raise typer.Exit(code=2)


@app.command()
def dashboard(port: int = 8000):
    """Run the web dashboard."""
    import uvicorn
    uvicorn.run("redscout.web_dashboard:app", host="0.0.0.0", port=port)


@app.command()
def verify_vault(path: str = "vault"):
    """Verify evidence vault integrity."""
    v = EvidenceVault(path)
    ok = v.verify_chain()
    console.print(f"[{'green' if ok else 'red'}]Vault chain valid: {ok}[/]")


if __name__ == "__main__":
    app()