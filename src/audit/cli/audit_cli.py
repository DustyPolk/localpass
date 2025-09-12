"""
Main audit CLI command with subcommands
Provides command-line interface for security audit functionality
"""
import typer
import json
from pathlib import Path
from typing import Optional

from ..services.static_analysis_service import StaticAnalysisService

app = typer.Typer(
    name="audit",
    help="LocalPass Security Audit Tool",
    add_completion=False
)


@app.command()
def scan(
    target_path: str = typer.Option(
        ".",
        "--target-path",
        help="Path to LocalPass project directory to scan"
    ),
    config: Optional[str] = typer.Option(
        None,
        "--config",
        help="Path to audit configuration file"
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", 
        help="Output file path for findings"
    ),
    format: str = typer.Option(
        "json",
        "--format",
        help="Output format (json, html, markdown)"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output"
    )
):
    """Run comprehensive security scan"""
    
    # Set defaults
    if config is None:
        config = "audit-workspace/configs/audit-config.json"
    
    if output is None:
        output = "audit-workspace/findings/static-analysis.json"
    
    # Validate inputs
    target = Path(target_path)
    if not target.exists():
        typer.echo(f"❌ Target path does not exist: {target_path}", err=True)
        raise typer.Exit(1)
    
    config_path = Path(config)
    if not config_path.exists():
        typer.echo(f"❌ Config file does not exist: {config}", err=True)
        raise typer.Exit(1)
    
    if verbose:
        typer.echo(f"🔍 Starting security scan...")
        typer.echo(f"   Target: {target_path}")
        typer.echo(f"   Config: {config}")
        typer.echo(f"   Output: {output}")
    
    # Run static analysis
    try:
        service = StaticAnalysisService()
        result = service.run_static_analysis(
            target_path=str(target.absolute()),
            config_path=str(config_path.absolute()),
            output_path=output
        )
        
        # Display results
        findings_count = result['findings_count']
        tools_used = result['tools_used']
        errors = result.get('errors', [])
        
        if findings_count == 0:
            typer.echo("✅ No security issues found")
        else:
            typer.echo(f"🔍 Found {findings_count} security findings")
        
        if verbose:
            typer.echo(f"   Tools used: {', '.join(tools_used)}")
            if errors:
                typer.echo(f"   Warnings: {len(errors)}")
                for error in errors:
                    typer.echo(f"     - {error}")
        
        typer.echo(f"📄 Results saved to: {output}")
        
    except Exception as e:
        typer.echo(f"❌ Scan failed: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def report(
    findings: str = typer.Option(
        "audit-workspace/findings/*.json",
        "--findings",
        help="Pattern for findings files to include"
    ),
    format: str = typer.Option(
        "html",
        "--format",
        help="Report format (html, pdf, json, markdown)"
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        help="Output file path for report"
    ),
    template: str = typer.Option(
        "comprehensive",
        "--template",
        help="Report template (comprehensive, executive, technical)"
    )
):
    """Generate security audit report"""
    
    if output is None:
        output = f"audit-workspace/reports/security-report.{format.lower()}"
    
    typer.echo(f"📊 Generating {format.upper()} report...")
    typer.echo(f"   Findings: {findings}")
    typer.echo(f"   Template: {template}")
    typer.echo(f"   Output: {output}")
    
    # Placeholder implementation
    typer.echo("⚠️  Report generation not yet implemented")
    typer.echo("   This will be implemented in the report generator service")


@app.command()
def version():
    """Show audit tool version"""
    typer.echo("LocalPass Security Audit Tool v1.1.0")


if __name__ == "__main__":
    app()