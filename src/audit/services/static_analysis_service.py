"""
Static Analysis Service - Security scanning with bandit and semgrep
Implements Phase 1 of the audit workflow from quickstart.md
"""
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..models import AuditFinding, Severity, Status


class StaticAnalysisService:
    """Service for running static security analysis tools"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.tools_available = self._check_tool_availability()
    
    def _check_tool_availability(self) -> Dict[str, bool]:
        """Check which static analysis tools are available"""
        tools = {}
        
        # Check bandit
        try:
            result = subprocess.run(['bandit', '--version'], 
                                  capture_output=True, text=True, check=False)
            tools['bandit'] = result.returncode == 0
        except FileNotFoundError:
            tools['bandit'] = False
        
        # Check semgrep  
        try:
            result = subprocess.run(['semgrep', '--version'],
                                  capture_output=True, text=True, check=False)
            tools['semgrep'] = result.returncode == 0
        except FileNotFoundError:
            tools['semgrep'] = False
        
        return tools
    
    def run_static_analysis(self, target_path: str, config_path: str, output_path: str) -> Dict[str, Any]:
        """
        Run comprehensive static analysis workflow from quickstart
        Matches: uv run python -m audit_engine scan --target-path . --config ... --output ...
        """
        target = Path(target_path)
        config = Path(config_path) 
        output = Path(output_path)
        
        # Validate inputs
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")
        
        if not config.exists():
            raise FileNotFoundError(f"Config file does not exist: {config_path}")
        
        # Create output directory if needed
        output.parent.mkdir(parents=True, exist_ok=True)
        
        # Load config
        with open(config) as f:
            audit_config = json.load(f)
        
        # Run analysis tools
        findings = []
        errors = []
        
        if self.tools_available.get('bandit', False):
            try:
                bandit_findings = self.run_bandit_scan(target_path)
                findings.extend(bandit_findings)
            except Exception as e:
                errors.append(f"Bandit scan failed: {str(e)}")
        
        if self.tools_available.get('semgrep', False):
            try:
                semgrep_findings = self.run_semgrep_scan(target_path)
                findings.extend(semgrep_findings)
            except Exception as e:
                errors.append(f"Semgrep scan failed: {str(e)}")
        
        # Consolidate findings
        consolidated_findings = self.consolidate_findings(findings)
        
        # Filter by severity threshold
        threshold = audit_config.get('severity_threshold', 'Info')
        filtered_findings = self._filter_by_severity(consolidated_findings, threshold)
        
        # Save results
        results = {
            'scan_type': 'static_analysis',
            'target_path': target_path,
            'findings_count': len(filtered_findings),
            'findings': [f.to_dict() for f in filtered_findings],
            'errors': errors,
            'generated_at': datetime.now().isoformat(),
            'tools_used': [tool for tool, available in self.tools_available.items() if available]
        }
        
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def run_bandit_scan(self, target_path: str) -> List[Dict[str, Any]]:
        """Run bandit security scanner"""
        if not self.tools_available.get('bandit', False):
            raise RuntimeError("Bandit is not available")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            # Run bandit with JSON output
            cmd = [
                'bandit', 
                '-r', target_path,
                '-f', 'json',
                '-o', tmp_path,
                '-c', '.bandit'  # Use bandit config file
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            # Bandit returns non-zero exit codes when findings are found
            if result.returncode not in [0, 1]:
                raise RuntimeError(f"Bandit failed: {result.stderr}")
            
            # Parse bandit output
            with open(tmp_path, 'r') as f:
                bandit_data = json.load(f)
            
            return bandit_data.get('results', [])
            
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    
    def run_semgrep_scan(self, target_path: str) -> List[Dict[str, Any]]:
        """Run semgrep pattern-based analysis"""
        if not self.tools_available.get('semgrep', False):
            raise RuntimeError("Semgrep is not available")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            # Run semgrep with auto config
            cmd = [
                'semgrep',
                '--config=auto',
                '--json',
                f'--output={tmp_path}',
                target_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode not in [0, 1]:
                raise RuntimeError(f"Semgrep failed: {result.stderr}")
            
            # Parse semgrep output
            with open(tmp_path, 'r') as f:
                semgrep_data = json.load(f)
            
            return semgrep_data.get('results', [])
            
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    
    def consolidate_findings(self, raw_findings: List[Dict[str, Any]]) -> List[AuditFinding]:
        """Convert tool findings to AuditFinding objects"""
        consolidated = []
        
        for raw_finding in raw_findings:
            try:
                finding = self._convert_to_audit_finding(raw_finding)
                if finding:
                    consolidated.append(finding)
            except Exception as e:
                # Log but don't fail the entire scan
                print(f"Warning: Could not convert finding: {e}")
        
        return consolidated
    
    def _convert_to_audit_finding(self, raw_finding: Dict[str, Any]) -> Optional[AuditFinding]:
        """Convert raw tool finding to AuditFinding object"""
        # Determine tool source
        if 'test_name' in raw_finding:
            return self._convert_bandit_finding(raw_finding)
        elif 'check_id' in raw_finding:
            return self._convert_semgrep_finding(raw_finding)
        else:
            return None
    
    def _convert_bandit_finding(self, bandit_finding: Dict[str, Any]) -> AuditFinding:
        """Convert bandit finding to AuditFinding"""
        # Map bandit severity to our enum
        severity_mapping = {
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM, 
            'LOW': Severity.LOW
        }
        
        severity = severity_mapping.get(bandit_finding.get('issue_severity', 'LOW'), Severity.LOW)
        
        # Map severity to CVSS score
        cvss_mapping = {
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.0
        }
        
        return AuditFinding(
            severity=severity,
            cvss_score=cvss_mapping[severity],
            title=f"Bandit: {bandit_finding.get('test_name', 'Security Issue')}",
            description=bandit_finding.get('issue_text', ''),
            file_path=bandit_finding.get('filename', ''),
            line_number=bandit_finding.get('line_number'),
            code_snippet=bandit_finding.get('code', ''),
            discovered_by='bandit',
            discovered_at=datetime.now(),
            remediation=bandit_finding.get('issue_text', ''),  # Use issue text as basic remediation
            references=[
                f"https://bandit.readthedocs.io/en/latest/plugins/{bandit_finding.get('test_id', 'index')}.html"
            ] if bandit_finding.get('test_id') else []
        )
    
    def _convert_semgrep_finding(self, semgrep_finding: Dict[str, Any]) -> AuditFinding:
        """Convert semgrep finding to AuditFinding"""
        # Default to medium severity for semgrep findings
        severity = Severity.MEDIUM
        cvss_score = 5.0
        
        # Try to extract severity from semgrep metadata
        extra = semgrep_finding.get('extra', {})
        metadata = extra.get('metadata', {})
        
        if 'severity' in metadata:
            sem_severity = metadata['severity'].upper()
            severity_mapping = {
                'ERROR': Severity.HIGH,
                'WARNING': Severity.MEDIUM,
                'INFO': Severity.LOW
            }
            severity = severity_mapping.get(sem_severity, Severity.MEDIUM)
            
            cvss_mapping = {
                Severity.HIGH: 7.5,
                Severity.MEDIUM: 5.0,
                Severity.LOW: 2.0
            }
            cvss_score = cvss_mapping[severity]
        
        # Extract location info
        start = semgrep_finding.get('start', {})
        
        return AuditFinding(
            severity=severity,
            cvss_score=cvss_score,
            title=f"Semgrep: {semgrep_finding.get('check_id', 'Pattern Match')}",
            description=extra.get('message', ''),
            file_path=semgrep_finding.get('path', ''),
            line_number=start.get('line'),
            discovered_by='semgrep',
            discovered_at=datetime.now(),
            remediation=metadata.get('fix_regex', ''),  # Use fix regex if available
            references=metadata.get('references', []) if isinstance(metadata.get('references'), list) else []
        )
    
    def _filter_by_severity(self, findings: List[AuditFinding], threshold: str) -> List[AuditFinding]:
        """Filter findings by minimum severity threshold"""
        severity_order = [
            'Info', 'Low', 'Medium', 'High', 'Critical'
        ]
        
        try:
            min_index = severity_order.index(threshold)
        except ValueError:
            min_index = 0  # Default to Info if invalid threshold
        
        filtered = []
        for finding in findings:
            finding_index = severity_order.index(finding.severity.value)
            if finding_index >= min_index:
                filtered.append(finding)
        
        return filtered
    
    def validate_output(self, output_path: str) -> bool:
        """Validate static analysis output file"""
        try:
            output = Path(output_path)
            if not output.exists():
                return False
            
            with open(output) as f:
                data = json.load(f)
            
            # Check required fields
            required_fields = ['findings_count', 'findings', 'generated_at']
            if not all(field in data for field in required_fields):
                return False
            
            # Check findings structure
            findings = data['findings']
            if not isinstance(findings, list):
                return False
            
            for finding in findings:
                if not isinstance(finding, dict):
                    return False
                
                # Check AuditFinding required fields
                required_finding_fields = [
                    'id', 'severity', 'cvss_score', 'title', 
                    'description', 'file_path', 'discovered_at', 'status'
                ]
                if not all(field in finding for field in required_finding_fields):
                    return False
            
            return True
            
        except (json.JSONDecodeError, KeyError, TypeError):
            return False


# Module-level functions for integration tests

def run_static_analysis(target_path: str, config_path: str, output_path: str) -> Dict[str, Any]:
    """Module-level function for integration test compatibility"""
    service = StaticAnalysisService()
    return service.run_static_analysis(target_path, config_path, output_path)


def validate_output(output_path: str) -> bool:
    """Module-level function for integration test compatibility"""
    service = StaticAnalysisService()
    return service.validate_output(output_path)