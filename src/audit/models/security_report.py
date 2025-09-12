"""
SecurityReport model - Comprehensive audit report with executive summary
Aggregates all findings and provides stakeholder communication
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime
from uuid import uuid4
from enum import Enum


class ReportFormat(Enum):
    """Report output formats"""
    HTML = "HTML"
    PDF = "PDF"
    MARKDOWN = "Markdown"
    JSON = "JSON"


class ComplianceRating(Enum):
    """Overall compliance with security standards"""
    COMPLIANT = "Compliant"
    MOSTLY_COMPLIANT = "MostlyCompliant"
    PARTIALLY_COMPLIANT = "PartiallyCompliant"
    NON_COMPLIANT = "NonCompliant"


@dataclass
class SecurityReport:
    """
    Comprehensive security report entity with aggregation logic
    Consolidates all audit findings for stakeholder communication
    """
    # Required fields
    audit_date: datetime
    scope: str
    methodology: str
    findings_summary: Dict[str, int]
    total_findings: int
    risk_score: float
    
    # Optional fields
    id: str = field(default_factory=lambda: str(uuid4()))
    auditor: Optional[str] = None
    executive_summary: Optional[str] = None
    compliance_rating: Optional[ComplianceRating] = None
    key_recommendations: List[str] = field(default_factory=list)
    report_format: ReportFormat = ReportFormat.JSON
    generated_at: datetime = field(default_factory=datetime.now)
    version: str = "1.0"
    
    def __post_init__(self):
        """Validate security report data"""
        self._validate_findings_summary()
        self._validate_total_findings()
        self._validate_risk_score()
        self._validate_key_recommendations()
        self._calculate_compliance_rating()
    
    def _validate_findings_summary(self):
        """Validate findings summary counts match actual findings"""
        if not isinstance(self.findings_summary, dict):
            raise ValueError("Findings summary must be dictionary")
        
        # Expected severity levels
        expected_severities = ["Critical", "High", "Medium", "Low", "Info"]
        
        for severity in expected_severities:
            if severity not in self.findings_summary:
                self.findings_summary[severity] = 0
            
            if not isinstance(self.findings_summary[severity], int) or self.findings_summary[severity] < 0:
                raise ValueError(f"Findings count for {severity} must be non-negative integer")
    
    def _validate_total_findings(self):
        """Validate total findings equals sum of findings_summary values"""
        calculated_total = sum(self.findings_summary.values())
        
        if self.total_findings != calculated_total:
            raise ValueError(
                f"Total findings ({self.total_findings}) doesn't match sum of "
                f"findings_summary ({calculated_total})"
            )
    
    def _validate_risk_score(self):
        """Validate risk score is calculated from finding severities and CVSS scores"""
        if not isinstance(self.risk_score, (int, float)):
            raise ValueError("Risk score must be numeric")
        
        if not (0.0 <= self.risk_score <= 100.0):
            raise ValueError("Risk score must be 0-100")
    
    def _validate_key_recommendations(self):
        """Validate key recommendations reference actual findings"""
        if not isinstance(self.key_recommendations, list):
            raise ValueError("Key recommendations must be list")
        
        if len(self.key_recommendations) > 5:
            raise ValueError("Key recommendations limited to 5 items")
        
        for rec in self.key_recommendations:
            if not isinstance(rec, str) or not rec.strip():
                raise ValueError("Each recommendation must be non-empty string")
    
    def _calculate_compliance_rating(self):
        """Calculate overall compliance rating from findings distribution"""
        if self.compliance_rating is not None:
            return  # Already set
        
        # Compliance rating thresholds from contract tests
        critical_count = self.findings_summary.get("Critical", 0)
        high_count = self.findings_summary.get("High", 0)
        
        if critical_count >= 2 or high_count >= 16:
            self.compliance_rating = ComplianceRating.NON_COMPLIANT
        elif critical_count >= 1 or high_count >= 6:
            self.compliance_rating = ComplianceRating.PARTIALLY_COMPLIANT
        elif critical_count == 0 and high_count <= 5:
            if high_count <= 1:
                self.compliance_rating = ComplianceRating.COMPLIANT
            else:
                self.compliance_rating = ComplianceRating.MOSTLY_COMPLIANT
        else:
            self.compliance_rating = ComplianceRating.MOSTLY_COMPLIANT
    
    def calculate_weighted_risk_score(self) -> float:
        """
        Calculate weighted risk score from findings distribution
        Uses severity weights from executive summary research
        """
        # Severity weight factors from research.md
        severity_weights = {
            "Critical": 10.0,
            "High": 7.5,
            "Medium": 5.0,
            "Low": 2.5,
            "Info": 0.0
        }
        
        if self.total_findings == 0:
            return 0.0
        
        weighted_sum = 0.0
        for severity, count in self.findings_summary.items():
            weight = severity_weights.get(severity, 0.0)
            weighted_sum += count * weight
        
        # Normalize to 0-100 scale
        max_possible_score = self.total_findings * severity_weights["Critical"]
        if max_possible_score == 0:
            return 0.0
        
        normalized_score = (weighted_sum / max_possible_score) * 100
        self.risk_score = min(normalized_score, 100.0)
        
        return self.risk_score
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary from findings data"""
        if self.executive_summary:
            return self.executive_summary
        
        # Generate summary based on findings
        summary_parts = []
        
        # Overall assessment
        if self.compliance_rating == ComplianceRating.COMPLIANT:
            summary_parts.append("The security audit found LocalPass to be in good security standing.")
        elif self.compliance_rating == ComplianceRating.NON_COMPLIANT:
            summary_parts.append("The security audit identified critical security issues requiring immediate attention.")
        else:
            summary_parts.append("The security audit identified several security issues that should be addressed.")
        
        # Findings breakdown
        critical = self.findings_summary.get("Critical", 0)
        high = self.findings_summary.get("High", 0)
        
        if critical > 0:
            summary_parts.append(f"Found {critical} Critical severity issues requiring immediate remediation.")
        
        if high > 0:
            summary_parts.append(f"Identified {high} High severity vulnerabilities needing prompt attention.")
        
        # Risk assessment
        if self.risk_score >= 70:
            risk_level = "high"
        elif self.risk_score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        summary_parts.append(f"Overall security risk is assessed as {risk_level} (score: {self.risk_score:.1f}/100).")
        
        self.executive_summary = " ".join(summary_parts)
        return self.executive_summary
    
    def get_findings_by_severity(self, severity: str) -> int:
        """Get count of findings for specific severity level"""
        return self.findings_summary.get(severity, 0)
    
    def get_top_recommendations(self, limit: int = 3) -> List[str]:
        """Get top priority recommendations"""
        return self.key_recommendations[:limit]
    
    def to_dict(self) -> dict:
        """Convert security report to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "audit_date": self.audit_date.isoformat(),
            "auditor": self.auditor,
            "scope": self.scope,
            "methodology": self.methodology,
            "executive_summary": self.generate_executive_summary(),
            "findings_summary": self.findings_summary,
            "total_findings": self.total_findings,
            "risk_score": self.risk_score,
            "compliance_rating": self.compliance_rating.value if self.compliance_rating else None,
            "key_recommendations": self.key_recommendations,
            "report_format": self.report_format.value,
            "generated_at": self.generated_at.isoformat(),
            "version": self.version
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'SecurityReport':
        """Create security report from dictionary (JSON deserialization)"""
        audit_date = datetime.fromisoformat(data["audit_date"])
        generated_at = datetime.fromisoformat(data["generated_at"])
        
        report = cls(
            id=data["id"],
            audit_date=audit_date,
            auditor=data.get("auditor"),
            scope=data["scope"],
            methodology=data["methodology"],
            executive_summary=data.get("executive_summary"),
            findings_summary=data["findings_summary"],
            total_findings=data["total_findings"],
            risk_score=data["risk_score"],
            compliance_rating=ComplianceRating(data["compliance_rating"]) if data.get("compliance_rating") else None,
            key_recommendations=data.get("key_recommendations", []),
            report_format=ReportFormat(data["report_format"]),
            generated_at=generated_at,
            version=data.get("version", "1.0")
        )
        
        return report
    
    @classmethod
    def create_from_findings(cls, findings: List[dict], scope: str, methodology: str) -> 'SecurityReport':
        """
        Create security report from audit findings list
        Aggregates findings data into summary statistics
        """
        # Count findings by severity
        findings_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        
        for finding in findings:
            severity = finding.get("severity", "Info")
            if severity in findings_summary:
                findings_summary[severity] += 1
        
        total_findings = len(findings)
        
        # Create report instance
        report = cls(
            audit_date=datetime.now(),
            scope=scope,
            methodology=methodology,
            findings_summary=findings_summary,
            total_findings=total_findings,
            risk_score=0.0  # Will be calculated in post_init
        )
        
        # Calculate risk score
        report.calculate_weighted_risk_score()
        
        return report