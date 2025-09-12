"""
Security audit models package
Core entities for security audit findings, assessments, and reports
"""

from .audit_finding import AuditFinding, Severity, Status, validate_references
from .vulnerability_assessment import VulnerabilityAssessment, AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, Impact
from .security_control import SecurityControl, ControlCategory, Effectiveness, detect_localpass_controls, assess_control_effectiveness, map_compliance_standards
from .threat_vector import ThreatVector, RiskLevel, RiskRating
from .compliance_gap import ComplianceGap, ComplianceStatus, RemediationEffort
from .remediation_plan import RemediationPlan, PlanStatus  
from .security_report import SecurityReport, ReportFormat, ComplianceRating

__all__ = [
    # Core entities
    'AuditFinding',
    'VulnerabilityAssessment', 
    'SecurityControl',
    'ThreatVector',
    'ComplianceGap',
    'RemediationPlan',
    'SecurityReport',
    
    # Enums
    'Severity',
    'Status',
    'AttackVector',
    'AttackComplexity',
    'PrivilegesRequired',
    'UserInteraction', 
    'Scope',
    'Impact',
    'ControlCategory',
    'Effectiveness',
    'RiskLevel',
    'RiskRating',
    'ComplianceStatus',
    'RemediationEffort',
    'PlanStatus',
    'ReportFormat',
    'ComplianceRating',
    
    # Utility functions
    'validate_references',
    'detect_localpass_controls',
    'assess_control_effectiveness',
    'map_compliance_standards'
]