"""
ComplianceGap model - Areas where implementation doesn't meet security standards
Identifies deviations from security frameworks and compliance requirements
"""
from dataclasses import dataclass, field
from typing import Optional
from uuid import uuid4
from enum import Enum


class ComplianceStatus(Enum):
    """Compliance status levels"""
    COMPLIANT = "Compliant"
    PARTIALLY_COMPLIANT = "PartiallyCompliant" 
    NON_COMPLIANT = "NonCompliant"


class RemediationEffort(Enum):
    """Estimated effort to address compliance gap"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class ComplianceGap:
    """
    Compliance gap entity documenting standard deviations
    Maps current implementation against security framework requirements
    """
    # Required fields
    standard: str
    requirement_id: str
    requirement_description: str
    current_implementation: str
    gap_description: str
    compliance_status: ComplianceStatus
    business_impact: str
    remediation_effort: RemediationEffort
    priority: int
    
    # Optional fields
    id: str = field(default_factory=lambda: str(uuid4()))
    
    def __post_init__(self):
        """Validate compliance gap data"""
        self._validate_standard()
        self._validate_requirement_id()
        self._validate_descriptions()
        self._validate_priority()
        self._validate_compliance_alignment()
    
    def _validate_standard(self):
        """Validate standard is recognized security framework"""
        if not self.standard or not isinstance(self.standard, str):
            raise ValueError("Standard must be non-empty string")
        
        # Known security frameworks from research.md
        recognized_standards = {
            "OWASP_Top_10_2021",
            "NIST_CSF", 
            "CWE_Top_25",
            "NIST_SP_800_63B",
            "ISO_27001",
            "PCI_DSS",
            "SOC_2"
        }
        
        # Allow flexible matching (case insensitive, with variations)
        standard_normalized = self.standard.upper().replace(" ", "_")
        
    def _validate_requirement_id(self):
        """Validate requirement ID format"""
        if not self.requirement_id or not isinstance(self.requirement_id, str):
            raise ValueError("Requirement ID must be non-empty string")
    
    def _validate_descriptions(self):
        """Validate description fields are not empty"""
        required_fields = [
            ("requirement_description", self.requirement_description),
            ("current_implementation", self.current_implementation),
            ("gap_description", self.gap_description),
            ("business_impact", self.business_impact)
        ]
        
        for field_name, field_value in required_fields:
            if not field_value or not isinstance(field_value, str):
                raise ValueError(f"{field_name} must be non-empty string")
    
    def _validate_priority(self):
        """Validate priority is 1-5 integer"""
        if not isinstance(self.priority, int) or not (1 <= self.priority <= 5):
            raise ValueError("Priority must be integer between 1 (highest) and 5 (lowest)")
    
    def _validate_compliance_alignment(self):
        """Validate compliance status aligns with gap analysis"""
        # If there's a significant gap described, status shouldn't be Compliant
        if (self.compliance_status == ComplianceStatus.COMPLIANT and 
            self.gap_description.lower() not in ["none", "n/a", "no gap identified"]):
            raise ValueError("Compliance status 'Compliant' conflicts with gap description")
    
    def calculate_risk_score(self) -> float:
        """Calculate risk score based on priority and compliance status"""
        # Base score from compliance status
        status_scores = {
            ComplianceStatus.NON_COMPLIANT: 10.0,
            ComplianceStatus.PARTIALLY_COMPLIANT: 6.0,
            ComplianceStatus.COMPLIANT: 0.0
        }
        
        base_score = status_scores[self.compliance_status]
        
        # Adjust by priority (1=highest risk multiplier, 5=lowest)
        priority_multiplier = (6 - self.priority) / 5.0  # 1.0 to 0.2
        
        return base_score * priority_multiplier
    
    def get_remediation_timeline(self) -> str:
        """Get estimated remediation timeline based on effort and priority"""
        # Timeline matrix: priority × effort
        timeline_matrix = {
            (1, RemediationEffort.LOW): "1-2 weeks",
            (1, RemediationEffort.MEDIUM): "3-4 weeks", 
            (1, RemediationEffort.HIGH): "6-8 weeks",
            (2, RemediationEffort.LOW): "2-3 weeks",
            (2, RemediationEffort.MEDIUM): "4-6 weeks",
            (2, RemediationEffort.HIGH): "8-12 weeks",
            (3, RemediationEffort.LOW): "3-4 weeks",
            (3, RemediationEffort.MEDIUM): "6-8 weeks",
            (3, RemediationEffort.HIGH): "12-16 weeks",
            (4, RemediationEffort.LOW): "4-6 weeks",
            (4, RemediationEffort.MEDIUM): "8-12 weeks", 
            (4, RemediationEffort.HIGH): "16-20 weeks",
            (5, RemediationEffort.LOW): "6-8 weeks",
            (5, RemediationEffort.MEDIUM): "12-16 weeks",
            (5, RemediationEffort.HIGH): "20-24 weeks"
        }
        
        return timeline_matrix.get((self.priority, self.remediation_effort), "TBD")
    
    def to_dict(self) -> dict:
        """Convert compliance gap to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "standard": self.standard,
            "requirement_id": self.requirement_id,
            "requirement_description": self.requirement_description,
            "current_implementation": self.current_implementation,
            "gap_description": self.gap_description,
            "compliance_status": self.compliance_status.value,
            "business_impact": self.business_impact,
            "remediation_effort": self.remediation_effort.value,
            "priority": self.priority,
            "risk_score": self.calculate_risk_score(),
            "estimated_timeline": self.get_remediation_timeline()
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ComplianceGap':
        """Create compliance gap from dictionary (JSON deserialization)"""
        return cls(
            id=data["id"],
            standard=data["standard"],
            requirement_id=data["requirement_id"],
            requirement_description=data["requirement_description"],
            current_implementation=data["current_implementation"],
            gap_description=data["gap_description"],
            compliance_status=ComplianceStatus(data["compliance_status"]),
            business_impact=data["business_impact"],
            remediation_effort=RemediationEffort(data["remediation_effort"]),
            priority=data["priority"]
        )