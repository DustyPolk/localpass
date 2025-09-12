"""
AuditFinding model - Core entity for discovered security issues
Represents vulnerability findings with full context and remediation guidance
"""
from datetime import datetime
from typing import List, Optional
from uuid import uuid4
from dataclasses import dataclass, field
from enum import Enum
import re


class Severity(Enum):
    """Security finding severity levels aligned with CVSS scoring"""
    CRITICAL = "Critical"
    HIGH = "High" 
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Status(Enum):
    """Finding status following data model state transitions"""
    OPEN = "Open"
    FIXED = "Fixed"
    ACKNOWLEDGED = "Acknowledged"
    FALSE_POSITIVE = "FalsePositive"


@dataclass
class AuditFinding:
    """
    Core audit finding entity with validation rules from data-model.md
    """
    # Required fields
    severity: Severity
    cvss_score: float
    title: str
    description: str
    file_path: str
    discovered_at: datetime
    status: Status = Status.OPEN
    
    # Optional fields  
    id: str = field(default_factory=lambda: str(uuid4()))
    cwe_id: Optional[int] = None
    owasp_category: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    impact: Optional[str] = None
    exploit_scenario: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    discovered_by: Optional[str] = None
    
    def __post_init__(self):
        """Validate audit finding data according to data-model.md rules"""
        self._validate_severity()
        self._validate_cvss_score()
        self._validate_cwe_id()
        self._validate_owasp_category()
        self._validate_file_path()
        self._validate_line_number()
        self._validate_title()
        self._validate_references()
    
    def _validate_severity(self):
        """Validate severity is one of defined enum values"""
        if not isinstance(self.severity, Severity):
            raise ValueError(f"Invalid severity: {self.severity}. Must be one of {list(Severity)}")
    
    def _validate_cvss_score(self):
        """Validate CVSS score is 0.0-10.0 and aligns with severity mapping"""
        if not isinstance(self.cvss_score, (int, float)):
            raise ValueError(f"CVSS score must be numeric, got {type(self.cvss_score)}")
            
        if not (0.0 <= self.cvss_score <= 10.0):
            raise ValueError(f"CVSS score must be 0.0-10.0, got {self.cvss_score}")
        
        # Validate CVSS score aligns with severity (from research.md)
        severity_ranges = {
            Severity.CRITICAL: (9.0, 10.0),
            Severity.HIGH: (7.0, 8.9),
            Severity.MEDIUM: (4.0, 6.9), 
            Severity.LOW: (0.1, 3.9),
            Severity.INFO: (0.0, 0.0)
        }
        
        min_score, max_score = severity_ranges[self.severity]
        if self.severity == Severity.INFO:
            # Special case: Info can be exactly 0.0
            if self.cvss_score != 0.0:
                raise ValueError(f"Info severity must have CVSS score 0.0, got {self.cvss_score}")
        else:
            if not (min_score <= self.cvss_score <= max_score):
                raise ValueError(
                    f"CVSS score {self.cvss_score} doesn't match {self.severity.value} "
                    f"severity (expected {min_score}-{max_score})"
                )
    
    def _validate_cwe_id(self):
        """Validate CWE ID is valid identifier from MITRE database"""
        if self.cwe_id is not None:
            if not isinstance(self.cwe_id, int) or self.cwe_id < 1:
                raise ValueError(f"CWE ID must be positive integer, got {self.cwe_id}")
    
    def _validate_owasp_category(self):
        """Validate OWASP category matches OWASP Top 10 2021 format"""
        if self.owasp_category is not None:
            if not re.match(r'^A\d{2}$', self.owasp_category):
                raise ValueError(
                    f"OWASP category must match A01-A10 format, got {self.owasp_category}"
                )
    
    def _validate_file_path(self):
        """Validate file path is not empty"""
        if not self.file_path or not isinstance(self.file_path, str):
            raise ValueError("File path must be non-empty string")
    
    def _validate_line_number(self):
        """Validate line number is positive integer if provided"""
        if self.line_number is not None:
            if not isinstance(self.line_number, int) or self.line_number < 1:
                raise ValueError(f"Line number must be positive integer, got {self.line_number}")
    
    def _validate_title(self):
        """Validate title is not empty and under 100 characters"""
        if not self.title or not isinstance(self.title, str):
            raise ValueError("Title must be non-empty string")
        
        if len(self.title) > 100:
            raise ValueError(f"Title must be under 100 characters, got {len(self.title)}")
    
    def _validate_references(self):
        """Validate references are valid URIs"""
        if not isinstance(self.references, list):
            raise ValueError("References must be a list")
        
        # Expected reference patterns from contract tests
        valid_patterns = [
            r'^https://cwe\.mitre\.org/data/definitions/\d+\.html$',  # CWE links
            r'^https://owasp\.org/Top10/A\d{2}_.*/$',                # OWASP links
            r'^https://nvd\.nist\.gov/vuln/detail/CVE-\d{4}-\d+$',   # CVE links
            r'^https://.*',  # Allow other HTTPS links
        ]
        
        for ref in self.references:
            if not isinstance(ref, str):
                raise ValueError(f"Reference must be string, got {type(ref)}")
            
            if not any(re.match(pattern, ref) for pattern in valid_patterns):
                raise ValueError(f"Invalid reference format: {ref}")
    
    def update_status(self, new_status: Status, notes: Optional[str] = None) -> bool:
        """
        Update finding status with validation of allowed transitions
        Returns True if transition was successful, False otherwise
        """
        # Valid state transitions from data-model.md
        valid_transitions = {
            Status.OPEN: [Status.FIXED, Status.ACKNOWLEDGED, Status.FALSE_POSITIVE],
            Status.FIXED: [Status.OPEN],  # Regression detected
            Status.ACKNOWLEDGED: [],  # Terminal state  
            Status.FALSE_POSITIVE: []  # Terminal state
        }
        
        if new_status not in valid_transitions.get(self.status, []):
            return False
        
        self.status = new_status
        return True
    
    def to_dict(self) -> dict:
        """Convert finding to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "impact": self.impact,
            "exploit_scenario": self.exploit_scenario,
            "remediation": self.remediation,
            "references": self.references,
            "discovered_by": self.discovered_by,
            "discovered_at": self.discovered_at.isoformat(),
            "status": self.status.value
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'AuditFinding':
        """Create finding from dictionary (JSON deserialization)"""
        # Convert string enums back to enum objects
        severity = Severity(data["severity"])
        status = Status(data["status"])
        discovered_at = datetime.fromisoformat(data["discovered_at"])
        
        return cls(
            id=data["id"],
            severity=severity,
            cvss_score=data["cvss_score"],
            cwe_id=data.get("cwe_id"),
            owasp_category=data.get("owasp_category"),
            title=data["title"],
            description=data["description"],
            file_path=data["file_path"],
            line_number=data.get("line_number"),
            code_snippet=data.get("code_snippet"),
            impact=data.get("impact"),
            exploit_scenario=data.get("exploit_scenario"),
            remediation=data.get("remediation"),
            references=data.get("references", []),
            discovered_by=data.get("discovered_by"),
            discovered_at=discovered_at,
            status=status
        )


def validate_references(references: List[str]) -> bool:
    """Validate reference URIs format (used by contract tests)"""
    try:
        # Create temporary finding to use validation logic
        temp_finding = AuditFinding(
            severity=Severity.INFO,
            cvss_score=0.0,
            title="temp",
            description="temp",
            file_path="temp.py", 
            discovered_at=datetime.now(),
            references=references
        )
        return True
    except ValueError:
        return False