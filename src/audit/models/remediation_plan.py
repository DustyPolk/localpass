"""
RemediationPlan model - Prioritized action items with timelines and resources
Represents structured approach to addressing security findings
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
from uuid import uuid4
from enum import Enum


class PlanStatus(Enum):
    """Remediation plan status"""
    PLANNED = "Planned"
    IN_PROGRESS = "InProgress"
    COMPLETED = "Completed"
    DEFERRED = "Deferred"


@dataclass  
class RemediationPlan:
    """
    Remediation plan entity with timeline validation
    Links to multiple AuditFindings and provides implementation roadmap
    """
    # Required fields
    finding_ids: List[str]
    title: str
    description: str
    priority: int
    effort_estimate: str
    skills_required: List[str]
    validation_steps: List[str]
    timeline: Dict[str, datetime]
    
    # Optional fields
    id: str = field(default_factory=lambda: str(uuid4()))
    dependencies: List[str] = field(default_factory=list)
    assigned_to: Optional[str] = None
    status: PlanStatus = PlanStatus.PLANNED
    implementation_notes: Optional[str] = None
    
    def __post_init__(self):
        """Validate remediation plan data"""
        self._validate_finding_ids()
        self._validate_title_description()
        self._validate_priority()
        self._validate_timeline()
        self._validate_validation_steps()
        self._validate_dependencies()
    
    def _validate_finding_ids(self):
        """Validate finding IDs reference existing AuditFinding entities"""
        if not isinstance(self.finding_ids, list) or not self.finding_ids:
            raise ValueError("Finding IDs must be non-empty list")
        
        # UUID format validation
        import re
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        
        for finding_id in self.finding_ids:
            if not isinstance(finding_id, str):
                raise ValueError(f"Finding ID must be string: {finding_id}")
            
            if not re.match(uuid_pattern, finding_id, re.IGNORECASE):
                raise ValueError(f"Finding ID must be valid UUID: {finding_id}")
    
    def _validate_title_description(self):
        """Validate title and description are not empty"""
        if not self.title or not isinstance(self.title, str):
            raise ValueError("Title must be non-empty string")
        
        if not self.description or not isinstance(self.description, str):
            raise ValueError("Description must be non-empty string")
    
    def _validate_priority(self):
        """Validate priority is 1-5 integer and aligns with finding severities"""
        if not isinstance(self.priority, int) or not (1 <= self.priority <= 5):
            raise ValueError("Priority must be integer between 1 (Critical) and 5 (Informational)")
    
    def _validate_timeline(self):
        """Validate timeline has required dates and logical ordering"""
        if not isinstance(self.timeline, dict):
            raise ValueError("Timeline must be dictionary")
        
        required_dates = ["start_date", "target_date"]
        for date_key in required_dates:
            if date_key not in self.timeline:
                raise ValueError(f"Timeline must include {date_key}")
            
            if not isinstance(self.timeline[date_key], datetime):
                raise ValueError(f"Timeline {date_key} must be datetime object")
        
        # Validate target_date is after start_date
        if self.timeline["target_date"] <= self.timeline["start_date"]:
            raise ValueError("Target date must be after start date")
    
    def _validate_validation_steps(self):
        """Validate validation steps are verifiable and measurable"""
        if not isinstance(self.validation_steps, list) or not self.validation_steps:
            raise ValueError("Validation steps must be non-empty list")
        
        for step in self.validation_steps:
            if not isinstance(step, str) or not step.strip():
                raise ValueError("Each validation step must be non-empty string")
    
    def _validate_dependencies(self):
        """Validate dependencies reference other RemediationPlan entities"""
        if not isinstance(self.dependencies, list):
            raise ValueError("Dependencies must be list")
        
        # UUID format validation for dependencies
        import re
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        
        for dep_id in self.dependencies:
            if not isinstance(dep_id, str):
                raise ValueError(f"Dependency ID must be string: {dep_id}")
            
            if not re.match(uuid_pattern, dep_id, re.IGNORECASE):
                raise ValueError(f"Dependency ID must be valid UUID: {dep_id}")
    
    def update_status(self, new_status: PlanStatus, notes: Optional[str] = None) -> bool:
        """
        Update plan status with validation of allowed transitions
        Returns True if transition was successful, False otherwise
        """
        # Valid state transitions from data-model.md
        valid_transitions = {
            PlanStatus.PLANNED: [PlanStatus.IN_PROGRESS, PlanStatus.DEFERRED],
            PlanStatus.IN_PROGRESS: [PlanStatus.COMPLETED, PlanStatus.DEFERRED],
            PlanStatus.DEFERRED: [PlanStatus.PLANNED],
            PlanStatus.COMPLETED: []  # Terminal state
        }
        
        if new_status not in valid_transitions.get(self.status, []):
            return False
        
        self.status = new_status
        if notes:
            self.implementation_notes = notes
        
        return True
    
    def calculate_duration_days(self) -> int:
        """Calculate plan duration in days"""
        duration = self.timeline["target_date"] - self.timeline["start_date"]
        return duration.days
    
    def estimate_resource_days(self, team_size: int = 1) -> float:
        """
        Estimate resource requirements in person-days
        Parses effort_estimate string and converts to days
        """
        effort_str = self.effort_estimate.lower()
        
        # Parse common effort formats
        if "hour" in effort_str:
            # Extract hours
            import re
            hours_match = re.search(r'(\d+(?:\.\d+)?)\s*hour', effort_str)
            if hours_match:
                hours = float(hours_match.group(1))
                return hours / 8.0  # Convert to days (8 hour workday)
        
        elif "day" in effort_str:
            # Extract days
            import re
            days_match = re.search(r'(\d+(?:\.\d+)?)\s*day', effort_str)
            if days_match:
                return float(days_match.group(1))
        
        elif "week" in effort_str:
            # Extract weeks
            import re
            weeks_match = re.search(r'(\d+(?:\.\d+)?)\s*week', effort_str)
            if weeks_match:
                weeks = float(weeks_match.group(1))
                return weeks * 5.0 * team_size  # 5 workdays per week
        
        # Default estimate based on priority
        priority_estimates = {
            1: 20.0,  # Critical: ~4 weeks
            2: 15.0,  # High: ~3 weeks
            3: 10.0,  # Medium: ~2 weeks
            4: 5.0,   # Low: ~1 week
            5: 2.0    # Info: ~2 days
        }
        
        return priority_estimates.get(self.priority, 10.0)
    
    def to_dict(self) -> dict:
        """Convert remediation plan to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "finding_ids": self.finding_ids,
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "effort_estimate": self.effort_estimate,
            "skills_required": self.skills_required,
            "dependencies": self.dependencies,
            "validation_steps": self.validation_steps,
            "timeline": {
                key: value.isoformat() for key, value in self.timeline.items()
            },
            "assigned_to": self.assigned_to,
            "status": self.status.value,
            "implementation_notes": self.implementation_notes,
            "duration_days": self.calculate_duration_days(),
            "estimated_resource_days": self.estimate_resource_days()
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'RemediationPlan':
        """Create remediation plan from dictionary (JSON deserialization)"""
        # Convert ISO datetime strings back to datetime objects
        timeline = {}
        for key, value in data["timeline"].items():
            timeline[key] = datetime.fromisoformat(value)
        
        return cls(
            id=data["id"],
            finding_ids=data["finding_ids"],
            title=data["title"],
            description=data["description"],
            priority=data["priority"],
            effort_estimate=data["effort_estimate"],
            skills_required=data["skills_required"],
            dependencies=data.get("dependencies", []),
            validation_steps=data["validation_steps"],
            timeline=timeline,
            assigned_to=data.get("assigned_to"),
            status=PlanStatus(data["status"]),
            implementation_notes=data.get("implementation_notes")
        )