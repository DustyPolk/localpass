"""
ThreatVector model - Potential attack paths and associated risks
Represents attack scenarios and their likelihood/impact assessment
"""
from dataclasses import dataclass, field
from typing import List, Optional
from uuid import uuid4
from enum import Enum


class RiskLevel(Enum):
    """Risk level enumeration for likelihood and impact"""
    VERY_LOW = "VeryLow"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    VERY_HIGH = "VeryHigh"


class RiskRating(Enum):
    """Overall risk rating calculated from likelihood × impact"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class ThreatVector:
    """
    Attack path entity with risk assessment
    Used for threat modeling and risk analysis
    """
    # Required fields
    name: str
    description: str
    likelihood: RiskLevel
    impact: RiskLevel
    
    # Optional fields
    id: str = field(default_factory=lambda: str(uuid4()))
    risk_rating: Optional[RiskRating] = None
    attack_steps: List[str] = field(default_factory=list)
    mitigating_controls: List[str] = field(default_factory=list)
    residual_risk: Optional[str] = None
    attack_tools: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate risk rating and validate threat vector"""
        self._validate_name_and_description()
        self._calculate_risk_rating()
        self._validate_attack_steps()
        
    def _validate_name_and_description(self):
        """Validate name and description are not empty"""
        if not self.name or not isinstance(self.name, str):
            raise ValueError("Threat vector name must be non-empty string")
        
        if not self.description or not isinstance(self.description, str):
            raise ValueError("Threat vector description must be non-empty string")
    
    def _calculate_risk_rating(self):
        """Calculate risk rating from likelihood × impact matrix"""
        # Risk matrix from data model validation rules
        risk_matrix = {
            (RiskLevel.VERY_HIGH, RiskLevel.VERY_HIGH): RiskRating.CRITICAL,
            (RiskLevel.VERY_HIGH, RiskLevel.HIGH): RiskRating.CRITICAL,
            (RiskLevel.HIGH, RiskLevel.VERY_HIGH): RiskRating.CRITICAL,
            (RiskLevel.HIGH, RiskLevel.HIGH): RiskRating.HIGH,
            (RiskLevel.VERY_HIGH, RiskLevel.MEDIUM): RiskRating.HIGH,
            (RiskLevel.MEDIUM, RiskLevel.VERY_HIGH): RiskRating.HIGH,
            (RiskLevel.HIGH, RiskLevel.MEDIUM): RiskRating.MEDIUM,
            (RiskLevel.MEDIUM, RiskLevel.HIGH): RiskRating.MEDIUM,
            (RiskLevel.MEDIUM, RiskLevel.MEDIUM): RiskRating.MEDIUM,
            (RiskLevel.LOW, RiskLevel.HIGH): RiskRating.MEDIUM,
            (RiskLevel.HIGH, RiskLevel.LOW): RiskRating.MEDIUM,
            (RiskLevel.LOW, RiskLevel.MEDIUM): RiskRating.LOW,
            (RiskLevel.MEDIUM, RiskLevel.LOW): RiskRating.LOW,
            (RiskLevel.LOW, RiskLevel.LOW): RiskRating.LOW,
            (RiskLevel.VERY_LOW, RiskLevel.MEDIUM): RiskRating.LOW,
            (RiskLevel.MEDIUM, RiskLevel.VERY_LOW): RiskRating.LOW,
            (RiskLevel.VERY_LOW, RiskLevel.HIGH): RiskRating.LOW,
            (RiskLevel.HIGH, RiskLevel.VERY_LOW): RiskRating.LOW,
        }
        
        # Default to low risk for unspecified combinations
        self.risk_rating = risk_matrix.get((self.likelihood, self.impact), RiskRating.LOW)
        
        # Handle remaining very low combinations
        if self.likelihood == RiskLevel.VERY_LOW or self.impact == RiskLevel.VERY_LOW:
            if self.risk_rating not in [RiskRating.MEDIUM, RiskRating.HIGH, RiskRating.CRITICAL]:
                self.risk_rating = RiskRating.LOW
    
    def _validate_attack_steps(self):
        """Validate attack steps are ordered sequence"""
        if not isinstance(self.attack_steps, list):
            raise ValueError("Attack steps must be a list")
        
        for step in self.attack_steps:
            if not isinstance(step, str) or not step.strip():
                raise ValueError("Each attack step must be non-empty string")
    
    def assess_residual_risk(self, control_effectiveness: dict) -> str:
        """
        Calculate residual risk after mitigating controls
        control_effectiveness: dict mapping control names to effectiveness ratings
        """
        if not self.mitigating_controls:
            return self.risk_rating.value
        
        # Simple residual risk calculation
        effective_controls = 0
        for control in self.mitigating_controls:
            effectiveness = control_effectiveness.get(control, "NotImplemented")
            if effectiveness == "Effective":
                effective_controls += 1
            elif effectiveness == "PartiallyEffective":
                effective_controls += 0.5
        
        # Reduce risk based on effective controls
        risk_reduction = min(effective_controls / len(self.mitigating_controls), 0.8)
        
        if risk_reduction >= 0.6:
            # Significant risk reduction
            if self.risk_rating == RiskRating.CRITICAL:
                residual = "High"
            elif self.risk_rating == RiskRating.HIGH:
                residual = "Medium"
            elif self.risk_rating == RiskRating.MEDIUM:
                residual = "Low"
            else:
                residual = "Low"
        elif risk_reduction >= 0.3:
            # Moderate risk reduction  
            if self.risk_rating == RiskRating.CRITICAL:
                residual = "High"
            elif self.risk_rating == RiskRating.HIGH:
                residual = "Medium"
            else:
                residual = self.risk_rating.value
        else:
            # Minimal risk reduction
            residual = self.risk_rating.value
        
        self.residual_risk = residual
        return residual
    
    def to_dict(self) -> dict:
        """Convert threat vector to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "likelihood": self.likelihood.value,
            "impact": self.impact.value,
            "risk_rating": self.risk_rating.value if self.risk_rating else None,
            "attack_steps": self.attack_steps,
            "mitigating_controls": self.mitigating_controls,
            "residual_risk": self.residual_risk,
            "attack_tools": self.attack_tools
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ThreatVector':
        """Create threat vector from dictionary (JSON deserialization)"""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            likelihood=RiskLevel(data["likelihood"]),
            impact=RiskLevel(data["impact"]),
            risk_rating=RiskRating(data["risk_rating"]) if data.get("risk_rating") else None,
            attack_steps=data.get("attack_steps", []),
            mitigating_controls=data.get("mitigating_controls", []),
            residual_risk=data.get("residual_risk"),
            attack_tools=data.get("attack_tools", [])
        )