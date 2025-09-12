"""Password Generator Service.

Generates secure passwords with customizable parameters.
"""
import secrets
import string
from typing import Optional


class PasswordGenerator:
    """Service for generating secure passwords."""
    
    def __init__(self):
        """Initialize password generator."""
        # Character sets
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ambiguous characters that could be confused
        self.ambiguous = "0O1lI|"
    
    def generate_secure_password(self, length: int = 16, include_uppercase: bool = True,
                                include_lowercase: bool = True, include_digits: bool = True,
                                include_symbols: bool = True, exclude_ambiguous: bool = False,
                                min_uppercase: int = 1, min_lowercase: int = 1,
                                min_digits: int = 1, min_symbols: int = 0) -> str:
        """Generate a cryptographically secure password.
        
        Args:
            length: Password length (8-128 characters)
            include_uppercase: Include uppercase letters
            include_lowercase: Include lowercase letters
            include_digits: Include numbers
            include_symbols: Include symbols
            exclude_ambiguous: Exclude ambiguous characters (0O1lI|)
            min_uppercase: Minimum uppercase letters required
            min_lowercase: Minimum lowercase letters required
            min_digits: Minimum digits required
            min_symbols: Minimum symbols required
            
        Returns:
            Secure password string
            
        Raises:
            ValueError: If parameters are invalid
        """
        # Validate length
        if not isinstance(length, int) or not (8 <= length <= 128):
            raise ValueError("Password length must be between 8 and 128 characters")
        
        # Build character set
        charset = ""
        required_chars = []
        
        if include_lowercase:
            chars = self.lowercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            charset += chars
            if min_lowercase > 0:
                required_chars.extend(secrets.choice(chars) for _ in range(min_lowercase))
        
        if include_uppercase:
            chars = self.uppercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            charset += chars
            if min_uppercase > 0:
                required_chars.extend(secrets.choice(chars) for _ in range(min_uppercase))
        
        if include_digits:
            chars = self.digits
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            charset += chars
            if min_digits > 0:
                required_chars.extend(secrets.choice(chars) for _ in range(min_digits))
        
        if include_symbols:
            chars = self.symbols
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            charset += chars
            if min_symbols > 0:
                required_chars.extend(secrets.choice(chars) for _ in range(min_symbols))
        
        if not charset:
            raise ValueError("At least one character type must be enabled")
        
        # Check if minimum requirements exceed length
        if len(required_chars) > length:
            raise ValueError("Minimum character requirements exceed password length")
        
        # Generate password
        password = required_chars.copy()
        
        # Fill remaining length with random characters
        remaining_length = length - len(required_chars)
        password.extend(secrets.choice(charset) for _ in range(remaining_length))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def generate_passphrase(self, num_words: int = 4, separator: str = "-",
                           capitalize: bool = True, include_number: bool = True) -> str:
        """Generate a memorable passphrase using common words.
        
        Args:
            num_words: Number of words (2-8)
            separator: Character to separate words
            capitalize: Capitalize each word
            include_number: Add a random number
            
        Returns:
            Generated passphrase
            
        Raises:
            ValueError: If parameters are invalid
        """
        if not isinstance(num_words, int) or not (2 <= num_words <= 8):
            raise ValueError("Number of words must be between 2 and 8")
        
        # Simple word list (in practice, would load from file)
        words = [
            "apple", "banana", "cherry", "dragon", "elephant", "forest", "guitar", "harbor",
            "island", "jungle", "kitchen", "laptop", "mountain", "ocean", "piano", "quiet",
            "river", "sunset", "tiger", "umbrella", "village", "window", "yellow", "zebra",
            "bridge", "castle", "desert", "energy", "flower", "garden", "helmet", "ice",
            "journey", "koala", "lemon", "magic", "night", "orange", "penguin", "quartz",
            "rocket", "silver", "turtle", "universe", "violet", "wizard", "xylophone", "youth"
        ]
        
        # Select random words
        selected_words = []
        for _ in range(num_words):
            word = secrets.choice(words)
            if capitalize:
                word = word.capitalize()
            selected_words.append(word)
        
        # Join with separator
        passphrase = separator.join(selected_words)
        
        # Add random number if requested
        if include_number:
            number = secrets.randbelow(1000)
            passphrase += f"{separator}{number:03d}"
        
        return passphrase
    
    def assess_strength(self, password: str) -> dict:
        """Assess password strength and provide feedback.
        
        Args:
            password: Password to assess
            
        Returns:
            Dictionary with strength assessment
        """
        if not password:
            return {
                "score": 0,
                "strength": "Very Weak",
                "feedback": ["Password is empty"]
            }
        
        length = len(password)
        has_lowercase = any(c in self.lowercase for c in password)
        has_uppercase = any(c in self.uppercase for c in password)
        has_digits = any(c in self.digits for c in password)
        has_symbols = any(c in self.symbols for c in password)
        
        # Calculate base score
        score = 0
        feedback = []
        
        # Length scoring
        if length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        else:
            score += 5
            feedback.append("Use at least 8 characters")
        
        # Character variety scoring
        if has_lowercase:
            score += 15
        else:
            feedback.append("Include lowercase letters")
        
        if has_uppercase:
            score += 15
        else:
            feedback.append("Include uppercase letters")
        
        if has_digits:
            score += 15
        else:
            feedback.append("Include numbers")
        
        if has_symbols:
            score += 20
        else:
            feedback.append("Include symbols")
        
        # Additional length bonus
        if length >= 16:
            score += 10
        
        # Determine strength category
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return {
            "score": min(100, score),
            "strength": strength,
            "length": length,
            "has_lowercase": has_lowercase,
            "has_uppercase": has_uppercase,
            "has_digits": has_digits,
            "has_symbols": has_symbols,
            "feedback": feedback
        }
    
    def get_generator_info(self) -> dict:
        """Get information about password generator capabilities.
        
        Returns:
            Dictionary with generator information
        """
        return {
            "supported_lengths": "8-128 characters",
            "character_sets": {
                "lowercase": len(self.lowercase),
                "uppercase": len(self.uppercase), 
                "digits": len(self.digits),
                "symbols": len(self.symbols)
            },
            "features": [
                "Cryptographically secure random generation",
                "Customizable character sets",
                "Minimum character requirements",
                "Ambiguous character exclusion",
                "Passphrase generation",
                "Strength assessment"
            ]
        }