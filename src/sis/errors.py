class SISError(Exception):
    """Safe, user-reportable error."""

class InvalidInput(SISError):
    pass

class RuleRejected(SISError):
    pass

class LLMError(SISError):
    pass
