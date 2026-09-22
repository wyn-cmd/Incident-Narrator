from typing import List, Dict, Any

def build_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sorts a list of incident events chronologically based on their time key."""
    if not isinstance(events, list):
        raise TypeError(f"Expected list of events, got {type(events).__name__}")
    
    return sorted(events, key=lambda event: event["time"])