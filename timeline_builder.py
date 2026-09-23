from typing import List, Dict, Any

# Sorts incident events chronologically by their time key
def build_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(events, list):
        raise TypeError(f"Expected list of events, got {type(events).__name__}")
    
    return sorted(events, key=lambda event: event["time"])