# risk_engine.py
# Purpose: Calculate weighted Risk Index from detected clauses
# Author: Member B (Chandsi Turkar)
# Input: List of detected clauses from policy_analyzer
# Output: {ri_score, level, explanation}

# Clause risk weights (P=Privacy, L=Legal, S=Security)
# ✅ FIXED: Keys now match policy_analyzer.py output
CLAUSE_RISK_MAP = {
    "Data Selling": {"P": 95, "L": 60, "S": 40},
    "Behavioral Tracking": {"P": 85, "L": 40, "S": 50},
    "Location Tracking": {"P": 90, "L": 50, "S": 60},
    "Auto-Renewing Subscriptions": {"P": 20, "L": 80, "S": 10},  # ✅ FIXED
    "Arbitration Clause": {"P": 10, "L": 95, "S": 10},           # ✅ FIXED
    "Liability Waiver": {"P": 15, "L": 90, "S": 20},
    "Broad Data Sharing": {"P": 80, "L": 55, "S": 45}
}

# Human-readable explanations for each clause
# ✅ FIXED: Keys now match policy_analyzer.py output
CLAUSE_EXPLANATIONS = {
    "Data Selling": "Your personal data may be sold to third parties or advertisers without explicit consent.",
    "Behavioral Tracking": "Your browsing behavior is being tracked across sites to build a profile about you.",
    "Location Tracking": "Your precise GPS location is being collected and potentially stored.",
    "Auto-Renewing Subscriptions": "Your subscription automatically renews. You may be charged without prior notification.",  # ✅ FIXED
    "Arbitration Clause": "You are waiving your right to sue in court. Any disputes will be resolved through arbitration.",  # ✅ FIXED
    "Liability Waiver": "The service provider disclaims liability for damages or data loss.",
    "Broad Data Sharing": "Your data may be shared with affiliates, partners, and other third parties."
}

def compute(clauses):
    """
    Compute the weighted Risk Index from detected clauses.
    
    Args:
        clauses (list): List of dicts [{"type": "Data Selling", "confidence": 0.92}, ...]
    
    Returns:
        dict: {
            "ri_score": int (0-100),
            "level": str ("LOW", "MEDIUM", "HIGH"),
            "explanation": str
        }
    """
    
    # If no clauses detected, return safe
    if not clauses:
        return {
            "ri_score": 0,
            "level": "LOW",
            "explanation": "No significant risks detected in this policy."
        }
    
    # Separate clauses by category
    p_clauses = []
    l_clauses = []
    s_clauses = []
    explanation_parts = []
    
    for clause in clauses:
        clause_type = clause.get("type", "")
        confidence = clause.get("confidence", 1.0)
        
        # Get weights for this clause type
        weights = CLAUSE_RISK_MAP.get(clause_type)
        if not weights:
            # Log unknown clause types for debugging
            continue
            
        # Weight each clause's contribution by its confidence
        p_clauses.append(weights["P"] * confidence)
        l_clauses.append(weights["L"] * confidence)
        s_clauses.append(weights["S"] * confidence)
        
        # Add explanation if available
        if clause_type in CLAUSE_EXPLANATIONS:
            explanation_parts.append(CLAUSE_EXPLANATIONS[clause_type])
    
    # Calculate average scores for each category
    p_avg = sum(p_clauses) / len(p_clauses) if p_clauses else 0
    l_avg = sum(l_clauses) / len(l_clauses) if l_clauses else 0
    s_avg = sum(s_clauses) / len(s_clauses) if s_clauses else 0
    
    # Calculate final Risk Index: RI = 0.5P + 0.3L + 0.2S
    ri_score = (0.5 * p_avg) + (0.3 * l_avg) + (0.2 * s_avg)
    ri_score = round(min(ri_score, 100))
    
    # Determine risk level
    if ri_score <= 30:
        level = "LOW"
    elif ri_score <= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"
    
    # Combine unique explanations
    explanation = " ".join(set(explanation_parts))
    
    return {
        "ri_score": ri_score,
        "level": level,
        "explanation": explanation
    }