from fastapi import APIRouter, HTTPException
from ..schemas.network_schemas import (
    NetworkTrafficInput, 
    DetectionResponse, 
    ClassificationResponse,
    FullAnalysisResponse
)
import pandas as pd
from network_traffic_models.src.models.detection_model import DetectionModel
from network_traffic_models.src.models.classification_model import ClassificationModel

router = APIRouter()

# Initialize models
detection_model = DetectionModel()
classification_model = ClassificationModel()

@router.post("/detect", response_model=DetectionResponse)
async def detect_attack(input_data: NetworkTrafficInput):
    """Endpoint for binary attack detection"""
    try:
        # Convert input to DataFrame
        df = pd.DataFrame([input_data.dict()])
        
        # Get prediction and probability
        is_attack = bool(detection_model.predict(df)[0])
        attack_prob = float(detection_model.predict_proba(df)[0])
        
        return DetectionResponse(
            is_attack=is_attack,
            attack_probability=attack_prob
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/classify", response_model=ClassificationResponse)
async def classify_attack(input_data: NetworkTrafficInput):
    """Endpoint for attack type classification"""
    try:
        # Convert input to DataFrame
        df = pd.DataFrame([input_data.dict()])
        
        # Get classification and probabilities
        attack_type = classification_model.predict(df)[0]
        probabilities = classification_model.predict_proba(df)[0]
        
        # Create probability dictionary
        prob_dict = {}
        if hasattr(classification_model.model, 'classes_'):
            prob_dict = {
                str(cls): float(prob) 
                for cls, prob in zip(classification_model.model.classes_, probabilities)
            }
        
        return ClassificationResponse(
            attack_type=str(attack_type),
            attack_probabilities=prob_dict
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze", response_model=FullAnalysisResponse)
async def full_analysis(input_data: NetworkTrafficInput):
    """Endpoint for full traffic analysis (detection + classification)"""
    try:
        # Convert input to DataFrame
        df = pd.DataFrame([input_data.dict()])
        
        # Stage 1: Detection
        is_attack = bool(detection_model.predict(df)[0])
        attack_prob = float(detection_model.predict_proba(df)[0])
        
        # Prepare response
        response = FullAnalysisResponse(
            is_attack=is_attack,
            attack_probability=attack_prob
        )
        
        # Stage 2: Classification (only if attack detected)
        if is_attack:
            attack_type = classification_model.predict(df)[0]
            probabilities = classification_model.predict_proba(df)[0]
            
            # Create probability dictionary
            prob_dict = {}
            if hasattr(classification_model.model, 'classes_'):
                prob_dict = {
                    str(cls): float(prob) 
                    for cls, prob in zip(classification_model.model.classes_, probabilities)
                }
            
            response.attack_type = str(attack_type)
            response.attack_probabilities = prob_dict
        
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))