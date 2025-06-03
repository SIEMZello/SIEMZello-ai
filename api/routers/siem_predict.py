from fastapi import APIRouter, HTTPException
import pandas as pd

from api.schemas.memory_schemas import (
    MemoryLogEntry,
    MemoryAnalysisResult
)
from api.schemas.process_schemas import (
    ProcessLogEntry,
    ProcessAnalysisResult
)
from api.schemas.disk_schemas import (
    DiskLogEntry,
 
    DiskAnalysisResult
)
from memory_models.memory_analyzer import MemoryAnalyzer
from process_models.process_analyzer import ProcessAnalyzer
from disk_models.disk_analyzer import DiskAnalyzer

router = APIRouter()

# Initialize the analyzers
memory_analyzer = MemoryAnalyzer()
process_analyzer = ProcessAnalyzer()
disk_analyzer = DiskAnalyzer()

@router.post("/predict/memory", response_model=MemoryAnalysisResult)
async def predict_memory_anomalies(request: MemoryLogEntry):
    """
    Analyze a single memory log for anomalies.
    
    Args:
        request: MemoryLogEntry containing a single memory log  
        
    Returns:
        MemoryAnalysisResult with analysis result
    """
    try:
        # Convert request data to DataFrame
        memory_data = pd.DataFrame([request.dict()])
        
        if memory_data.empty:
            raise HTTPException(status_code=400, detail="No memory log provided")
            
        # Analyze memory data
        results = memory_analyzer.analyze(memory_data)
        
        if not results:
            raise HTTPException(status_code=500, detail="No result from analyzer")
            
        result = results[0]
        
        return MemoryAnalysisResult(
            record_id=result["record_id"],
            is_anomaly=result["is_anomaly"],
            anomaly_probability=result["anomaly_probability"],
            ts=result.get("ts"),
            CMD=result.get("CMD"),
            RDDSK=result.get("RDDSK"),
            WRDSK=result.get("WRDSK"),
            DSK=result.get("DSK")
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing memory log: {str(e)}")

@router.get("/health/memory")
async def check_memory_analyzer_health():
    """
    Check if the memory analyzer service is healthy and responding
    """
    try:
        # Generate a small sample of test data
        test_data = pd.DataFrame([{
            "PID": 1234,
            "ts": 1600000000,
            "CMD": "test",
            "RDDSK": "0K",
            "WRDSK": "0K",
            "WCANCL": "0",
            "DSK": "0%"
        }])
        
        # Try to analyze it
        memory_analyzer.analyze(test_data)
        return {"status": "healthy", "message": "Memory analyzer is functioning correctly"}
        
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Memory analyzer health check failed: {str(e)}"
        )

@router.post("/predict/process", response_model=ProcessAnalysisResult)
async def predict_process_anomalies(request: ProcessLogEntry):
    """
    Analyze a single process/CPU log for anomalies.
    
    Args:
        request: ProcessLogEntry containing a single process log
        
    Returns:
        ProcessAnalysisResult with analysis result
    """
    try:
        process_data = pd.DataFrame([request.dict()])
        
        if process_data.empty:
            raise HTTPException(status_code=400, detail="No process log provided")
            
        # Analyze process data
        results = process_analyzer.analyze(process_data)
        
        if not results:
            raise HTTPException(status_code=500, detail="No result from analyzer")
            
        result = results[0]
        
        return ProcessAnalysisResult(
            record_id=result["record_id"],
            is_anomaly=result["is_anomaly"],
            anomaly_probability=result["anomaly_probability"],
            ts=result.get("ts"),
            CMD=result.get("CMD"),
            CPU=result.get("CPU"),
            MEM=result.get("MEM"),
            STATUS=result.get("STATUS")
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing process log: {str(e)}")

@router.get("/health/process")
async def check_process_analyzer_health():
    """
    Check if the process analyzer service is healthy and responding
    """
    try:
        # Generate a small sample of test data
        test_data = pd.DataFrame([{
            "PID": 1234,
            "ts": 1600000000,
            "CMD": "test",
            "CPU": 5.0,
            "MEM": 2.5,
            "STATUS": "S"
        }])
        
        # Try to analyze it
        process_analyzer.analyze(test_data)
        return {"status": "healthy", "message": "Process analyzer is functioning correctly"}
        
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Process analyzer health check failed: {str(e)}"
        )

@router.post("/predict/disk", response_model=DiskAnalysisResult)
async def predict_disk_anomalies(request: DiskLogEntry):
    """
    Analyze a single disk I/O log for anomalies.
    
    Args:
        request: DiskLogEntry containing a single disk log
        
    Returns:
        DiskAnalysisResult with analysis result
    """
    try:
        # Convert request data to DataFrame
        disk_data = pd.DataFrame([request.dict()])
        
        if disk_data.empty:
            raise HTTPException(status_code=400, detail="No disk log provided")
            
        # Analyze disk data
        results = disk_analyzer.analyze(disk_data)
        
        if not results:
            raise HTTPException(status_code=500, detail="No result from analyzer")
            
        result = results[0]
        
        return DiskAnalysisResult(
            record_id=result["record_id"],
            is_anomaly=result["is_anomaly"],
            anomaly_probability=result["anomaly_probability"],
            ts=result.get("ts"),
            CMD=result.get("CMD"),
            disk_reads=result.get("disk_reads"),
            disk_writes=result.get("disk_writes"),
            disk_read_bytes=result.get("disk_read_bytes"),
            disk_write_bytes=result.get("disk_write_bytes"),
            disk_utilization=result.get("disk_utilization")
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing disk log: {str(e)}")

@router.get("/health/disk")
async def check_disk_analyzer_health():
    """
    Check if the disk analyzer service is healthy and responding
    """
    try:
        # Generate a small sample of test data
        test_data = pd.DataFrame([{
            "PID": 1234,
            "ts": 1600000000,
            "CMD": "test",
            "disk_reads": 100.0,
            "disk_writes": 50.0,
            "disk_read_bytes": 1024.0,
            "disk_write_bytes": 512.0,
            "disk_utilization": 25.0
        }])
        
        # Try to analyze it
        disk_analyzer.analyze(test_data)
        return {"status": "healthy", "message": "Disk analyzer is functioning correctly"}
        
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Disk analyzer health check failed: {str(e)}"
        )