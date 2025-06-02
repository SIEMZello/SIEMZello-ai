from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routers import network_predict,siem_predict



app = FastAPI(
    title="Network Traffic Analysis API",
    description="API for detecting and classifying network traffic anomalies",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(
    network_predict.router,
    prefix="/api/v1",
    tags=["predictions"]
)


app.include_router(
    siem_predict.router,
    prefix="/api/v1",
    tags=["siem"]
)


@app.get("/health")
async def health_check():
    return {"status": "healthy"}