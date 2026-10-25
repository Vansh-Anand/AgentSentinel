from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
from .routers import health, experiments, pipeline, evidence, status, agent, runtime, secure_lab
from .body_limit import LabBodyLimit

app = FastAPI(
    title="AgentSentinel Dashboard API",
    description="Backend API for the AgentSentinel Dashboard",
    version="1.0.0"
)
app.add_middleware(LabBodyLimit)

# Configure CORS for local React/Vite development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:5173",
                   os.environ.get("AGENTSENTINEL_UI_ORIGIN", "http://127.0.0.1:5173")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(health.router, prefix="/api/health", tags=["health"])
app.include_router(status.router, prefix="/api/system/status", tags=["system-status"])
app.include_router(experiments.router, prefix="/api/experiments", tags=["experiments"])
app.include_router(pipeline.router, prefix="/api/pipeline", tags=["pipeline"])
app.include_router(evidence.router, prefix="/api/evidence", tags=["evidence"])
app.include_router(agent.router, prefix="/api/agent", tags=["agent"])
app.include_router(runtime.router, prefix="/api/runtime", tags=["runtime"])
app.include_router(secure_lab.router, prefix="/api/lab", tags=["portable-security-lab"])

@app.get("/")
def read_root():
    return {"message": "Welcome to AgentSentinel Dashboard API"}
