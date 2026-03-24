from fastapi import FastAPI

app = FastAPI(title="Vuln-Scanner", version="1.0.0")


@app.get("/")
def root():
    return {
        "name": "vuln-scanner",
        "version": "1.0.0",
        "description": "CI/CD Pipeline with Automated Vulnerability Scanning",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
