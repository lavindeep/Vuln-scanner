# =============================================================================
# STAGE 1: BUILDER
# =============================================================================
# "FROM" tells Docker which base image to start from. Think of it like choosing
# an operating system template. We use python:3.12-slim which is a lightweight
# Debian Linux with Python 3.12 pre-installed.
#
# "AS builder" gives this stage a name. We install dependencies here but WON'T
# ship this stage to production — only the final stage becomes the real image.
# This is called a "multi-stage build" and it keeps the final image small and
# secure by leaving build tools (pip, compilers, etc.) behind.
# =============================================================================
FROM python:3.12-slim AS builder

# WORKDIR sets the directory inside the container where all following commands
# run. If the directory doesn't exist, Docker creates it automatically.
# Think of it like "cd /app" that persists for every subsequent instruction.
WORKDIR /app

# COPY moves files from your computer (the "build context") into the container.
# We copy requirements.txt FIRST and install dependencies BEFORE copying the
# rest of the code. Why? Docker caches each step (called a "layer"). If your
# code changes but requirements.txt hasn't, Docker reuses the cached dependency
# install — saving minutes on rebuilds.
COPY app/requirements.txt .

# RUN executes a command inside the container during the build process.
#   pip install         — Python's package installer
#   --no-cache-dir      — don't save pip's download cache (smaller image)
#   --target=/app/pkgs  — install packages into a specific folder so we can
#                         copy ONLY the packages to the final stage (no pip
#                         toolchain, no build artifacts)
#   -r requirements.txt — install everything listed in the requirements file
RUN pip install --no-cache-dir --target=/app/pkgs -r requirements.txt


# =============================================================================
# STAGE 2: FINAL (this is the image that actually gets deployed/scanned)
# =============================================================================
# We start fresh from the same base image. Nothing from the builder stage is
# carried over unless we explicitly COPY it. This means the final image does
# NOT contain pip, setuptools, or any build-time files — only what we need
# to run the application.
# =============================================================================
FROM python:3.12-slim AS final

# LABEL adds metadata to the image. These are key-value pairs that tools can
# read. Our OPA security policies will check that these three labels exist:
#   - maintainer: who owns this image
#   - version: the application version
#   - description: what this image does
# Without these labels, the OPA policy check in our CI/CD pipeline will FAIL.
LABEL maintainer="lavindeep"
LABEL version="1.0.0"
LABEL description="CI/CD Pipeline with Automated Vulnerability Scanning"

# Create a non-root user called "appuser". By default, containers run as root,
# which is a major security risk — if an attacker breaks into the container,
# they have full root access. Federal compliance (NIST 800-53 CM-6) requires
# running applications with least privilege.
#   addgroup --system  — create a system group (no login, no home directory)
#   adduser --system   — create a system user
#   --ingroup appuser  — put the user in the group we just created
RUN addgroup --system appuser && adduser --system --ingroup appuser appuser

WORKDIR /app

# Copy the installed Python packages from the builder stage. The syntax
# "--from=builder" tells Docker to pull files from the named stage above,
# not from your local machine.
COPY --from=builder /app/pkgs /app/pkgs

# Copy only the application code. We don't copy requirements.txt or anything
# else — the final image should contain only what's needed at runtime.
COPY app/main.py .

# ENV sets an environment variable inside the container. PYTHONPATH tells
# Python where to look for installed packages. Since we installed them into
# /app/pkgs (not the default site-packages), we need to point Python there.
ENV PYTHONPATH=/app/pkgs

# USER switches all subsequent commands (and the running container) to run
# as "appuser" instead of root. This is the line that actually enforces the
# non-root security requirement. Always place this AFTER all RUN commands
# that need root (like adduser), but BEFORE CMD.
USER appuser

# EXPOSE documents which port the application listens on. It does NOT actually
# open the port — you still need "-p 8000:8000" when running the container.
# Think of it as a note to other developers: "this container expects port 8000."
EXPOSE 8000

# CMD defines the default command that runs when the container starts.
# We use the "exec form" (JSON array) instead of the "shell form" (plain string)
# because exec form runs the process directly without a shell wrapper, which
# means the process receives OS signals (like SIGTERM for graceful shutdown)
# correctly.
#   python -m uvicorn  — run uvicorn as a Python module
#   main:app           — look for the "app" object in "main.py"
#   --host 0.0.0.0     — listen on ALL network interfaces (required so traffic
#                         from outside the container can reach the app; using
#                         127.0.0.1 would only allow connections from inside)
#   --port 8000        — match the EXPOSE port above
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
