"""FrostGate Forge Playbook Runner Service.

Executes deterministic success criteria playbooks for scenario evaluation.
Provides a structured way to define and run evaluation steps.
"""

from __future__ import annotations

import logging
import os
from enum import Enum
from pathlib import Path
from typing import Any

import docker
import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("forge_playbook_runner")

# Configuration
TEMPLATE_DIR = Path(os.getenv("TEMPLATE_DIR", "/templates"))
PLAYBOOK_DIR = Path(os.getenv("PLAYBOOK_DIR", "/playbooks"))


class StepType(str, Enum):
    EXECUTE_COMMAND = "execute_command"
    CHECK_FILE = "check_file"
    CHECK_SERVICE = "check_service"
    CHECK_NETWORK = "check_network"
    WAIT = "wait"


class StepExpectation(BaseModel):
    exit_code: int | None = None
    stdout_contains: str | None = None
    stdout_not_contains: str | None = None
    stderr_contains: str | None = None
    file_exists: bool | None = None
    contains: str | None = None
    service_running: bool | None = None
    port_open: bool | None = None


class PlaybookStep(BaseModel):
    step: StepType
    name: str = ""
    container: str = "learner_vm"
    command: str | None = None
    path: str | None = None
    service: str | None = None
    port: int | None = None
    timeout: int = 30
    expect: StepExpectation = Field(default_factory=StepExpectation)


class PlaybookResult(BaseModel):
    step_name: str
    step_type: StepType
    passed: bool
    output: str | None = None
    error: str | None = None
    duration_ms: int = 0


class PlaybookRunResult(BaseModel):
    scenario_id: str
    playbook_name: str
    passed: bool
    steps: list[PlaybookResult] = Field(default_factory=list)
    total_steps: int = 0
    passed_steps: int = 0


class Playbook(BaseModel):
    name: str
    description: str = ""
    steps: list[PlaybookStep] = Field(default_factory=list)


# Docker client
docker_client: docker.DockerClient | None = None


def get_docker_client() -> docker.DockerClient:
    global docker_client
    if docker_client is None:
        docker_client = docker.from_env()
    return docker_client


def find_container(
    scenario_id: str, container_name: str
) -> docker.models.containers.Container | None:
    """Find a container by scenario ID and name."""
    client = get_docker_client()
    containers = client.containers.list(
        filters={
            "label": [
                f"forge.scenario_id={scenario_id}",
                f"forge.container_name={container_name}",
            ]
        }
    )
    return containers[0] if containers else None


def execute_step(
    scenario_id: str, step: PlaybookStep
) -> PlaybookResult:
    """Execute a single playbook step."""
    import time

    start_time = time.time()
    result = PlaybookResult(
        step_name=step.name or f"{step.step.value}",
        step_type=step.step,
        passed=False,
    )

    try:
        if step.step == StepType.EXECUTE_COMMAND:
            result = execute_command_step(scenario_id, step)
        elif step.step == StepType.CHECK_FILE:
            result = check_file_step(scenario_id, step)
        elif step.step == StepType.CHECK_SERVICE:
            result = check_service_step(scenario_id, step)
        elif step.step == StepType.CHECK_NETWORK:
            result = check_network_step(scenario_id, step)
        elif step.step == StepType.WAIT:
            import asyncio
            asyncio.get_event_loop().run_until_complete(
                asyncio.sleep(step.timeout)
            )
            result.passed = True
            result.output = f"Waited {step.timeout} seconds"
    except Exception as e:
        result.error = str(e)
        result.passed = False

    result.duration_ms = int((time.time() - start_time) * 1000)
    return result


def execute_command_step(
    scenario_id: str, step: PlaybookStep
) -> PlaybookResult:
    """Execute a command in a container."""
    result = PlaybookResult(
        step_name=step.name or "execute_command",
        step_type=StepType.EXECUTE_COMMAND,
        passed=False,
    )

    container = find_container(scenario_id, step.container)
    if not container:
        result.error = f"Container {step.container} not found"
        return result

    try:
        exec_result = container.exec_run(
            cmd=["sh", "-c", step.command or "true"],
            demux=True,
        )
        exit_code = exec_result.exit_code
        stdout = exec_result.output[0].decode() if exec_result.output[0] else ""
        stderr = exec_result.output[1].decode() if exec_result.output[1] else ""

        result.output = f"exit_code={exit_code}\nstdout:\n{stdout}\nstderr:\n{stderr}"

        # Check expectations
        passed = True
        if step.expect.exit_code is not None:
            if exit_code != step.expect.exit_code:
                passed = False
                result.error = f"Expected exit code {step.expect.exit_code}, got {exit_code}"

        if step.expect.stdout_contains:
            if step.expect.stdout_contains not in stdout:
                passed = False
                result.error = f"stdout missing '{step.expect.stdout_contains}'"

        if step.expect.stdout_not_contains:
            if step.expect.stdout_not_contains in stdout:
                passed = False
                result.error = f"stdout contains forbidden '{step.expect.stdout_not_contains}'"

        if step.expect.stderr_contains:
            if step.expect.stderr_contains not in stderr:
                passed = False
                result.error = f"stderr missing '{step.expect.stderr_contains}'"

        result.passed = passed

    except Exception as e:
        result.error = str(e)

    return result


def check_file_step(
    scenario_id: str, step: PlaybookStep
) -> PlaybookResult:
    """Check if a file exists and optionally validate its contents."""
    result = PlaybookResult(
        step_name=step.name or "check_file",
        step_type=StepType.CHECK_FILE,
        passed=False,
    )

    container = find_container(scenario_id, step.container)
    if not container:
        result.error = f"Container {step.container} not found"
        return result

    try:
        # Check if file exists
        exec_result = container.exec_run(
            cmd=["test", "-f", step.path or "/dev/null"],
        )
        file_exists = exec_result.exit_code == 0

        if step.expect.file_exists is not None:
            if file_exists != step.expect.file_exists:
                result.error = f"file_exists={file_exists}, expected={step.expect.file_exists}"
                return result

        # Check contents if needed
        if step.expect.contains and file_exists:
            exec_result = container.exec_run(
                cmd=["cat", step.path],
                demux=True,
            )
            content = exec_result.output[0].decode() if exec_result.output[0] else ""
            result.output = content[:1000]  # Truncate for safety

            if step.expect.contains not in content:
                result.error = f"File missing '{step.expect.contains}'"
                return result

        result.passed = True

    except Exception as e:
        result.error = str(e)

    return result


def check_service_step(
    scenario_id: str, step: PlaybookStep
) -> PlaybookResult:
    """Check if a service is running in a container."""
    result = PlaybookResult(
        step_name=step.name or "check_service",
        step_type=StepType.CHECK_SERVICE,
        passed=False,
    )

    container = find_container(scenario_id, step.container)
    if not container:
        result.error = f"Container {step.container} not found"
        return result

    try:
        # Check if service process is running
        exec_result = container.exec_run(
            cmd=["pgrep", "-f", step.service or ""],
        )
        service_running = exec_result.exit_code == 0

        result.output = f"service_running={service_running}"

        if step.expect.service_running is not None:
            if service_running != step.expect.service_running:
                result.error = f"service_running={service_running}, expected={step.expect.service_running}"
                return result

        result.passed = True

    except Exception as e:
        result.error = str(e)

    return result


def check_network_step(
    scenario_id: str, step: PlaybookStep
) -> PlaybookResult:
    """Check network connectivity or port availability."""
    result = PlaybookResult(
        step_name=step.name or "check_network",
        step_type=StepType.CHECK_NETWORK,
        passed=False,
    )

    container = find_container(scenario_id, step.container)
    if not container:
        result.error = f"Container {step.container} not found"
        return result

    try:
        if step.port:
            # Check if port is open using nc
            exec_result = container.exec_run(
                cmd=["sh", "-c", f"nc -z localhost {step.port}"],
            )
            port_open = exec_result.exit_code == 0
            result.output = f"port_open={port_open}"

            if step.expect.port_open is not None:
                if port_open != step.expect.port_open:
                    result.error = f"port_open={port_open}, expected={step.expect.port_open}"
                    return result

        result.passed = True

    except Exception as e:
        result.error = str(e)

    return result


def load_playbook(playbook_name: str) -> Playbook:
    """Load a playbook from file."""
    playbook_path = PLAYBOOK_DIR / f"{playbook_name}.yaml"
    if not playbook_path.exists():
        raise HTTPException(status_code=404, detail=f"Playbook not found: {playbook_name}")

    with playbook_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return Playbook(
        name=data.get("name", playbook_name),
        description=data.get("description", ""),
        steps=[PlaybookStep(**s) for s in data.get("playbook", [])],
    )


def run_playbook(scenario_id: str, playbook: Playbook) -> PlaybookRunResult:
    """Run a playbook against a scenario."""
    results = []
    all_passed = True

    for step in playbook.steps:
        logger.info(
            "Running step: %s (%s) on %s",
            step.name or step.step.value,
            step.step.value,
            step.container,
        )
        result = execute_step(scenario_id, step)
        results.append(result)

        if not result.passed:
            all_passed = False
            logger.warning("Step failed: %s - %s", step.name, result.error)

    return PlaybookRunResult(
        scenario_id=scenario_id,
        playbook_name=playbook.name,
        passed=all_passed,
        steps=results,
        total_steps=len(results),
        passed_steps=sum(1 for r in results if r.passed),
    )


app = FastAPI(title="FrostGate Forge Playbook Runner")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "forge_playbook_runner"}


@app.post("/v1/run/{scenario_id}")
async def run_scenario_playbook(
    scenario_id: str, playbook_name: str
) -> PlaybookRunResult:
    """Run a named playbook against a scenario."""
    playbook = load_playbook(playbook_name)
    return run_playbook(scenario_id, playbook)


@app.post("/v1/run/{scenario_id}/inline")
async def run_inline_playbook(
    scenario_id: str, playbook: Playbook
) -> PlaybookRunResult:
    """Run an inline playbook against a scenario."""
    return run_playbook(scenario_id, playbook)


@app.get("/v1/playbooks")
async def list_playbooks() -> list[str]:
    """List available playbooks."""
    if not PLAYBOOK_DIR.exists():
        return []
    return [p.stem for p in PLAYBOOK_DIR.glob("*.yaml")]


@app.get("/v1/playbooks/{playbook_name}")
async def get_playbook(playbook_name: str) -> Playbook:
    """Get a playbook definition."""
    return load_playbook(playbook_name)
