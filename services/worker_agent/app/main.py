"""FrostGate Forge Worker Agent Service.

Executes scenario playbooks and collects evidence for scoring.
Subscribes to scenario.created events and runs success criteria checks.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import tarfile
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Any

import docker
import nats
from fastapi import FastAPI, HTTPException
from minio import Minio
from nats.js.api import ConsumerConfig, DeliverPolicy
from pydantic import BaseModel, Field

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("forge_worker_agent")

# Configuration
NATS_URL = os.getenv("NATS_URL", "nats://forge_nats:4222")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "forge_minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "forgeadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "forgeadmin123")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "forge-evidence")
TEMPLATE_DIR = Path(os.getenv("TEMPLATE_DIR", "/templates"))


class EvidenceType(str, Enum):
    COMMAND_OUTPUT = "command_output"
    FILE_CAPTURE = "file_capture"
    NETWORK_CAPTURE = "network_capture"
    STATE_SNAPSHOT = "state_snapshot"


class Artifact(BaseModel):
    type: EvidenceType
    name: str
    content_hash: str
    size_bytes: int
    content: str | None = None  # Base64 encoded for binary


class CriterionResult(BaseModel):
    criterion_id: str
    passed: bool
    evidence_refs: list[str] = Field(default_factory=list)
    message: str | None = None


class EvidenceBundle(BaseModel):
    scenario_id: str
    track: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    artifacts: list[Artifact] = Field(default_factory=list)
    criteria_results: list[CriterionResult] = Field(default_factory=list)


# Docker client
docker_client: docker.DockerClient | None = None

# NATS client
nc: nats.NATS | None = None
js: Any = None

# MinIO client
minio_client: Minio | None = None


def get_docker_client() -> docker.DockerClient:
    global docker_client
    if docker_client is None:
        docker_client = docker.from_env()
    return docker_client


def get_minio_client() -> Minio:
    global minio_client
    if minio_client is None:
        minio_client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=False,
        )
        # Ensure bucket exists
        if not minio_client.bucket_exists(MINIO_BUCKET):
            minio_client.make_bucket(MINIO_BUCKET)
    return minio_client


def load_template(track: str) -> dict:
    """Load scenario template from filesystem."""
    import yaml

    template_path = TEMPLATE_DIR / f"{track}.yaml"
    if not template_path.exists():
        raise ValueError(f"Template not found: {track}")
    with template_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def find_container(scenario_id: str, container_name: str) -> docker.models.containers.Container | None:
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


def execute_command(
    scenario_id: str, container_name: str, command: str
) -> tuple[int, str, str]:
    """Execute a command in a scenario container."""
    container = find_container(scenario_id, container_name)
    if not container:
        return -1, "", f"Container {container_name} not found"

    try:
        result = container.exec_run(
            cmd=["sh", "-c", command],
            demux=True,
        )
        exit_code = result.exit_code
        stdout = result.output[0].decode() if result.output[0] else ""
        stderr = result.output[1].decode() if result.output[1] else ""
        return exit_code, stdout, stderr
    except Exception as e:
        return -1, "", str(e)


def capture_file(
    scenario_id: str, container_name: str, file_path: str
) -> tuple[bool, str]:
    """Capture a file from a scenario container."""
    container = find_container(scenario_id, container_name)
    if not container:
        return False, f"Container {container_name} not found"

    try:
        bits, _ = container.get_archive(file_path)
        # Extract tar content
        tar_bytes = b"".join(bits)
        with tarfile.open(fileobj=BytesIO(tar_bytes)) as tar:
            for member in tar.getmembers():
                if member.isfile():
                    f = tar.extractfile(member)
                    if f:
                        return True, f.read().decode(errors="replace")
        return False, "File not found in archive"
    except Exception as e:
        return False, str(e)


def evaluate_criterion(
    scenario_id: str, criterion: dict, artifacts: list[Artifact]
) -> CriterionResult:
    """Evaluate a single success criterion."""
    criterion_id = criterion.get("id", "unknown")
    evidence_specs = criterion.get("evidence", [])

    passed = True
    messages = []
    evidence_refs = []

    for evidence_spec in evidence_specs:
        evidence_type = evidence_spec.get("type", "command")
        container_name = evidence_spec.get("container", "learner_vm")
        expect = evidence_spec.get("expect", {})

        if evidence_type == "command":
            command = evidence_spec.get("command", "true")
            exit_code, stdout, stderr = execute_command(
                scenario_id, container_name, command
            )

            # Create artifact
            artifact_name = f"{criterion_id}_{container_name}_cmd"
            content = f"exit_code: {exit_code}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            content_hash = hashlib.sha256(content.encode()).hexdigest()

            artifact = Artifact(
                type=EvidenceType.COMMAND_OUTPUT,
                name=artifact_name,
                content_hash=content_hash,
                size_bytes=len(content),
                content=content,
            )
            artifacts.append(artifact)
            evidence_refs.append(artifact_name)

            # Check expectations
            expected_exit = expect.get("exit_code")
            if expected_exit is not None and exit_code != expected_exit:
                passed = False
                messages.append(
                    f"Expected exit code {expected_exit}, got {exit_code}"
                )

            expected_stdout = expect.get("stdout_contains")
            if expected_stdout and expected_stdout not in stdout:
                passed = False
                messages.append(f"stdout missing '{expected_stdout}'")

        elif evidence_type == "file":
            file_path = evidence_spec.get("path", "/dev/null")
            success, content = capture_file(scenario_id, container_name, file_path)

            artifact_name = f"{criterion_id}_{container_name}_file"
            content_hash = hashlib.sha256(content.encode()).hexdigest()

            artifact = Artifact(
                type=EvidenceType.FILE_CAPTURE,
                name=artifact_name,
                content_hash=content_hash,
                size_bytes=len(content),
                content=content if len(content) < 10000 else content[:10000],
            )
            artifacts.append(artifact)
            evidence_refs.append(artifact_name)

            # Check expectations
            if expect.get("file_exists") and not success:
                passed = False
                messages.append(f"File {file_path} not found")

            expected_contains = expect.get("contains")
            if expected_contains and expected_contains not in content:
                passed = False
                messages.append(f"File missing '{expected_contains}'")

    return CriterionResult(
        criterion_id=criterion_id,
        passed=passed,
        evidence_refs=evidence_refs,
        message="; ".join(messages) if messages else None,
    )


def collect_evidence(scenario_id: str, track: str) -> EvidenceBundle:
    """Collect evidence for a scenario based on its success criteria."""
    template = load_template(track)
    success_criteria = template.get("successCriteria", [])

    artifacts: list[Artifact] = []
    criteria_results: list[CriterionResult] = []

    for criterion in success_criteria:
        result = evaluate_criterion(scenario_id, criterion, artifacts)
        criteria_results.append(result)
        logger.info(
            "Criterion %s: %s",
            criterion.get("id"),
            "PASS" if result.passed else "FAIL",
        )

    return EvidenceBundle(
        scenario_id=scenario_id,
        track=track,
        artifacts=artifacts,
        criteria_results=criteria_results,
    )


def store_evidence(bundle: EvidenceBundle) -> str:
    """Store evidence bundle in MinIO."""
    client = get_minio_client()

    # Create tar.zst archive (using tar.gz for simplicity)
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        with tarfile.open(tmp.name, "w:gz") as tar:
            # Add evidence.json
            evidence_json = bundle.model_dump_json(indent=2)
            evidence_bytes = evidence_json.encode()
            info = tarfile.TarInfo(name="evidence.json")
            info.size = len(evidence_bytes)
            tar.addfile(info, BytesIO(evidence_bytes))

            # Add individual artifacts
            for artifact in bundle.artifacts:
                if artifact.content:
                    artifact_bytes = artifact.content.encode()
                    info = tarfile.TarInfo(name=f"artifacts/{artifact.name}.txt")
                    info.size = len(artifact_bytes)
                    tar.addfile(info, BytesIO(artifact_bytes))

        # Upload to MinIO
        object_name = f"{bundle.scenario_id}/evidence.tar.gz"
        client.fput_object(MINIO_BUCKET, object_name, tmp.name)

        # Cleanup temp file
        Path(tmp.name).unlink()

    logger.info("Stored evidence bundle at %s/%s", MINIO_BUCKET, object_name)
    return f"s3://{MINIO_BUCKET}/{object_name}"


async def process_scenario_created(msg: Any) -> None:
    """Process scenario.created events and collect evidence."""
    try:
        data = json.loads(msg.data.decode())
        scenario_id = data.get("scenario_id")
        track = data.get("track")

        logger.info("Processing scenario.created: %s (track=%s)", scenario_id, track)

        # Wait for containers to be ready
        await asyncio.sleep(5)

        # Collect evidence
        bundle = collect_evidence(scenario_id, track)

        # Store evidence
        evidence_url = store_evidence(bundle)

        # Calculate quick score
        passed = sum(1 for r in bundle.criteria_results if r.passed)
        total = len(bundle.criteria_results)
        score = passed / total if total > 0 else 0.0

        # Publish scenario.completed event
        if js:
            await js.publish(
                "scenario.completed",
                json.dumps(
                    {
                        "scenario_id": scenario_id,
                        "track": track,
                        "score": score,
                        "passed": passed,
                        "total": total,
                        "evidence_url": evidence_url,
                    }
                ).encode(),
            )

        logger.info(
            "Scenario %s completed: score=%.2f (%d/%d)",
            scenario_id,
            score,
            passed,
            total,
        )

        await msg.ack()

    except Exception as e:
        logger.exception("Error processing scenario.created: %s", e)
        if msg:
            await msg.nak()


async def nats_subscriber() -> None:
    """Subscribe to NATS scenario events."""
    global nc, js

    try:
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()

        # Subscribe to scenario.created events
        consumer_config = ConsumerConfig(
            durable_name="worker_agent",
            deliver_policy=DeliverPolicy.ALL,
            ack_wait=60,  # Longer timeout for evidence collection
        )

        await js.subscribe(
            "scenario.created",
            cb=process_scenario_created,
            config=consumer_config,
        )
        logger.info("Subscribed to scenario.created")

        # Keep running
        while True:
            await asyncio.sleep(1)

    except Exception as e:
        logger.error("NATS subscriber error: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    task = asyncio.create_task(nats_subscriber())
    logger.info("Worker agent started")
    yield
    task.cancel()
    if nc:
        await nc.close()
    logger.info("Worker agent stopped")


app = FastAPI(title="FrostGate Forge Worker Agent", lifespan=lifespan)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "forge_worker_agent"}


@app.post("/v1/collect/{scenario_id}")
async def collect(scenario_id: str, track: str) -> dict:
    """Manually trigger evidence collection for a scenario."""
    try:
        bundle = collect_evidence(scenario_id, track)
        evidence_url = store_evidence(bundle)

        passed = sum(1 for r in bundle.criteria_results if r.passed)
        total = len(bundle.criteria_results)

        return {
            "scenario_id": scenario_id,
            "score": passed / total if total > 0 else 0.0,
            "passed": passed,
            "total": total,
            "evidence_url": evidence_url,
            "criteria": [r.model_dump() for r in bundle.criteria_results],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
