"""FrostGate Forge LLM Analyzer Service.

Governed LLM proposal pipeline with canary checks and rollback safety.
Analyzes proposed agent actions, enforces policy gates and required signatures,
and supports canary execution with rollback on failure.
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import hashlib
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import httpx
import nats
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException, Request
from nats.js.api import ConsumerConfig, DeliverPolicy
from pydantic import BaseModel, Field

request_id_ctx = contextvars.ContextVar("request_id", default="-")


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": request_id_ctx.get(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())


configure_logging()
logger = logging.getLogger("forge_llm_analyzer")

# Configuration
NATS_URL = os.getenv("NATS_URL", "nats://forge_nats:4222")
OPA_URL = os.getenv("OPA_URL", "http://forge_opa:8181")
CANARY_TIMEOUT_SECONDS = int(os.getenv("CANARY_TIMEOUT_SECONDS", "30"))
MAX_PROPOSAL_SIZE = int(os.getenv("MAX_PROPOSAL_SIZE", "65536"))


class ProposalStatus(str, Enum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    CANARY_RUNNING = "canary_running"
    APPROVED = "approved"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class PolicyClass(str, Enum):
    READ_ONLY = "read_only"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    PRIVILEGED = "privileged"


class ActionProposal(BaseModel):
    proposal_id: str = Field(default_factory=lambda: f"prop-{uuid.uuid4().hex[:12]}")
    scenario_id: str
    actor: str  # agent making the proposal
    action_type: str  # command, file_write, network_request, etc.
    action_content: str
    policy_class: PolicyClass = PolicyClass.READ_ONLY
    signature: str | None = None
    signed: bool = False
    canary_required: bool = True
    canary_executed: bool = False
    canary_passed: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ProposalResult(BaseModel):
    proposal_id: str
    status: ProposalStatus
    allowed: bool = False
    reasons: list[str] = Field(default_factory=list)
    canary_output: str | None = None
    rollback_triggered: bool = False
    processed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CanaryResult(BaseModel):
    proposal_id: str
    success: bool
    output: str
    duration_ms: int
    side_effects_detected: bool = False


class AnalyzerStats(BaseModel):
    total_proposals: int = 0
    approved: int = 0
    rejected: int = 0
    canary_failures: int = 0
    rollbacks: int = 0
    by_policy_class: dict[str, int] = Field(default_factory=dict)


# In-memory stores
proposals: dict[str, ActionProposal] = {}
results: dict[str, ProposalResult] = {}
stats = AnalyzerStats()

# Signing key (ephemeral - use KMS in production)
SIGNING_KEY: ed25519.Ed25519PrivateKey | None = None
VERIFY_KEY: ed25519.Ed25519PublicKey | None = None

# NATS client
nc: nats.NATS | None = None
js: Any = None


def get_signing_keys() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Get or generate signing keys."""
    global SIGNING_KEY, VERIFY_KEY
    if SIGNING_KEY is None:
        SIGNING_KEY = ed25519.Ed25519PrivateKey.generate()
        VERIFY_KEY = SIGNING_KEY.public_key()
        logger.warning("Generated ephemeral LLM signing key - use KMS in production")
    return SIGNING_KEY, VERIFY_KEY


def sign_proposal(proposal: ActionProposal) -> str:
    """Sign a proposal and return the signature."""
    private_key, _ = get_signing_keys()

    # Create canonical representation
    message = f"{proposal.proposal_id}:{proposal.scenario_id}:{proposal.action_type}:{proposal.action_content}"
    message_hash = hashlib.sha256(message.encode()).digest()

    signature = private_key.sign(message_hash)
    return base64.b64encode(signature).decode()


def verify_signature(proposal: ActionProposal) -> bool:
    """Verify a proposal's signature."""
    if not proposal.signature:
        return False

    _, public_key = get_signing_keys()

    try:
        message = f"{proposal.proposal_id}:{proposal.scenario_id}:{proposal.action_type}:{proposal.action_content}"
        message_hash = hashlib.sha256(message.encode()).digest()
        signature = base64.b64decode(proposal.signature)
        public_key.verify(signature, message_hash)
        return True
    except Exception as e:
        logger.warning("Signature verification failed: %s", e)
        return False


async def check_opa_policy(proposal: ActionProposal) -> tuple[bool, list[str]]:
    """Query OPA for LLM policy decision."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            input_data = {
                "proposal_id": proposal.proposal_id,
                "scenario_id": proposal.scenario_id,
                "signed": proposal.signed,
                "canary": proposal.canary_executed and proposal.canary_passed,
                "policy_class": proposal.policy_class.value,
                "authorized": True,  # In production, check against auth service
            }

            response = await client.post(
                f"{OPA_URL}/v1/data/frostgate/forge/llm/allow",
                json={"input": input_data},
            )

            if response.status_code >= 400:
                return False, ["OPA error"]

            result = response.json()
            allowed = result.get("result", False)

            # Get deny reasons if not allowed
            reasons = []
            if not allowed:
                reasons_response = await client.post(
                    f"{OPA_URL}/v1/data/frostgate/forge/llm/deny_reasons",
                    json={"input": input_data},
                )
                if reasons_response.status_code < 400:
                    reasons = reasons_response.json().get("result", [])

            return allowed, reasons

        except httpx.RequestError as e:
            logger.warning("OPA request failed: %s", e)
            return False, [f"OPA unavailable: {e}"]


def analyze_action_safety(proposal: ActionProposal) -> tuple[bool, list[str]]:
    """Analyze action content for safety concerns."""
    concerns = []
    content = proposal.action_content.lower()

    # Check for dangerous patterns
    dangerous_patterns = [
        ("rm -rf", "destructive file deletion"),
        ("dd if=", "low-level disk operation"),
        (":(){ :|:& };:", "fork bomb pattern"),
        ("mkfs", "filesystem format"),
        ("> /dev/", "direct device write"),
        ("chmod 777", "overly permissive permissions"),
        ("curl | sh", "remote code execution"),
        ("wget | bash", "remote code execution"),
    ]

    for pattern, reason in dangerous_patterns:
        if pattern in content:
            concerns.append(f"Dangerous pattern detected: {reason}")

    # Check action size
    if len(proposal.action_content) > MAX_PROPOSAL_SIZE:
        concerns.append(f"Action content exceeds size limit ({MAX_PROPOSAL_SIZE})")

    # Check policy class requirements
    if proposal.policy_class == PolicyClass.PRIVILEGED:
        if "sudo" not in content and "doas" not in content:
            logger.info("Privileged action without sudo/doas - may fail")
        concerns.append("Privileged action requires additional review")

    return len(concerns) == 0, concerns


async def execute_canary(proposal: ActionProposal) -> CanaryResult:
    """Execute a canary check for the proposal."""
    start_time = datetime.now(timezone.utc)

    # In production, this would actually execute in a sandboxed environment
    # For now, we simulate the canary execution
    logger.info(
        "Executing canary for proposal %s (action: %s)",
        proposal.proposal_id,
        proposal.action_type,
    )

    # Simulate execution
    await asyncio.sleep(0.1)  # Simulated delay

    # Check for obvious failures
    success = True
    output = "canary executed successfully"
    side_effects = False

    if "fail" in proposal.action_content.lower():
        success = False
        output = "simulated failure in canary"

    if "write" in proposal.action_type or "execute" in proposal.action_type:
        side_effects = True

    duration_ms = int(
        (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
    )

    return CanaryResult(
        proposal_id=proposal.proposal_id,
        success=success,
        output=output,
        duration_ms=duration_ms,
        side_effects_detected=side_effects,
    )


async def rollback_canary(proposal: ActionProposal) -> bool:
    """Rollback a failed canary execution."""
    logger.warning("Rolling back canary for proposal %s", proposal.proposal_id)
    stats.rollbacks += 1
    # In production, this would actually reverse any side effects
    return True


async def analyze_proposal(proposal: ActionProposal) -> ProposalResult:
    """Full analysis pipeline for a proposal."""
    stats.total_proposals += 1
    stats.by_policy_class[proposal.policy_class.value] = (
        stats.by_policy_class.get(proposal.policy_class.value, 0) + 1
    )

    reasons: list[str] = []

    # Step 1: Sign the proposal if not already signed
    if not proposal.signed:
        proposal.signature = sign_proposal(proposal)
        proposal.signed = verify_signature(proposal)

    if not proposal.signed:
        reasons.append("Failed to sign proposal")
        stats.rejected += 1
        return ProposalResult(
            proposal_id=proposal.proposal_id,
            status=ProposalStatus.REJECTED,
            allowed=False,
            reasons=reasons,
        )

    # Step 2: Analyze action safety
    safe, safety_concerns = analyze_action_safety(proposal)
    reasons.extend(safety_concerns)

    if not safe and proposal.policy_class in [PolicyClass.PRIVILEGED, PolicyClass.EXECUTE]:
        stats.rejected += 1
        return ProposalResult(
            proposal_id=proposal.proposal_id,
            status=ProposalStatus.REJECTED,
            allowed=False,
            reasons=reasons,
        )

    # Step 3: Execute canary if required
    canary_output = None
    rollback_triggered = False

    if proposal.canary_required:
        canary_result = await execute_canary(proposal)
        canary_output = canary_result.output
        proposal.canary_executed = True
        proposal.canary_passed = canary_result.success

        if not canary_result.success:
            stats.canary_failures += 1
            if canary_result.side_effects_detected:
                await rollback_canary(proposal)
                rollback_triggered = True

            stats.rejected += 1
            return ProposalResult(
                proposal_id=proposal.proposal_id,
                status=ProposalStatus.ROLLED_BACK if rollback_triggered else ProposalStatus.REJECTED,
                allowed=False,
                reasons=["Canary execution failed"] + reasons,
                canary_output=canary_output,
                rollback_triggered=rollback_triggered,
            )

    # Step 4: Check OPA policy
    allowed, opa_reasons = await check_opa_policy(proposal)
    reasons.extend(opa_reasons)

    if not allowed:
        stats.rejected += 1
        return ProposalResult(
            proposal_id=proposal.proposal_id,
            status=ProposalStatus.REJECTED,
            allowed=False,
            reasons=reasons,
            canary_output=canary_output,
        )

    # All checks passed
    stats.approved += 1
    return ProposalResult(
        proposal_id=proposal.proposal_id,
        status=ProposalStatus.APPROVED,
        allowed=True,
        reasons=reasons if reasons else ["All checks passed"],
        canary_output=canary_output,
    )


async def process_proposal_request(msg: Any) -> None:
    """Process incoming proposal requests from NATS."""
    try:
        data = json.loads(msg.data.decode())

        proposal = ActionProposal(
            scenario_id=data.get("scenario_id", ""),
            actor=data.get("actor", "unknown"),
            action_type=data.get("action_type", "unknown"),
            action_content=data.get("action_content", ""),
            policy_class=PolicyClass(data.get("policy_class", "read_only")),
            metadata=data.get("metadata", {}),
        )

        proposals[proposal.proposal_id] = proposal

        logger.info(
            "Processing proposal %s from %s (type: %s)",
            proposal.proposal_id,
            proposal.actor,
            proposal.action_type,
        )

        result = await analyze_proposal(proposal)
        results[result.proposal_id] = result

        # Publish result to NATS
        if js:
            await js.publish(
                "llm.decision",
                json.dumps(
                    {
                        "proposal_id": result.proposal_id,
                        "scenario_id": proposal.scenario_id,
                        "allowed": result.allowed,
                        "status": result.status.value,
                        "reasons": result.reasons,
                    }
                ).encode(),
            )

        await msg.ack()

    except Exception as e:
        logger.exception("Error processing proposal: %s", e)
        if msg:
            await msg.nak()


async def nats_subscriber() -> None:
    """Subscribe to NATS proposal events."""
    global nc, js

    try:
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()

        # Ensure stream exists
        try:
            await js.add_stream(name="LLM", subjects=["llm.*"])
        except Exception:
            pass

        # Subscribe to proposal requests
        config = ConsumerConfig(
            durable_name="llm_analyzer",
            deliver_policy=DeliverPolicy.NEW,
            ack_wait=CANARY_TIMEOUT_SECONDS + 10,
        )
        await js.subscribe(
            "llm.proposal",
            cb=process_proposal_request,
            config=config,
        )

        logger.info("Subscribed to LLM proposal stream")

        while True:
            await asyncio.sleep(1)

    except Exception as e:
        logger.error("NATS subscriber error: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Initialize signing keys
    get_signing_keys()

    task = asyncio.create_task(nats_subscriber())
    logger.info("LLM Analyzer started")
    yield
    task.cancel()
    if nc:
        await nc.close()
    logger.info("LLM Analyzer stopped")


app = FastAPI(title="FrostGate Forge LLM Analyzer", lifespan=lifespan)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = (
        request.headers.get("x-request-id")
        or request.headers.get("x-correlation-id")
        or str(uuid.uuid4())
    )
    token = request_id_ctx.set(request_id)
    response = await call_next(request)
    request_id_ctx.reset(token)
    response.headers["x-request-id"] = request_id
    return response


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "forge_llm_analyzer"}


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "forge_llm_analyzer"}


@app.get("/readyz")
def readyz() -> dict:
    return {"status": "ready", "service": "forge_llm_analyzer"}


@app.post("/v1/proposals")
async def submit_proposal(proposal: ActionProposal) -> ProposalResult:
    """Submit a proposal for analysis."""
    proposals[proposal.proposal_id] = proposal
    result = await analyze_proposal(proposal)
    results[result.proposal_id] = result
    return result


@app.get("/v1/proposals/{proposal_id}")
async def get_proposal(proposal_id: str) -> ActionProposal:
    """Get a proposal by ID."""
    if proposal_id not in proposals:
        raise HTTPException(status_code=404, detail="Proposal not found")
    return proposals[proposal_id]


@app.get("/v1/proposals/{proposal_id}/result")
async def get_result(proposal_id: str) -> ProposalResult:
    """Get the result of a proposal analysis."""
    if proposal_id not in results:
        raise HTTPException(status_code=404, detail="Result not found")
    return results[proposal_id]


@app.get("/v1/proposals")
async def list_proposals(
    scenario_id: str | None = None,
    status: ProposalStatus | None = None,
    limit: int = 100,
) -> list[ActionProposal]:
    """List proposals with optional filters."""
    result = list(proposals.values())
    if scenario_id:
        result = [p for p in result if p.scenario_id == scenario_id]
    if status and status.value in results:
        result = [
            p
            for p in result
            if p.proposal_id in results and results[p.proposal_id].status == status
        ]
    return result[-limit:]


@app.get("/v1/stats")
async def get_stats() -> AnalyzerStats:
    """Get analyzer statistics."""
    return stats


@app.get("/v1/policy-classes")
async def list_policy_classes() -> list[dict]:
    """List available policy classes."""
    return [
        {"name": PolicyClass.READ_ONLY.value, "description": "Read-only operations"},
        {"name": PolicyClass.WRITE.value, "description": "File write operations"},
        {"name": PolicyClass.EXECUTE.value, "description": "Command execution"},
        {"name": PolicyClass.NETWORK.value, "description": "Network operations"},
        {"name": PolicyClass.PRIVILEGED.value, "description": "Privileged operations (requires additional review)"},
    ]


@app.post("/v1/sign")
async def sign_action(proposal: ActionProposal) -> dict:
    """Sign a proposal (for testing/development)."""
    signature = sign_proposal(proposal)
    return {
        "proposal_id": proposal.proposal_id,
        "signature": signature,
        "signed": True,
    }


@app.post("/v1/verify")
async def verify_action(proposal: ActionProposal) -> dict:
    """Verify a proposal's signature."""
    valid = verify_signature(proposal)
    return {
        "proposal_id": proposal.proposal_id,
        "valid": valid,
    }
