"""Explainable wireless security rules.

Rules evaluate *advertised* configuration from beacon/probe response metadata.
They never perform active testing. A configuration observation can be promoted
to a verified vulnerability by the assessor after review; otherwise it is
reported as a potential risk.
"""

from __future__ import annotations

from dataclasses import dataclass

from .domain import (
    Finding,
    FindingStatus,
    NetworkObservation,
    SecurityFamily,
    Severity,
    classify_security,
)


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    rule_id: str
    title: str
    severity: Severity
    category: str


RULES: dict[str, RuleMetadata] = {
    "SS-INV-001": RuleMetadata(
        "SS-INV-001", "Network observed", Severity.INFO, "Inventory"
    ),
    "SS-AUTH-001": RuleMetadata(
        "SS-AUTH-001", "Open wireless network", Severity.HIGH, "Authentication"
    ),
    "SS-AUTH-002": RuleMetadata(
        "SS-AUTH-002", "WEP encryption in use", Severity.CRITICAL, "Encryption"
    ),
    "SS-AUTH-003": RuleMetadata(
        "SS-AUTH-003", "Legacy WPA configuration", Severity.HIGH, "Authentication"
    ),
    "SS-AUTH-004": RuleMetadata(
        "SS-AUTH-004", "TKIP encryption in use", Severity.HIGH, "Encryption"
    ),
    "SS-AUTH-005": RuleMetadata(
        "SS-AUTH-005",
        "WPA2-Personal without protected management frames",
        Severity.LOW,
        "Management frame protection",
    ),
    "SS-AUTH-006": RuleMetadata(
        "SS-AUTH-006", "WPA3 transition mode enabled", Severity.LOW, "Authentication"
    ),
    "SS-AUTH-007": RuleMetadata(
        "SS-AUTH-007", "WPS enabled", Severity.HIGH, "Configuration"
    ),
    "SS-AUTH-008": RuleMetadata(
        "SS-AUTH-008", "Unknown or unclassified security", Severity.MEDIUM, "Configuration"
    ),
    "SS-OBS-001": RuleMetadata(
        "SS-OBS-001", "Hidden SSID in use", Severity.INFO, "Observation"
    ),
    "SS-OBS-002": RuleMetadata(
        "SS-OBS-002", "Legacy 802.11 standard advertised", Severity.LOW, "Protocol"
    ),
}


def _finding(
    network: NetworkObservation,
    rule_id: str,
    explanation: str,
    impact: str,
    remediation: str,
    *,
    status: FindingStatus = FindingStatus.POTENTIAL,
    confidence: str = "High",
    evidence: str | None = None,
) -> Finding:
    meta = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        title=meta.title,
        severity=meta.severity,
        category=meta.category,
        explanation=explanation,
        impact=impact,
        remediation=remediation,
        status=status,
        confidence=confidence,
        evidence=evidence
        or (
            f"Advertised security: {network.authentication or 'unknown'} / "
            f"{network.encryption or 'unknown'}; observed from {network.source}."
        ),
        bssid=network.bssid,
        ssid=network.display_ssid,
        assessment_id=network.assessment_id,
        network_id=network.id,
    )


def analyze_network(network: NetworkObservation) -> list[Finding]:
    """Return explainable findings for one observed network.

    Every network gets an inventory observation first, so the Inspector shows
    secure networks as well as networks with configuration risks.
    """
    findings: list[Finding] = []
    family = classify_security(network.authentication, network.encryption)
    encryption = (network.encryption or "").lower()
    authentication = (network.authentication or "").lower()
    pmf = (network.pmf or "").lower()
    wps = (network.wps or "").lower()
    standards = (network.standards or "").lower()

    findings.append(
        _finding(
            network,
            "SS-INV-001",
            "The network was observed during the assessment. Its advertised "
            "authentication, encryption and capability information is recorded below.",
            "This is an inventory observation, not evidence of an exploitable flaw. "
            "It keeps every observed network visible in the Inspector, including "
            "networks with no configuration findings.",
            "No action is required for this observation. Review any additional "
            "findings recorded against the same network.",
            status=FindingStatus.OBSERVATION,
            confidence="High",
        )
    )

    if family is SecurityFamily.OPEN:
        findings.append(
            _finding(
                network,
                "SS-AUTH-001",
                "The access point advertises an open authentication and encryption "
                "configuration. Traffic is not protected by a wireless link-layer "
                "cipher, so nearby devices can observe or inject unprotected traffic.",
                "An attacker within radio range may capture sensitive traffic and "
                "attempt client or portal attacks. The actual exposure depends on "
                "higher-layer protections and the network's intended use.",
                "Use WPA3-Personal (SAE) or, where legacy clients require it, "
                "WPA2-Personal with AES-CCMP. If open access is essential for a guest "
                "portal, isolate the guest VLAN and require an encrypted tunnel for "
                "sensitive services.",
                confidence="High",
            )
        )
    elif family is SecurityFamily.WEP:
        findings.append(
            _finding(
                network,
                "SS-AUTH-002",
                "The network advertises WEP, a deprecated encryption protocol with "
                "well-known cryptographic weaknesses that allow keys to be recovered "
                "from sufficient captured traffic.",
                "WEP cannot provide meaningful confidentiality or integrity. An "
                "attacker within range could recover the key and decrypt or forge "
                "traffic.",
                "Replace WEP with WPA3-Personal (SAE) or WPA2-Personal using AES-CCMP. "
                "Treat all data sent over WEP as compromised and rotate any shared "
                "credentials that may have traversed the network.",
                confidence="High",
            )
        )
    elif family is SecurityFamily.WPA:
        findings.append(
            _finding(
                network,
                "SS-AUTH-003",
                "The network advertises WPA (the original 802.11i draft or WPA1 "
                "implementation). WPA1 lacks the stronger cipher suites and "
                "protections expected of modern deployments.",
                "Legacy WPA configurations may expose clients to downgrade and "
                "offline guessing attacks, and often coexist with TKIP.",
                "Migrate to WPA3-Personal (SAE), or WPA2-Personal with AES-CCMP where "
                "client compatibility requires it. Disable WPA1 and TKIP.",
                confidence="High",
            )
        )

    if "tkip" in encryption or "wep" in encryption:
        if family not in {SecurityFamily.WEP, SecurityFamily.OPEN}:
            findings.append(
                _finding(
                    network,
                    "SS-AUTH-004",
                    "The access point advertises TKIP as a supported or active "
                    "encryption cipher. TKIP is deprecated and has known design "
                    "weaknesses.",
                    "TKIP reduces the effective security of the WPA/WPA2 deployment and "
                    "can create interoperability or downgrade pressure.",
                    "Configure AES-CCMP only. Remove TKIP from the access point's "
                    "supported cipher list and retire clients that cannot use AES.",
                    confidence="High",
                )
            )

    if family is SecurityFamily.WPA2 and pmf in {"disabled", "no", "not required"}:
        findings.append(
            _finding(
                network,
                "SS-AUTH-005",
                "The beacon indicates WPA2-Personal without Protected Management "
                "Frames (802.11w). PMF protects certain management frames against "
                "spoofing.",
                "Without PMF, management-frame spoofing may be easier in some "
                "environments. The practical risk depends on the deployment and "
                "client support; this observation was not tested actively.",
                "Enable PMF in capable mode where clients support it, and prefer WPA3 "
                "for protected management frames by default. Validate legacy client "
                "compatibility before enforcing PMF.",
                confidence="Medium",
            )
        )

    if "transition" in authentication or (
        "wpa2" in authentication and "wpa3" in authentication
    ):
        findings.append(
            _finding(
                network,
                "SS-AUTH-006",
                "The network advertises WPA3 transition mode alongside WPA2. "
                "Transition mode allows legacy clients while retaining WPA3 for "
                "capable clients, but it also preserves WPA2 attack surface.",
                "A mixed mode deployment may permit downgrade-style attacks against "
                "clients that support WPA3. The actual exposure depends on client "
                "policy and access point configuration.",
                "Plan migration to WPA3-only after validating client support. Monitor "
                "for legacy clients and maintain PMF where possible.",
                confidence="Medium",
            )
        )

    if wps in {"enabled", "yes", "true", "configured", "1"}:
        findings.append(
            _finding(
                network,
                "SS-AUTH-007",
                "The access point advertises Wi-Fi Protected Setup (WPS). WPS PIN "
                "implementations have historically enabled offline or online PIN "
                "guessing against the access point.",
                "If WPS PIN or Push-Button configuration is exposed, an attacker "
                "within range may be able to obtain the network credential.",
                "Disable WPS unless it is operationally required. If required, prefer "
                "Push-Button Configuration, monitor for repeated WPS failures and "
                "update access point firmware.",
                status=FindingStatus.POTENTIAL,
                confidence="Medium",
                evidence=f"WPS advertised as {network.wps}.",
            )
        )

    if family is SecurityFamily.UNKNOWN and not authentication and not encryption:
        findings.append(
            _finding(
                network,
                "SS-AUTH-008",
                "The discovery data did not include a recognised authentication or "
                "encryption configuration.",
                "The security posture of this network cannot be assessed from the "
                "available observation. It may be incomplete discovery data rather "
                "than a weakness.",
                "Re-scan from a trusted discovery source, verify the access point's "
                "configuration and record the result before drawing a conclusion.",
                status=FindingStatus.OBSERVATION,
                confidence="Low",
            )
        )

    if network.hidden:
        findings.append(
            _finding(
                network,
                "SS-OBS-001",
                "The network does not advertise a readable SSID. Hiding the SSID is "
                "not a security control and can be discovered by observing client "
                "probe traffic.",
                "The network name may be exposed by clients. Hidden SSIDs can also "
                "complicate troubleshooting and client roaming.",
                "Do not rely on SSID hiding for security. Use strong WPA3 or WPA2 "
                "authentication and treat the SSID as public information.",
                status=FindingStatus.OBSERVATION,
                confidence="High",
            )
        )

    legacy_markers = ("802.11b", "802.11g")
    if any(marker in standards for marker in legacy_markers) and "802.11n" not in standards:
        findings.append(
            _finding(
                network,
                "SS-OBS-002",
                "Only legacy 802.11b/g radio standards were advertised in the "
                "discovery data.",
                "Legacy rates and radios can reduce throughput and may indicate older "
                "access point hardware that no longer receives security updates.",
                "Plan hardware refresh and disable legacy rates where client support "
                "allows. This is an observation, not evidence of an exploitable flaw.",
                status=FindingStatus.OBSERVATION,
                confidence="Low",
            )
        )

    return findings


def analyze_networks(networks: list[NetworkObservation]) -> list[Finding]:
    findings: list[Finding] = []
    for network in networks:
        findings.extend(analyze_network(network))
    return findings


def rule_count() -> int:
    return len(RULES)

