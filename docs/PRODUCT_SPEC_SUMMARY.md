# CyberRange — product spec summary

Condensed from `CyberRange_Product_Spec.docx` v1.0 (2026-07-20). This file
records the product intent this repo implements an MVP of; see the source
document for the full text.

## Vision

Give defenders, attackers, and joint teams a safe, repeatable environment to
execute realistic adversary behaviors, observe telemetry, validate controls,
and prove measurable readiness — without exposing production systems.

## MVP decision statement

A single-node or small-cluster MVP supporting 1–20 concurrent ranges, Windows
and Linux targets, Docker Engine/Compose workloads, an attacker workstation,
centralized telemetry, browser-based access, scenario reset, role-specific
objectives, and an initial catalog of 24 safe TTP emulations. The control
plane is designed to scale later to Kubernetes-managed hypervisor pools and
cloud-hosted ranges.

## Personas

Red operator, Blue analyst, Purple lead, Instructor, Range administrator,
Security leader — each with distinct objectives and success measures.

## Reference topology

Each exercise is an ephemeral tenant with **no route** to other tenants, the
host management plane, or the Internet (unless an admin enables a controlled
proxy allowlist). Zones: access (bastion), red (attacker), enterprise user,
server (AD/DNS, app, file), container (Docker host, Compose, private OCI
registry), security (SIEM/EDR/sensors), and a control plane that is never
reachable from tenant workloads.

## Detection stack (MVP)

Wazuh (endpoint/SIEM) + Sysmon (Windows) + auditd/journald (Linux) + Docker
listener + Suricata (network IDS) + Falco (container runtime). All behind a
normalized telemetry adapter so customers can substitute Elastic, Sentinel,
Splunk, or their SOC stack.

## Functional requirements (FR-01…FR-14)

Scenario catalog, topology templates, lifecycle, scenario engine, role
workspaces, TTP emulation, telemetry, detection content, scoring, replay,
reporting, administration, authoring SDK, and REST/event APIs.

## Lifecycle

`REQUESTED → PREFLIGHT → PROVISIONING → SEEDING → READY → RUNNING ↔ PAUSED →
COMPLETING → EVIDENCE_LOCKED → ARCHIVED → DESTROYED`. Any anomalous workload
transitions to `QUARANTINED`; only an administrator can release or destroy it.

## Scoring dimensions

Red execution 25%, Detection 25%, Investigation 20%, Response 20%,
Collaboration 10%. Score = weighted objective points − safety/policy
penalties. Every input is explainable and override-audited. Purple improvement
is reported as baseline-to-replay change, never win/lose.

## Safety classes

- **S0 Simulation** — synthetic telemetry / benign endpoint (author approval).
- **S1 Atomic emulation** — bounded behavior on disposable assets, auto-cleanup
  (security content reviewer).
- **S2 High-impact lab action** — may disrupt a lab VM / change identity state
  (admin + explicit scenario policy).
- **Prohibited** — self-propagation, external targeting, real credential theft,
  live malware. Never permitted.

## MVP scope (12–16 weeks)

SSO/RBAC; Red/Blue/Purple/instructor roles; KVM/Proxmox or VMware adapter;
Windows/AD/Linux/attacker/security templates + a Docker host template; isolated
networking, browser access, lifecycle + reset; **7 launch scenarios**, **≥24
signed S0/S1 behavior modules** across Windows/Linux/Docker; bundled
Wazuh/Suricata/Falco telemetry; objective engine, evidence submission,
automatic scoring, instructor overrides, DOCX/PDF/JSON reporting;
baseline/replay comparison; audit, retention, quota, emergency kill.

## What this repository implements

A runnable **control-plane MVP** of the above: the data model, lifecycle state
machine, catalog, RBAC, scoring, replay comparison, evidence timeline,
reporting, audit ledger, a REST API, and an operator dashboard. Actual
hypervisor provisioning, live sensors, and SSO are represented by clean
seams (topology templates, telemetry events, header-based identity) intended
to be backed by real adapters in later phases.
