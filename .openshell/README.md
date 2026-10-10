# OpenShell configuration for volta

<!-- SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0 -->
<!-- Copyright (c) 2026 Qompass AI -->

ORIGINATED, NOT REPLICATED: no project repo in the Qompass estate
carries a repo-level OpenShell config (verified 2026-10-10 across
light-show, phlow, volta, vongola, and the GitHub mirrors). The only
established pattern is machine-level: the NVIDIA OpenShell gateway
configuration in the operator's home (`~/.config/openshell/
gateway.toml`, version 2, podman driver, mTLS) documented by
`agents/openshell/CONFIGURATION.md` in the diver configuration.

This directory is the minimal idiomatic equivalent for volta:
`gateway.toml.example` mirrors the machine gateway's shape with
volta-specific naming, so a volta development sandbox can be run
behind the same gateway conventions. It contains no secrets; real
gateway state stays in the operator's home configuration.
