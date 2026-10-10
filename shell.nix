# #################################################################
# /qompassai/volta/shell.nix
# Qompass AI Flake-Compat Shell Shim
# SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
# Copyright (c) 2026 Qompass AI
#
# This file was authored by Qompass AI and is dual-licensed
# under AGPL-3.0 or Apache-2.0 at the recipient's choice
# (see LICENSE-AGPL, LICENSE, and NOTICE). Volta as a whole
# is Hagrid-derived and distributed under AGPL-3.0; the
# Apache choice applies to Qompass-authored material only.
# Non-flake entry point: lands `nix-shell` users in the same shell
# flake.nix defines, via flake-compat. The canonical definition is
# the flake; edit that, not this.
(import (
  let
    lock = builtins.fromJSON (builtins.readFile ./flake.lock);
  in
    fetchTarball {
      url = "https://github.com/edolstra/flake-compat/archive/${lock.nodes.flake-compat.locked.rev}.tar.gz";
      sha256 = lock.nodes.flake-compat.locked.narHash;
    }
) {src = ./.;})
.shellNix
