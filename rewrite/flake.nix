# #################################################################
# /qompassai/volta/rewrite/flake.nix
# Qompass AI Volta Clean-Room Rewrite — Flake
# SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
# Copyright (c) 2026 Qompass AI
#
# Original work of Qompass AI (clean-room rewrite, 2026-10-10).
# #################################################################
{
  description = "Volta (clean-room rewrite) — secure key server for MCP and A2A: OpenPGP key service, ephemeral hybrid-PQC keys, WebAuthn operator auth, fail-closed proxy chains";

  inputs = {
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = {
    fenix,
    nixpkgs,
    self,
    ...
  }: let
    forAllSystems = nixpkgs.lib.genAttrs ["x86_64-linux"];
  in {
    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      toolchain = fenix.packages.${system}.fromToolchainFile {
        dir = ./.;
        sha256 = "sha256-3ok3kaNc8lhDSnZ9bZAJwmHgUrdB9CC5m+ZJBwFPWnA=";
      };
    in {
      default = pkgs.mkShell {
        packages = [
          pkgs.mdbook
          pkgs.sqlite
          toolchain
        ];
      };
    });

    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      toolchain = fenix.packages.${system}.fromToolchainFile {
        dir = ./.;
        sha256 = "sha256-3ok3kaNc8lhDSnZ9bZAJwmHgUrdB9CC5m+ZJBwFPWnA=";
      };
      rustPlatform = pkgs.makeRustPlatform {
        cargo = toolchain;
        rustc = toolchain;
      };
    in {
      default = self.packages.${system}.volta-server;
      volta-cli = rustPlatform.buildRustPackage {
        pname = "volta-cli";
        version = "2.0.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = ["--package" "volta-cli"];
        doCheck = false;
        meta.license = with pkgs.lib.licenses; [agpl3Only asl20];
      };
      volta-server = rustPlatform.buildRustPackage {
        pname = "volta-server";
        version = "2.0.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = ["--package" "volta-server"];
        doCheck = false;
        meta.license = with pkgs.lib.licenses; [agpl3Only asl20];
      };
    });
  };
}
