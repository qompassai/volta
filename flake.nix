# #################################################################
# /qompassai/volta/flake.nix
# Qompass AI Flake (Package And Development Shell)
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Qompass AI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
{
  description = "Volta — an OpenPGP key server (Hagrid-derived): HKP, VKS API, and Web Key Directory";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # sequoia-openpgp's crypto-nettle backend needs nettle 3.x
    # headers: nettle 4 removed nettle/pgp.h, which nettle-sys
    # consumes via bindgen. This older nixpkgs supplies nettle 3.10
    # and is used for that library only.
    nixpkgs-nettle.url = "github:NixOS/nixpkgs/nixos-24.11";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = {
    self,
    nixpkgs,
    nixpkgs-nettle,
    fenix,
    ...
  }: let
    systems = ["x86_64-linux"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
    toolchainFor = system:
      fenix.packages.${system}.fromToolchainFile {
        file = ./rust-toolchain.toml;
        sha256 = "sha256-3ok3kaNc8lhDSnZ9bZAJwmHgUrdB9CC5m+ZJBwFPWnA=";
      };
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      nettle3 = nixpkgs-nettle.legacyPackages.${system}.nettle;
      toolchain = toolchainFor system;
      rustPlatform = pkgs.makeRustPlatform {
        cargo = toolchain;
        rustc = toolchain;
      };
    in {
      default = rustPlatform.buildRustPackage {
        pname = "volta";
        version = "1.1.0";
        src = ./.;
        cargoLock = {
          lockFile = ./Cargo.lock;
          # lettre is pinned to a git revision in the lockfile;
          # importCargoLock requires the fetched tree's hash here.
          outputHashes = {
            "lettre-0.10.0-pre" = "sha256-f2RkuoGRRS74c37pbtXJHgvTgMmqc84Z6rj4nJo31/E=";
          };
        };

        nativeBuildInputs = [
          pkgs.gettext
          pkgs.git
          pkgs.pkg-config
          # nettle-sys runs bindgen; the hook wires libclang up with
          # the C library's headers (a bare LIBCLANG_PATH is not
          # enough — bindgen then cannot find stdlib.h).
          pkgs.rustPlatform.bindgenHook
          # The link does not record an rpath for nettle 3 (it is
          # found through pkg-config's -L into the -dev output);
          # patch the shipped binaries so they find libnettle.so.8.
          pkgs.autoPatchelfHook
        ];
        buildInputs = [
          nettle3
          pkgs.sqlite
        ];

        # The repo's .cargo/config.toml redirects target-dir to
        # .target (a workstation convenience); buildRustPackage's
        # install hooks look in target/, so drop the file in the
        # packaging copy.
        postPatch = ''
          rm -f .cargo/config.toml

          # Gettext catalogs are compiled by a gettext-macros side
          # effect of the first macro expansion in a fresh tree, and
          # a release-first build stamps en-only catalogs into
          # target/debug/gettext_macros (release registers en only).
          # The debug check build then embeds whatever it finds, so
          # pre-compile all three catalogs from the .po sources.
          for lang in en de ja; do
            mkdir -p "target/debug/gettext_macros/$lang"
            msgfmt \
              --output-file="target/debug/gettext_macros/$lang/volta.mo" \
              "po/volta/$lang.po"
          done
        '';

        # build.rs stamps version keys with vergen, which requires a
        # git checkout; the flake source copy has none. Give the
        # build a one-commit snapshot repository so vergen can read
        # a SHA (it identifies the packaging snapshot, not upstream).
        preBuild = ''
          git init -q
          git config user.email "nix@qompass.ai"
          git config user.name "nix build"
          git add -A
          git commit -qm "nix build snapshot"
        '';

        # The test suite is the gate on the workstation; it also
        # runs here. Test binaries link nettle 3 without an rpath
        # (see autoPatchelfHook above), so give the check phase the
        # library path explicitly.
        doCheck = true;
        # The suite only passes in debug: init_i18n! compiles the
        # de/ja gettext catalogs in debug builds only (release ships
        # en-only — pre-existing upstream design), and the ja/de
        # mail + translation tests exercise those catalogs. The
        # package build itself stays release.
        checkType = "debug";
        # Build every workspace member so the package ships
        # voltactl alongside the server binaries (the check phase
        # already tests the whole workspace).
        cargoBuildFlags = ["--workspace"];
        preCheck = ''
          export LD_LIBRARY_PATH="${nettle3}/lib:${pkgs.gmp}/lib"
        '';

        meta = {
          description = "OpenPGP key server (Hagrid-derived): HKP, VKS API, and Web Key Directory";
          license = nixpkgs.lib.licenses.asl20;
          mainProgram = "volta";
        };
      };
    });

    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      nettle3 = nixpkgs-nettle.legacyPackages.${system}.nettle;
    in {
      default = pkgs.mkShell {
        packages = [
          (toolchainFor system)
          pkgs.gettext
          pkgs.llvmPackages.libclang
          pkgs.mdbook
          nettle3
          pkgs.pkg-config
          pkgs.sqlite
        ];
        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        # So binaries built in the shell find nettle 3 at runtime.
        LD_LIBRARY_PATH = "${nettle3}/lib";
      };
    });

    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.alejandra);
  };
}
