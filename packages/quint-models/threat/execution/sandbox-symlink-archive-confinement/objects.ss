;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Adversarial (ADV-L4) AI-defensive sandbox confinement model: symlink ancestor
;;; & leaf escape defense, manifest entry-path containment, duplicate/alias tar
;;; entry shadowing refusal, and cumulative decompression bomb caps (SM22).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SandboxSymlinkArchiveConfinementModel)

(.def (SandboxSymlinkArchiveConfinementModel @ ThreatModel.)
  identity: 'threat.execution.sandbox-symlink-archive-confinement
  family: 'threat.execution.sandbox-symlink-archive-confinement
  title: "Adversarial (ADV-L4) Sandbox Symlink, Path Traversal & Archive Shadowing Confinement"
  subdomain: 'quint.threat.execution
  papers:
  '(("Linux openat2(2) RESOLVE_BENEATH / RESOLVE_NO_SYMLINKS (2020)"
     "Lexical relative-path checks alone are defeated by intermediate directory or leaf symlinks; every traversed ancestor must remain confined inside canonical root.")
    ("Snyk Zip Slip / CVE-2018-1002200 & Archive Ambiguity Research"
     "Untrusted manifest entry paths and duplicate or non-canonical archive member paths (./, //, shadowing) bypass naive extraction and signature verifiers.")
    ("D. Fifield (USENIX WOOT 2019)"
     "A Better Zip Bomb — single-entry size checks fail against multi-entry or multistream decompression bombs without cumulative decompressed byte caps."))
  quint-module: "execution_sandbox_symlink_archive_confinement"
  quint-file: "SandboxSymlinkArchiveConfinement.qnt"
  domain-dir: "threat/execution/sandbox-symlink-archive-confinement"
  rules:
  '((exec-conf-no-symlink-escape EXEC-CONF-NO-SYMLINK-ESCAPE quint)
    (exec-conf-manifest-root EXEC-CONF-MANIFEST-ROOT quint)
    (exec-conf-no-dup-tar-shadow EXEC-CONF-NO-DUP-TAR-SHADOW quint)
    (exec-conf-cumulative-decompress EXEC-CONF-CUMULATIVE-DECOMPRESS quint))
  dependencies:
  '((EXEC-CONF-NO-SYMLINK-ESCAPE source)
    (EXEC-CONF-NO-SYMLINK-ESCAPE profile)
    (EXEC-CONF-NO-SYMLINK-ESCAPE method)
    (EXEC-CONF-MANIFEST-ROOT source)
    (EXEC-CONF-MANIFEST-ROOT profile)
    (EXEC-CONF-MANIFEST-ROOT method)
    (EXEC-CONF-NO-DUP-TAR-SHADOW source)
    (EXEC-CONF-NO-DUP-TAR-SHADOW profile)
    (EXEC-CONF-NO-DUP-TAR-SHADOW method)
    (EXEC-CONF-CUMULATIVE-DECOMPRESS source)
    (EXEC-CONF-CUMULATIVE-DECOMPRESS profile)
    (EXEC-CONF-CUMULATIVE-DECOMPRESS method))
  invariant: "Under ADV-L4 hostile inputs, sandbox file writes never traverse symlinks outside canonical root (symlinkEscapes == 0), manifest entry paths stay confined beneath staging root (traversalEscapes == 0), verified archives reject duplicate or non-canonical alias entries (duplicateShadows == 0), and cumulative decompressed bytes never exceed maxDecompressed (decompressionOverruns == 0)."
  limits: "Finite 4-unit cumulative extraction cap and canonical path/symlink/archive-entry abstraction (ADV-L4 hostile attack tier); verifies symlink ancestor confinement, manifest entry containment, duplicate/alias archive rejection, and cumulative decompression caps, not OS kernel openat2 VFS race windows or gzip Huffman internals.")
