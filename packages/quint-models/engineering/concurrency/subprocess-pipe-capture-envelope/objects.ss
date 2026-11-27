;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Bounded subprocess pipe output capture, drain-to-sink deadlock freedom, and
;;; bounded single-line framing envelope (SM20).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SubprocessPipeCaptureEnvelopeModel)

(.def (SubprocessPipeCaptureEnvelopeModel @ ThreatModel.)
  identity: 'engineering.concurrency.subprocess-pipe-capture-envelope
  family: 'engineering.concurrency.subprocess-pipe-capture-envelope
  title: "Bounded Subprocess Pipe Capture, Drain-to-Sink Deadlock Freedom & Line Framing Envelope"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("W. R. Stevens & S. A. Rago (Addison-Wesley 2013)"
     "Advanced Programming in the UNIX Environment (APUE, Ch. 15 Pipes) — failing to drain stdout/stderr pipes past kernel pipe-buffer capacity blocks the child writer and deadlocks parent wait().")
    ("M. Grottke & K. S. Trivedi (IEEE Computer 2007)"
     "Fighting Bugs: Remove, Retry, Replicate, and Rejuvenate — unbounded wait_with_output/read_to_end followed by post-hoc truncate() retains spike payloads in heap until OOM.")
    ("S. A. Crosby & D. S. Wallach (USENIX Security 2003)"
     "Denial of Service via Algorithmic Complexity — unbounded single-line BufReader::read_line() without a byte limit lets a single delimiter-free payload exhaust host memory."))
  quint-module: "concurrency_subprocess_pipe_capture_envelope"
  quint-file: "SubprocessPipeCaptureEnvelope.qnt"
  domain-dir: "engineering/concurrency/subprocess-pipe-capture-envelope"
  rules:
  '((conc-pipe-precap-retain CONC-PIPE-PRECAP-RETAIN quint)
    (conc-pipe-drain-to-sink CONC-PIPE-DRAIN-TO-SINK quint)
    (conc-pipe-bounded-line CONC-PIPE-BOUNDED-LINE quint))
  dependencies:
  '((CONC-PIPE-PRECAP-RETAIN source)
    (CONC-PIPE-PRECAP-RETAIN profile)
    (CONC-PIPE-PRECAP-RETAIN method)
    (CONC-PIPE-DRAIN-TO-SINK source)
    (CONC-PIPE-DRAIN-TO-SINK profile)
    (CONC-PIPE-DRAIN-TO-SINK method)
    (CONC-PIPE-BOUNDED-LINE source)
    (CONC-PIPE-BOUNDED-LINE profile)
    (CONC-PIPE-BOUNDED-LINE method))
  invariant: "Subprocess stdout/stderr capture retains at most maxRetainBytes in heap (peakRetainedBytes <= maxRetainBytes, never buffering full output before post-hoc truncation), continuously drains excess pipe bytes into a fixed-size discard buffer until EOF so the child never deadlocks on a full kernel pipe (pipeDeadlocks == 0), and enforces an explicit byte cap on every line-framed subprocess read (lineCapBreaches == 0)."
  limits: "Finite 4-unit retained pipe budget and 3-unit single-line frame cap abstraction; verifies pre-allocation retain capping, drain-to-sink pipe liveness past OS pipe capacity, and bounded line framing, not kernel splice/zero-copy syscall internals or PTY line disciplines.")
