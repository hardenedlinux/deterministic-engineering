;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object)
(export CbmcExecutor. NativeExecutor. C11Language. Cpp11Language.
        DirectContract. CheckedContract. ReplacedContract. SourceContractScenario.)

;; Pure strategy descriptors. Methods specialize their prototype ancestry.
(.def CbmcExecutor.
  identity: 'cbmc
  method: 'cbmc
  requires-properties?: #t)
(.def NativeExecutor.
  identity: 'native
  method: 'native
  requires-properties?: #f)
(.def C11Language.
  identity: 'c11
  compiler-key: 'cc
  native-standard: "-std=c11"
  verifier-flags: '("--c11"))
(.def Cpp11Language.
  identity: 'cpp11
  compiler-key: 'cxx
  native-standard: "-std=c++11"
  verifier-flags: '("--cpp11"))
(.def DirectContract.
  identity: 'direct
  option: ""
  requires-function?: #f)
(.def CheckedContract.
  identity: 'enforce
  option: "--enforce-contract"
  requires-function?: #t)
(.def (ReplacedContract. @ CheckedContract.)
  identity: 'replace
  option: "--replace-call-with-contract")

;; A Scenario binds domain meaning and a Profile to a source location. It is
;; declarative data; source capture, tools and issued observations belong to Host.
(.def SourceContractScenario.
  root: (error "The consuming project supplies its source directory")
  entry: (error "Select a domain Catalog leaf")
  profile: (error "Select the language Profile"))
