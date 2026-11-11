(import :clan/poo/object)
(export SourceContractPolicy
        CbmcExecutor. NativeExecutor. C11Language. Cpp11Language.
        DirectContract. CheckedContract. ReplacedContract.)

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

(.def SourceContractPolicy
  timeout: 45
  safety-flags: '("--bounds-check" "--pointer-check" "--signed-overflow-check"
                  "--unsigned-overflow-check" "--unwinding-assertions" "--unwind" "8"))
