;;; -*- Gerbil -*-
;;; Evidence admission describes inputs and results; it grants no execution authority.
(import
  (only-in :clan/poo/object .o)
  (only-in :clan/poo/mop Type. Object Function define-type element?)
  (only-in :clan/poo/type Record Symbol List Pair Exactly)
  (only-in :clan/poo/object-contract ObjectContract.)
  (only-in :yuanxu/object-types/contracts YuanxuContract.)
  (only-in :gerbil-ascent/program/types
           GerbilAscentProgramContract GerbilAscentSessionContract)
  (only-in :gerbil-ascent/rules/declaration rule-module? rule-module-program)
  (only-in "../../../types.ss"
           LibraryNonemptyString LibrarySymbolPair LibrarySymbolTriple LibraryScopeBinding))

(export
  ResourceEvidenceScopeContract
  ResourceEvidencePolicyType
  ResourceEvidenceEntryProjection
  ResourceEvidenceProfileProjection
  ResourceEvidenceModuleType
  ResourceMakeEvidenceSignature
  ResourceOpenReviewSignature)

;; Consume only the declared projection. Full family admission stays with its Library.
;; Object is the explicit open envelope; extra fields are not domain-admitted here.
(define-type (ResourceEvidenceEntryProjection @ ObjectContract.)
  identity: 'resource-evidence/entry-projection
  extra-fields: 'delegate
  constraints: (list Object)
  responsibilities:
  (.o
    identity: Symbol
    rules: (List LibrarySymbolTriple)
    dependencies: (List LibrarySymbolPair)))

(define-type (ResourceEvidenceProfileProjection @ ObjectContract.)
  identity: 'resource-evidence/profile-projection
  extra-fields: 'delegate
  constraints: (list Object)
  responsibilities:
  (.o
    factors: (List Symbol)))

;; A public rule-module tag alone does not establish a valid relational Program.
(define-type (ResourceEvidenceModuleType @ Type.)
  .element?:
  (lambda (value)
    (and (rule-module? value)
         (element? GerbilAscentProgramContract (rule-module-program value)))))

(define-type
  (ResourceEvidencePolicyType @
   (Record
     result-kind: [(Exactly 'recorded-only)]
     closure: [(Exactly 'exact-required-inputs)]
     outcomes: [(Exactly '(pass fail))]))
  sealed: #t)

(define-type ResourceMakeEvidenceSignature
  (Function (list ResourceEvidenceModuleType) '()))

(define-type ResourceOpenReviewSignature
  (Function
   (list GerbilAscentSessionContract)
   (list ResourceEvidenceEntryProjection
         ResourceEvidenceProfileProjection
         Symbol
         LibraryNonemptyString
         (List LibraryScopeBinding))))

;; This publication exposes exactly three capabilities. Extensions require a declared schema.
(define-type
  (ResourceEvidenceScopeShape @
   (Record
     make-evidence: [ResourceMakeEvidenceSignature]
     open-review: [ResourceOpenReviewSignature]
     policy: [ResourceEvidencePolicyType]))
  sealed: #t)

(define-type (ResourceEvidenceScopeContract @ YuanxuContract.)
  identity: 'resource-evidence/scope
  value-contract: ResourceEvidenceScopeShape)
