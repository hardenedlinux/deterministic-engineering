(import :clan/poo/object)
(export FormationCase LocalCodexConsent)
(def FormationCase (.o identity: 'library-project-formation purpose: 'design-reasoning))

;; Source-channel decoding data for this explicitly confirmed local scope.
;; These localized labels describe human choices; they are not Library versions.
(def LocalCodexConsent
 (.o identity: 'local-codex-consent revision: "bounded-project-operation"
     role-answer: "授予 project-owner 和 implementation-owner，限本仓库设计、实现与验证"
     trust-answer: "采用本机受信来源，保留限制，不扩展到独立审查或交付"
     roles: '(project-owner implementation-owner)
     purposes: '(repository-design implementation verification)
     trust-boundary: 'trusted-local-codex
     limitations: '(no-historical-account-signature no-independent-review no-delivery no-recipient-authority)))
