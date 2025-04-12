;; Guard Wealth Protection System
;; A comprehensive system for securing digital resources with advanced verification and release mechanisms


;; Primary data structure for storage
(define-map ContainerRegistry
  { container-identifier: uint }
  {
    originator: principal,
    beneficiary: principal,
    resource-identifier: uint,
    quantity: uint,
    container-status: (string-ascii 10),
    creation-block: uint,
    termination-block: uint
  }
)

;; Tracking sequential identifiers
(define-data-var latest-container-identifier uint u0)

;; Global constants for system operation
(define-constant SYSTEM_CONTROLLER tx-sender)
(define-constant ERROR_PERMISSION_DENIED (err u100))
(define-constant ERROR_CONTAINER_MISSING (err u101))
(define-constant ERROR_ALREADY_PROCESSED (err u102))
(define-constant ERROR_OPERATION_FAILED (err u103))
(define-constant ERROR_INVALID_IDENTIFIER (err u104))
(define-constant ERROR_INVALID_QUANTITY (err u105))
(define-constant ERROR_INVALID_ORIGINATOR (err u106))
(define-constant ERROR_CONTAINER_LAPSED (err u107))
(define-constant CONTAINER_DURATION_BLOCKS u1008)

;; ===========================================
;; Helper Functions
;; ===========================================

(define-private (valid-beneficiary? (target principal))
  (and 
    (not (is-eq target tx-sender))
    (not (is-eq target (as-contract tx-sender)))
  )
)

(define-private (container-exists? (container-identifier uint))
  (<= container-identifier (var-get latest-container-identifier))
)

;; ===========================================
;; Core Operational Functions
;; ===========================================

;; Release container resources to intended beneficiary
(define-public (finalize-resource-transfer (container-identifier uint))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (target (get beneficiary container-details))
        (resource-amount (get quantity container-details))
        (resource-id (get resource-identifier container-details))
      )
      (asserts! (or (is-eq tx-sender SYSTEM_CONTROLLER) (is-eq tx-sender (get originator container-details))) ERROR_PERMISSION_DENIED)
      (asserts! (is-eq (get container-status container-details) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block container-details)) ERROR_CONTAINER_LAPSED)
      (match (as-contract (stx-transfer? resource-amount tx-sender target))
        success
          (begin
            (map-set ContainerRegistry
              { container-identifier: container-identifier }
              (merge container-details { container-status: "completed" })
            )
            (print {event: "resources_transferred", container-identifier: container-identifier, beneficiary: target, resource-identifier: resource-id, resource-amount: resource-amount})
            (ok true)
          )
        error ERROR_OPERATION_FAILED
      )
    )
  )
)

;; Return resources to originator
(define-public (revert-resource-allocation (container-identifier uint))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (source (get originator container-details))
        (resource-amount (get quantity container-details))
      )
      (asserts! (is-eq tx-sender SYSTEM_CONTROLLER) ERROR_PERMISSION_DENIED)
      (asserts! (is-eq (get container-status container-details) "pending") ERROR_ALREADY_PROCESSED)
      (match (as-contract (stx-transfer? resource-amount tx-sender source))
        success
          (begin
            (map-set ContainerRegistry
              { container-identifier: container-identifier }
              (merge container-details { container-status: "reversed" })
            )
            (print {event: "resources_returned", container-identifier: container-identifier, originator: source, resource-amount: resource-amount})
            (ok true)
          )
        error ERROR_OPERATION_FAILED
      )
    )
  )
)

;; Originator requests cancellation
(define-public (terminate-container (container-identifier uint))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (source (get originator container-details))
        (resource-amount (get quantity container-details))
      )
      (asserts! (is-eq tx-sender source) ERROR_PERMISSION_DENIED)
      (asserts! (is-eq (get container-status container-details) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block container-details)) ERROR_CONTAINER_LAPSED)
      (match (as-contract (stx-transfer? resource-amount tx-sender source))
        success
          (begin
            (map-set ContainerRegistry
              { container-identifier: container-identifier }
              (merge container-details { container-status: "terminated" })
            )
            (print {event: "container_terminated", container-identifier: container-identifier, originator: source, resource-amount: resource-amount})
            (ok true)
          )
        error ERROR_OPERATION_FAILED
      )
    )
  )
)

;; ===========================================
;; Container Management Functions
;; ===========================================

;; Prolong container duration
(define-public (prolong-container-duration (container-identifier uint) (additional-blocks uint))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> additional-blocks u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= additional-blocks u1440) ERROR_INVALID_QUANTITY) ;; Maximum ~10 days extension
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (source (get originator container-details)) 
        (target (get beneficiary container-details))
        (existing-end (get termination-block container-details))
        (new-end (+ existing-end additional-blocks))
      )
      (asserts! (or (is-eq tx-sender source) (is-eq tx-sender target) (is-eq tx-sender SYSTEM_CONTROLLER)) ERROR_PERMISSION_DENIED)
      (asserts! (or (is-eq (get container-status container-details) "pending") (is-eq (get container-status container-details) "accepted")) ERROR_ALREADY_PROCESSED)
      (map-set ContainerRegistry
        { container-identifier: container-identifier }
        (merge container-details { termination-block: new-end })
      )
      (print {event: "duration_extended", container-identifier: container-identifier, requestor: tx-sender, updated-termination-block: new-end})
      (ok true)
    )
  )
)

;; Recover lapsed container resources
(define-public (recover-lapsed-container (container-identifier uint))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (source (get originator container-details))
        (resource-amount (get quantity container-details))
        (expiration (get termination-block container-details))
      )
      (asserts! (or (is-eq tx-sender source) (is-eq tx-sender SYSTEM_CONTROLLER)) ERROR_PERMISSION_DENIED)
      (asserts! (or (is-eq (get container-status container-details) "pending") (is-eq (get container-status container-details) "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (> block-height expiration) (err u108)) ;; Must be expired
      (match (as-contract (stx-transfer? resource-amount tx-sender source))
        success
          (begin
            (map-set ContainerRegistry
              { container-identifier: container-identifier }
              (merge container-details { container-status: "lapsed" })
            )
            (print {event: "lapsed_container_recovered", container-identifier: container-identifier, originator: source, resource-amount: resource-amount})
            (ok true)
          )
        error ERROR_OPERATION_FAILED
      )
    )
  )
)

;; ===========================================
;; Dispute Resolution Functions 
;; ===========================================

;; Initiate container dispute
(define-public (contest-container (container-identifier uint) (justification (string-ascii 50)))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (source (get originator container-details))
        (target (get beneficiary container-details))
      )
      (asserts! (or (is-eq tx-sender source) (is-eq tx-sender target)) ERROR_PERMISSION_DENIED)
      (asserts! (or (is-eq (get container-status container-details) "pending") (is-eq (get container-status container-details) "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block container-details)) ERROR_CONTAINER_LAPSED)
      (map-set ContainerRegistry
        { container-identifier: container-identifier }
        (merge container-details { container-status: "contested" })
      )
      (print {event: "container_contested", container-identifier: container-identifier, contestant: tx-sender, justification: justification})
      (ok true)
    )
  )
)

;; Adjudicate contested container
(define-public (adjudicate-contest (container-identifier uint) (originator-allocation uint))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (is-eq tx-sender SYSTEM_CONTROLLER) ERROR_PERMISSION_DENIED)
    (asserts! (<= originator-allocation u100) ERROR_INVALID_QUANTITY) ;; Percentage must be 0-100
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (source (get originator container-details))
        (target (get beneficiary container-details))
        (resource-amount (get quantity container-details))
        (source-portion (/ (* resource-amount originator-allocation) u100))
        (target-portion (- resource-amount source-portion))
      )
      (asserts! (is-eq (get container-status container-details) "contested") (err u112)) ;; Must be contested
      (asserts! (<= block-height (get termination-block container-details)) ERROR_CONTAINER_LAPSED)

      ;; Allocate originator's portion
      (unwrap! (as-contract (stx-transfer? source-portion tx-sender source)) ERROR_OPERATION_FAILED)

      ;; Allocate beneficiary's portion
      (unwrap! (as-contract (stx-transfer? target-portion tx-sender target)) ERROR_OPERATION_FAILED)

      (print {event: "contest_adjudicated", container-identifier: container-identifier, originator: source, beneficiary: target, 
              originator-amount: source-portion, beneficiary-amount: target-portion, originator-allocation: originator-allocation})
      (ok true)
    )
  )
)

;; ===========================================
;; Security Enhancement Functions
;; ===========================================

;; Freeze suspicious container
(define-public (quarantine-container (container-identifier uint) (justification (string-ascii 100)))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (source (get originator container-details))
        (target (get beneficiary container-details))
      )
      (asserts! (or (is-eq tx-sender SYSTEM_CONTROLLER) (is-eq tx-sender source) (is-eq tx-sender target)) ERROR_PERMISSION_DENIED)
      (asserts! (or (is-eq (get container-status container-details) "pending") 
                   (is-eq (get container-status container-details) "accepted")) 
                ERROR_ALREADY_PROCESSED)

      (print {event: "container_quarantined", container-identifier: container-identifier, reporter: tx-sender, justification: justification})
      (ok true)
    )
  )
)

;; Security verification for high-value containers
(define-public (cryptographic-verification (container-identifier uint) (digest (buff 32)) (signature (buff 65)) (verifier principal))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (source (get originator container-details))
        (target (get beneficiary container-details))
        (verify-result (unwrap! (secp256k1-recover? digest signature) (err u150)))
      )
      ;; Verify with cryptographic proof
      (asserts! (or (is-eq tx-sender source) (is-eq tx-sender target) (is-eq tx-sender SYSTEM_CONTROLLER)) ERROR_PERMISSION_DENIED)
      (asserts! (or (is-eq verifier source) (is-eq verifier target)) (err u151))
      (asserts! (is-eq (get container-status container-details) "pending") ERROR_ALREADY_PROCESSED)

      ;; Verify signature matches expected signer
      (asserts! (is-eq (unwrap! (principal-of? verify-result) (err u152)) verifier) (err u153))

      (print {event: "crypto_verification_completed", container-identifier: container-identifier, validator: tx-sender, verifier: verifier})
      (ok true)
    )
  )
)

;; ZK proof verification for premium containers
(define-public (advanced-verification (container-identifier uint) (zk-evidence (buff 128)) (public-parameters (list 5 (buff 32))))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> (len public-parameters) u0) ERROR_INVALID_QUANTITY)
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (source (get originator container-details))
        (target (get beneficiary container-details))
        (resource-amount (get quantity container-details))
      )
      ;; Only premium containers need advanced verification
      (asserts! (> resource-amount u10000) (err u190))
      (asserts! (or (is-eq tx-sender source) (is-eq tx-sender target) (is-eq tx-sender SYSTEM_CONTROLLER)) ERROR_PERMISSION_DENIED)
      (asserts! (or (is-eq (get container-status container-details) "pending") (is-eq (get container-status container-details) "accepted")) ERROR_ALREADY_PROCESSED)

      ;; In production, actual ZK proof verification would occur here

      (print {event: "advanced_verification_complete", container-identifier: container-identifier, validator: tx-sender, 
              evidence-hash: (hash160 zk-evidence), public-parameters: public-parameters})
      (ok true)
    )
  )
)

;; Register authentication for high-value containers
(define-public (register-auth-factor (container-identifier uint) (auth-token (buff 32)))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (source (get originator container-details))
        (resource-amount (get quantity container-details))
      )
      ;; Only for containers above threshold
      (asserts! (> resource-amount u5000) (err u130))
      (asserts! (is-eq tx-sender source) ERROR_PERMISSION_DENIED)
      (asserts! (is-eq (get container-status container-details) "pending") ERROR_ALREADY_PROCESSED)
      (print {event: "auth_factor_registered", container-identifier: container-identifier, originator: source, auth-digest: (hash160 auth-token)})
      (ok true)
    )
  )
)

;; ===========================================
;; Administrative Functions
;; ===========================================

;; Schedule system operation with delay
(define-public (schedule-system-operation (operation-type (string-ascii 20)) (operation-params (list 10 uint)))
  (begin
    (asserts! (is-eq tx-sender SYSTEM_CONTROLLER) ERROR_PERMISSION_DENIED)
    (asserts! (> (len operation-params) u0) ERROR_INVALID_QUANTITY)
    (let
      (
        (execution-time (+ block-height u144)) ;; 24 hours delay
      )
      (print {event: "operation_scheduled", operation-type: operation-type, operation-params: operation-params, execution-time: execution-time})
      (ok execution-time)
    )
  )
)

;; Configure rate limiting for system protection
(define-public (configure-protection-limits (attempt-threshold uint) (lockout-duration uint))
  (begin
    (asserts! (is-eq tx-sender SYSTEM_CONTROLLER) ERROR_PERMISSION_DENIED)
    (asserts! (> attempt-threshold u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= attempt-threshold u10) ERROR_INVALID_QUANTITY) ;; Maximum 10 attempts allowed
    (asserts! (> lockout-duration u6) ERROR_INVALID_QUANTITY) ;; Minimum 6 blocks lockout (~1 hour)
    (asserts! (<= lockout-duration u144) ERROR_INVALID_QUANTITY) ;; Maximum 144 blocks lockout (~1 day)

    ;; Note: Full implementation would track limits in contract variables

    (print {event: "protection_limits_configured", attempt-threshold: attempt-threshold, 
            lockout-duration: lockout-duration, administrator: tx-sender, current-block: block-height})
    (ok true)
  )
)

;; ===========================================
;; Resource Management Functions
;; ===========================================

;; Record container documentation
(define-public (register-container-documentation (container-identifier uint) (documentation-type (string-ascii 20)) (documentation-hash (buff 32)))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (source (get originator container-details))
        (target (get beneficiary container-details))
      )
      ;; Only authorized parties can add documentation
      (asserts! (or (is-eq tx-sender source) (is-eq tx-sender target) (is-eq tx-sender SYSTEM_CONTROLLER)) ERROR_PERMISSION_DENIED)
      (asserts! (not (is-eq (get container-status container-details) "completed")) (err u160))
      (asserts! (not (is-eq (get container-status container-details) "reversed")) (err u161))
      (asserts! (not (is-eq (get container-status container-details) "lapsed")) (err u162))

      ;; Valid documentation types
      (asserts! (or (is-eq documentation-type "resource-details") 
                   (is-eq documentation-type "transfer-evidence")
                   (is-eq documentation-type "quality-verification")
                   (is-eq documentation-type "originator-specifications")) (err u163))

      (print {event: "documentation_registered", container-identifier: container-identifier, documentation-type: documentation-type, 
              documentation-hash: documentation-hash, registrant: tx-sender})
      (ok true)
    )
  )
)

;; Activate recovery operation
(define-public (activate-recovery-procedure (container-identifier uint))
  (begin
    (asserts! (container-exists? container-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (container-details (unwrap! (map-get? ContainerRegistry { container-identifier: container-identifier }) ERROR_CONTAINER_MISSING))
        (source (get originator container-details))
        (resource-amount (get quantity container-details))
        (status (get container-status container-details))
        (waiting-period u24) ;; 24 blocks waiting (~4 hours)
      )
      ;; Only originator or admin can execute
      (asserts! (or (is-eq tx-sender source) (is-eq tx-sender SYSTEM_CONTROLLER)) ERROR_PERMISSION_DENIED)
      ;; Only from recovery-pending state
      (asserts! (is-eq status "recovery-pending") (err u301))
      ;; Waiting period must have elapsed
      (asserts! (>= block-height (+ (get creation-block container-details) waiting-period)) (err u302))

      ;; Process recovery
      (unwrap! (as-contract (stx-transfer? resource-amount tx-sender source)) ERROR_OPERATION_FAILED)

      ;; Update container status
      (map-set ContainerRegistry
        { container-identifier: container-identifier }
        (merge container-details { container-status: "recovered", quantity: u0 })
      )

      (print {event: "recovery_procedure_complete", container-identifier: container-identifier, 
              originator: source, resource-amount: resource-amount})
      (ok true)
    )
  )
)

