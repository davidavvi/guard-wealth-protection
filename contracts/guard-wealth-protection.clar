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

