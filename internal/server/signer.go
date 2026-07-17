package server

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
)

// ErrSignerNotImplemented is returned by the Phase B stub Signer. Phase C
// replaces the stub with a real implementation that adapts internal/sign +
// internal/token. Until then POST /sign/data answers 501 (see signHandler).
var ErrSignerNotImplemented = errors.New("openmdsignd: signing not implemented in this phase (Phase C)")

// SignRequest is the parsed, validated PROTOCOL.md §4.2 request body. It is the
// input to the Phase C Signer. Field semantics:
//
//   - Algorithm is a CLIENT HINT ONLY. Per PROTOCOL.md §5 it lied in the
//     captures (said "SHA-1" on a job that emitted SHA-256). The Signer MUST
//     drive the container digest from SignFormat + profile rules, NEVER from
//     Algorithm. Kept here only for logging/telemetry.
//   - Certificate is the chosen certificateModel object, verbatim, so the
//     Signer can recover the CKA_ID / provider and pick the on-token key.
//   - SignFormat ("PAdES-T" | "XAdES-T") selects the profile AND the digest.
//   - ContentType ("Pdf" | "Text") distinguishes a full document from a
//     pre-hashed challenge.
//   - Data is the decoded base64 payload (full PDF or pre-hashed challenge).
//   - Origin is the requesting site's Origin header (e.g. https://msign.gov.md),
//     threaded from the handler so the per-operation confirmation dialog can name
//     WHO is asking to sign. It is the anti-oracle protection alongside the CORS
//     allowlist: the user consciously authorizes THIS site's THIS operation.
type SignRequest struct {
	Algorithm     string
	Certificate   json.RawMessage
	SignatureType string
	SignFormat    string
	ContentType   string
	Data          []byte
	Origin        string
}

// SignResult is what a Phase C Signer produces: the finished container plus the
// identifiers the §4.2 Location header and §4.3 fetch route are built from.
type SignResult struct {
	// UUID keys the job in the JobStore and appears in the §4.2 Location.
	UUID string
	// Format is the Location path segment: "pdf" (PAdES) or "XAdES".
	Format string
	// Base64File is the base64 of the finished signed container (§4.3 body).
	Base64File string
}

// Signer is the Phase C seam. Phase B injects a stub (NewStubSigner) that always
// returns ErrSignerNotImplemented; Phase C injects a real implementation.
//
// The synchronous PIN entry + per-operation confirmation dialog (PROTOCOL.md §7)
// live INSIDE a real Sign implementation — that is the single point where the
// 201 is emitted only once the user has confirmed and the token has signed. The
// PIN policy (one C_Login, no retry) stays in the token layer; the daemon never
// handles a PIN itself.
type Signer interface {
	// Sign performs the whole synchronous operation (PIN → confirm → token sign
	// → package) and returns the finished result, or an error. Phase B's stub
	// returns ErrSignerNotImplemented.
	Sign(ctx context.Context, req SignRequest) (SignResult, error)
}

// stubSigner is the Phase B placeholder Signer.
type stubSigner struct{}

// NewStubSigner returns the Phase B Signer that always reports
// ErrSignerNotImplemented. The full request-parse/validate path still runs
// ahead of it, so the 501 only fires once a well-formed §4.2 body is accepted.
func NewStubSigner() Signer { return stubSigner{} }

func (stubSigner) Sign(context.Context, SignRequest) (SignResult, error) {
	return SignResult{}, ErrSignerNotImplemented
}

// Job is a completed signing job held for retrieval by the §4.3 fetch route.
type Job struct {
	// Format is the container format segment ("pdf" | "XAdES").
	Format string
	// Base64File is the §4.3 response body payload.
	Base64File string
}

// JobStore holds finished jobs keyed by uuid, bridging POST /sign/data (§4.2,
// which stores) and GET /sign/data/PKCS11/{uuid}/{format} (§4.3, which reads).
// Phase C populates it from real Sign results; Phase B wires it end-to-end so
// the fetch route is already functional against injected/test jobs.
type JobStore interface {
	Put(uuid string, job Job)
	Get(uuid string) (Job, bool)
}

// memJobStore is a concurrency-safe in-memory JobStore.
type memJobStore struct {
	mu   sync.Mutex
	jobs map[string]Job
}

// NewMemJobStore returns an in-memory JobStore.
func NewMemJobStore() JobStore {
	return &memJobStore{jobs: make(map[string]Job)}
}

func (s *memJobStore) Put(uuid string, job Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[uuid] = job
}

func (s *memJobStore) Get(uuid string) (Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[uuid]
	return j, ok
}
