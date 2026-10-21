package lifecycle

import (
	"sync"
	"testing"
	"time"
)

func TestLostKeysRevokesOnlyLostTokensPastTheGraceAndAuditsTheRevocation(t *testing.T) {
	f := newLifecycleFixture(t)
	f.addToken(t, "1001", "lost", 25*time.Hour)   // past the grace period: revoke
	f.addToken(t, "1002", "lost", time.Hour)      // inside the grace period: keep
	f.addToken(t, "1003", "active", 0)            // never lost: keep
	f.addToken(t, "1004", "active", 25*time.Hour) // lost, then found: status is active again, keep
	authority := newFakeCA()

	result, err := f.job(authority, 24*time.Hour).Tick(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Revoked != 1 || result.Failed != 0 || result.Skipped {
		t.Fatalf("tick result = %+v, want exactly one revocation", result)
	}
	if authority.count("cert-1001") != 1 || authority.reasons["cert-1001"] != reasonKeyCompromise {
		t.Fatalf("CA revocations = %v, want one keyCompromise for the lost token", authority.revoked)
	}
	if authority.count("cert-1002") != 0 || authority.count("cert-1003") != 0 || authority.count("cert-1004") != 0 {
		t.Fatalf("CA revocations = %v; only the lost token past the grace period may be revoked", authority.revoked)
	}
	if status := f.certificateStatus(t, "1001"); status != "revoked" {
		t.Fatalf("certificate status = %q, want revoked", status)
	}
	var reason string
	var revokedAt *time.Time
	if err := f.store.Pool.QueryRow(f.ctx, `
		SELECT revocation_reason, revoked_at FROM certificates WHERE serial_number = 'cert-1001'
	`).Scan(&reason, &revokedAt); err != nil {
		t.Fatal(err)
	}
	if reason != "keyCompromise" || revokedAt == nil {
		t.Fatalf("revocation reason=%q revoked_at=%v", reason, revokedAt)
	}
	var auditCount int
	if err := f.store.Pool.QueryRow(f.ctx, `
		SELECT count(*) FROM audit_events
		WHERE action = 'RevokeCertificate' AND actor_type = 'system' AND actor_id = 'lost-key-job' AND outcome = 'success'
	`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("revocation audit records = %d, want 1", auditCount)
	}
}

func TestLostKeysPassIsIdempotent(t *testing.T) {
	f := newLifecycleFixture(t)
	f.addToken(t, "2001", "lost", 48*time.Hour)
	authority := newFakeCA()
	job := f.job(authority, 24*time.Hour)
	if _, err := job.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	result, err := job.Tick(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Revoked != 0 || authority.count("cert-2001") != 1 {
		t.Fatalf("second pass = %+v, CA calls for the certificate = %d; want no new revocation", result, authority.count("cert-2001"))
	}
}

func TestLostKeysRetriesACertificateTheCARefused(t *testing.T) {
	f := newLifecycleFixture(t)
	f.addToken(t, "3001", "lost", 48*time.Hour)
	authority := newFakeCA()
	authority.refuse["cert-3001"] = true
	job := f.job(authority, 24*time.Hour)

	result, err := job.Tick(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Failed != 1 || result.Revoked != 0 {
		t.Fatalf("refused pass = %+v, want one failure", result)
	}
	if status := f.certificateStatus(t, "3001"); status != "active" {
		t.Fatalf("a refused certificate must stay active for the next pass; status = %q", status)
	}
	var errorAudits int
	if err := f.store.Pool.QueryRow(f.ctx, `
		SELECT count(*) FROM audit_events WHERE action = 'RevokeCertificate' AND outcome = 'error'
	`).Scan(&errorAudits); err != nil {
		t.Fatal(err)
	}
	if errorAudits != 1 {
		t.Fatalf("error audit records = %d, want 1", errorAudits)
	}

	delete(authority.refuse, "cert-3001")
	result, err = job.Tick(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Revoked != 1 || f.certificateStatus(t, "3001") != "revoked" {
		t.Fatalf("retry pass = %+v; the certificate should now be revoked", result)
	}
}

func TestLostKeysConcurrentInstancesRevokeEachCertificateOnce(t *testing.T) {
	f := newLifecycleFixture(t)
	serials := []string{"4001", "4002", "4003", "4004", "4005"}
	for _, serial := range serials {
		f.addToken(t, serial, "lost", 48*time.Hour)
	}
	authority := newFakeCA()
	first := f.job(authority, 24*time.Hour)
	second := f.job(authority, 24*time.Hour)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, job := range []*LostKeys{first, second} {
		wg.Add(1)
		go func(job *LostKeys) {
			defer wg.Done()
			for pass := 0; pass < 3; pass++ {
				if _, err := job.Tick(f.ctx); err != nil {
					errs <- err
					return
				}
			}
		}(job)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for _, serial := range serials {
		if count := authority.count("cert-" + serial); count != 1 {
			t.Fatalf("certificate %s was revoked at the CA %d times, want exactly once", serial, count)
		}
		if status := f.certificateStatus(t, serial); status != "revoked" {
			t.Fatalf("certificate %s status = %q, want revoked", serial, status)
		}
	}
}

func TestLostKeysRecordsACertificateTheCAAlreadyRevoked(t *testing.T) {
	f := newLifecycleFixture(t)
	f.addToken(t, "5001", "lost", 48*time.Hour)
	authority := newFakeCA()
	authority.already["cert-5001"] = true
	result, err := f.job(authority, 24*time.Hour).Tick(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Revoked != 1 || result.Failed != 0 {
		t.Fatalf("tick result = %+v, want the certificate counted as revoked", result)
	}
	if status := f.certificateStatus(t, "5001"); status != "revoked" {
		t.Fatalf("certificate status = %q, want revoked", status)
	}
	var alreadyRevoked bool
	if err := f.store.Pool.QueryRow(f.ctx, "SELECT (detail->>'already_revoked')::boolean FROM audit_events WHERE action = 'RevokeCertificate' AND outcome = 'success'").Scan(&alreadyRevoked); err != nil {
		t.Fatal(err)
	}
	if !alreadyRevoked {
		t.Fatal("the audit record must say already_revoked")
	}
}
