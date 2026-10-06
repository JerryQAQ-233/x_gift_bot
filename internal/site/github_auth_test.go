package site

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func githubQuotaFixture(t *testing.T) *server {
	t.Helper()
	s := resumeFixture(t, "review", "created")
	if err := migrateGithubAbuse(s.db); err != nil { t.Fatal(err) }
	s.github = githubAuthConfig{Enabled: true, MaxXAccounts: 2, AttemptWindow: 24 * time.Hour, MaxAttempts: 5, Cooldown: 0, MaxConcurrent: 1, SessionTTL: 24 * time.Hour}
	return s
}

func TestGithubQuotaTargetLimit(t *testing.T) {
	s := githubQuotaFixture(t)
	s.github.MaxXAccounts = 1
	owner := githubOwner(123)
	if !s.admitGithubPublicLink(httptest.NewRecorder(), owner, "first") { t.Fatal("first target rejected") }
	w := httptest.NewRecorder()
	if s.admitGithubPublicLink(w, owner, "second") || w.Code != 403 { t.Fatalf("target limit not enforced: %d", w.Code) }
}

func TestGithubQuotaAttemptsAndCooldown(t *testing.T) {
	t.Run("attempt window", func(t *testing.T) {
		s := githubQuotaFixture(t)
		s.github.MaxXAccounts = 0
		s.github.MaxAttempts = 2
		owner := githubOwner(456)
		if !s.admitGithubPublicLink(httptest.NewRecorder(), owner, "one") { t.Fatal("first attempt rejected") }
		if !s.admitGithubPublicLink(httptest.NewRecorder(), owner, "two") { t.Fatal("second attempt rejected") }
		w := httptest.NewRecorder()
		if s.admitGithubPublicLink(w, owner, "three") || w.Code != 429 || w.Header().Get("Retry-After") == "" { t.Fatalf("attempt limit not enforced: %d", w.Code) }
	})
	t.Run("cooldown", func(t *testing.T) {
		s := githubQuotaFixture(t)
		s.github.MaxXAccounts = 0
		s.github.MaxAttempts = 0
		s.github.Cooldown = 30 * time.Minute
		owner := githubOwner(789)
		if !s.admitGithubPublicLink(httptest.NewRecorder(), owner, "one") { t.Fatal("first attempt rejected") }
		w := httptest.NewRecorder()
		if s.admitGithubPublicLink(w, owner, "two") || w.Code != 429 { t.Fatalf("cooldown not enforced: %d", w.Code) }
	})
}

func TestGithubQuotaConcurrentQueue(t *testing.T) {
	s := githubQuotaFixture(t)
	owner := githubOwner(999)
	s.linkQueue.jobs = []*publicLinkJob{{id: "ticket", owner: owner, state: "queued", request: manualLinkRequest{Username: "first", Months: 3}}}
	w := httptest.NewRecorder()
	if s.admitGithubPublicLink(w, owner, "second") || w.Code != 409 { t.Fatalf("concurrent queue limit not enforced: %d", w.Code) }
}

func TestGithubSignedSession(t *testing.T) {
	s := &server{adminHash: sha256.Sum256([]byte("test-admin-secret")), github: githubAuthConfig{Enabled: true, MinAccountAgeDays: 180, SessionTTL: 24 * time.Hour}}
	now := time.Now()
	value, err := s.encodeGithubSession(githubSession{ID: 42, Login: "tester", CreatedAt: now.Add(-365 * 24 * time.Hour).Unix(), ExpiresAt: now.Add(time.Hour).Unix()})
	if err != nil { t.Fatal(err) }
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: githubSessionCookie, Value: value})
	got, ok := s.githubSessionFromRequest(r)
	if !ok || got.ID != 42 || got.Login != "tester" { t.Fatal("valid session rejected") }
}
