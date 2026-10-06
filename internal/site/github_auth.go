package site

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	githubSessionCookie = "__Host-xgift-github"
	githubStateCookie   = "__Host-xgift-github-state"
)

type githubAuthConfig struct {
	Enabled           bool
	ClientID          string
	ClientSecret      string
	MinAccountAgeDays int
	MaxXAccounts      int
	AttemptWindow     time.Duration
	MaxAttempts       int
	Cooldown          time.Duration
	MaxConcurrent     int
	SessionTTL        time.Duration
	HTTP              *http.Client
}

type githubSession struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}

func githubEnvInt(name string, fallback, min, max int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < min || value > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, min, max)
	}
	return value, nil
}

func (s *server) configureGithub() error {
	cfg := githubAuthConfig{Enabled: strings.EqualFold(strings.TrimSpace(os.Getenv("XGIFT_GITHUB_AUTH_ENABLED")), "true")}
	var err error
	if cfg.MinAccountAgeDays, err = githubEnvInt("XGIFT_GITHUB_MIN_ACCOUNT_AGE_DAYS", 180, 0, 36500); err != nil { return err }
	if cfg.MaxXAccounts, err = githubEnvInt("XGIFT_GITHUB_MAX_X_ACCOUNTS", 3, 0, 10000); err != nil { return err }
	windowHours, err := githubEnvInt("XGIFT_GITHUB_ATTEMPT_WINDOW_HOURS", 24, 0, 87600)
	if err != nil { return err }
	if cfg.MaxAttempts, err = githubEnvInt("XGIFT_GITHUB_MAX_ATTEMPTS", 5, 0, 1000000); err != nil { return err }
	cooldownMinutes, err := githubEnvInt("XGIFT_GITHUB_COOLDOWN_MINUTES", 30, 0, 5256000)
	if err != nil { return err }
	if cfg.MaxConcurrent, err = githubEnvInt("XGIFT_GITHUB_MAX_CONCURRENT_QUEUE", 1, 0, 1000); err != nil { return err }
	sessionHours, err := githubEnvInt("XGIFT_GITHUB_SESSION_HOURS", 168, 1, 87600)
	if err != nil { return err }
	if cfg.MaxAttempts > 0 && windowHours == 0 {
		return errors.New("XGIFT_GITHUB_ATTEMPT_WINDOW_HOURS must be > 0 when XGIFT_GITHUB_MAX_ATTEMPTS is enabled")
	}
	cfg.AttemptWindow = time.Duration(windowHours) * time.Hour
	cfg.Cooldown = time.Duration(cooldownMinutes) * time.Minute
	cfg.SessionTTL = time.Duration(sessionHours) * time.Hour
	cfg.HTTP = &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("unexpected GitHub redirect") }}
	if cfg.Enabled {
		cfg.ClientID = strings.TrimSpace(os.Getenv("XGIFT_GITHUB_CLIENT_ID"))
		secretPath := strings.TrimSpace(os.Getenv("XGIFT_GITHUB_CLIENT_SECRET_FILE"))
		if cfg.ClientID == "" || secretPath == "" {
			return errors.New("GitHub auth requires XGIFT_GITHUB_CLIENT_ID and XGIFT_GITHUB_CLIENT_SECRET_FILE")
		}
		secret, err := privateFile(secretPath)
		if err != nil { return err }
		defer clear(secret)
		cfg.ClientSecret = strings.TrimSpace(string(secret))
		if len(cfg.ClientSecret) < 20 {
			return errors.New("GitHub client secret is invalid")
		}
	}
	s.github = cfg
	return nil
}

func githubOwner(id int64) string { return "github:" + strconv.FormatInt(id, 10) }
func parseGithubOwner(owner string) (int64, bool) {
	if !strings.HasPrefix(owner, "github:") { return 0, false }
	id, err := strconv.ParseInt(strings.TrimPrefix(owner, "github:"), 10, 64)
	return id, err == nil && id > 0
}

func (s *server) encodeGithubSession(session githubSession) (string, error) {
	payload, err := json.Marshal(session)
	if err != nil { return "", err }
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.adminHash[:])
	_, _ = mac.Write([]byte(encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + sig, nil
}

func (s *server) githubSessionFromRequest(r *http.Request) (githubSession, bool) {
	var session githubSession
	if !s.github.Enabled { return session, false }
	cookie, err := r.Cookie(githubSessionCookie)
	if err != nil || len(cookie.Value) > 2048 { return session, false }
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 { return session, false }
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil { return session, false }
	mac := hmac.New(sha256.New, s.adminHash[:])
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(sig, mac.Sum(nil)) { return session, false }
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(payload, &session) != nil { return githubSession{}, false }
	now := time.Now()
	if session.ID <= 0 || session.Login == "" || session.ExpiresAt <= now.Unix() || session.CreatedAt <= 0 { return githubSession{}, false }
	if s.github.MinAccountAgeDays > 0 {
		threshold := now.Add(-time.Duration(s.github.MinAccountAgeDays) * 24 * time.Hour)
		if !time.Unix(session.CreatedAt, 0).Before(threshold) { return githubSession{}, false }
	}
	return session, true
}

func clearGithubCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}

func (s *server) githubLogin(w http.ResponseWriter, r *http.Request) {
	if !s.github.Enabled { http.NotFound(w, r); return }
	state := token(32)
	http.SetCookie(w, &http.Cookie{Name: githubStateCookie, Value: state, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	q := url.Values{
		"client_id": {s.github.ClientID},
		"redirect_uri": {s.origin + "/auth/github/callback"},
		"scope": {"read:user"},
		"state": {state},
		"allow_signup": {"false"},
	}
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+q.Encode(), http.StatusFound)
}

func (s *server) githubCallback(w http.ResponseWriter, r *http.Request) {
	if !s.github.Enabled { http.NotFound(w, r); return }
	stateCookie, err := r.Cookie(githubStateCookie)
	state := r.URL.Query().Get("state")
	clearGithubCookie(w, githubStateCookie)
	if err != nil || state == "" || len(state) != len(stateCookie.Value) || subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie.Value)) != 1 {
		message(w, http.StatusBadRequest, "GitHub 登录状态已失效，请重新登录。")
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" { message(w, http.StatusBadRequest, "GitHub 未返回授权码。") ; return }
	form := url.Values{"client_id": {s.github.ClientID}, "client_secret": {s.github.ClientSecret}, "code": {code}, "redirect_uri": {s.origin + "/auth/github/callback"}}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil { message(w, 503, "暂时无法完成 GitHub 登录。") ; return }
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "xgift")
	res, err := s.github.HTTP.Do(req)
	if err != nil { message(w, 503, "暂时无法连接 GitHub，请稍后重试。") ; return }
	defer res.Body.Close()
	var tokenResult struct { AccessToken string `json:"access_token"`; Error string `json:"error"` }
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 16<<10)).Decode(&tokenResult) != nil || tokenResult.AccessToken == "" || tokenResult.Error != "" {
		message(w, 502, "GitHub 授权失败，请重新登录。")
		return
	}
	userReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://api.github.com/user", nil)
	if err != nil { message(w, 503, "暂时无法读取 GitHub 账号。") ; return }
	userReq.Header.Set("Authorization", "Bearer "+tokenResult.AccessToken)
	userReq.Header.Set("Accept", "application/vnd.github+json")
	userReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	userReq.Header.Set("User-Agent", "xgift")
	userRes, err := s.github.HTTP.Do(userReq)
	if err != nil { message(w, 503, "暂时无法读取 GitHub 账号。") ; return }
	defer userRes.Body.Close()
	var user struct { ID int64 `json:"id"`; Login string `json:"login"`; CreatedAt time.Time `json:"created_at"` }
	if userRes.StatusCode != 200 || json.NewDecoder(io.LimitReader(userRes.Body, 32<<10)).Decode(&user) != nil || user.ID <= 0 || user.Login == "" || user.CreatedAt.IsZero() {
		message(w, 502, "无法验证 GitHub 账号信息。")
		return
	}
	if s.github.MinAccountAgeDays > 0 {
		threshold := time.Now().Add(-time.Duration(s.github.MinAccountAgeDays) * 24 * time.Hour)
		if !user.CreatedAt.Before(threshold) {
			message(w, http.StatusForbidden, fmt.Sprintf("GitHub 账号注册时间需要超过 %d 天。", s.github.MinAccountAgeDays))
			return
		}
	}
	now := time.Now()
	session := githubSession{ID: user.ID, Login: user.Login, CreatedAt: user.CreatedAt.Unix(), ExpiresAt: now.Add(s.github.SessionTTL).Unix()}
	value, err := s.encodeGithubSession(session)
	if err != nil { message(w, 503, "暂时无法创建登录会话。") ; return }
	http.SetCookie(w, &http.Cookie{Name: githubSessionCookie, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(s.github.SessionTTL / time.Second)})
	http.Redirect(w, r, s.origin+"/", http.StatusSeeOther)
}

func (s *server) githubLogout(w http.ResponseWriter, r *http.Request) {
	clearGithubCookie(w, githubSessionCookie)
	reply(w, 200, map[string]any{"ok": true})
}

func (s *server) githubStatus(w http.ResponseWriter, r *http.Request) {
	result := map[string]any{
		"enabled": s.github.Enabled,
		"authenticated": false,
		"min_account_age_days": s.github.MinAccountAgeDays,
		"max_x_accounts": s.github.MaxXAccounts,
		"attempt_window_hours": int(s.github.AttemptWindow / time.Hour),
		"max_attempts": s.github.MaxAttempts,
		"cooldown_minutes": int(s.github.Cooldown / time.Minute),
		"max_concurrent_queue": s.github.MaxConcurrent,
		"session_hours": int(s.github.SessionTTL / time.Hour),
	}
	if !s.github.Enabled { reply(w, 200, result); return }
	session, ok := s.githubSessionFromRequest(r)
	if !ok { reply(w, 200, result); return }
	usage, err := s.githubUsage(session.ID)
	if err != nil { message(w, 503, "暂时无法读取 GitHub 使用额度。") ; return }
	result["authenticated"] = true
	result["login"] = session.Login
	result["github_id"] = session.ID
	result["bound_x_accounts"] = usage.BoundXAccounts
	result["attempts_in_window"] = usage.AttemptsInWindow
	result["remaining_x_accounts"] = usage.RemainingXAccounts
	result["remaining_attempts"] = usage.RemainingAttempts
	result["next_allowed_at"] = usage.NextAllowedAt
	reply(w, 200, result)
}

func (s *server) publicLinkOwner(w http.ResponseWriter, r *http.Request) (string, bool) {
	if s.github.Enabled {
		session, ok := s.githubSessionFromRequest(r)
		if !ok {
			message(w, http.StatusUnauthorized, "请先使用 GitHub 登录后再生成或查看付款链接。")
			return "", false
		}
		return githubOwner(session.ID), true
	}
	cookie, err := r.Cookie("__Host-xgift-link")
	if err != nil || cookie == nil || cookie.Value == "" {
		message(w, 400, "请刷新页面后重新生成链接。")
		return "", false
	}
	return cookie.Value, true
}

func (s *server) publicLinkQueueCurrent(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.publicLinkOwner(w, r)
	if !ok { return }
	q := &s.linkQueue
	q.mu.Lock()
	q.prune(time.Now())
	var active *publicLinkJob
	var latest *publicLinkJob
	for _, job := range q.jobs {
		if job.owner != owner || job.cancelled { continue }
		if job.state != "done" && active == nil { active = job }
		if job.state == "done" && (latest == nil || job.finished.After(latest.finished)) { latest = job }
	}
	job := active
	if job == nil { job = latest }
	if job == nil {
		q.mu.Unlock()
		message(w, 404, "当前没有可恢复的排队任务。")
		return
	}
	id := job.id
	q.mu.Unlock()
	r.SetPathValue("ticket", id)
	s.publicLinkQueueStatus(w, r)
}
