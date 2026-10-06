package site

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"
)

type githubUsageSummary struct {
	BoundXAccounts    int
	AttemptsInWindow int
	RemainingXAccounts int
	RemainingAttempts int
	NextAllowedAt     int64
}

func migrateGithubAbuse(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS github_link_bindings (
			github_id INTEGER NOT NULL,
			username TEXT NOT NULL,
			created INTEGER NOT NULL,
			PRIMARY KEY (github_id, username)
		);
		CREATE TABLE IF NOT EXISTS github_link_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			github_id INTEGER NOT NULL,
			username TEXT NOT NULL,
			created INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS github_link_attempts_account_created ON github_link_attempts(github_id, created);
	`)
	return err
}

func (s *server) githubUsage(id int64) (githubUsageSummary, error) {
	usage := githubUsageSummary{RemainingXAccounts: -1, RemainingAttempts: -1}
	if s.db == nil { return usage, sql.ErrConnDone }
	if err := s.db.QueryRow("SELECT COUNT(*) FROM github_link_bindings WHERE github_id=?", id).Scan(&usage.BoundXAccounts); err != nil { return usage, err }
	now := time.Now().Unix()
	if s.github.MaxXAccounts > 0 {
		usage.RemainingXAccounts = s.github.MaxXAccounts - usage.BoundXAccounts
		if usage.RemainingXAccounts < 0 { usage.RemainingXAccounts = 0 }
	}
	var latest int64
	if err := s.db.QueryRow("SELECT COALESCE(MAX(created),0) FROM github_link_attempts WHERE github_id=?", id).Scan(&latest); err != nil { return usage, err }
	if s.github.Cooldown > 0 && latest > 0 {
		next := latest + int64(s.github.Cooldown/time.Second)
		if next > now { usage.NextAllowedAt = next }
	}
	if s.github.MaxAttempts > 0 && s.github.AttemptWindow > 0 {
		cutoff := now - int64(s.github.AttemptWindow/time.Second)
		var oldest int64
		if err := s.db.QueryRow("SELECT COUNT(*), COALESCE(MIN(created),0) FROM github_link_attempts WHERE github_id=? AND created>?", id, cutoff).Scan(&usage.AttemptsInWindow, &oldest); err != nil { return usage, err }
		usage.RemainingAttempts = s.github.MaxAttempts - usage.AttemptsInWindow
		if usage.RemainingAttempts < 0 { usage.RemainingAttempts = 0 }
		if usage.AttemptsInWindow >= s.github.MaxAttempts && oldest > 0 {
			next := oldest + int64(s.github.AttemptWindow/time.Second)
			if next > usage.NextAllowedAt { usage.NextAllowedAt = next }
		}
	}
	return usage, nil
}

// Caller holds the public queue mutex, so queue concurrency and quota admission
// are serialized with the ticket that consumes the quota.
func (s *server) admitGithubPublicLink(w http.ResponseWriter, owner, username string) bool {
	id, ok := parseGithubOwner(owner)
	if !ok || !s.github.Enabled { return true }
	active := 0
	for _, job := range s.linkQueue.jobs {
		if job.owner == owner && job.state != "done" && !job.cancelled { active++ }
	}
	if s.github.MaxConcurrent > 0 && active >= s.github.MaxConcurrent {
		message(w, http.StatusConflict, "该 GitHub 账号已有正在排队或生成中的任务，请先等待当前任务完成。")
		return false
	}
	tx, err := s.db.Begin()
	if err != nil { message(w, 503, "暂时无法记录使用额度，请稍后重试。") ; return false }
	defer tx.Rollback()
	now := time.Now().Unix()
	retention := s.github.AttemptWindow
	if s.github.Cooldown > retention { retention = s.github.Cooldown }
	if retention > 0 {
		_, _ = tx.Exec("DELETE FROM github_link_attempts WHERE github_id=? AND created<?", id, now-int64(retention/time.Second)-60)
	}
	waitSeconds := int64(0)
	if s.github.MaxAttempts > 0 && s.github.AttemptWindow > 0 {
		cutoff := now - int64(s.github.AttemptWindow/time.Second)
		var count int
		var oldest int64
		if err = tx.QueryRow("SELECT COUNT(*), COALESCE(MIN(created),0) FROM github_link_attempts WHERE github_id=? AND created>?", id, cutoff).Scan(&count, &oldest); err != nil {
			message(w, 503, "暂时无法读取使用额度，请稍后重试。")
			return false
		}
		if count >= s.github.MaxAttempts && oldest > 0 {
			waitSeconds = oldest + int64(s.github.AttemptWindow/time.Second) - now
		}
	}
	if s.github.Cooldown > 0 {
		var latest int64
		if err = tx.QueryRow("SELECT COALESCE(MAX(created),0) FROM github_link_attempts WHERE github_id=?", id).Scan(&latest); err != nil {
			message(w, 503, "暂时无法读取使用额度，请稍后重试。")
			return false
		}
		if latest > 0 {
			cooldownWait := latest + int64(s.github.Cooldown/time.Second) - now
			if cooldownWait > waitSeconds { waitSeconds = cooldownWait }
		}
	}
	if waitSeconds > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(waitSeconds, 10))
		message(w, http.StatusTooManyRequests, "该 GitHub 账号当前处于生成冷却或次数限制中，请稍后再试。")
		return false
	}
	var bound int
	if err = tx.QueryRow("SELECT COUNT(*) FROM github_link_bindings WHERE github_id=? AND username=?", id, username).Scan(&bound); err != nil {
		message(w, 503, "暂时无法读取账号绑定记录，请稍后重试。")
		return false
	}
	if bound == 0 && s.github.MaxXAccounts > 0 {
		var total int
		if err = tx.QueryRow("SELECT COUNT(*) FROM github_link_bindings WHERE github_id=?", id).Scan(&total); err != nil {
			message(w, 503, "暂时无法读取账号绑定记录，请稍后重试。")
			return false
		}
		if total >= s.github.MaxXAccounts {
			message(w, http.StatusForbidden, "该 GitHub 账号已达到可绑定 X 账号数量上限。")
			return false
		}
	}
	if _, err = tx.Exec("INSERT OR IGNORE INTO github_link_bindings(github_id,username,created) VALUES(?,?,?)", id, username, now); err != nil {
		message(w, 503, "暂时无法保存账号绑定记录，请稍后重试。")
		return false
	}
	if s.github.MaxAttempts > 0 || s.github.Cooldown > 0 {
		if _, err = tx.Exec("INSERT INTO github_link_attempts(github_id,username,created) VALUES(?,?,?)", id, username, now); err != nil {
			message(w, 503, "暂时无法记录使用额度，请稍后重试。")
			return false
		}
	}
	if err = tx.Commit(); err != nil {
		message(w, 503, "暂时无法保存使用额度，请稍后重试。")
		return false
	}
	return true
}
