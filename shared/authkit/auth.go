package authkit

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Schema creates the tables authkit needs. Each product runs it as part of
// its own migrations.
const Schema = `
CREATE TABLE IF NOT EXISTS admin_users (
  id                   BIGSERIAL PRIMARY KEY,
  email                TEXT NOT NULL UNIQUE,
  password_hash        TEXT NOT NULL,
  totp_secret_enc      BYTEA,
  totp_enabled         BOOLEAN NOT NULL DEFAULT false,
  totp_last_step       BIGINT NOT NULL DEFAULT 0,
  failed_logins        INT NOT NULL DEFAULT 0,
  locked_until         TIMESTAMPTZ,
  must_change_password BOOLEAN NOT NULL DEFAULT false,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at        TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS admin_sessions (
  id_hash      TEXT PRIMARY KEY,
  user_id      BIGINT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
  csrf_token   TEXT NOT NULL,
  mfa_ok       BOOLEAN NOT NULL DEFAULT false,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip           TEXT NOT NULL DEFAULT '',
  user_agent   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS admin_sessions_user ON admin_sessions(user_id);
CREATE TABLE IF NOT EXISTS audit_log (
  id      BIGSERIAL PRIMARY KEY,
  at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor   TEXT NOT NULL,
  action  TEXT NOT NULL,
  target  TEXT NOT NULL DEFAULT '',
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log(at DESC);
`

const (
	maxFailedLogins  = 5
	lockoutDuration  = 15 * time.Minute
	preMFALifetime   = 10 * time.Minute
	idleTimeout      = 30 * time.Minute
	absoluteLifetime = 12 * time.Hour
	csrfHeader       = "X-CSRF-Token"
)

// Auth wires authentication into a Fiber app.
type Auth struct {
	DB          *pgxpool.Pool
	Box         *SecretBox
	Issuer      string // shown in authenticator apps
	CookieName  string
	Secure      bool // set the Secure flag on cookies (true behind HTTPS)
	RequireTOTP bool
}

// User is the authenticated administrator.
type User struct {
	ID                 int64  `json:"id"`
	Email              string `json:"email"`
	TOTPEnabled        bool   `json:"totp_enabled"`
	MustChangePassword bool   `json:"must_change_password"`
}

type session struct {
	IDHash string
	CSRF   string
	MFAOK  bool
	User   User
}

// APIError is the JSON error body used by both products.
func APIError(c *fiber.Ctx, status int, code, msg string) error {
	return c.Status(status).JSON(fiber.Map{"error": msg, "code": code})
}

// Audit records an action in the audit log. Failures are logged, not fatal.
func Audit(ctx context.Context, db *pgxpool.Pool, actor, action, target string, details any, ip string) {
	if details == nil {
		details = map[string]any{}
	}
	raw, _ := json.Marshal(details)
	if _, err := db.Exec(ctx, `INSERT INTO audit_log(actor, action, target, details, ip) VALUES ($1,$2,$3,$4,$5)`,
		actor, action, target, raw, ip); err != nil {
		log.Printf("audit: %v", err)
	}
}

// AuditC is Audit for the current request's administrator.
func (a *Auth) AuditC(c *fiber.Ctx, action, target string, details any) {
	actor := "system"
	if u := CurrentUser(c); u != nil {
		actor = u.Email
	}
	Audit(c.UserContext(), a.DB, actor, action, target, details, c.IP())
}

// EnsureBootstrapAdmin creates the first administrator when none exists.
// The bootstrap password must be changed at first login.
func (a *Auth) EnsureBootstrapAdmin(ctx context.Context, email, password string) error {
	var n int
	if err := a.DB.QueryRow(ctx, `SELECT count(*) FROM admin_users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if email == "" || password == "" {
		return errors.New("no administrator exists: set the bootstrap admin email and password")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("bootstrap admin password: %w", err)
	}
	_, err = a.DB.Exec(ctx, `INSERT INTO admin_users(email, password_hash, must_change_password) VALUES ($1,$2,true)`,
		strings.ToLower(strings.TrimSpace(email)), hash)
	if err == nil {
		Audit(ctx, a.DB, "system", "admin.bootstrap", email, nil, "")
	}
	return err
}

// Origin guard: browsers always send Origin on cross-site state-changing
// requests; reject any whose host is not ours.
func (a *Auth) OriginGuard() fiber.Handler {
	return func(c *fiber.Ctx) error {
		switch c.Method() {
		case fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions:
			return c.Next()
		}
		if o := c.Get(fiber.HeaderOrigin); o != "" {
			u, err := url.Parse(o)
			if err != nil || !strings.EqualFold(u.Host, c.Hostname()) {
				return APIError(c, fiber.StatusForbidden, "bad_origin", "cross-origin request refused")
			}
		}
		return c.Next()
	}
}

func (a *Auth) setCookie(c *fiber.Ctx, value string, expires time.Time) {
	c.Cookie(&fiber.Cookie{
		Name: a.CookieName, Value: value, Path: "/", Expires: expires,
		HTTPOnly: true, Secure: a.Secure, SameSite: fiber.CookieSameSiteStrictMode,
	})
}

func (a *Auth) loadSession(c *fiber.Ctx) (*session, error) {
	tok := c.Cookies(a.CookieName)
	if tok == "" {
		return nil, nil
	}
	s := &session{IDHash: HashToken(tok)}
	var lastSeen, created time.Time
	err := a.DB.QueryRow(c.UserContext(), `
		SELECT s.csrf_token, s.mfa_ok, s.last_seen_at, s.created_at,
		       u.id, u.email, u.totp_enabled, u.must_change_password
		FROM admin_sessions s JOIN admin_users u ON u.id = s.user_id
		WHERE s.id_hash = $1 AND s.expires_at > now()`, s.IDHash).
		Scan(&s.CSRF, &s.MFAOK, &lastSeen, &created, &s.User.ID, &s.User.Email, &s.User.TOTPEnabled, &s.User.MustChangePassword)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if time.Since(lastSeen) > idleTimeout || time.Since(created) > absoluteLifetime {
		_, _ = a.DB.Exec(c.UserContext(), `DELETE FROM admin_sessions WHERE id_hash=$1`, s.IDHash)
		return nil, nil
	}
	_, _ = a.DB.Exec(c.UserContext(), `UPDATE admin_sessions SET last_seen_at = now() WHERE id_hash=$1`, s.IDHash)
	return s, nil
}

// CurrentUser returns the administrator attached by a Require* middleware.
func CurrentUser(c *fiber.Ctx) *User {
	if s, ok := c.Locals("authkit.session").(*session); ok {
		return &s.User
	}
	return nil
}

func (a *Auth) csrfOK(c *fiber.Ctx, s *session) bool {
	switch c.Method() {
	case fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions:
		return true
	}
	got := c.Get(csrfHeader)
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.CSRF)) == 1
}

// requireSession loads the session and enforces CSRF. If full is true the
// session must also have passed TOTP and not be pending a password change.
func (a *Auth) requireSession(full bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		s, err := a.loadSession(c)
		if err != nil {
			return err
		}
		if s == nil {
			return APIError(c, fiber.StatusUnauthorized, "unauthenticated", "please sign in")
		}
		if !a.csrfOK(c, s) {
			return APIError(c, fiber.StatusForbidden, "csrf", "missing or invalid CSRF token")
		}
		c.Locals("authkit.session", s)
		if full {
			if !s.MFAOK {
				return APIError(c, fiber.StatusForbidden, "mfa_required", "two-factor authentication is required")
			}
			if s.User.MustChangePassword {
				return APIError(c, fiber.StatusForbidden, "password_change_required", "change your password first")
			}
		}
		return c.Next()
	}
}

// Require protects a route group: signed in, TOTP passed, password current.
func (a *Auth) Require() fiber.Handler { return a.requireSession(true) }

// Mount registers the /auth routes on r.
func (a *Auth) Mount(r fiber.Router) {
	r.Post("/login", a.login)
	partial := a.requireSession(false)
	r.Get("/me", partial, a.me)
	r.Post("/logout", partial, a.logout)
	r.Get("/totp/enroll", partial, a.totpEnrollStart)
	r.Post("/totp/enroll", partial, a.totpEnrollFinish)
	r.Post("/totp/verify", partial, a.totpVerify)
	r.Post("/password", partial, a.changePassword)
}

// nextStep tells the console what the user must do next.
func (a *Auth) nextStep(s *session) string {
	switch {
	case !s.MFAOK && s.User.TOTPEnabled:
		return "totp_verify"
	case !s.MFAOK && a.RequireTOTP:
		return "totp_enroll"
	case s.User.MustChangePassword:
		return "change_password"
	default:
		return "ready"
	}
}

func (a *Auth) meBody(s *session) fiber.Map {
	return fiber.Map{"user": s.User, "csrf_token": s.CSRF, "next": a.nextStep(s)}
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *Auth) login(c *fiber.Ctx) error {
	if !strings.HasPrefix(c.Get(fiber.HeaderContentType), fiber.MIMEApplicationJSON) {
		return APIError(c, fiber.StatusUnsupportedMediaType, "bad_request", "JSON body required")
	}
	var req loginReq
	if err := c.BodyParser(&req); err != nil {
		return APIError(c, fiber.StatusBadRequest, "bad_request", "invalid body")
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	ctx := c.UserContext()
	var (
		id          int64
		hash        string
		totpEnabled bool
		mustChange  bool
		lockedUntil *time.Time
	)
	err := a.DB.QueryRow(ctx, `SELECT id, password_hash, totp_enabled, must_change_password, locked_until FROM admin_users WHERE email=$1`, email).
		Scan(&id, &hash, &totpEnabled, &mustChange, &lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		CheckPassword("$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g", req.Password) // even out timing
		Audit(ctx, a.DB, email, "auth.login_failed", "", map[string]string{"reason": "unknown user"}, c.IP())
		return APIError(c, fiber.StatusUnauthorized, "bad_credentials", "wrong email or password")
	}
	if err != nil {
		return err
	}
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		Audit(ctx, a.DB, email, "auth.login_locked", "", nil, c.IP())
		return APIError(c, fiber.StatusTooManyRequests, "locked", "too many failed attempts; try again later")
	}
	if !CheckPassword(hash, req.Password) {
		a.recordFailure(ctx, id)
		Audit(ctx, a.DB, email, "auth.login_failed", "", map[string]string{"reason": "bad password"}, c.IP())
		return APIError(c, fiber.StatusUnauthorized, "bad_credentials", "wrong email or password")
	}
	_, _ = a.DB.Exec(ctx, `UPDATE admin_users SET failed_logins=0, locked_until=NULL WHERE id=$1`, id)

	tok := RandomToken(32)
	csrf := RandomToken(24)
	mfaOK := !totpEnabled && !a.RequireTOTP
	expires := time.Now().Add(preMFALifetime)
	if mfaOK {
		expires = time.Now().Add(absoluteLifetime)
	}
	if _, err := a.DB.Exec(ctx, `INSERT INTO admin_sessions(id_hash, user_id, csrf_token, mfa_ok, expires_at, ip, user_agent)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, HashToken(tok), id, csrf, mfaOK, expires, c.IP(), c.Get(fiber.HeaderUserAgent)); err != nil {
		return err
	}
	a.setCookie(c, tok, time.Now().Add(absoluteLifetime))
	Audit(ctx, a.DB, email, "auth.password_ok", "", nil, c.IP())
	s := &session{IDHash: HashToken(tok), CSRF: csrf, MFAOK: mfaOK,
		User: User{ID: id, Email: email, TOTPEnabled: totpEnabled, MustChangePassword: mustChange}}
	return c.JSON(a.meBody(s))
}

func (a *Auth) recordFailure(ctx context.Context, id int64) {
	_, _ = a.DB.Exec(ctx, `UPDATE admin_users SET failed_logins = failed_logins + 1,
		locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + $3::interval ELSE locked_until END
		WHERE id=$1`, id, maxFailedLogins, fmt.Sprintf("%d seconds", int(lockoutDuration.Seconds())))
}

func (a *Auth) sess(c *fiber.Ctx) *session { return c.Locals("authkit.session").(*session) }

func (a *Auth) me(c *fiber.Ctx) error { return c.JSON(a.meBody(a.sess(c))) }

func (a *Auth) logout(c *fiber.Ctx) error {
	s := a.sess(c)
	_, _ = a.DB.Exec(c.UserContext(), `DELETE FROM admin_sessions WHERE id_hash=$1`, s.IDHash)
	a.setCookie(c, "", time.Unix(0, 0))
	Audit(c.UserContext(), a.DB, s.User.Email, "auth.logout", "", nil, c.IP())
	return c.JSON(fiber.Map{"ok": true})
}

func (a *Auth) totpEnrollStart(c *fiber.Ctx) error {
	s := a.sess(c)
	if s.User.TOTPEnabled {
		return APIError(c, fiber.StatusConflict, "already_enrolled", "two-factor authentication is already set up")
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: a.Issuer, AccountName: s.User.Email})
	if err != nil {
		return err
	}
	enc := a.Box.Seal([]byte(key.Secret()), fmt.Sprintf("totp:%d", s.User.ID))
	if _, err := a.DB.Exec(c.UserContext(), `UPDATE admin_users SET totp_secret_enc=$2 WHERE id=$1`, s.User.ID, enc); err != nil {
		return err
	}
	img, err := key.Image(220, 220)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"secret":      key.Secret(),
		"otpauth_url": key.URL(),
		"qr_png":      "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
	})
}

type codeReq struct {
	Code string `json:"code"`
}

// checkCode validates a TOTP code and refuses to accept the same time step
// twice (replay protection).
func (a *Auth) checkCode(ctx context.Context, userID int64, code string) (bool, error) {
	var enc []byte
	var lastStep int64
	if err := a.DB.QueryRow(ctx, `SELECT totp_secret_enc, totp_last_step FROM admin_users WHERE id=$1`, userID).Scan(&enc, &lastStep); err != nil {
		return false, err
	}
	if enc == nil {
		return false, nil
	}
	secret, err := a.Box.Open(enc, fmt.Sprintf("totp:%d", userID))
	if err != nil {
		return false, fmt.Errorf("decrypt TOTP secret (wrong master key?): %w", err)
	}
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	now := time.Now().Unix() / 30
	for skew := int64(-1); skew <= 1; skew++ {
		step := now + skew
		want, err := totp.GenerateCodeCustom(string(secret), time.Unix(step*30, 0), totp.ValidateOpts{
			Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return false, err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			if step <= lastStep {
				return false, nil // already used
			}
			_, err := a.DB.Exec(ctx, `UPDATE admin_users SET totp_last_step=$2 WHERE id=$1`, userID, step)
			return err == nil, err
		}
	}
	return false, nil
}

func (a *Auth) upgradeSession(c *fiber.Ctx, s *session) error {
	_, err := a.DB.Exec(c.UserContext(), `UPDATE admin_sessions SET mfa_ok=true, expires_at=$2 WHERE id_hash=$1`,
		s.IDHash, time.Now().Add(absoluteLifetime))
	if err != nil {
		return err
	}
	_, err = a.DB.Exec(c.UserContext(), `UPDATE admin_users SET last_login_at=now() WHERE id=$1`, s.User.ID)
	s.MFAOK = true
	return err
}

func (a *Auth) totpEnrollFinish(c *fiber.Ctx) error {
	s := a.sess(c)
	if s.User.TOTPEnabled {
		return APIError(c, fiber.StatusConflict, "already_enrolled", "two-factor authentication is already set up")
	}
	var req codeReq
	if err := c.BodyParser(&req); err != nil {
		return APIError(c, fiber.StatusBadRequest, "bad_request", "invalid body")
	}
	ok, err := a.checkCode(c.UserContext(), s.User.ID, req.Code)
	if err != nil {
		return err
	}
	if !ok {
		a.recordFailure(c.UserContext(), s.User.ID)
		return APIError(c, fiber.StatusUnauthorized, "bad_code", "that code is not valid")
	}
	if _, err := a.DB.Exec(c.UserContext(), `UPDATE admin_users SET totp_enabled=true WHERE id=$1`, s.User.ID); err != nil {
		return err
	}
	s.User.TOTPEnabled = true
	if err := a.upgradeSession(c, s); err != nil {
		return err
	}
	Audit(c.UserContext(), a.DB, s.User.Email, "auth.totp_enrolled", "", nil, c.IP())
	return c.JSON(a.meBody(s))
}

func (a *Auth) totpVerify(c *fiber.Ctx) error {
	s := a.sess(c)
	if !s.User.TOTPEnabled {
		return APIError(c, fiber.StatusConflict, "not_enrolled", "set up two-factor authentication first")
	}
	var req codeReq
	if err := c.BodyParser(&req); err != nil {
		return APIError(c, fiber.StatusBadRequest, "bad_request", "invalid body")
	}
	var lockedUntil *time.Time
	_ = a.DB.QueryRow(c.UserContext(), `SELECT locked_until FROM admin_users WHERE id=$1`, s.User.ID).Scan(&lockedUntil)
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		return APIError(c, fiber.StatusTooManyRequests, "locked", "too many failed attempts; try again later")
	}
	ok, err := a.checkCode(c.UserContext(), s.User.ID, req.Code)
	if err != nil {
		return err
	}
	if !ok {
		a.recordFailure(c.UserContext(), s.User.ID)
		Audit(c.UserContext(), a.DB, s.User.Email, "auth.totp_failed", "", nil, c.IP())
		return APIError(c, fiber.StatusUnauthorized, "bad_code", "that code is not valid")
	}
	_, _ = a.DB.Exec(c.UserContext(), `UPDATE admin_users SET failed_logins=0 WHERE id=$1`, s.User.ID)
	if err := a.upgradeSession(c, s); err != nil {
		return err
	}
	Audit(c.UserContext(), a.DB, s.User.Email, "auth.login", "", nil, c.IP())
	return c.JSON(a.meBody(s))
}

type pwReq struct {
	Current string `json:"current_password"`
	New     string `json:"new_password"`
}

func (a *Auth) changePassword(c *fiber.Ctx) error {
	s := a.sess(c)
	if !s.MFAOK {
		return APIError(c, fiber.StatusForbidden, "mfa_required", "two-factor authentication is required")
	}
	var req pwReq
	if err := c.BodyParser(&req); err != nil {
		return APIError(c, fiber.StatusBadRequest, "bad_request", "invalid body")
	}
	var hash string
	if err := a.DB.QueryRow(c.UserContext(), `SELECT password_hash FROM admin_users WHERE id=$1`, s.User.ID).Scan(&hash); err != nil {
		return err
	}
	if !CheckPassword(hash, req.Current) {
		return APIError(c, fiber.StatusUnauthorized, "bad_credentials", "current password is wrong")
	}
	if req.New == req.Current {
		return APIError(c, fiber.StatusBadRequest, "weak_password", "choose a different password")
	}
	newHash, err := HashPassword(req.New)
	if err != nil {
		return APIError(c, fiber.StatusBadRequest, "weak_password", err.Error())
	}
	if _, err := a.DB.Exec(c.UserContext(), `UPDATE admin_users SET password_hash=$2, must_change_password=false WHERE id=$1`, s.User.ID, newHash); err != nil {
		return err
	}
	// Sign out every other session of this user.
	_, _ = a.DB.Exec(c.UserContext(), `DELETE FROM admin_sessions WHERE user_id=$1 AND id_hash<>$2`, s.User.ID, s.IDHash)
	s.User.MustChangePassword = false
	Audit(c.UserContext(), a.DB, s.User.Email, "auth.password_changed", "", nil, c.IP())
	return c.JSON(a.meBody(s))
}
