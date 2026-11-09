package authkit

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AdminInfo is one row of the administrators list.
type AdminInfo struct {
	ID          int64      `json:"id"`
	Email       string     `json:"email"`
	TOTPEnabled bool       `json:"totp_enabled"`
	Locked      bool       `json:"locked"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

// ListAdmins returns every administrator.
func ListAdmins(ctx context.Context, db *pgxpool.Pool) ([]AdminInfo, error) {
	rows, err := db.Query(ctx, `SELECT id, email, totp_enabled, coalesce(locked_until > now(), false), created_at, last_login_at
		FROM admin_users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminInfo{}
	for rows.Next() {
		var x AdminInfo
		if err := rows.Scan(&x.ID, &x.Email, &x.TOTPEnabled, &x.Locked, &x.CreatedAt, &x.LastLoginAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// MountAdmins registers administrator management on r (which must already
// require a full session): GET /, POST / {email,password}, DELETE /:id.
// New administrators must set up two-factor authentication and change the
// password at their first sign-in.
func (a *Auth) MountAdmins(r fiber.Router) {
	r.Get("/", func(c *fiber.Ctx) error {
		list, err := ListAdmins(c.UserContext(), a.DB)
		if err != nil {
			return err
		}
		return c.JSON(list)
	})
	r.Post("/", func(c *fiber.Ctx) error {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.BodyParser(&req); err != nil {
			return APIError(c, fiber.StatusBadRequest, "bad_request", "invalid body")
		}
		email := strings.ToLower(strings.TrimSpace(req.Email))
		if !strings.Contains(email, "@") || len(email) > 200 {
			return APIError(c, fiber.StatusBadRequest, "bad_request", "a valid email is required")
		}
		hash, err := HashPassword(req.Password)
		if err != nil {
			return APIError(c, fiber.StatusBadRequest, "weak_password", err.Error())
		}
		var id int64
		err = a.DB.QueryRow(c.UserContext(), `INSERT INTO admin_users(email, password_hash, must_change_password) VALUES ($1,$2,true) RETURNING id`,
			email, hash).Scan(&id)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate key") {
				return APIError(c, fiber.StatusConflict, "exists", "an administrator with that email already exists")
			}
			return err
		}
		a.AuditC(c, "admin.created", email, nil)
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": id})
	})
	r.Delete("/:id", func(c *fiber.Ctx) error {
		id, err := strconv.ParseInt(c.Params("id"), 10, 64)
		if err != nil {
			return APIError(c, fiber.StatusNotFound, "not_found", "not found")
		}
		if id == CurrentUser(c).ID {
			return APIError(c, fiber.StatusBadRequest, "bad_request", "you cannot delete your own account")
		}
		var email string
		err = a.DB.QueryRow(c.UserContext(), `DELETE FROM admin_users WHERE id=$1 RETURNING email`, id).Scan(&email)
		if errors.Is(err, pgx.ErrNoRows) {
			return APIError(c, fiber.StatusNotFound, "not_found", "not found")
		}
		if err != nil {
			return err
		}
		a.AuditC(c, "admin.deleted", email, nil)
		return c.JSON(fiber.Map{"ok": true})
	})
}

// ErrNoSuchAdmin is returned by the recovery functions.
var ErrNoSuchAdmin = errors.New("no administrator with that email")

// ResetPassword sets a new random password that must be changed at the next
// sign-in, clears the lockout and signs the user out everywhere. For
// recovery from the server's command line.
func ResetPassword(ctx context.Context, db *pgxpool.Pool, email string) (string, error) {
	pw := RandomToken(15) // 20 characters
	hash, err := HashPassword(pw)
	if err != nil {
		return "", err
	}
	tag, err := db.Exec(ctx, `UPDATE admin_users SET password_hash=$2, must_change_password=true, failed_logins=0, locked_until=NULL
		WHERE email=$1`, strings.ToLower(strings.TrimSpace(email)), hash)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", ErrNoSuchAdmin
	}
	_, _ = db.Exec(ctx, `DELETE FROM admin_sessions WHERE user_id=(SELECT id FROM admin_users WHERE email=$1)`, strings.ToLower(strings.TrimSpace(email)))
	Audit(ctx, db, "console-cli", "admin.password_reset", email, nil, "")
	return pw, nil
}

// ResetTOTP removes two-factor authentication; the user enrols again at the
// next sign-in. Sessions are ended.
func ResetTOTP(ctx context.Context, db *pgxpool.Pool, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	tag, err := db.Exec(ctx, `UPDATE admin_users SET totp_enabled=false, totp_secret_enc=NULL, totp_last_step=0, failed_logins=0, locked_until=NULL
		WHERE email=$1`, email)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchAdmin
	}
	_, _ = db.Exec(ctx, `DELETE FROM admin_sessions WHERE user_id=(SELECT id FROM admin_users WHERE email=$1)`, email)
	Audit(ctx, db, "console-cli", "admin.totp_reset", email, nil, "")
	return nil
}
