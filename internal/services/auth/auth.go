package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/maestro-milagro/gRPC_Sample/internal/domain/models"
	"github.com/maestro-milagro/gRPC_Sample/internal/lib/jwt"
	"github.com/maestro-milagro/gRPC_Sample/internal/lib/logger/sl"
	"github.com/maestro-milagro/gRPC_Sample/internal/storage"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"time"
)

type Auth struct {
	log         *slog.Logger
	usrSaver    UserSaver
	usrProvider UserProvider
	appProvider AppProvider
	tokenTTL    time.Duration
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

var (
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrInvalidAppId         = errors.New("invalid app id")
	ErrInvalidUserExistence = errors.New("user exist")
)

func New(
	log *slog.Logger,
	usrSaver UserSaver,
	appProvider AppProvider,
	usrProvider UserProvider,

	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:         log,
		usrSaver:    usrSaver,
		usrProvider: usrProvider,
		appProvider: appProvider,
		tokenTTL:    tokenTTL,
	}
}

func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (token string, err error) {
	const op = "auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", op),
	)

	log.Info("login user")

	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", sl.Err(err))

			return "", fmt.Errorf("%s: %w", op, err)
		}

		a.log.Error("failed to get user", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged successfully")

	token, err = jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to get user", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}
func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	password string,
) (userID int64, err error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", op),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.usrSaver.SaveUser(ctx, email, passHash)

	if err != nil {

		if errors.Is(err, storage.ErrUserExist) {
			a.log.Warn("user exist", sl.Err(err))

			return 0, fmt.Errorf("%s: %w", op, ErrInvalidUserExistence)
		}

		log.Error("failed to save user", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil

}
func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", op),
	)

	log.Info("check for is admin")

	flag, err := a.usrProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("wrong app id", sl.Err(err))

			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppId)
		}

		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("is_admin", flag))

	return flag, nil
}
