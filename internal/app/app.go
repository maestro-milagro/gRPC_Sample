package app

import (
	grpcapp "github.com/maestro-milagro/gRPC_Sample/internal/app/grpc"
	"github.com/maestro-milagro/gRPC_Sample/internal/services/auth"
	"github.com/maestro-milagro/gRPC_Sample/internal/storage/sqlite"
	"log/slog"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	storagePath string,
	tokenTTL time.Duration,
) *App {
	storage, err := sqlite.New(storagePath)
	if err != nil {
		panic(err)
	}

	authService := auth.New(log, storage, storage, storage, tokenTTL)

	grpcApp := grpcapp.New(log, authService, grpcPort)

	return &App{
		GRPCSrv: grpcApp,
	}
}
