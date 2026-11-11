package application

import (
	"tenant-access-service/internal/config"
	"tenant-access-service/internal/permission"
	"tenant-access-service/internal/repository"
	"tenant-access-service/internal/role"
	"tenant-access-service/internal/service"
	"tenant-access-service/internal/tenant"
	"tenant-access-service/internal/user"
)

func NewServer(db repository.Pool, cfg config.Config) *Server {
	repo := repository.NewPostgres(db)
	cache := permission.NewCache(cfg.PermissionCacheTTL)
	return &Server{
		health: repo, cfg: cfg,
		auth:   service.NewAuthService(repo, cfg, cache),
		tenant: tenant.NewService(repo),
		users:  user.NewService(repo, cache),
		roles:  role.NewService(repo, cache),
	}
}
