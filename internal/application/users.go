package application

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"tenant-access-service/internal/domain"
	"tenant-access-service/internal/middleware"
	"tenant-access-service/internal/response"
)

func (s *Server) createUser(c *gin.Context) {
	principal := currentPrincipal(c)
	var input struct {
		Email    string `json:"email" binding:"required,email,max=255"`
		Password string `json:"password" binding:"required,min=8,max=72"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.users.Create(ctx, principal, input.Email, input.Password)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusCreated, item, "User created successfully")
}

func (s *Server) listUsers(c *gin.Context) {
	principal := currentPrincipal(c)
	limit, offset, err := parsePagination(c)
	if err != nil {
		writeError(c, err)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	items, err := s.users.List(ctx, principal, c.Query("email"), limit, offset)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, items, "Users fetched successfully")
}

func (s *Server) getUser(c *gin.Context) {
	principal := currentPrincipal(c)
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.users.Get(ctx, principal, c.Param("id"))
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, item, "User fetched successfully")
}

func (s *Server) updateUser(c *gin.Context) {
	principal := currentPrincipal(c)
	var input struct {
		Email    *string `json:"email" binding:"omitempty,email,max=255"`
		Password *string `json:"password" binding:"omitempty,min=8,max=72"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	if input.Email == nil && input.Password == nil {
		writeError(c, errNoFields)
		return
	}
	if input.Email != nil {
		normalized := strings.TrimSpace(*input.Email)
		if normalized == "" {
			writeError(c, errNoFields)
			return
		}
		input.Email = &normalized
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.users.Update(ctx, principal, c.Param("id"), input.Email, input.Password)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, item, "User updated successfully")
}

func (s *Server) updateGlobalUser(c *gin.Context) {
	session, _ := middleware.ExtractAuthContext(c)
	var input struct {
		Email    *string `json:"email" binding:"omitempty,email,max=255"`
		Password *string `json:"password" binding:"omitempty,min=8,max=72"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	if input.Email == nil && input.Password == nil {
		writeError(c, errNoFields)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.users.UpdateGlobal(ctx, session.UserID, c.Param("id"), input.Email, input.Password)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, item, "Global user updated successfully")
}

func (s *Server) deleteUser(c *gin.Context) {
	principal := currentPrincipal(c)
	ctx, cancel := s.dbContext(c)
	defer cancel()
	if err := s.users.Delete(ctx, principal, c.Param("id")); err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, gin.H{"id": c.Param("id")}, "User membership deactivated successfully")
}

func (s *Server) addMembership(c *gin.Context) {
	principal := currentPrincipal(c)
	userID, err := parseID(c.Param("id"))
	if err != nil {
		writeError(c, err)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.users.AddMembership(ctx, principal, userID)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusCreated, item, "Membership created successfully")
}

func (s *Server) replaceUserRoles(c *gin.Context) {
	principal := currentPrincipal(c)
	var input struct {
		RoleIDs *[]string `json:"role_ids"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	if input.RoleIDs == nil {
		writeError(c, errNoFields)
		return
	}
	roleIDs, err := parseIDs(*input.RoleIDs)
	if err != nil {
		writeError(c, err)
		return
	}
	s.changeUserRoles(c, principal, roleIDs, true)
}

func (s *Server) removeUserRoles(c *gin.Context) {
	principal := currentPrincipal(c)
	var input struct {
		RoleIDs []string `json:"role_ids" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	roleIDs, err := parseIDs(input.RoleIDs)
	if err != nil {
		writeError(c, err)
		return
	}
	s.changeUserRoles(c, principal, roleIDs, false)
}

func (s *Server) changeUserRoles(c *gin.Context, principal domain.Actor, roleIDs []string, replace bool) {
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.users.ChangeRoles(ctx, principal, c.Param("id"), roleIDs, replace)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, item, "Role assignments updated successfully")
}

var errInvalidID = domain.ErrInvalidInput

func parseIDs(values []string) ([]string, error) {
	ids := make([]string, 0, len(values))
	seen := make(map[uuid.UUID]struct{}, len(values))
	for _, value := range values {
		id, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil {
			return nil, errInvalidID
		}
		if _, ok := seen[id]; !ok {
			ids = append(ids, id.String())
			seen[id] = struct{}{}
		}
	}
	return ids, nil
}
