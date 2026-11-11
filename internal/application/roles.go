package application

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"tenant-access-service/internal/response"
)

func (s *Server) createRole(c *gin.Context) {
	principal := currentPrincipal(c)
	var input struct {
		Name string `json:"name" binding:"required,min=1,max=100"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		writeError(c, errNoFields)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.roles.Create(ctx, principal, name)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusCreated, item, "Role created successfully")
}

func (s *Server) listRoles(c *gin.Context) {
	principal := currentPrincipal(c)
	limit, offset, err := parsePagination(c)
	if err != nil {
		writeError(c, err)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	items, err := s.roles.List(ctx, principal, c.Query("name"), limit, offset)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, items, "Roles fetched successfully")
}

func (s *Server) getRole(c *gin.Context) {
	principal := currentPrincipal(c)
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.roles.Get(ctx, principal, c.Param("id"))
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, item, "Role fetched successfully")
}

func (s *Server) updateRole(c *gin.Context) {
	principal := currentPrincipal(c)
	var input struct {
		Name string `json:"name" binding:"required,min=1,max=100"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		writeError(c, errNoFields)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.roles.Update(ctx, principal, c.Param("id"), name)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, item, "Role updated successfully")
}

func (s *Server) deleteRole(c *gin.Context) {
	principal := currentPrincipal(c)
	roleID, err := parseID(c.Param("id"))
	if err != nil {
		writeError(c, err)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	err = s.roles.Delete(ctx, principal, roleID)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, gin.H{"id": roleID}, "Role deleted successfully")
}

func (s *Server) listPermissions(c *gin.Context) {
	principal := currentPrincipal(c)
	limit, offset, err := parsePagination(c)
	if err != nil {
		writeError(c, err)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	items, err := s.roles.ListPermissions(ctx, principal, c.Query("resource"), limit, offset)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, items, "Permissions fetched successfully")
}

func (s *Server) getRolePermissions(c *gin.Context) {
	principal := currentPrincipal(c)
	ctx, cancel := s.dbContext(c)
	defer cancel()
	items, err := s.roles.Permissions(ctx, principal, c.Param("id"))
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, items, "Role permissions fetched successfully")
}

func (s *Server) replaceRolePermissions(c *gin.Context) {
	principal := currentPrincipal(c)
	var input struct {
		PermissionIDs *[]string `json:"permission_ids"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	if input.PermissionIDs == nil {
		writeError(c, errNoFields)
		return
	}
	permissionIDs, err := parseIDs(*input.PermissionIDs)
	if err != nil {
		writeError(c, err)
		return
	}
	roleID, err := parseID(c.Param("id"))
	if err != nil {
		writeError(c, err)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.roles.ReplacePermissions(ctx, principal, roleID, permissionIDs)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, item, "Role permissions updated successfully")
}
