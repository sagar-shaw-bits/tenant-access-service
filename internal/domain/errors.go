package domain

import "errors"

var (
	ErrNotFound       = errors.New("resource not found")
	ErrConflict       = errors.New("resource conflicts with an existing value")
	ErrSharedIdentity = errors.New("shared login identity requires platform administrator")
	ErrInvalidInput   = errors.New("invalid input")
)
