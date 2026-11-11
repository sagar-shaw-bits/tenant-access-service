package response

import "github.com/gin-gonic/gin"

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Envelope struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

func Success(c *gin.Context, statusCode int, data interface{}, message string) {
	c.JSON(statusCode, Envelope{Success: true, Data: data, Message: message})
}

func Error(c *gin.Context, statusCode int, code, message string) {
	c.JSON(statusCode, Envelope{Success: false, Error: &APIError{Code: code, Message: message}})
}
