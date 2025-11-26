package utils

import "github.com/gin-gonic/gin"

type ErrorResponse struct {
    Success bool   `json:"success"`
    Message string `json:"message"`
    Error   string `json:"error,omitempty"`
}

type SuccessResponse struct {
    Success bool        `json:"success"`
    Message string      `json:"message"`
    Data    interface{} `json:"data,omitempty"`
}

func SendError(c *gin.Context, statusCode int, message string, err error) {
    response := ErrorResponse{
        Success: false,
        Message: message,
    }
    if err != nil {
        response.Error = err.Error()
    }
    c.JSON(statusCode, response)
}

func SendSuccess(c *gin.Context, statusCode int, message string, data interface{}) {
    c.JSON(statusCode, SuccessResponse{
        Success: true,
        Message: message,
        Data:    data,
    })
}