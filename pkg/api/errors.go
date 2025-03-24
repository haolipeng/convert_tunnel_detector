package api

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

// 错误代码常量
const (
	// 通用错误
	ErrCodeInternalServerError = http.StatusInternalServerError // 服务器内部错误
	ErrCodeBadRequest          = http.StatusBadRequest          // 请求参数错误
	ErrCodeNotFound            = http.StatusNotFound            // 资源不存在
	ErrCodeConflict            = http.StatusConflict            // 资源冲突

	// 规则相关错误
	ErrCodeRuleNotFound       = http.StatusNotFound   // 规则不存在
	ErrCodeRuleAlreadyExists  = http.StatusConflict   // 规则已存在
	ErrCodeInvalidRuleFormat  = http.StatusBadRequest // 规则格式无效
	ErrCodeRuleValidationFail = http.StatusBadRequest // 规则验证失败
)

// RuleError 自定义规则错误类型
type RuleError struct {
	Code    int         // HTTP 状态码
	Message string      // 错误消息
	Err     error       // 原始错误
	Data    interface{} // 附加数据（可选）
}

// Error 实现 error 接口
func (e *RuleError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// NewRuleError 创建新的规则错误
func NewRuleError(code int, message string, err error) *RuleError {
	return &RuleError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// NewRuleNotFoundError 创建规则不存在错误
func NewRuleNotFoundError(ruleID string) *RuleError {
	return &RuleError{
		Code:    ErrCodeRuleNotFound,
		Message: fmt.Sprintf("规则 %s 不存在", ruleID),
	}
}

// NewRuleAlreadyExistsError 创建规则已存在错误
func NewRuleAlreadyExistsError(ruleID string) *RuleError {
	return &RuleError{
		Code:    ErrCodeRuleAlreadyExists,
		Message: fmt.Sprintf("规则 %s 已存在", ruleID),
	}
}

// NewInvalidRuleFormatError 创建规则格式无效错误
func NewInvalidRuleFormatError(err error) *RuleError {
	return &RuleError{
		Code:    ErrCodeInvalidRuleFormat,
		Message: "规则格式无效",
		Err:     err,
	}
}

// NewRuleValidationError 创建规则验证失败错误
func NewRuleValidationError(err error) *RuleError {
	return &RuleError{
		Code:    ErrCodeRuleValidationFail,
		Message: "规则验证失败",
		Err:     err,
	}
}

// NewInternalServerError 创建服务器内部错误
func NewInternalServerError(err error) *RuleError {
	return &RuleError{
		Code:    ErrCodeInternalServerError,
		Message: "服务器内部错误",
		Err:     err,
	}
}

// HandleError 统一错误处理函数
func HandleError(c echo.Context, err error) error {
	// 记录错误日志
	logrus.WithFields(logrus.Fields{
		"error":      err.Error(),
		"request_id": c.Response().Header().Get(echo.HeaderXRequestID),
		"path":       c.Request().URL.Path,
		"method":     c.Request().Method,
	}).Error("API 错误")

	// 处理自定义错误
	if ruleErr, ok := err.(*RuleError); ok {
		// 返回错误响应
		resp := Response{
			Code:    ruleErr.Code,
			Message: ruleErr.Message,
		}

		// 在开发环境中可以添加详细错误信息
		// 这里可以根据环境变量等配置来决定是否添加详细错误
		if ruleErr.Err != nil && IsDebugMode() {
			resp.Data = map[string]string{
				"error_detail": ruleErr.Err.Error(),
			}
		}

		// 返回json格式的错误响应
		return c.JSON(ruleErr.Code, resp)
	}

	// 处理未知错误
	return c.JSON(http.StatusInternalServerError, Response{
		Code:    http.StatusInternalServerError,
		Message: "服务器内部错误",
	})
}

// IsDebugMode 判断是否为调试模式
func IsDebugMode() bool {
	// 可以根据环境变量或配置来判断
	// 这里暂时返回 false
	return false
}
