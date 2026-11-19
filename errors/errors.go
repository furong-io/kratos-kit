// Package errors 提供基于 kratos error 的通用错误包装工具
package errors

import (
	kerrors "github.com/go-kratos/kratos/v3/errors"
)

const (
	InternalServerReason  = "INTERNAL_SERVER"
	InternalServerMessage = "internal server"
)

func WrapUnknownError(err error) error {
	if err == nil {
		return nil
	}
	se := new(kerrors.Error)
	if kerrors.As(err, &se) {
		return err
	}
	return kerrors.InternalServer(InternalServerReason, InternalServerMessage).WithCause(err)
}
