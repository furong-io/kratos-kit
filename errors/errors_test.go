package errors

import (
	"testing"

	"errors"

	kerrors "github.com/go-kratos/kratos/v3/errors"
	"github.com/stretchr/testify/require"
)

func TestWrapUnknownError(t *testing.T) {
	tests := []struct {
		name  string
		input error
		want  error
	}{
		{
			name:  "nil, want nil",
			input: nil,
			want:  nil,
		},
		{
			name:  "kratos error, want kratos error",
			input: kerrors.BadRequest("BAD_REQUEST", "bad request"),
			want:  kerrors.BadRequest("BAD_REQUEST", "bad request"),
		},
		{
			name:  "输入未知错误，期待包装的kratos错误",
			input: errors.New("123"),
			want: kerrors.InternalServer(InternalServerReason, InternalServerMessage).
				WithCause(errors.New("123")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WrapUnknownError(tt.input)
			require.Equal(t, tt.want, err)
		})
	}
}
