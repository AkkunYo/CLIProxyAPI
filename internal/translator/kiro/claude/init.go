package claude

import (
	"context"

	. "github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/translator/translator"
)

func init() {
	translator.Register(
		Claude,
		"kiro",
		func(model string, body []byte, stream bool) []byte { return body },
		interfaces.TranslateResponse{
			Stream: func(_ context.Context, model string, origReq, transReq, body []byte, param *any) [][]byte {
				return [][]byte{body}
			},
			NonStream: func(_ context.Context, model string, origReq, transReq, body []byte, param *any) []byte {
				return body
			},
		},
	)
}
