package autherr

import (
	"errors"
	"fmt"

	"github.com/urfave/cli/v2"
)

const (
	CodeUnknownError      = 1
	CodeUnknownSubcommand = 2 // Also happens to be used for flag.Parse errors, which is fitting
	CodeUnimplemented     = 3
	CodeBadParams         = 4
	CodeAuthFailure       = 5
	CodeTokenStoreFailure = 6
	CodeReauthRequired    = 7
)

var ErrUnexpectedHTML = errors.New("request to JSON API returned HTML unexpectedly")

// CodedError wraps an error with an integer code that can be used as e.g. a
// return code from an application.
func CodedErrorf(code int, format string, args ...any) error {
	return cli.Exit(fmt.Errorf(format, args...), code)
}

func ReauthRequired(cluster string) error {
	const reauthMessage = "Missing/invalid/expired credentials for cluster: %s\n" +
		"Please refresh credentials by running:\n\n\t" +
		"engflow_auth login %s\n"
	return CodedErrorf(CodeReauthRequired, reauthMessage, cluster, cluster)
}
