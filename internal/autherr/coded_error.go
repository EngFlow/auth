package autherr

import (
	"errors"
	"fmt"
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

var UnexpectedHTML = errors.New("request to JSON API returned HTML unexpectedly")

// CodedError wraps an error with an integer code that can be used as e.g. a
// return code from an application.
type CodedError struct {
	Code int
	Err  error
}

func (e *CodedError) Error() string {
	return e.Err.Error()
}

func (e *CodedError) ExitCode() int {
	return e.Code
}

func CodedErrorf(code int, format string, args ...any) error {
	return &CodedError{
		Code: code,
		Err:  fmt.Errorf(format, args...),
	}
}

func ReauthRequired(cluster string) error {
	const reauthMessage = "Missing/invalid/expired credentials for cluster: %s\n" +
		"Please refresh credentials by running:\n\n\t" +
		"engflow_auth login %s\n"
	return CodedErrorf(CodeReauthRequired, reauthMessage, cluster, cluster)
}
