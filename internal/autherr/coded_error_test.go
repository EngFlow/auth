package autherr

import (
	"github.com/urfave/cli/v2"
)

var _ cli.ExitCoder = (*CodedError)(nil)
