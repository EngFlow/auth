package browser

import (
	"fmt"
	"net/url"
	"os"
)

type Opener interface {
	Open(*url.URL) error
}

type StderrPrint struct{}

func (p *StderrPrint) Open(u *url.URL) error {
	fmt.Fprintf(
		os.Stderr,
		"Please open the following URL in your web browser to authenticate:\n\n\t%s\n\n",
		u,
	)
	return nil
}
