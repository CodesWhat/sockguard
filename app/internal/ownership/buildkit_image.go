package ownership

import (
	"context"
	"fmt"
	"net/http"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerclient"
)

// NewBuildkitImageAuthorizer checks names assigned by mediated image exporters.
func NewBuildkitImageAuthorizer(rt http.RoundTripper, opts Options) func(context.Context, string) error {
	inspector := upstreamInspector{client: dockerclient.NewWithRoundTripper(rt)}
	return func(ctx context.Context, name string) error {
		if opts.Owner == "" {
			return nil
		}
		destination, problem := imageDestinationFor(name, "", imageTagNamingFor(opts.UpstreamFlavor))
		if problem != imageDestinationReadable {
			return fmt.Errorf("invalid image destination")
		}
		verdict, _, err := checkImageDestination(ctx, inspector.inspectResource, destination, opts, "image destination is owned by another client")
		if err != nil {
			return err
		}
		if verdict.denied() {
			return fmt.Errorf("image destination is outside this owner")
		}
		return nil
	}
}
