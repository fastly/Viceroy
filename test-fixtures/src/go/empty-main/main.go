// Reproduction/regression fixture for https://github.com/fastly/Viceroy/issues/491.
// Fixed by shifting the adapter's pages in the adapter so the go
// runtime doesn't overwite them on startup. See 92a76f4 (https://github.com/fastly/Viceroy/pull/538)
package main

import (
	"context"

	"github.com/fastly/compute-sdk-go/fsthttp"
)

func main() {
	// Issue says that an empty main should be enough to trigger, but I wasn't able to reproduce.
	// Using the sdk with no additional logic seems to work though.
	fsthttp.ServeFunc(func(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {})
}
