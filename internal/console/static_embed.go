package console

import "embed"

// consoleStaticFiles holds the built web console assets.
//
//go:embed all:static
var consoleStaticFiles embed.FS
