package filter

import "regexp"

// CDI qualified names are vendor/class=device, not daemon host paths.
// Keep the grammar aligned with tags.cncf.io/container-device-interface's
// parser without adding its implementation to the request path.
var qualifiedCDIDevice = regexp.MustCompile(`^[A-Za-z](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?/[A-Za-z](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?=[A-Za-z0-9](?:[A-Za-z0-9_.:-]*[A-Za-z0-9])?$`)
