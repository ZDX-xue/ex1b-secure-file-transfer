// Package portal contains the browser client and administration console.
package portal

import "embed"

//go:embed web/index.html web/style.css web/app.js
var Assets embed.FS
