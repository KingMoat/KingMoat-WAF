// Package naming centralizes the externally visible deployment names so no
// call site hardcodes them: renaming a deployment identity is a one-constant
// change here, and grep audits have a single source of truth. Deliberately
// dependency-free so both internal/upgrade and internal/api can import it
// (the upgrade package must not import the api package, and the console
// port-change flow must stay independent of the upgrade pipeline).
package naming

// ServiceName is the systemd unit name the product's service runs under,
// without the ".service" suffix (as used by `systemctl restart` and unit
// management commands). It must match the unit installed by deploy/install.sh
// (the deploy card owns that file); a mismatch silently restarts nothing.
const ServiceName = "kingmoatwaf"
