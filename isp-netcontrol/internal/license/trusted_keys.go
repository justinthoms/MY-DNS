package license

// builtinTrustedKeys holds the License Manager's public signing key(s).
//
// It is written by scripts/set-trusted-keys.sh before a release build. While
// it is empty, ISP NetControl refuses to start and install.sh refuses to run.
const builtinTrustedKeys = ``
