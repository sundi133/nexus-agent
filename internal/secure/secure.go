// Package secure locks down directories holding agent secrets (device token,
// enrollment token, cached policy) so only root/SYSTEM and administrators can
// read them.
package secure

// RestrictDir creates dir if needed and restricts access to privileged
// principals. On Unix this is mode 0700 (owner = root). On Windows it
// replaces the inherited %ProgramData% ACL (which grants Users read access)
// with a protected DACL for SYSTEM and Administrators only.
func RestrictDir(dir string) error { return restrictDir(dir) }
