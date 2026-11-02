package inventory

import "syscall"

// uname returns the running kernel release, as `uname -r` prints it.
func uname() (string, error) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return "", err
	}
	// The field is int8 or uint8 depending on the architecture.
	release := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		release = append(release, byte(c))
	}
	return string(release), nil
}
