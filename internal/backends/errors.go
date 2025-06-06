package backends

import (
	"errors"
)

// Define custom errors for the backends package
var ErrUserExpired = errors.New("password is expired")
var ErrUserNotFound = errors.New("user not found")
