package PasswordEncoder

import "errors"

// UnmappedIdPasswordEncoder is a default encoder for unmapped ids.
type UnmappedIdPasswordEncoder struct{}

// Encode does nothing and returns the raw password.
func (u *UnmappedIdPasswordEncoder) Encode(rawPassword string) (string, error) {
	return rawPassword, nil
}

// Matches always returns false for unmapped ids.
func (u *UnmappedIdPasswordEncoder) Matches(rawPassword string, encodedPassword string) (bool, error) {
	if rawPassword == encodedPassword {
		return true, nil
	} else {
		return false, errors.New("wrong password")
	}
}

func (u *UnmappedIdPasswordEncoder) UpgradeEncoding(encodedPassword string) (bool, error) {
	return false, nil
}
