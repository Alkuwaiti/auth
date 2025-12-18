package user

import "golang.org/x/crypto/bcrypt"

func hashPassword(password string) (string, error) {
	// TODO: change this to use a configuration value.
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedBytes), nil
}
