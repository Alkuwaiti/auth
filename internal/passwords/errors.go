package passwords

import "errors"

var (
	ErrPasswordTooShort         = errors.New("password must be at least 8 characters")
	ErrPasswordTooLong          = errors.New("password cannot exceed 255 characters")
	ErrPasswordMissingUppercase = errors.New("password must contain at least one uppercase letter")
	ErrPasswordMissingLowercase = errors.New("password must contain at least one lowercase letter")
	ErrPasswordMissingNumber    = errors.New("password must contain at least one number")
	ErrPasswordMissingSpecial   = errors.New("password must contain at least one special character")
)
