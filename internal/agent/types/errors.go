package types

type NotFoundError struct {
	Detail string
}

func (e NotFoundError) Error() string {
	return e.Detail
}

func NewNotFoundError(detail string) NotFoundError {
	return NotFoundError{Detail: detail}
}

type ConflictError struct {
	Detail string
}

func (e ConflictError) Error() string {
	return e.Detail
}

func NewConflictError(detail string) ConflictError {
	return ConflictError{Detail: detail}
}
