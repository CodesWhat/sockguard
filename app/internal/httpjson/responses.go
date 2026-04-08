package httpjson

// ErrorResponse is the JSON body returned by HTTP handlers for generic client-facing errors.
type ErrorResponse struct {
	Message string `json:"message"`
}
