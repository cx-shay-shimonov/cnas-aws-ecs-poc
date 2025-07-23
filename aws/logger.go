package aws

// InfoLogger interface for logging with info level
type InfoLogger interface {
	Info() MsgfLogger
}

// MsgfLogger interface for formatted message logging
type MsgfLogger interface {
	Msgf(format string, args ...any)
}

// LogFunc represents a logging function that accepts formatted messages
type LogFunc func(format string, args ...any)

// CreatePrefixedLogger creates a logging function that prefixes all messages
func CreatePrefixedLogger(logger InfoLogger, prefix string) LogFunc {
	return func(format string, args ...any) {
		fullFormat := prefix + format + "\n"
		logger.Info().Msgf(fullFormat, args...)
	}
}
