package logger

// Logger is used to log extra info within the SDK detailing what's happening.
// You can set a logger during initialization. If you leave it unititialized, no
// logging will happen. If you set it to the DefaultLogger, you'll get
// timestamped lines sent to STDOUT. Pass in your own implementation of the
// interface to send it in to your own logger. An instance of the go package
// log.Logger satisfies this interface.
type Logger interface {
	// Printf accepts the same msg, args style as fmt.Printf().
	Printf(msg string, args ...interface{})

	Tracef(format string, args ...interface{})

	Debugf(format string, args ...interface{})

	Infof(format string, args ...interface{})

	Warnf(format string, args ...interface{})

	Warningf(format string, args ...interface{})

	Errorf(format string, args ...interface{})

	Fatalf(format string, args ...interface{})

	Panicf(format string, args ...interface{})
}

type NullLogger struct{}

// Printf swallows messages
func (n *NullLogger) Printf(msg string, args ...interface{}) {
	// nothing to see here.
}
func (n *NullLogger) Tracef(msg string, args ...interface{}) {
	// nothing to see here.
}
func (n *NullLogger) Debugf(msg string, args ...interface{}) {
	// nothing to see here.
}
func (n *NullLogger) Warnf(format string, args ...interface{}) {
	// nothing to see here.
}
func (n *NullLogger) Infof(msg string, args ...interface{}) {
	// nothing to see here.
}
func (n *NullLogger) Warningf(msg string, args ...interface{}) {
	// nothing to see here.
}
func (n *NullLogger) Errorf(msg string, args ...interface{}) {
	// nothing to see here.
}
func (n *NullLogger) Fatalf(msg string, args ...interface{}) {
	// nothing to see here.
}
func (n *NullLogger) Panicf(msg string, args ...interface{}) {
	// nothing to see here.
}
