package util

import (
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type contextKey string

func (c contextKey) String() string {
	return "context key " + string(c)
}

func NewLogger() *zap.Logger {
	return NewLoggerWithLevel(zap.DebugLevel)
}
func NewLoggerWithLevel(level zapcore.Level) *zap.Logger {
	conf := zap.NewProductionConfig()
	conf.Level.SetLevel(level)
	log, err := conf.Build()
	if err != nil {
		panic("failed to create logger")
	}
	return log.WithOptions(zap.WithCaller(true), zap.AddStacktrace(zap.WarnLevel))
}

func CtxLogOrPanic(ctx context.Context) *zap.Logger {
	log, ok := ctx.Value(contextKey("logger")).(*zap.Logger)
	if !ok {
		panic("context lacks logger")
	}
	return log
}

func CtxLogOrInjectNew(ctx context.Context) (*zap.Logger, context.Context) {
	log, ok := ctx.Value(contextKey("logger")).(*zap.Logger)
	if !ok {
		log = NewLogger()
		return log, CtxWithLog(ctx, log)
	}
	return log, ctx
}

func CtxWithLog(ctx context.Context, log *zap.Logger) context.Context {
	return context.WithValue(ctx, contextKey("logger"), log)
}
