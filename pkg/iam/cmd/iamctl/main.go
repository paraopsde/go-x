package main

import (
	"os"

	cli "github.com/jawher/mow.cli"
	"go.uber.org/zap"
)

func main() {
	app := cli.App("iamctl", "iam cli")

	app.Command("verify-authz", "verify authorization", verifyAuthzCmd)
	app.Run(os.Args)
}

var cachedLogger *zap.Logger

func logger() *zap.Logger {
	if cachedLogger == nil {
		l, e := zap.NewDevelopment()
		if e == nil {
			cachedLogger = l
		}
	}
	return cachedLogger.WithOptions(zap.WithCaller(true), zap.AddStacktrace(zap.PanicLevel))
}
