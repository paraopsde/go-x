package main

import (
	cli "github.com/jawher/mow.cli"

	paraiam "github.com/paraopsde/go-x/pkg/iam"
)

func verifyAuthzCmd(cmd *cli.Cmd) {
	cmd.Spec = "USERNAME"
	usernameFlag := cmd.StringArg("USERNAME", "", "user to check")

	cmd.Action = func() {
		log := logger().Sugar()
		defer log.Sync()

		auth, err := paraiam.NewAuthzProvider()
		if err != nil {
			log.Fatalf("failed to create authz provider: %v", err)
		}

		log.Infof("test: %s", *usernameFlag)

		x, err := auth.Verify(*usernameFlag)
		if err != nil {
			log.Fatalf("failed to verify '%s': %v", *usernameFlag, err)
		}
		log.Infof("result: %v", x)
	}

}
