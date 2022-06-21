module github.com/smallstep/step-kms-plugin

go 1.18

require (
	github.com/spf13/cobra v1.4.0
	github.com/spf13/pflag v1.0.5
	go.step.sm/crypto v0.16.2
)

require (
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/ThalesIgnite/crypto11 v1.2.5 // indirect
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/manifoldco/promptui v0.9.0 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	go.step.sm/cli-utils v0.7.3 // indirect
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3 // indirect
	golang.org/x/sys v0.0.0-20220610221304-9f5ed59c137d // indirect
)

replace go.step.sm/crypto => ../crypto
