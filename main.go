package main

import (
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/realzollsoft/cert-manager-webhook-inwx/internal/solver"
)

func main() {
	cmd.RunWebhookServer("cert-manager-webhook-inwx.realzollsoft.github.com",
		solver.New(),
	)
}
