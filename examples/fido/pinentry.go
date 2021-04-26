package main

import (
	"context"
	"fmt"
	"os/exec"

	assuan "github.com/foxcpp/go-assuan/client"
	"github.com/foxcpp/go-assuan/pinentry"
)

func ConfirmPresence(ctx context.Context, prompt string) (bool, error) {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	p, err := launchPinEntry(childCtx)
	if err != nil {
		return false, fmt.Errorf("failed to start pinentry: %w", err)
	}
	defer p.Shutdown()
	p.SetTitle("AWSesh")
	p.SetPrompt("AWSesh")
	p.SetDesc(prompt)

	result := make(chan bool)

	go func() {
		err := p.Confirm()
		result <- err == nil
	}()

	select {
	case ok := <-result:
		return ok, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func launchPinEntry(ctx context.Context) (*pinentry.Client, error) {
	cmd := exec.CommandContext(ctx, "pinentry")

	var c pinentry.Client
	var err error
	c.Session, err = assuan.InitCmd(cmd)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
