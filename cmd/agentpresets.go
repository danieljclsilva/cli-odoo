package cmd

import (
	"fmt"
	"github.com/danieljclsilva/cli-odoo/internal/output"
	"github.com/spf13/cobra"
)

type agentPreset struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Models      []string `json:"models"`
}

func agentPresets() []agentPreset {
	names := []string{}
	for _, m := range investigationModels() {
		names = append(names, m.name)
	}
	return []agentPreset{{"investigation", "Comprehensive installed business models; stored fields including custom fields; linked chatter/attachments; no arbitrary methods", names}}
}

func agentFindPreset(name string) (agentPreset, error) {
	for _, p := range agentPresets() {
		if p.Name == name {
			return p, nil
		}
	}
	return agentPreset{}, fmt.Errorf("unknown preset %q: use investigation (odoo agent presets shows the proposal)", name)
}

func init() {
	agentSetupParent().AddCommand(&cobra.Command{
		Use: "presets", Short: "Show the comprehensive investigation proposal (offline)",
		Run: func(cmd *cobra.Command, args []string) { output.Ok("agent_presets", agentPresets(), 1) },
	})
}
