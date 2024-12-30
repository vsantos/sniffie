/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"sniffie/manager"
	"sniffie/ui"

	"github.com/spf13/cobra"
)

var (
	enablePcap     bool
	pcapName       string
	resolvePodName bool
	inet           string
	output         string
)

// snifferCmd represents the sniffer command
var snifferCmd = &cobra.Command{
	Use:   "sniff",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {

		switch output {
		case "table":
			t := ui.NewTUI()
			ui.SetTable(t.Table)
			go ui.UpdateTime(t)

			if err := t.Start(); err != nil {
				panic(err)
			}
		}

		var s manager.Sniffer

		s = &manager.SnifferConfig{
			Net: manager.NetConfig{
				InterfaceName: cmd.Flag("inet").Value.String(),
				GeneratePcap:  true,
			},
			Integrations: manager.SnifferIntegration{
				Name:    "Kubernetes",
				Enabled: true,
				Opts:    []string{"ae"},
			},
			Output: manager.SnifferOutput{
				OutputType: cmd.Flag("output").Value.String(),
				OutputPath: cmd.Flag("pcap-file-name").Value.String(),
			},
		}

		fmt.Println("== ", pcapName)
		s.Watch()
	},
}

func init() {
	rootCmd.AddCommand(snifferCmd)

	snifferCmd.PersistentFlags().BoolVarP(&enablePcap, "generate-pcap", "p", true, "If a pcap will be generated with individual packets. Default: true")
	snifferCmd.PersistentFlags().StringVarP(&pcapName, "pcap-file-name", "f", "./sniffie.pcap", ".pcap filename. Default: sniffie.pcap")

	snifferCmd.PersistentFlags().BoolVarP(&resolvePodName, "resolve-pod-name", "r", true, "Enable kubernetes integration to fetch origin and dst pod name")

	snifferCmd.PersistentFlags().StringVarP(&inet, "inet", "i", "", "Network interface.")
	snifferCmd.PersistentFlags().StringVarP(&output, "output", "o", "table", "Sniff output. Options: table,json")

	snifferCmd.MarkPersistentFlagRequired("inet")
}
