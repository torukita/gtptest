package cmd

import (
	"fmt"
	_ "os"
	_ "strings"
	"github.com/spf13/cobra"
	"github.com/torukita/gtptest/gtp"
)

var versionCmd = &cobra.Command{
    Use:   "version",
    Short: "Print the version",
    Long:  `All software has versions.`,
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("v0.0.1")
    },
}

var RootCmd = &cobra.Command{
    Use:   "hoge",
    Short: "hoge is a very fast static site generator",
    Long: `A Fast and Flexible Static Site Generator built with
                love by spf13 and friends in Go.
                Complete documentation is available at http://hugo.spf13.com`,
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("command root")
    },
}

var pcapCmd = &cobra.Command{
	Use: "pcap",
	Short: "offline",
	Long: `Start Testing offline pcap file`,
	Run: func(cmd *cobra.Command, args []string) {
		gtp.RunOffline(args[0])
	},
}

var liveCmd = &cobra.Command{
	Use: "live",
	Short: "live",
	Long: `Start Testing live file`,
	Run: func(cmd *cobra.Command, args []string) {
		gtp.RunLive(args[0])
	},
}
		
func init() {
    RootCmd.AddCommand(versionCmd)
    RootCmd.AddCommand(pcapCmd)
    RootCmd.AddCommand(liveCmd)
}
