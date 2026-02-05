package main

import (
	"os"

	"github.com/sliverarmory/beignet"
	"github.com/spf13/cobra"
)

var (
	outPath     string
	entrySymbol string
	compress    bool
)

var rootCmd = &cobra.Command{
	Use:          "beignet <payload.dylib>",
	Short:        "Convert a darwin/arm64 dylib into a shellcode buffer",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		sc, err := beignet.DylibFileToShellcode(args[0], beignet.Options{
			EntrySymbol: entrySymbol,
			Compress:    compress,
		})
		if err != nil {
			return err
		}
		return os.WriteFile(outPath, sc, 0o644)
	},
}

func init() {
	rootCmd.Flags().StringVarP(&outPath, "out", "o", "payload.bin", "Output file path for the raw shellcode buffer")
	rootCmd.Flags().StringVar(&entrySymbol, "entry", "", "Entry symbol to resolve in the dylib (default: _StartW)")
	rootCmd.Flags().BoolVar(&compress, "compress", false, "Compress the staged dylib using aPLib (AP32)")

	rootCmd.AddCommand(dumpLoaderCCmd)
}
