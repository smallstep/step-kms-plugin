// Copyright 2022 Smallstep Labs, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	Version     string
	ReleaseDate string
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "print the current version",
	Long:  "Prints the current version.",
	Run: func(cmd *cobra.Command, _ []string) {
		if Version == "" {
			Version = "0000000-dev"
		}
		if ReleaseDate == "" {
			ReleaseDate = time.Now().UTC().Format("2006-01-02 15:04 MST")
		}

		if strings.Contains(os.Getenv("LANG"), "UTF-8") {
			fmt.Printf("🔐 %s/%s (%s/%s)\n", cmd.Parent().Name(), Version, runtime.GOOS, runtime.GOARCH)
			fmt.Printf("   Release Date: %s\n", ReleaseDate)
		} else {
			fmt.Printf("%s/%s (%s/%s)\n", cmd.Parent().Name(), Version, runtime.GOOS, runtime.GOARCH)
			fmt.Printf("Release Date: %s\n", ReleaseDate)
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
