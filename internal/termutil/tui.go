// Copyright 2021 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//nolint:gocritic,errorlint // this file is borrowed from age
package termutil

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/term"
)

// clearLine clears the current line on the terminal, or opens a new line if
// terminal escape codes don't work.
func clearLine(out io.Writer) {
	const (
		CUI = "\033["   // Control Sequence Introducer
		CPL = CUI + "F" // Cursor Previous Line
		EL  = CUI + "K" // Erase in Line
	)

	// First, open a new line, which is guaranteed to work everywhere. Then, try
	// to erase the line above with escape codes.
	//
	// (We use CRLF instead of LF to work around an apparent bug in WSL2's
	// handling of CONOUT$. Only when running a Windows binary from WSL2, the
	// cursor would not go back to the start of the line with a simple LF.
	// Honestly, it's impressive CONIN$ and CONOUT$ work at all inside WSL2.)
	fmt.Fprintf(out, "\r\n"+CPL+EL)
}

// withTerminal runs f with the terminal input and output files, if available.
// withTerminal does not open a non-terminal stdin, so the caller does not need
// to check stdinInUse.
func withTerminal(f func(in, out *os.File) error) error {
	if runtime.GOOS == "windows" {
		in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer out.Close()
		return f(in, out)
	} else if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		return f(tty, tty)
	} else if term.IsTerminal(int(os.Stdin.Fd())) {
		return f(os.Stdin, os.Stdin)
	} else {
		return fmt.Errorf("standard input is not a terminal, and /dev/tty is not available: %v", err)
	}
}

// ReadPassword reads a value from the terminal with no echo. The prompt is
// ephemeral.
func ReadPassword(prompt string) (s []byte, err error) {
	err = withTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, "%s ", prompt)
		defer clearLine(out)
		s, err = term.ReadPassword(int(in.Fd()))
		return err
	})
	return
}

// WriteFile writes data to the named file. If the file exists it will ask
// for confirmation before overwriting it.
func WriteFile(name string, data []byte, perm os.FileMode) error {
	st, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(name, data, perm)
		}
		return err
	}

	if st.IsDir() {
		return fmt.Errorf("file %q is a directory", name)
	}

	c, err := readCharacter("Would you like to overwrite %q [y/n]: ", name)
	if err != nil {
		return err
	}

	for {
		switch c {
		case 'y', 'Y':
			return os.WriteFile(name, data, perm)
		case 'n', 'N':
			return os.ErrExist
		case '\x03': // CTRL-C
			return fmt.Errorf("user canceled prompt")
		default:
			c, err = readCharacter("Invalid selection %q. Would you like to overwrite %q [y/n]: ", c, name)
			if err != nil {
				return err
			}
		}
	}
}

// readCharacter reads a single character from the terminal with no echo. The
// prompt is ephemeral.
func readCharacter(prompt string, args ...any) (c byte, err error) {
	err = withTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, prompt, args...)
		defer clearLine(out)

		oldState, err := term.MakeRaw(int(in.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(in.Fd()), oldState)

		b := make([]byte, 1)
		if _, err := in.Read(b); err != nil {
			return err
		}

		c = b[0]
		return nil
	})
	return
}
