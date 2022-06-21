package flagutil

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

// MustString returns the string value of a flag with the given name, it will
// panic if the flag does not exists or is not the desired type.
func MustString(flagSet *pflag.FlagSet, name string) string {
	v, err := flagSet.GetString(name)
	if err != nil {
		panic(err)
	}
	return v
}

// MustInt returns the int value of a flag with the given name, it will panic if
// the flag does not exists or is not the desired type.
func MustInt(flagSet *pflag.FlagSet, name string) int {
	v, err := flagSet.GetInt(name)
	if err != nil {
		panic(err)
	}
	return v
}

// MustBool returns the bool value of a flag with the given name, it will panic
// if the flag does not exists or is not the desired type.
func MustBool(flagSet *pflag.FlagSet, name string) bool {
	v, err := flagSet.GetBool(name)
	if err != nil {
		panic(err)
	}
	return v
}

type value struct {
	Name      string
	Allowed   []string
	Value     string
	Normalize func(string) string
}

// Value returns a pflag.Value interface with that will only accept values from
// a given list.
func Value(name string, allowed []string, defaultValue string) pflag.Value {
	return &value{
		Name:    name,
		Allowed: allowed,
		Value:   defaultValue,
	}
}

// UpperValue returns a pflag.Value interface with that will only accept
// values from a given list, but before checking the allowed list it will
// normalized values to upper-case.
func UpperValue(name string, allowed []string, defaultValue string) pflag.Value {
	return &value{
		Name:    name,
		Allowed: allowed,
		Value:   defaultValue,
		Normalize: func(s string) string {
			return strings.ToUpper(s)
		},
	}
}

// LowerValue returns a pflag.Value interface with that will only accept
// values from a given list, but before checking the allowed list it will
// normalized values to lower-case.
func LowerValue(name string, allowed []string, defaultValue string) pflag.Value {
	return &value{
		Name:    name,
		Allowed: allowed,
		Value:   defaultValue,
		Normalize: func(s string) string {
			return strings.ToLower(s)
		},
	}
}

// NormalizedValue returns a pflag.Value interface with that will only accept
// values from a given list, but before checking the allowed list it will
// normalized values to upper-case and remove any dash or hyphens.
func NormalizedValue(name string, allowed []string, defaultValue string) pflag.Value {
	return &value{
		Name:    name,
		Allowed: allowed,
		Value:   defaultValue,
		Normalize: func(s string) string {
			s = strings.ReplaceAll(strings.ToUpper(s), "-", "") // Dash, hyphen-minus (-)
			s = strings.ReplaceAll(s, "\u2010", "")             // Hyphen (‐)
			s = strings.ReplaceAll(s, "\u2011", "")             // Non breaking hyphen (‑)
			s = strings.ReplaceAll(s, "\u2012", "")             // Figure Dash (‒)
			s = strings.ReplaceAll(s, "\u2013", "")             // En dash (–)
			return strings.ReplaceAll(s, "\u2014", "")          // Em dash (—)
		},
	}
}

func (v *value) String() string {
	return v.Value
}

func (v *value) Set(s string) error {
	if v.Normalize != nil {
		s = v.Normalize(s)
	}
	for _, a := range v.Allowed {
		if a == s {
			v.Value = a
			return nil
		}
	}
	return fmt.Errorf("value for flag --%s is not valid, options are %s", v.Name, strings.Join(v.Allowed, ","))
}

func (v *value) Type() string {
	return "string"
}
