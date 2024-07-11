package dataprocessor

import "strings"

type Redacted struct {
}

func NewRedacted() *Redacted {
	return &Redacted{}
}

func (r Redacted) Process(data string) string {
	return strings.Repeat("*", len(data))
}
