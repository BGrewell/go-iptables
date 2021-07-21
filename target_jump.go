package iptables

import "fmt"

const (
	TargetJumpStr string = "--jump"
)

type TargetJump struct {
	Value string `json:"value" yaml:"value" xml:"value"`
}

func (t TargetJump) String() string {
	return fmt.Sprintf("%s %s", TargetJumpStr, t.Value)
}

// Returns if the target is valid when applied with the specified rule
func (t TargetJump) Validate(rule Rule) error {
	return nil
}

func (t *TargetJump) Parse(option string, value string) {

}