package iptables

import "fmt"

const (
	TargetGotoStr string = "--goto"
)

type TargetGoto struct {
	Value string `json:"value" yaml:"value" xml:"value"`
}

func (t TargetGoto) String() string {
	return fmt.Sprintf("%s %s", TargetGotoStr, t.Value)
}

// Returns if the target is valid when applied with the specified rule
func (t TargetGoto) Validate(rule Rule) error {
	return nil
}

func (t *TargetGoto) Parse(option string, value string) {

}
