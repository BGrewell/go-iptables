package iptables

// Action represents the default actions for a rule
type Action string

const (
	ActionJump Action = "jump"
	ActionGoTo Action = "goto"
)
