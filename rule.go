package iptables

import (
	"fmt"
	"github.com/BGrewell/go-execute"
	"log"
	"strconv"
	"strings"
)

func NewRule(id string, name *string) *Rule {
	r := &Rule{}
	r.SetId(id)

	if name != nil {
		r.SetName(*name)
	}

	r.Markers = make([]Marker, 0)
	r.Matches = make([]Match, 0)
	r.setDefaults()
	r.Valid = false
	r.Applied = false

	return r
}

type Rule struct {
	Id                     string   `json:"id,omitempty" yaml:"id" xml:"id"`
	Name                   string   `json:"name,omitempty" yaml:"name" xml:"name"`
	Table                  Table    `json:"table,omitempty" yaml:"table" xml:"table"`
	Chain                  Chain    `json:"chain,omitempty" yaml:"chain" xml:"chain"`
	IpVersion              IPVer    `json:"ip_version,omitempty" yaml:"ip_version" xml:"ip_version"`
	Protocol               Protocol `json:"protocol,omitempty" yaml:"protocol" xml:"protocol"`
	ProtocolNegated        bool     `json:"protocol_negated,omitempty" yaml:"protocol_negated" xml:"protocol_negated"`
	Opt                    string   `json:"opt,omitempty" yaml:"opt" xml:"opt"`
	Input                  string   `json:"input,omitempty" yaml:"input" xml:"input"`
	InputNegated           bool     `json:"input_negated,omitempty" yaml:"input_negated" xml:"input_negated"`
	Output                 string   `json:"output,omitempty" yaml:"output" xml:"output"`
	OutputNegated          bool     `json:"output_negated,omitempty" yaml:"output_negated" xml:"output_negated"`
	Source                 string   `json:"source,omitempty" yaml:"source" xml:"source"`
	SourceNegated          bool     `json:"source_negated,omitempty" yaml:"source_negated" xml:"source_negated"`
	SourcePort             string   `json:"source_port,omitempty" yaml:"source_port" xml:"source_port"`
	SourcePortNegated      bool     `json:"source_port_negated,omitempty" yaml:"source_port_negated" xml:"source_port_negated"`
	Destination            string   `json:"destination,omitempty" yaml:"destination" xml:"destination"`
	DestinationNegated     bool     `json:"destination_negated,omitempty" yaml:"destination_negated" xml:"destination_negated"`
	DestinationPort        string   `json:"destination_port,omitempty" yaml:"destination_port" xml:"destination_port"`
	DestinationPortNegated bool     `json:"destination_port_negated,omitempty" yaml:"destination_port_negated" xml:"destination_port_negated"`
	Action                 Action   `json:"action,omitempty" yaml:"action" xml:"action"`
	Target                 Target   `json:"target,omitempty" yaml:"target" xml:"target"`
	Markers                []Marker `json:"markers,omitempty" yaml:"markers" xml:"markers"`
	Matches                []Match  `json:"matches,omitempty" yaml:"matches" xml:"matches"`
	Counters               Counter  `json:"counters,omitempty" yaml:"counters" xml:"counters"`
	Valid                  bool     `json:"valid,omitempty" yaml:"valid" xml:"valid"`
	Applied                bool     `json:"applied,omitempty" yaml:"applied" xml:"applied"`
	Number                 int      `json:"rule_number,omitempty" yaml:"rule_number" xml:"rule_number"`
	Debug                  bool     `json:"debug,omitempty" yaml:"debug" xml:"debug"`
	command                Cmd      `json:"command,omitempty" yaml:"command" xml:"command"`
}

func (r *Rule) setDefaults() {
	// Default to ipv4
	if r.IpVersion == "" {
		r.IpVersion = IPv4
	}

	// Default to a jump target with the accept target
	if r.Target == nil {
		r.Target = &TargetJump{
			Value: TargetAccept,
		}
	}

	// Default command to append
	if r.command == "" {
		r.command = CmdAppend
	}
}

func (r *Rule) setState(valid, applied bool) {
	r.Valid = valid
	r.Applied = applied
}

func (r *Rule) execute() (err error) {
	if validation := r.Validate(); validation != nil {
		return validation
	}

	result, err := execute.ExecuteCmd(r.String())
	if r.Debug {
		log.Println(result)
	}

	if err != nil {
		r.setState(false, false)
		return err
	}

	r.setState(true, true)
	return nil
}

func (r *Rule) updateRuleNumber() {
	if r.Id == "" {
		log.Println("unable to update rule number as rule has no id")
		return
	}
	ipt, _ := GetIptablesBinaryPath(string(r.IpVersion))
	listCmd := fmt.Sprintf("%s -t %s -vnL %s --line-numbers", ipt, r.Table, r.Chain)
	result, err := execute.ExecuteCmd(listCmd)
	if err != nil {
		log.Printf("error failed to get rule number: %s\n", err)
	}
	rules := strings.Split(result, "\n")[2:]
	for _, rule := range rules {
		if strings.Contains(rule, r.Id) {
			fields := strings.Fields(rule)
			r.Number, err = strconv.Atoi(fields[0])
			if err != nil {
				log.Printf("failed to extract rule number: %s\n", err)
			}
		}
	}
}

func (r *Rule) String() string {

	r.setDefaults()
	var output = make([]string, 0)
	binaryPath, err := GetIptablesBinaryPath(string(r.IpVersion))
	if err != nil {
		panic(err)
	}
	output = append(output, binaryPath)

	if r.Table != "" {
		output = append(output, fmt.Sprintf("-t %s", r.Table))
	}

	if r.command != "" {
		output = append(output, fmt.Sprintf("--%s", r.command))

		if r.Chain != "" {
			output = append(output, string(r.Chain))
		}

		if r.command == CmdInsert || r.command == CmdReplace {
			output = append(output, strconv.Itoa(r.Number))
		}
	}

	if r.Protocol != "" {
		n := GetNegatedPattern(r.ProtocolNegated)
		output = append(output, fmt.Sprintf("%s--protocol %s", n, r.Protocol))
	}

	if r.Source != "" {
		n := GetNegatedPattern(r.SourceNegated)
		output = append(output, fmt.Sprintf("%s--source %s", n, r.Source))
	}

	if r.Destination != "" {
		n := GetNegatedPattern(r.DestinationNegated)
		output = append(output, fmt.Sprintf("%s--destination %s", n, r.Destination))
	}

	if r.SourcePort != "" {
		n := GetNegatedPattern(r.SourcePortNegated)
		output = append(output, fmt.Sprintf("--match multiport %s--sports %s", n, r.SourcePort))
	}

	if r.DestinationPort != "" {
		n := GetNegatedPattern(r.DestinationPortNegated)
		output = append(output, fmt.Sprintf("--match multiport %s--dports %s", n, r.DestinationPort))
	}

	if r.Input != "" {
		n := GetNegatedPattern(r.InputNegated)
		output = append(output, fmt.Sprintf("%s--in-interface %s", n, r.Input))
	}

	if r.Output != "" {
		n := GetNegatedPattern(r.OutputNegated)
		output = append(output, fmt.Sprintf("%s--out-interface %s", n, r.Output))
	}

	for _, match := range r.Matches {
		matchValue := match.Value()
		if match.Name() == "comment" {
			matchValue = strconv.Quote(match.Value())
		}
		n := GetNegatedPattern(match.Negated())
		output = append(output, fmt.Sprintf("--match %s %s--%s %s", match.Name(), n, match.Option(), matchValue))
	}

	if r.Id != "" {
		output = append(output, fmt.Sprintf("-m comment --comment id:%s", r.Id))
	}

	if r.Name != "" {
		output = append(output, fmt.Sprintf("-m comment --comment name:%s", r.Name))
	}

	if r.Target != nil {
		output = append(output, r.Target.String())
	}

	return strings.Join(output, " ")
}

func (r *Rule) Validate() (err error) {
	// Check if target is valid
	if err := r.Target.Validate(*r); err != nil {
		return err
	}

	// Check to make sure id doesn't exist
	if IdExists(r.Id) && (r.command == CmdInsert || r.command == CmdAppend) {
		return fmt.Errorf("a rule with the id %s already exists", r.Id)
	}

	// Check to make sure name doesn't exist
	if NameExists(r.Name) {
		return fmt.Errorf("a rule with the name %s already exists", r.Name)
	}

	// Make sure we are running as root so we can manipulate iptables
	if !RunningAsRoot() {
		return fmt.Errorf("this application must be run as root to manipulate ip(6)tables")
	}

	// Rule is valid return nil
	return nil
}

func (r *Rule) Parse(table string, ruleLine string) (err error) {
	r.Table, err = ConvertToTable(table)
	if err != nil {
		r.Valid = false
		return err
	}

	fields := strings.Fields(ruleLine)

	for idx := 0; idx < len(fields); {
		negated := false
		if fields[idx] == "!" {
			negated = true
			idx += 1
		}

		switch fields[idx] {

		case "-A", "-I":
			r.Chain = Chain(fields[idx+1])
			idx += 2
		case "-s":
			r.Source = fields[idx+1]
			r.SourceNegated = negated
			idx += 2
		case "-d":
			r.Destination = fields[idx+1]
			r.DestinationNegated = negated
			idx += 2
		case "-i":
			r.Input = fields[idx+1]
			r.InputNegated = negated
			idx += 2
		case "-o":
			r.Output = fields[idx+1]
			r.OutputNegated = negated
			idx += 2
		case "-p":
			r.Protocol = Protocol(fields[idx+1])
			r.ProtocolNegated = negated
			idx += 2
		case "-m":
			var m Match
			name := fields[idx+1]
			if fields[idx+2] == "!" {
				negated = true
				idx++
			}
			option := strings.Replace(fields[idx+2], "--", "", 1)
			value := fields[idx+3]

			if (name == "tcp" || name == "udp") && (strings.HasPrefix(option, "dport") || strings.HasPrefix(option, "sport")) {
				if strings.HasPrefix(option, "dport") {
					r.DestinationPort = value
					r.DestinationPortNegated = negated
				} else {
					r.SourcePort = value
					r.SourcePortNegated = negated
				}
			} else {
				if fields[idx+1] == "comment" {
					m = &MatchComment{}
					comment := make([]string, 0)
					for !strings.HasPrefix(fields[idx+3], "-") {
						comment = append(comment, fields[idx+3])
						idx++
					}
					idx-- // rewind the index

					value = strings.Join(comment, " ")
					value = strings.ReplaceAll(value, "\\\"", "")
					value = strings.ReplaceAll(value, "\"", "")
					value = strings.ReplaceAll(value, "'", "")
					if strings.Contains(value, ":") {
						parts := strings.Split(value, ":")
						if len(parts) == 2 {
							mark := &MarkerGeneric{
								name:  parts[0],
								value: parts[1],
							}
							r.AddMarker(mark)
						}
					}
				} else {
					m = &MatchGeneric{}
					err = m.SetName(name)
					if err != nil {
						return err
					}
					err = m.SetOption(option)
					if err != nil {
						return err
					}
				}
				err = m.SetValue(value)
				if err != nil {
					return err
				}
				m.SetNegated(negated)

				if m.Name() == "comment" && strings.HasPrefix(m.Value(), "id:") {
					r.Id = strings.Replace(m.Value(), "id:", "", 1)
				} else if m.Name() == "comment" && strings.HasPrefix(m.Value(), "name:") {
					r.Name = strings.Replace(m.Value(), "name:", "", 1)
				} else {
					r.AddMatch(m)
				}
			}

			idx += 4
		case "-j", "-g":
			target := fields[idx+1]
			switch target {
			case "ACCEPT", "DROP", "QUEUE", "RETURN":
				var t Target
				if fields[idx] == "-j" {
					t = &TargetJump{Value: target}
				} else {
					t = &TargetGoto{Value: target}
				}
				r.Target = t
				idx += 2
			case "DNAT":
				t := &TargetDNat{}
				t.Parse(fields[idx+2], fields[idx+3])
				r.Target = t
				idx += 4
			case "SNAT":
				t := &TargetSNat{}
				t.Parse(fields[idx+2], fields[idx+3])
				r.Target = t
				idx += 4
			case "DSCP":
				t := &TargetDSCP{}
				t.Parse(fields[idx+2], fields[idx+3])
				r.Target = t
				idx += 4
			case "MASQUERADE":
				t := &TargetMasquerade{}
				if len(fields) > idx+2 && fields[idx+2] == "--to-ports" {
					t.Parse(fields[idx+2], fields[idx+3])
					idx += 4
				} else {
					idx += 2
				}
				r.Target = t
			default:
				if !ValidChain(table, target) {
					log.Printf("unkown target %s\n", target)
					log.Printf("line: %s\n", ruleLine)
				}

				var t Target
				if fields[idx] == "-j" {
					t = &TargetJump{Value: target}
				} else {
					t = &TargetGoto{Value: target}
				}
				r.Target = t
				idx += 2
			}

		default:
			log.Printf("unknown field %s this rule was not completely parsed\n", fields[idx])
			log.Printf("line: %s\n", ruleLine)
			idx += 1
		}
	}

	return nil
}

func (r *Rule) Append() (err error) {
	r.command = CmdAppend
	return r.execute()
}

func (r *Rule) Insert(index int) (err error) {
	r.command = CmdInsert
	r.Number = index
	return r.execute()
}

func (r *Rule) Replace() (err error) {
	r.command = CmdReplace
	return r.execute()
}

func (r *Rule) Delete() (err error) {
	r.command = CmdDelete
	return r.execute()
}

func (r *Rule) SetApp(app string) {
	mark := MarkerGeneric{}
	mark.SetName("app")
	mark.SetValue(app)
	r.Markers = append(r.Markers, &mark)

	match := MatchComment{}
	match.SetValue(mark.String())

	r.Matches = append(r.Matches, &match)
}

func (r *Rule) SetName(name string) {
	r.Name = name
}

func (r *Rule) SetId(id string) {
	r.Id = id
}

func (r *Rule) AddMarker(marker Marker) {
	r.Markers = append(r.Markers, marker)
}

func (r *Rule) AddMatch(match Match) {
	r.Matches = append(r.Matches, match)
}

func (r *Rule) Update(rule *Rule) {
	if rule.Name != "" { r.Name = rule.Name }
	//TODO: Protocol has an issue here because it's an *enum* value so it always has a default value which may or may not be what the user wants
	if rule.Input != "" {r.Input = rule.Input }
	if rule.InputNegated {r.InputNegated = rule.InputNegated }
	if rule.Output != "" {r.Output = rule.Output }
	if rule.OutputNegated {r.OutputNegated = rule.OutputNegated }
	if rule.Source != "" {r.Source = rule.Source}
	if rule.SourceNegated {r.OutputNegated = rule.SourceNegated }
	if rule.SourcePort != "" {r.SourcePort = rule.SourcePort }
	if rule.SourcePortNegated {r.SourcePortNegated = rule.SourcePortNegated }
	if rule.Destination != "" {r.Destination = rule.Destination }
	if rule.DestinationNegated {r.DestinationNegated = rule.DestinationPortNegated }
	if rule.DestinationPort != "" {r.DestinationPort = rule.DestinationPort }
	if rule.DestinationPortNegated {r.DestinationPortNegated = rule.DestinationPortNegated }
}

// TODO: Don't put the id or name into the markers or matches array's and instead parse those values out
//       of those arrays when reading rules in, only have other markers and matches in there.
