// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package traps

import (
	"encoding/json"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"strings"
	"time" //JMW
	"unicode"

	"github.com/gosnmp/gosnmp"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const ddsource string = "snmp-traps"

// Formatter is an interface to extract and format raw SNMP Traps
type Formatter interface {
	FormatPacket(packet *SnmpPacket) ([]byte, error)
}

// JSONFormatter is a Formatter implementation that transforms Traps into JSON
type JSONFormatter struct {
	oidResolver OIDResolver
	aggregator  sender.Sender
}

type trapVariable struct {
	OID     string      `json:"oid"`
	VarType string      `json:"type"`
	Value   interface{} `json:"value"`
}

const (
	sysUpTimeInstanceOID = "1.3.6.1.2.1.1.3.0"
	snmpTrapOID          = "1.3.6.1.6.3.1.1.4.1.0"

	telemetryTrapsNotEnriched = "datadog.snmp_traps.traps_not_enriched"
	telemetryVarsNotEnriched  = "datadog.snmp_traps.vars_not_enriched"
	telemetryIncorrectFormat  = "datadog.snmp_traps.incorrect_format"
)

// NewJSONFormatter creates a new JSONFormatter instance with an optional OIDResolver variable.
func NewJSONFormatter(oidResolver OIDResolver, aggregator sender.Sender) (JSONFormatter, error) {
	if oidResolver == nil {
		return JSONFormatter{}, fmt.Errorf("NewJSONFormatter called with a nil OIDResolver")
	}
	return JSONFormatter{oidResolver, aggregator}, nil
}

// FormatPacket converts a raw SNMP trap packet to a FormattedSnmpPacket containing the JSON data and the tags to attach
//
//	{
//		"trap": {
//	   "ddsource": "snmp-traps",
//	   "ddtags": "namespace:default,snmp_device:10.0.0.2,...",
//	   "timestamp": 123456789,
//	   "snmpTrapName": "...",
//	   "snmpTrapOID": "1.3.6.1.5.3.....",
//	   "snmpTrapMIB": "...",
//	   "uptime": "12345",
//	   "genericTrap": "5", # v1 only
//	   "specificTrap": "0",  # v1 only
//	   "variables": [
//	     {
//	       "oid": "1.3.4.1....",
//	       "type": "integer",
//	       "value": 12
//	     },
//	     ...
//	   ],
//	  }
//	}
func (f JSONFormatter) FormatPacket(packet *SnmpPacket) ([]byte, error) { //JMW0
	payload := make(map[string]interface{})
	var formattedTrap map[string]interface{}
	var err error
	if packet.Content.Version == gosnmp.Version1 {
		formattedTrap = f.formatV1Trap(packet)
	} else {
		formattedTrap, err = f.formatTrap(packet) //JMW1
		if err != nil {
			return nil, err
		}
	}
	formattedTrap["ddsource"] = ddsource
	formattedTrap["ddtags"] = strings.Join(packet.getTags(), ",")
	formattedTrap["timestamp"] = packet.Timestamp
	payload["trap"] = formattedTrap
	fmt.Printf("JMW------- FormatPacket() payload=%v\n------------\n\n", payload)
	//JMWreturn json.Marshal(payload)
	return json.MarshalIndent(payload, "", "    ") //JMW
}

func (f JSONFormatter) formatV1Trap(packet *SnmpPacket) map[string]interface{} {
	content := packet.Content
	tags := packet.getTags()

	data := make(map[string]interface{})
	data["uptime"] = uint32(content.Timestamp)
	enterpriseOid := NormalizeOID(content.Enterprise)
	genericTrap := content.GenericTrap
	specificTrap := content.SpecificTrap
	var trapOID string
	if genericTrap == 6 {
		// Vendor-specific trap
		trapOID = fmt.Sprintf("%s.0.%d", enterpriseOid, specificTrap)
	} else {
		// Generic trap
		trapOID = fmt.Sprintf("%s.%d", genericTrapOid, genericTrap+1)
	}
	data["snmpTrapOID"] = trapOID
	trapMetadata, err := f.oidResolver.GetTrapMetadata(trapOID)
	if err != nil {
		f.aggregator.Count(telemetryTrapsNotEnriched, 1, "", tags)
		log.Debugf("unable to resolve OID: %s", err)
	} else {
		data["snmpTrapName"] = trapMetadata.Name
		data["snmpTrapMIB"] = trapMetadata.MIBName
	}
	data["enterpriseOID"] = enterpriseOid
	data["genericTrap"] = genericTrap
	data["specificTrap"] = specificTrap
	parsedVariables, enrichedValues := f.parseVariables(trapOID, content.Variables)
	enrichmentFailed := len(content.Variables) - len(enrichedValues)
	if enrichmentFailed > 0 {
		f.aggregator.Count(telemetryVarsNotEnriched, float64(enrichmentFailed), "", tags)
	}
	data["variables"] = parsedVariables
	for key, value := range enrichedValues {
		data[key] = value
	}
	return data
}

func (f JSONFormatter) formatTrap(packet *SnmpPacket) (map[string]interface{}, error) { //JMW2
	/*
		An SNMP v2 or v3 trap packet consists in the following variables (PDUs):
		{sysUpTime.0, snmpTrapOID.0, additionalDataVariables...}
		See: https://tools.ietf.org/html/rfc3416#section-4.2.6
	*/
	tags := packet.getTags()

	variables := packet.Content.Variables
	if len(variables) < 2 {
		f.aggregator.Count(telemetryIncorrectFormat, 1, "", append(tags, "error:invalid_variables"))
		return nil, fmt.Errorf("expected at least 2 variables, got %d", len(variables))
	}

	data := make(map[string]interface{})

	uptime, err := parseSysUpTime(variables[0])
	if err != nil {
		f.aggregator.Count(telemetryIncorrectFormat, 1, "", append(tags, "error:invalid_sys_uptime"))
		return nil, err
	}
	data["uptime"] = uptime

	trapOID, err := parseSnmpTrapOID(variables[1])
	if err != nil {
		f.aggregator.Count(telemetryIncorrectFormat, 1, "", append(tags, "error:invalid_trap_oid"))
		return nil, err
	}
	data["snmpTrapOID"] = trapOID

	trapMetadata, err := f.oidResolver.GetTrapMetadata(trapOID)
	if err != nil {
		f.aggregator.Count(telemetryTrapsNotEnriched, 1, "", tags)
		log.Debugf("unable to resolve OID: %s", err)
	} else {
		data["snmpTrapName"] = trapMetadata.Name
		data["snmpTrapMIB"] = trapMetadata.MIBName
	}

	parsedVariables, enrichedValues := f.parseVariables(trapOID, variables[2:]) //JMW3
	enrichmentFailed := len(variables) - 2 - len(enrichedValues)                // Subtract 2 for sysUpTime and trapOID
	if enrichmentFailed > 0 {
		f.aggregator.Count(telemetryVarsNotEnriched, float64(enrichmentFailed), "", tags)
	}
	data["variables"] = parsedVariables
	for key, value := range enrichedValues {
		data[key] = value
	}
	return data, nil
}

// NormalizeOID convert an OID from the absolute form ".1.2.3..." to a relative form "1.2.3..."
func NormalizeOID(value string) string {
	// OIDs can be formatted as ".1.2.3..." ("absolute form") or "1.2.3..." ("relative form").
	// Convert everything to relative form, like we do in the Python check.
	return strings.TrimLeft(value, ".")
}

// IsValidOID returns true if a looks like a valid OID.
// An OID is made of digits and dots, but OIDs do not end with a dot and there are always
// digits between dots.
func IsValidOID(value string) bool {
	var previousChar rune
	for _, char := range value {
		if char != '.' && !unicode.IsDigit(char) {
			return false
		}
		if char == '.' && previousChar == '.' {
			return false
		}
		previousChar = char
	}
	return previousChar != '.'
}

// enrichEnum checks to see if the variable has a mapping in an enum and
// returns the mapping if it exists, otherwise returns the value unchanged
func enrichEnum(variable trapVariable, varMetadata VariableMetadata) interface{} {
	// if we find a mapping set it and return
	i, ok := variable.Value.(int)
	if !ok {
		log.Warnf("unable to enrich variable %q %s with integer enum, received value was not int, was %T", varMetadata.Name, variable.OID, variable.Value)
		return variable.Value
	}
	if value, ok := varMetadata.Enumeration[i]; ok {
		return value
	}

	// if no mapping is found or type is not integer
	log.Debugf("unable to find enum mapping for value %d variable %q", i, varMetadata.Name)
	return variable.Value
}

// enrichBits checks to see if the variable has a mapping in bits and //JMW
// returns the mapping if it exists, otherwise returns the value unchanged
// JMW separate func for getting string from bits
func enrichBits(variable trapVariable, varMetadata VariableMetadata) (interface{}, string) {
	fmt.Printf("      JMW enrichBits() tv=%v varMetadata = %v\n", variable, varMetadata)
	// do bitwise search
	bytes, ok := variable.Value.([]byte)
	if !ok {
		log.Warnf("unable to enrich variable %q %s with BITS mapping, received value was not []byte, was %T", varMetadata.Name, variable.OID, variable.Value)
		return variable.Value, ""
	}
	enabledValues := make([]interface{}, 0)
	start := time.Now()
	//JMW should number of bits (len(varMetadata.Bits) determine length of string, for example, w/ 4 bits, should it display "1101" or "11010000"?
	//  JMW per discussion with Ken, NO, because we have seen out-of-date MIB info before so it is possible that we could be missing some fields in our traps_db, so always display
	//  the full info from all bytes in the snmp packet PDU's BITS (byte slice)
	var bitString strings.Builder
	bitString.Grow(len(bytes)*8 + len(bytes) - 1) //JMW 617ns vs 683ns (avg/5) w/out
	space := ""
	for i, b := range bytes {
		bitString.WriteString(space)
		for j := 0; j < 8; j++ {
			position := j + i*8                       // position is the index in the current byte plus 8 * the position in the byte array
			enabled, err := isBitEnabled(uint8(b), j) //JMW use bits package instead?
			if err != nil {
				log.Debugf("unable to determine status at position %d: %s", position, err.Error())
				continue
			}
			if enabled {
				bitString.WriteString("1")
				if value, ok := varMetadata.Bits[position]; !ok {
					log.Debugf("unable to find enum mapping for value %d variable %q", i, varMetadata.Name)
					enabledValues = append(enabledValues, position)
				} else {
					enabledValues = append(enabledValues, value)
				}
			} else {
				bitString.WriteString("0")
			}
		}
		space = " "
	}
	elapsed := time.Since(start)
	fmt.Printf("      JMW enrichBits() ----- bitString=%q (0x%x) ----- returning enabledValues=%v elapsed=%v\n", bitString.String(), bytes, enabledValues, elapsed) //JMWJMWJMW
	return enabledValues, bitString.String()
}

func parseSysUpTime(variable gosnmp.SnmpPDU) (uint32, error) {
	name := NormalizeOID(variable.Name)
	if name != sysUpTimeInstanceOID {
		return 0, fmt.Errorf("expected OID %s, got %s", sysUpTimeInstanceOID, name)
	}

	value, ok := variable.Value.(uint32)
	if !ok {
		return 0, fmt.Errorf("expected uptime to be uint32 (got %v of type %T)", variable.Value, variable.Value)
	}

	return value, nil
}

func parseSnmpTrapOID(variable gosnmp.SnmpPDU) (string, error) {
	name := NormalizeOID(variable.Name)
	if name != snmpTrapOID {
		return "", fmt.Errorf("expected OID %s, got %s", snmpTrapOID, name)
	}

	value := ""
	switch variable.Value.(type) {
	case string:
		value = variable.Value.(string)
	case []byte:
		value = string(variable.Value.([]byte))
	default:
		return "", fmt.Errorf("expected snmpTrapOID to be a string (got %v of type %T)", variable.Value, variable.Value)
	}

	return NormalizeOID(value), nil
}

func (f JSONFormatter) parseVariables(trapOID string, variables []gosnmp.SnmpPDU) ([]trapVariable, map[string]interface{}) { //JMW4
	fmt.Printf("JMW parseVariables(trapOID=%v, variables=%v)\n", trapOID, variables)
	var parsedVariables []trapVariable
	enrichedValues := make(map[string]interface{})

	for _, variable := range variables {
		varOID := NormalizeOID(variable.Name)
		varType := formatType(variable)

		tv := trapVariable{
			OID:     varOID,
			VarType: varType,
			Value:   variable.Value,
		}

		fmt.Printf("  JMW in parseVariables() for loop: variable=%v tv=%v\n", variable, tv)

		varMetadata, err := f.oidResolver.GetVariableMetadata(trapOID, varOID)
		if err != nil {
			log.Debugf("unable to enrich variable: %s", err)
			tv.Value = formatValue(variable)
			parsedVariables = append(parsedVariables, tv)
			continue
		}

		fmt.Printf("    JMW in parseVariables() for loop varMetadata=%v\n", varMetadata)

		if len(varMetadata.Enumeration) > 0 && len(varMetadata.Bits) > 0 {
			log.Errorf("Unable to enrich variable, trap variable %q has mappings for both integer enum and bits.", varMetadata.Name)
		} else if len(varMetadata.Enumeration) > 0 {
			fmt.Printf("      JMW Enumeration: varMetadata=%v\n", varMetadata)
			enrichedValues[varMetadata.Name] = enrichEnum(tv, varMetadata)
		} else if len(varMetadata.Bits) > 0 {
			//JMW is there ever a case where len(varMetadata.Bits) == 0 but it is a bit string?
			//  JMW per discussion with Ken, NO, if this is the case let it fall  thru to the default (the final else)
			fmt.Printf("      JMW Bits: varMetadata=%v\n", varMetadata)
			enrichedValues[varMetadata.Name], tv.Value = enrichBits(tv, varMetadata) //JMW5 //JMWenrichBits
			//fmt.Printf("**************JMW type of tv.Value=%T\n", tv.Value) //JMW []uint8
			//fmt.Printf("**************JMW overwriting tv.Value=%v with \"JMWOVERWRITESTRING\"\n", tv.Value)
			//tv.Value = "JMWOVERWRITESTRING"
			//fmt.Printf("**************JMW type of tv.Value=%T\n", tv.Value) //JMW string
		} else {
			// only format the value if it's not an enum type //JMW or Bits type, right?
			tv.Value = formatValue(variable) //JMWJMWJMW do it here?
			enrichedValues[varMetadata.Name] = tv.Value
		}

		parsedVariables = append(parsedVariables, tv)
	}

	fmt.Printf("JMW parseVariables() returning parsedVariables=%v, enrichedValues=%v\n", parsedVariables, enrichedValues)
	return parsedVariables, enrichedValues
}

func formatType(variable gosnmp.SnmpPDU) string {
	switch variable.Type {
	case gosnmp.UnknownType:
		return "unknown-type"
	case gosnmp.Boolean:
		return "boolean"
	case gosnmp.Integer, gosnmp.Uinteger32:
		return "integer"
	//JMWMON add test that exercises BitString
	//JMWMON look at "garbage" (actually base64 encoded) OctetStrings in tests
	case gosnmp.OctetString: //JMW - split into 2 separate case stmts?
		fmt.Printf("  JMW in formatType() got gosnmp.OctetString %v\n", variable)
		return "string"
	case gosnmp.BitString: //JMW - split into 2 separate case stmts?
		fmt.Printf("    JMW in formatType() got gosnmp.BitString %v\n", variable)
		return "string"
	case gosnmp.Null:
		return "null"
	case gosnmp.ObjectIdentifier:
		return "oid"
	case gosnmp.ObjectDescription:
		return "object-description"
	case gosnmp.IPAddress:
		return "ip-address"
	case gosnmp.Counter32:
		return "counter32"
	case gosnmp.Gauge32:
		return "gauge32"
	case gosnmp.TimeTicks:
		return "time-ticks"
	case gosnmp.Opaque, gosnmp.OpaqueFloat, gosnmp.OpaqueDouble:
		return "opaque"
	case gosnmp.NsapAddress:
		return "nsap-address"
	case gosnmp.Counter64:
		return "counter64"
	case gosnmp.NoSuchObject:
		return "no-such-object"
	case gosnmp.NoSuchInstance:
		return "no-such-instance"
	case gosnmp.EndOfMibView:
		return "end-of-mib-view"
	default:
		return "other"
	}
}

func formatValue(variable gosnmp.SnmpPDU) interface{} {
	switch variable.Value.(type) {
	case []byte:
		return string(variable.Value.([]byte))
	case string:
		if variable.Type == gosnmp.ObjectIdentifier {
			return NormalizeOID(variable.Value.(string))
		}
		//JMWJMWJWM if variable.Type == BitString generate string of bits???
		return variable.Value
	default:
		return variable.Value
	}
}

func formatVersion(packet *gosnmp.SnmpPacket) string {
	switch packet.Version {
	case gosnmp.Version3:
		return "3"
	case gosnmp.Version2c:
		return "2"
	case gosnmp.Version1:
		return "1"
	default:
		return "unknown"
	}
}

// isBitEnabled takes in a uint8 and returns true if
// the bit at the passed position is 1.
// Each byte is little endian meaning if
// you have the binary 10000000, passing position 0
// would return true and 7 would return false
func isBitEnabled(n uint8, pos int) (bool, error) { //JMW
	if pos < 0 || pos > 7 {
		return false, fmt.Errorf("invalid position %d, must be 0-7", pos)
	}
	val := n & uint8(1<<(7-pos))
	return val > 0, nil
}
