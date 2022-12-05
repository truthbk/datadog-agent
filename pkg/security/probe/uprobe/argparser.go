package uprobe

import "github.com/alecthomas/participle/v2"

var (
	argParser = participle.MustBuild[UProbeArgumentExpression](
		participle.Union[UProbeTypedArgument](UProbeU8Argument{}, UProbeU16Argument{}, UProbeU32Argument{}, UProbeU64Argument{}, UProbeStringArgument{}),
	)
)

type Value interface{ value() }

type UProbeArgumentExpression struct {
	Arg UProbeTypedArgument `@@`
}

type UProbeTypedArgument interface{ value() }

type UProbeU8Argument struct {
	Value uint8 `"uint8"@Int`
}

type UProbeU16Argument struct {
	Value uint16 `"uint16"@Int`
}

type UProbeU32Argument struct {
	Value uint32 `"uint32"@Int`
}

type UProbeU64Argument struct {
	Value uint64 `"uint64"@Int`
}

type UProbeStringArgument struct {
	Value string `"string"@Ident`
}

func (UProbeU8Argument) value()     {}
func (UProbeU16Argument) value()    {}
func (UProbeU32Argument) value()    {}
func (UProbeU64Argument) value()    {}
func (UProbeStringArgument) value() {}
