package glob

type Glob interface {
	Match(string) bool
}

func Compile(pattern string, separators ...rune) (Glob, error) {
	return nil, nil
}
