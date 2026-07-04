package action

// namePattern is the ASCII-slug charset shared by command/alternative names.
// It is the single source of the grammar: the ParamSpec tables below reference
// it declaratively (pkglint), and the handlers' runtime regexps (altNameRe,
// pathNameRe, completionNameRe) compile it directly.
const namePattern = `^[a-zA-Z0-9_-]+$`

// ParamKind classifies an action parameter's expected literal value. Params whose
// value is a computed !starlark expression are not type-checked (see Phase B).
type ParamKind int

// The parameter kinds a ParamSpec can declare.
const (
	KindString ParamKind = iota // arbitrary string
	KindPath                    // a path (scope-confined by the handler)
	KindMode                    // an octal mode string, e.g. "0o755"
	KindInt                     // an integer (may arrive int/int64/float64/string)
	KindEnum                    // one of Enum
)

// ParamSpec declares one parameter's contract for an action.
type ParamSpec struct {
	Name     string
	Required bool
	Kind     ParamKind
	Enum     []string // when Kind == KindEnum
	Pattern  string   // optional regex for name-like fields
}

// ConstraintKind classifies a cross-parameter rule.
type ConstraintKind int

const (
	// RequiredWith means every Others param must also be present when Param is present.
	RequiredWith ConstraintKind = iota
	// ForbiddenWith means no Others param may be present when Param is present.
	ForbiddenWith
	// RequiredWithout means every Others param must be present when Param is absent.
	RequiredWithout
	// Unsupported means none of Others may be present at all (Param is unused).
	Unsupported
)

// Constraint expresses a cross-parameter rule the flat ParamSpec table cannot.
type Constraint struct {
	Kind   ConstraintKind
	Param  string   // trigger param ("" for Unsupported)
	Others []string // affected params
}

// Spec is an action's complete declaration: how to run it and what it accepts.
type Spec struct {
	Name        string
	FilePlacing bool
	Params      []ParamSpec
	Constraints []Constraint
	Handler     func(Invocation, Scope) (Result, error)
}

// Registry is the single source of truth for polypkg's actions, consumed by the
// runner (dispatch) and the linter (validation). Param/Constraint tables are
// catalogued from the handler implementations in this package.
var Registry = map[string]Spec{
	"install": {
		Name: "install", FilePlacing: true, Handler: Install,
		Params: []ParamSpec{
			{Name: "src", Required: true, Kind: KindPath},
			{Name: "dest", Required: true, Kind: KindPath},
			{Name: "policy", Kind: KindEnum, Enum: []string{"symlink", "copy", "hardlink"}},
		},
	},
	"symlink": {
		Name: "symlink", FilePlacing: true, Handler: Symlink,
		Params: []ParamSpec{
			{Name: "src", Required: true, Kind: KindString},
			{Name: "dest", Required: true, Kind: KindPath},
		},
	},
	"dir": {
		Name: "dir", FilePlacing: true, Handler: Dir,
		Params: []ParamSpec{
			{Name: "path", Required: true, Kind: KindPath},
			{Name: "mode", Kind: KindMode},
		},
	},
	"perms": {
		Name: "perms", FilePlacing: true, Handler: Perms,
		Params: []ParamSpec{
			{Name: "path", Required: true, Kind: KindPath},
			{Name: "mode", Kind: KindMode},
		},
		Constraints: []Constraint{
			{Kind: Unsupported, Others: []string{"owner", "group"}},
		},
	},
	"config": {
		Name: "config", FilePlacing: true, Handler: Config,
		Params: []ParamSpec{
			{Name: "src", Required: true, Kind: KindPath},
			{Name: "dest", Required: true, Kind: KindPath},
			{Name: "policy", Kind: KindEnum, Enum: []string{"replace", "preserve", "preserve_warn", "three_way_merge"}},
		},
	},
	"unmanaged": {
		Name: "unmanaged", FilePlacing: true, Handler: Unmanaged,
		Params: []ParamSpec{
			{Name: "path", Required: true, Kind: KindPath},
		},
	},
	"state": {
		Name: "state", FilePlacing: true, Handler: State,
		Params: []ParamSpec{
			{Name: "path", Required: true, Kind: KindPath},
		},
	},
	"path": {
		Name: "path", FilePlacing: true, Handler: Path,
		Params: []ParamSpec{
			{Name: "name", Required: true, Kind: KindString, Pattern: namePattern},
			{Name: "source", Required: true, Kind: KindPath},
		},
	},
	"alternatives": {
		Name: "alternatives", FilePlacing: true, Handler: Alternatives,
		Params: []ParamSpec{
			{Name: "source", Required: true, Kind: KindPath},
			{Name: "name", Kind: KindString, Pattern: namePattern},
			{Name: "priority", Kind: KindInt},
			{Name: "master", Kind: KindString, Pattern: namePattern},
			{Name: "link", Kind: KindString},
		},
		Constraints: []Constraint{
			{Kind: ForbiddenWith, Param: "master", Others: []string{"name", "priority"}},
			{Kind: RequiredWith, Param: "master", Others: []string{"link"}},
			{Kind: RequiredWithout, Param: "master", Others: []string{"name", "priority"}},
		},
	},
	"completion": {
		Name: "completion", FilePlacing: true, Handler: Completion,
		Params: []ParamSpec{
			{Name: "shell", Required: true, Kind: KindEnum, Enum: []string{"bash", "zsh", "fish"}},
			{Name: "name", Required: true, Kind: KindString, Pattern: namePattern},
			{Name: "source", Required: true, Kind: KindPath},
		},
	},
	"desktop": {
		Name: "desktop", FilePlacing: true, Handler: Desktop,
		Params: []ParamSpec{
			{Name: "source", Required: true, Kind: KindPath},
		},
	},
	"mime": {
		Name: "mime", FilePlacing: true, Handler: Mime,
		Params: []ParamSpec{
			{Name: "source", Required: true, Kind: KindPath},
		},
	},
}
