package verifytable

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"strconv"
	"strings"
)

// tableRule is one entry of gcpperms' rules table, read from source so the
// verifier shares no code with the analyzer it checks.
type tableRule struct {
	Pattern string
	Perms   []string
	Maybe   []string
	Note    string
	Line    int
}

// parsedTable is a parsed table.go, with its package-level variables.
type parsedTable struct {
	fset *token.FileSet
	vars map[string]ast.Expr
}

func (r *tableRule) noop() bool { return len(r.Perms) == 0 && len(r.Maybe) == 0 && r.Note == "" }

// parseTable extracts the rules slice from table.go, read from src, or
// from file when src is nil. Field values may be string literals, []string
// literals, or identifiers naming package-level variables of those kinds.
func parseTable(file string, src []byte) ([]tableRule, error) {
	fset := token.NewFileSet()
	var source any
	if src != nil {
		source = src
	}
	f, err := parser.ParseFile(fset, file, source, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing the table: %w", err)
	}
	t := &parsedTable{fset: fset, vars: packageVars(f)}
	rulesLit, ok := t.vars["rules"].(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("%s: no rules composite literal", file)
	}
	var rules []tableRule
	for _, el := range rulesLit.Elts {
		r, err := t.rule(el)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// packageVars maps the name of each package-level variable in f to its
// value.
func packageVars(f *ast.File) map[string]ast.Expr {
	vars := make(map[string]ast.Expr)
	for _, decl := range f.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
			addVars(vars, gd)
		}
	}
	return vars
}

// addVars adds the variables gd declares with values to vars.
func addVars(vars map[string]ast.Expr, gd *ast.GenDecl) {
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range vs.Names {
			if i < len(vs.Values) {
				vars[name.Name] = vs.Values[i]
			}
		}
	}
}

// rule reads one element of the rules literal.
func (t *parsedTable) rule(el ast.Expr) (tableRule, error) {
	lit, ok := el.(*ast.CompositeLit)
	if !ok {
		return tableRule{}, fmt.Errorf(
			"%s: rule is not a composite literal",
			t.fset.Position(el.Pos()),
		)
	}
	r := tableRule{Line: t.fset.Position(lit.Pos()).Line}
	for _, field := range lit.Elts {
		kv, ok := field.(*ast.KeyValueExpr)
		if !ok {
			return tableRule{}, fmt.Errorf("%s: unkeyed rule field", t.fset.Position(lit.Pos()))
		}
		if err := t.setField(&r, kv); err != nil {
			return tableRule{}, err
		}
	}
	return r, nil
}

// setField sets the field of r that kv names. Fields the verifier does not
// read are ignored.
func (t *parsedTable) setField(r *tableRule, kv *ast.KeyValueExpr) error {
	var err error
	switch kv.Key.(*ast.Ident).Name {
	case "Pattern":
		r.Pattern, err = t.str(kv.Value)
	case "Perms":
		r.Perms, err = t.strs(kv.Value)
	case "Maybe":
		r.Maybe, err = t.strs(kv.Value)
	case "Note":
		r.Note, err = t.str(kv.Value)
	}
	return err
}

// resolve replaces an identifier naming a package-level variable with its
// value.
func (t *parsedTable) resolve(e ast.Expr) ast.Expr {
	if id, ok := e.(*ast.Ident); ok {
		if v, ok := t.vars[id.Name]; ok {
			return v
		}
	}
	return e
}

// str reads a string literal, or a sum of them, as long notes are written.
func (t *parsedTable) str(e ast.Expr) (string, error) {
	switch v := t.resolve(e).(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			s, err := strconv.Unquote(v.Value)
			if err != nil {
				return "", fmt.Errorf("%s: %w", t.fset.Position(e.Pos()), err)
			}
			return s, nil
		}
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			x, err := t.str(v.X)
			if err != nil {
				return "", err
			}
			y, err := t.str(v.Y)
			return x + y, err
		}
	}
	return "", fmt.Errorf("%s: not a string literal", t.fset.Position(e.Pos()))
}

// strs reads a []string literal.
func (t *parsedTable) strs(e ast.Expr) ([]string, error) {
	lit, ok := t.resolve(e).(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("%s: not a []string literal", t.fset.Position(e.Pos()))
	}
	var out []string
	for _, el := range lit.Elts {
		s, err := t.str(el)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// splitAPI splits "a/b/c.T.M" into "a/b/c" and "T.M".
func splitAPI(api string) (pkg, name string) {
	slash := strings.LastIndex(api, "/")
	dot := strings.Index(api[slash+1:], ".")
	if dot < 0 {
		return api, ""
	}
	return api[:slash+1+dot], api[slash+2+dot:]
}

// match returns the index of the first rule matching api, or -1. It
// follows the matching semantics documented on gcpperms' rule type.
func match(rules []tableRule, api string) int {
	pkg, name := splitAPI(api)
	for i, r := range rules {
		rpkg, rname := splitAPI(r.Pattern)
		if prefix, ok := strings.CutSuffix(rpkg, "*"); ok {
			if strings.HasPrefix(pkg, prefix) {
				return i
			}
			continue
		}
		if rpkg != pkg {
			continue
		}
		if ok, _ := path.Match(rname, name); ok {
			return i
		}
	}
	return -1
}
