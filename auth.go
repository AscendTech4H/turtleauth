package turtleauth

import "net/http"

//PermissionClass is a struct representing a premission
type PermissionClass struct {
	Name string
}

func (p PermissionClass) String() string {
	return p.Name
}

//Check checks if a PermissionClass is valid
func (p PermissionClass) Check() bool {
	for _, c := range []rune(p.Name) {
		if c > 'Z' || c < 'A' {
			return false
		}
	}
	return true
}

//AuthCheck is an authentication check request
type AuthCheck struct {
	C http.Cookie
	P PermissionClass
}
