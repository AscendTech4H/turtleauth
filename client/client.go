//Package client implements a client for the turtleauth protocol
package client

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"html"
	"net/http"
	"net/url"

	"github.com/AscendTech4H/turtleauth"
	"github.com/panux/consterr"
)

var ping, _ = url.Parse("/ping")
var perm, _ = url.Parse("/perm")
var info, _ = url.Parse("/info")

//AuthServer is an authentication server
type AuthServer struct {
	address url.URL
}

//NewAuthServer returns an AuthServer at the specified address
func NewAuthServer(addr *url.URL) *AuthServer {
	return &AuthServer{address: *addr}
}

func httpErr(r *http.Response) error {
	return consterr.Error(fmt.Sprintf("HTTP Error with status code %d and message \"%s\"", r.StatusCode, html.EscapeString(r.Status)))
}

//Ping tries to see if the server is up
func (a *AuthServer) Ping() error {
	ra := a.address.ResolveReference(ping)
	r, err := http.Get(ra.String())
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return httpErr(r)
	}
	return nil
}

//AuthUser checks user authorization
func (a *AuthServer) AuthUser(p turtleauth.PermissionClass, c http.Cookie) (bool, error) {
	ra := a.address.ResolveReference(perm)
	b := &bytes.Buffer{}
	err := gob.NewEncoder(b).Encode(turtleauth.AuthCheck{C: c, P: p})
	if err != nil {
		return false, err
	}
	r, err := http.Post(ra.String(), "application/gob", b)
	if err != nil {
		return false, err
	}
	defer r.Body.Close()
	switch r.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, httpErr(r)
	}
}

//GetInfo returns user info
func (a *AuthServer) GetInfo(c http.Cookie) (map[string]string, error) {
	ra := a.address.ResolveReference(info)
	b := &bytes.Buffer{}
	err := gob.NewEncoder(b).Encode(c)
	if err != nil {
		return nil, err
	}
	r, err := http.Post(ra.String(), "application/gob", b)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, httpErr(r)
	}
	o := make(map[string]string)
	err = gob.NewDecoder(r.Body).Decode(o)
	if err != nil {
		return nil, err
	}
	return o, nil
}

type authCheckHandler struct {
	a *AuthServer
	h http.Handler
	p turtleauth.PermissionClass
	e http.Handler
}

func (a authCheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("turtleauth")
	if err != nil {
		a.e.ServeHTTP(w, r)
		return
	}
	s, _ := a.a.AuthUser(a.p, *c)
	if s {
		a.h.ServeHTTP(w, r)
	} else {
		a.e.ServeHTTP(w, r)
	}
}

//AuthorizedHandler creates an http.Handler that checks for a permission before granting access
func AuthorizedHandler(perm *AuthServer, handler http.Handler, permission turtleauth.PermissionClass, errorHandler http.Handler) http.Handler {
	return authCheckHandler{a: perm, h: handler, p: permission, e: errorHandler}
}
