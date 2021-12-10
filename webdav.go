package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/net/webdav"
)

func isWebDAVUA(ua string) bool {
	return strings.HasPrefix(ua, "WebDAVLib/") || strings.HasPrefix(ua, "WebDAVFS/") || strings.HasPrefix(ua, "Cyberduck/")
}

type FilteredWebDAVDir struct {
	webdav.FileSystem

	filter func(string) bool
}

func (d *FilteredWebDAVDir) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	if !d.filter(name) {
		return os.ErrNotExist
	}

	return d.FileSystem.Mkdir(ctx, name, perm)
}

func (d *FilteredWebDAVDir) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	if !d.filter(name) {
		return nil, os.ErrNotExist
	}

	return d.FileSystem.OpenFile(ctx, name, flag, perm)
}

func (d *FilteredWebDAVDir) RemoveAll(ctx context.Context, name string) error {
	if !d.filter(name) {
		return os.ErrNotExist
	}

	return d.FileSystem.RemoveAll(ctx, name)
}

func (d *FilteredWebDAVDir) Rename(ctx context.Context, oldName, newName string) error {
	if !d.filter(oldName) {
		return os.ErrNotExist
	}

	return d.FileSystem.Rename(ctx, oldName, newName)
}

func (d *FilteredWebDAVDir) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	if !d.filter(name) {
		return nil, os.ErrNotExist
	}

	return d.FileSystem.Stat(ctx, name)
}

type UnifiWebDAV struct {
	admins     *mongo.Collection
	sites      *mongo.Collection
	privileges *mongo.Collection

	ls webdav.LockSystem
	fs webdav.FileSystem
}

func NewUnifiWebDAV(basedir string, ace *mongo.Database) *UnifiWebDAV {
	return &UnifiWebDAV{
		admins:     ace.Collection("admin"),
		sites:      ace.Collection("site"),
		privileges: ace.Collection("privilege"),

		ls: webdav.NewMemLS(),
		fs: webdav.Dir(path.Join(basedir, "data/sites")),
	}
}

func (u *UnifiWebDAV) validateUser(r *http.Request) (string, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", nil
	}

	var result bson.M
	if err := u.admins.FindOne(r.Context(), bson.M{"name": username}).Decode(&result); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", nil
		}

		return "", err
	}

	if err := sha512_crypt.New().Verify(result["x_shadow"].(string), []byte(password)); err != nil {
		if errors.Is(err, crypt.ErrKeyMismatch) {
			return "", nil
		}

		return "", err
	}

	return result["_id"].(primitive.ObjectID).Hex(), nil
}

func (u *UnifiWebDAV) getUserFilter(ctx context.Context, id string) (func(string) bool, error) {
	it, err := u.privileges.Find(ctx, bson.M{"admin_id": id, "role": "admin"})
	if err != nil {
		return nil, err
	}

	var siteIDs bson.A

	var result bson.M
	for it.Next(ctx) {
		if err := it.Decode(&result); err != nil {
			return nil, err
		}

		siteID, err := primitive.ObjectIDFromHex(result["site_id"].(string))
		if err != nil {
			return nil, err
		}

		siteIDs = append(siteIDs, siteID)
	}

	if err := it.Err(); err != nil {
		return nil, err
	}

	if len(siteIDs) == 0 {
		return func(string) bool {
			return false
		}, nil
	}

	it, err = u.sites.Find(ctx, bson.M{"_id": bson.M{"$in": siteIDs}})
	if err != nil {
		return nil, err
	}

	siteNames := make(map[string]bool, len(siteIDs))

	for it.Next(ctx) {
		if err := it.Decode(&result); err != nil {
			return nil, err
		}

		siteNames[result["name"].(string)] = true
	}

	if err := it.Err(); err != nil {
		return nil, err
	}

	return func(name string) bool {
		if len(name) == 0 {
			return false
		}

		if name[0] == '/' {
			name = name[1:]
		}

		if pos := strings.Index(name, "/"); pos != -1 {
			name = name[:pos]
		}

		return name == "" || siteNames[name]
	}, nil
}

func (u *UnifiWebDAV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := u.validateUser(r)
	if id == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+r.Host+`"`)

		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Println(err)

		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	filter, err := u.getUserFilter(r.Context(), id)
	if err != nil {
		log.Println(err)

		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	(&webdav.Handler{
		FileSystem: &FilteredWebDAVDir{
			FileSystem: u.fs,
			filter:     filter,
		},
		LockSystem: webdav.NewMemLS(),
	}).ServeHTTP(w, r)
}
