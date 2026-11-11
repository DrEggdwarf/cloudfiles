package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/net/webdav"
)

// davFS is the WebDAV view of filesDir (or of its DAV_ROOT sub-folder). Unlike webdav.Dir
// it refuses symbolic links (nothing may lead out of the root), writes through a temporary
// file renamed into place (an interrupted upload never truncates the previous version), and
// keeps cloud.db in step: a creation clears its path first, DELETE drops the records before
// the files, MOVE carries them along or is undone.
type davFS struct {
	root   string // absolute folder served at /dav/
	prefix string // that folder relative to filesDir, as cloud.db keys it ("" for filesDir)
}

// davTempPrefix marks in-flight uploads; they are hidden from listings and unreachable by URL.
const davTempPrefix = ".cloudfiles-dav-"

var errUploadAborted = errors.New("upload aborted")

func newDAVFS() (*davFS, error) {
	root := filepath.Clean(filesDir)
	sub := davRel(davRoot)
	if sub == "" {
		return &davFS{root: root}, nil
	}
	full, err := (&davFS{root: root}).resolve(sub)
	if err != nil {
		return nil, fmt.Errorf("DAV_ROOT: %w", err)
	}
	if err := mkdirAllClaimed(full); err != nil {
		return nil, fmt.Errorf("DAV_ROOT: %w", err)
	}
	return &davFS{root: full, prefix: sub}, nil
}

// davRel turns a WebDAV name ("/a/b", "a/../b") into a clean relative path ("a/b").
func davRel(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

// dbRel is the cloud.db key of a WebDAV name.
func (d *davFS) dbRel(name string) string {
	rel := davRel(name)
	if d.prefix == "" || rel == "" {
		return path.Join(d.prefix, rel)
	}
	return d.prefix + "/" + rel
}

// davName is the WebDAV name ("/a/b") of a cloud.db key, when the key lies in the WebDAV root ("/" for the root).
func (d *davFS) davName(rel string) (string, bool) {
	if rel != davRel(rel) {
		return "", false
	}
	if d.prefix == "" {
		return "/" + rel, true
	}
	if rel == d.prefix {
		return "/", true
	}
	if inner, ok := strings.CutPrefix(rel, d.prefix+"/"); ok {
		return "/" + inner, true
	}
	return "", false
}

// coversRoot tells whether a cloud.db key is the WebDAV root or a folder above it: sharing it shares the whole root.
func (d *davFS) coversRoot(rel string) bool {
	if rel == "." {
		rel = ""
	}
	if rel != davRel(rel) {
		return false
	}
	return rel == d.prefix || rel == "" || strings.HasPrefix(d.prefix, rel+"/")
}

// linkTarget resolves a WebDAV name to a regular file of the root, as WebDAV would (no way out, no symbolic link),
// and gives its cloud.db key. The share page finds its file through safePath, which trims each name: a name it would
// read as another ("Plan.pdf " for "Plan.pdf", a twin of a symbolic link) gets no link.
func (d *davFS) linkTarget(name string) (string, error) {
	full, err := d.resolve(name)
	if err != nil {
		return "", err
	}
	if !servedAsIs(d.dbRel(name)) {
		return "", os.ErrNotExist
	}
	fi, err := os.Lstat(full)
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		return "", errNotAFile
	}
	if !fi.Mode().IsRegular() {
		return "", os.ErrPermission
	}
	return d.dbRel(name), nil
}

func (d *davFS) resolve(name string) (string, error) {
	if strings.ContainsRune(name, 0) {
		return "", os.ErrNotExist
	}
	rel := davRel(name)
	root := filepath.Clean(d.root)
	if rel == "" {
		return root, nil
	}
	parts := strings.Split(rel, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, davTempPrefix) {
			return "", os.ErrNotExist
		}
	}
	cur := root
	for _, part := range parts {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			break
		}
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", os.ErrPermission
		}
	}
	full := filepath.Join(root, filepath.FromSlash(rel))
	if !strings.HasPrefix(full, root+string(os.PathSeparator)) {
		return "", os.ErrPermission
	}
	return full, nil
}

func exists(full string) bool {
	_, err := os.Lstat(full)
	return err == nil
}

func (d *davFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	full, err := d.resolve(name)
	if err != nil {
		return err
	}
	if exists(full) {
		return os.ErrExist
	}
	if err := claimNewPath(d.dbRel(name)); err != nil {
		return err
	}
	return os.Mkdir(full, 0755)
}

func (d *davFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	full, err := d.resolve(name)
	if err != nil {
		return nil, err
	}
	if flag&(os.O_WRONLY|os.O_RDWR) == 0 {
		f, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		return davFile{f}, nil
	}
	// webdav.Handler only ever writes with O_CREATE|O_TRUNC (PUT, COPY, LOCK on a new name).
	if flag&os.O_CREATE == 0 || flag&os.O_TRUNC == 0 {
		return nil, os.ErrPermission
	}
	if full == filepath.Clean(d.root) {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EISDIR}
	}
	fi, err := os.Lstat(full)
	switch {
	case err == nil && fi.IsDir():
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EISDIR}
	case os.IsNotExist(err):
		// A new name must not inherit the links of a file that once lived there; an
		// overwrite keeps them, so a published file can be updated in place.
		if err := claimNewPath(d.dbRel(name)); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(full), davTempPrefix+"*")
	if err != nil {
		return nil, err
	}
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	state, _ := ctx.Value(putStateKey{}).(*putState)
	return &atomicFile{tmp: tmp, target: full, state: state}, nil
}

func (d *davFS) RemoveAll(ctx context.Context, name string) error {
	full, err := d.resolve(name)
	if err != nil {
		return err
	}
	if full == filepath.Clean(d.root) {
		return os.ErrInvalid
	}
	if err := forgetPathRetry(d.dbRel(name)); err != nil {
		return err
	}
	return os.RemoveAll(full)
}

func (d *davFS) Rename(ctx context.Context, oldName, newName string) error {
	oldFull, err := d.resolve(oldName)
	if err != nil {
		return err
	}
	newFull, err := d.resolve(newName)
	if err != nil {
		return err
	}
	root := filepath.Clean(d.root)
	if oldFull == root || newFull == root {
		return os.ErrInvalid
	}
	return renameTracked(oldFull, newFull, d.dbRel(oldName), d.dbRel(newName))
}

func (d *davFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	full, err := d.resolve(name)
	if err != nil {
		return nil, err
	}
	return os.Stat(full)
}

// davFile is a file or folder opened for reading; listings skip links and in-flight uploads.
type davFile struct {
	*os.File
}

func (f davFile) Readdir(count int) ([]os.FileInfo, error) {
	infos, err := f.File.Readdir(count)
	kept := infos[:0]
	for _, fi := range infos {
		if fi.Mode()&os.ModeSymlink != 0 || strings.HasPrefix(fi.Name(), davTempPrefix) {
			continue
		}
		kept = append(kept, fi)
	}
	return kept, err
}

// atomicFile collects a write in a temporary file and renames it over the target on Close,
// unless the write or the request body failed on the way.
// It deliberately does not embed *os.File: a promoted ReadFrom would bypass Write.
type atomicFile struct {
	tmp    *os.File
	target string
	state  *putState
	failed bool
}

func (f *atomicFile) Write(p []byte) (int, error) {
	n, err := f.tmp.Write(p)
	if err != nil {
		f.failed = true
	}
	return n, err
}

func (f *atomicFile) Read(p []byte) (int, error) { return f.tmp.Read(p) }

func (f *atomicFile) Seek(offset int64, whence int) (int64, error) {
	return f.tmp.Seek(offset, whence)
}

func (f *atomicFile) Readdir(count int) ([]fs.FileInfo, error) {
	return nil, &os.PathError{Op: "readdir", Path: f.target, Err: syscall.ENOTDIR}
}

func (f *atomicFile) Stat() (os.FileInfo, error) {
	fi, err := f.tmp.Stat()
	if err != nil {
		return nil, err
	}
	return namedInfo{fi, filepath.Base(f.target)}, nil
}

func (f *atomicFile) Close() error {
	tmpName := f.tmp.Name()
	err := f.tmp.Close()
	if err == nil && (f.failed || (f.state != nil && f.state.failed)) {
		err = errUploadAborted
	}
	if err == nil {
		err = os.Rename(tmpName, f.target)
	}
	if err != nil {
		os.Remove(tmpName)
	}
	return err
}

type namedInfo struct {
	os.FileInfo
	name string
}

func (n namedInfo) Name() string { return n.name }
