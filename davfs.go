package main

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/net/webdav"
)

// davFS is the WebDAV view of filesDir. Unlike webdav.Dir it refuses symbolic links
// (nothing may lead out of the root), writes through a temporary file renamed into place
// (an interrupted upload never truncates the previous version), and keeps cloud.db in step
// on DELETE and MOVE.
type davFS struct {
	root string
}

// davTempPrefix marks in-flight uploads; they are hidden from listings and unreachable by URL.
const davTempPrefix = ".cloudfiles-dav-"

var errUploadAborted = errors.New("upload aborted")

// davRel turns a WebDAV name ("/a/b", "a/../b") into the relative path cloud.db keys on ("a/b").
func davRel(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
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

func (d *davFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	full, err := d.resolve(name)
	if err != nil {
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
	if fi, err := os.Lstat(full); err == nil && fi.IsDir() {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EISDIR}
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
	if err := os.RemoveAll(full); err != nil {
		return err
	}
	if err := forgetPath(davRel(name)); err != nil {
		log.Printf("dav: could not clean records after delete: %v", err)
	}
	return nil
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
	if err := os.Rename(oldFull, newFull); err != nil {
		return err
	}
	if err := movePath(davRel(oldName), davRel(newName)); err != nil {
		log.Printf("dav: could not move records: %v", err)
	}
	return nil
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

// removeDAVLeftovers deletes temporary files a crash may have left behind mid-upload.
func removeDAVLeftovers(root string) {
	filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err == nil && e.Type().IsRegular() && strings.HasPrefix(e.Name(), davTempPrefix) {
			os.Remove(p)
		}
		return nil
	})
}
