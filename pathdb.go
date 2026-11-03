package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"time"
)

// What cloud.db knows about a file is keyed by its path relative to filesDir:
// slugs (public /f/ links), shares (/s/ links) and file_meta (description, tags, AI name).
// These helpers keep those rows in step with the disk; the admin API and WebDAV both call them.
//
// A row left at a path is handed to whatever is created there next (its /f/ link, its shares),
// so the order matters: rows are dropped before a deletion or a creation reaches the disk, and
// the operation is refused if that fails; a disk rename is undone if its rows cannot follow.

var pathTables = []string{"slugs", "shares", "file_meta"}

// descendants returns [lo, hi) bounds matching every path strictly under rel.
// '0' is the byte right after '/', so the range holds exactly the strings starting with rel+"/".
func descendants(rel string) (lo, hi string) {
	return rel + "/", rel + "0"
}

func checkRel(rel string) error {
	if rel == "" || rel == "." || rel == "/" {
		return fmt.Errorf("refusing to touch the root's records")
	}
	return nil
}

func forgetIn(tx *sql.Tx, rel string) error {
	lo, hi := descendants(rel)
	for _, table := range pathTables {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE path = ? OR (path >= ? AND path < ?)`, rel, lo, hi); err != nil {
			return err
		}
	}
	return nil
}

// forgetPath drops every record about rel and, for a folder, everything under it.
func forgetPath(rel string) error {
	if err := checkRel(rel); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := forgetIn(tx, rel); err != nil {
		return err
	}
	return tx.Commit()
}

// movePath makes the records of oldRel (and its descendants) follow it to newRel.
// Rows already at newRel are stale (nothing lives there before the move) and are dropped first,
// otherwise the unique slug path would block the update.
func movePath(oldRel, newRel string) error {
	if err := checkRel(oldRel); err != nil {
		return err
	}
	if err := checkRel(newRel); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := forgetIn(tx, newRel); err != nil {
		return err
	}
	for _, table := range pathTables {
		if _, err := tx.Exec(`UPDATE `+table+` SET path = ? WHERE path = ?`, newRel, oldRel); err != nil {
			return err
		}
	}
	// A share shows the file name on its page.
	if _, err := tx.Exec(`UPDATE shares SET filename = ? WHERE path = ?`, path.Base(newRel), newRel); err != nil {
		return err
	}
	lo, hi := descendants(oldRel)
	for _, table := range pathTables {
		if _, err := tx.Exec(`UPDATE `+table+` SET path = ? || substr(path, length(?) + 1) WHERE path >= ? AND path < ?`,
			newRel+"/", lo, lo, hi); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// copyMeta gives a copy the description and tags of its source. Links and shares stay
// with the original: a copy is a new file nobody has been given yet.
func copyMeta(srcRel, dstRel string, withDescendants bool) error {
	if err := checkRel(srcRel); err != nil {
		return err
	}
	if err := checkRel(dstRel); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT OR REPLACE INTO file_meta (path, description, tags, ai_name, analyzed_at)
		SELECT ?, description, tags, ai_name, analyzed_at FROM file_meta WHERE path = ?`, dstRel, srcRel); err != nil {
		return err
	}
	if withDescendants {
		lo, hi := descendants(srcRel)
		if _, err := tx.Exec(`INSERT OR REPLACE INTO file_meta (path, description, tags, ai_name, analyzed_at)
			SELECT ? || substr(path, length(?) + 1), description, tags, ai_name, analyzed_at
			FROM file_meta WHERE path >= ? AND path < ?`, dstRel+"/", lo, lo, hi); err != nil {
			return err
		}
	}
	return tx.Commit()
}

var dbRetryDelays = []time.Duration{0, 50 * time.Millisecond, 250 * time.Millisecond, time.Second}

// withRetry gives a busy or briefly failing database a few chances before giving up.
func withRetry(op func() error) error {
	var err error
	for _, d := range dbRetryDelays {
		time.Sleep(d)
		if err = op(); err == nil {
			return nil
		}
	}
	return err
}

// claimNewPath clears rel before something is created there.
func claimNewPath(rel string) error {
	return withRetry(func() error { return forgetPath(rel) })
}

func forgetPathRetry(rel string) error {
	return withRetry(func() error { return forgetPath(rel) })
}

func movePathRetry(oldRel, newRel string) error {
	return withRetry(func() error { return movePath(oldRel, newRel) })
}

// renameTracked renames on disk and moves the records along, or undoes the rename.
func renameTracked(oldFull, newFull, oldRel, newRel string) error {
	if err := os.Rename(oldFull, newFull); err != nil {
		return err
	}
	if err := movePathRetry(oldRel, newRel); err != nil {
		if undoErr := os.Rename(newFull, oldFull); undoErr != nil {
			log.Printf("rename: records did not follow and the rename could not be undone: %v / %v", err, undoErr)
		}
		return fmt.Errorf("records did not follow the rename: %w", err)
	}
	return nil
}

// mkdirAllClaimed is os.MkdirAll that first clears the records of the highest folder it
// is about to create, and so of everything that could be created under it.
func mkdirAllClaimed(full string) error {
	root := filepath.Clean(filesDir)
	missing := ""
	for cur := filepath.Clean(full); cur != root; {
		if _, err := os.Lstat(cur); err == nil {
			break
		}
		missing = cur
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	if missing != "" {
		if err := claimNewPath(toRelPath(missing)); err != nil {
			return err
		}
	}
	return os.MkdirAll(full, 0755)
}

// sweepOrphanRecords drops, once per database, the records whose path no longer exists.
// Older versions left some (folder renames, deletions outside the app); since then every
// creation clears its path, so one pass is enough.
func sweepOrphanRecords() error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS housekeeping (name TEXT PRIMARY KEY, done_at DATETIME NOT NULL)`); err != nil {
		return err
	}
	var done int
	if err := db.QueryRow(`SELECT COUNT(*) FROM housekeeping WHERE name = 'orphan-sweep'`).Scan(&done); err != nil {
		return err
	}
	if done > 0 {
		return nil
	}
	rows, err := db.Query(`SELECT path FROM slugs UNION SELECT path FROM shares UNION SELECT path FROM file_meta`)
	if err != nil {
		return err
	}
	var all, orphans []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return err
		}
		all = append(all, p)
	}
	rows.Close()
	for _, p := range all {
		full, err := safePath(filesDir, p)
		if err != nil {
			orphans = append(orphans, p)
			continue
		}
		if _, err := os.Lstat(full); os.IsNotExist(err) {
			orphans = append(orphans, p)
		} else if err != nil {
			return err
		}
	}
	// An unmounted volume looks exactly like "every file is gone": refuse rather than wipe.
	if len(all) >= 5 && len(orphans) == len(all) {
		return errors.New("no recorded path exists on disk; is the files volume mounted? sweep skipped")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, p := range orphans {
		for _, table := range pathTables {
			if _, err := tx.Exec(`DELETE FROM `+table+` WHERE path = ?`, p); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`INSERT INTO housekeeping (name, done_at) VALUES ('orphan-sweep', ?)`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Printf("orphan sweep: %d of %d recorded paths no longer existed, records dropped", len(orphans), len(all))
	return nil
}
