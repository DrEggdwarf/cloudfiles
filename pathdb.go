package main

import (
	"database/sql"
	"fmt"
	"path"
)

// What cloud.db knows about a file is keyed by its path relative to filesDir:
// slugs (public /f/ links), shares (/s/ links) and file_meta (description, tags, AI name).
// These helpers keep those rows in step with the disk; the admin API and WebDAV both call them.

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
