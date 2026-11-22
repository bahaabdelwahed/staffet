// Test fixture: deliberately vulnerable code.
package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
)

func f(db *sql.DB, u string) {
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE u = '%s'", u))
	_ = &tls.Config{InsecureSkipVerify: true}
	exec.Command("sh", "-c", u)
	md5.New()
	for i := 0; i < 3; i++ {
		fh, _ := os.Open("x")
		defer fh.Close()
	}
}
