package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/japinder12/securefs-go/pkg/securefs"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	store, err := securefs.OpenStore(".securefs.json")
	if err != nil { panic(err) }

	switch os.Args[1] {
	case "signup":
		fs := flag.NewFlagSet("signup", flag.ExitOnError)
		user := fs.String("user", "", "username")
		pass := fs.String("pass", "", "password")
		fs.Parse(os.Args[2:])
		err := securefs.Signup(store, *user, *pass)
		check(err)
		fmt.Println("ok")
	case "login":
		fs := flag.NewFlagSet("login", flag.ExitOnError)
		user := fs.String("user", "", "username")
		pass := fs.String("pass", "", "password")
		fs.Parse(os.Args[2:])
		_, err := securefs.Login(store, *user, *pass)
		check(err)
		fmt.Println("ok")
	case "put":
		fs := flag.NewFlagSet("put", flag.ExitOnError)
		user := fs.String("user", "", "username")
		pass := fs.String("pass", "", "password")
		name := fs.String("name", "", "filename")
		data := fs.String("data", "", "content")
		fs.Parse(os.Args[2:])
		c, err := securefs.Login(store, *user, *pass)
		check(err)
		check(c.StoreFile(*name, []byte(*data)))
		fmt.Println("ok")
	case "get":
		fs := flag.NewFlagSet("get", flag.ExitOnError)
		user := fs.String("user", "", "username")
		pass := fs.String("pass", "", "password")
		name := fs.String("name", "", "filename")
		fs.Parse(os.Args[2:])
		c, err := securefs.Login(store, *user, *pass)
		check(err)
		b, err := c.LoadFile(*name)
		check(err)
		fmt.Println(string(b))
	case "append":
		fs := flag.NewFlagSet("append", flag.ExitOnError)
		user := fs.String("user", "", "username")
		pass := fs.String("pass", "", "password")
		name := fs.String("name", "", "filename")
		data := fs.String("data", "", "content")
		fs.Parse(os.Args[2:])
		c, err := securefs.Login(store, *user, *pass)
		check(err)
		check(c.AppendFile(*name, []byte(*data)))
		fmt.Println("ok")
	case "share":
		fs := flag.NewFlagSet("share", flag.ExitOnError)
		user := fs.String("user", "", "username")
		pass := fs.String("pass", "", "password")
		name := fs.String("name", "", "filename")
		fs.Parse(os.Args[2:])
		c, err := securefs.Login(store, *user, *pass)
		check(err)
		code, err := c.CreateShare(*name)
		check(err)
		fmt.Println(code)
	case "accept":
		fs := flag.NewFlagSet("accept", flag.ExitOnError)
		user := fs.String("user", "", "username")
		pass := fs.String("pass", "", "password")
		as := fs.String("as", "", "save as filename")
		code := fs.String("code", "", "share code")
		fs.Parse(os.Args[2:])
		c, err := securefs.Login(store, *user, *pass)
		check(err)
		check(c.AcceptShare(*as, *code))
		fmt.Println("ok")
	case "revoke":
		fs := flag.NewFlagSet("revoke", flag.ExitOnError)
		user := fs.String("user", "", "username")
		pass := fs.String("pass", "", "password")
		name := fs.String("name", "", "filename")
		fs.Parse(os.Args[2:])
		c, err := securefs.Login(store, *user, *pass)
		check(err)
		check(c.Revoke(*name))
		fmt.Println("ok")
	case "dump":
		// for debugging: print store
		b, _ := json.MarshalIndent(store, "", "  ")
		fmt.Println(string(b))
	default:
		usage()
	}
}

func usage() {
	fmt.Print(`securefs CLI
Usage:
  securefs signup  --user U --pass P
  securefs login   --user U --pass P
  securefs put     --user U --pass P --name F --data "hello"
  securefs get     --user U --pass P --name F
  securefs append  --user U --pass P --name F --data "more"
  securefs share   --user U --pass P --name F
  securefs accept  --user U --pass P --as G --code CODE
  securefs revoke  --user U --pass P --name F
`)
}

func check(err error) {
	if err != nil { panic(err) }
}
