package main

import (
	"fmt"
	"log"
	"os"

	"./admin"
	"./asymkey"
	"./user"
)

func main() {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "listusers":
			f, err := admin.FromFile()
			if err != nil {
				log.Fatal("Not logged in as admin: ", err)
			}

			f.ListUsers()

		case "list-shared":
			f, err := user.FromFile()
			if err != nil {
				log.Fatal("Not logged in as user: ", err)
			}

			f.GetSharedFolders()

		case "--help":
			fmt.Println("------Usage------")
			fmt.Println("client admin <email>")
			fmt.Println("client adduser <email> <RSA public key file path>")
			fmt.Println("client listusers")
			fmt.Println("client list-shared")
			fmt.Println("client upload <file path>")
			fmt.Println("client select-shared <shared folder name>")
			fmt.Println("client download <file name>")
			fmt.Println("client delete-file <file name>")
			fmt.Println("client user <email> <RSA private key file path>")
			fmt.Println("client remove-user <user email>")
		}

	} else if len(os.Args) == 3 {
		switch os.Args[1] {
		case "admin":
			f, _ := admin.FromFile()
			if f != nil && f.Username == os.Args[2] {
				fmt.Println("Already logged in as:", f.Username)
				return
			}

			fmt.Println("Logging in...")
			currUser := admin.New(os.Args[2])
			currUser.Login()

			fmt.Println("Successfully logged in!")
		case "upload":
			// Read in current admin user.
			f, err := admin.FromFile()
			if err != nil {
				log.Fatal("Not logged in as admin: ", err)
				os.Exit(1)
			}

			// Upload file.
			f.UploadFile(os.Args[2])

		case "select-shared":
			f, err := user.FromFile()
			if err != nil {
				log.Fatal("Not logged in as user: ", err)
			}

			f.SelectShared(os.Args[2])

		case "download":
			f, err := user.FromFile()
			if err != nil {
				log.Fatal("Not logged in as user: ", err)
			}

			f.Download(os.Args[2])

		case "remove-user":
			f, err := admin.FromFile()
			if err != nil {
				log.Fatal("Not logged in as admin: ", err)
				os.Exit(1)
			}

			f.RemoveUser(os.Args[2])

		case "delete-file":
			f, err := admin.FromFile()
			if err != nil {
				log.Fatal("Not logged in as admin: ", err)
				os.Exit(1)
			}

			f.DeleteFile(os.Args[2] + ".enc")
		}
	} else if len(os.Args) == 4 {
		switch os.Args[1] {
		case "adduser":
			// Read in current admin user.
			f, err := admin.FromFile()
			if err != nil {
				log.Fatal("Not logged in as admin: ", err)
				os.Exit(1)
			}

			// Get new users public key.
			publicKey, err := asymkey.GetPublicKeyFromFile(os.Args[3])
			if err != nil {
				log.Fatal("Problem getting users public key: ", err)
				os.Exit(1)
			}

			// Add user to Google Drive with read-only permissions.
			f.AddUser(os.Args[2], publicKey)
		case "user":
			// Check if user already logged in.
			f, _ := user.FromFile()
			if f != nil && f.Username == os.Args[2] {
				fmt.Println("Already logged in as:", f.Username)
			}

			// Create new user.
			fmt.Println("Logging in...")
			currUser := user.New(os.Args[2], os.Args[3])
			currUser.Login()

			fmt.Println("Successfully logged in!")
		}
	}
}
