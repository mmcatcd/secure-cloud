package admin

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"../asymkey"
	"../driveapi"
	"../symkey"
	"golang.org/x/oauth2"
	drive "google.golang.org/api/drive/v3"
)

// Admin is a cacheable structure that stores information about an admin user.
type Admin struct {
	Username    string        `json:"username"`
	Token       *oauth2.Token `json:"token"`
	SymKey      []byte        `json:"symkey"`
	driveClient *drive.Service
}

// AdminFile is the default name for the file to store cached admin information.
var AdminFile = "admin.json"

// New creates a new admin, generating a symmetric key for all encryption.
func New(username string) *Admin {
	// Generate symmetric key for file encryption.
	symkey, err := symkey.GenerateKey()
	if err != nil {
		return nil
	}

	admin := &Admin{}
	admin.Username = username
	admin.SymKey = symkey

	return admin
}

// FromFile reads in a cached admin from a json file.
func FromFile() (*Admin, error) {
	f, err := os.Open(AdminFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	admin := &Admin{}
	err = json.NewDecoder(f).Decode(admin)

	return admin, nil
}

// ToFile caches the admin in the form of a json file.
func (admin *Admin) ToFile() {
	f, err := os.OpenFile(AdminFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache admin: %v", err)
	}

	defer f.Close()
	json.NewEncoder(f).Encode(admin)
}

// Login gets a token for Google Drive and creates a new shared folder in the users root directory.
func (admin *Admin) Login() {
	// Generating a token for the user to access Google Drive if one doesn't already exist.
	if admin.Token != nil {
		fmt.Println("Admin already logged in!")
		return
	}

	fmt.Println("Getting a Google Drive token for admin...")
	config := driveapi.GenerateConfig("admin")
	token := driveapi.GetTokenFromWeb(config)
	admin.Token = token
	fmt.Println("Token received!")

	admin.driveClient = driveapi.NewDriveClient("admin", admin.Token)

	// Saving the current user.
	admin.ToFile()

	// Create shared directory if needed.
	driveapi.CreateDir(admin.driveClient, admin.Username+"-shared", "root")
}

/*
AddUser adds read-only access to the shared folder in the Google Drive and uploads
the public key encrypted symmetric key to the 'keys' folder.
*/
func (admin *Admin) AddUser(email string, publicKey *rsa.PublicKey) {
	// Encrypt symmetric key with users public key.
	fmt.Println("Encrypting Symmetric Key with ", email, " public key...")
	encryptedsymkey, err := asymkey.Encrypt(admin.SymKey, publicKey)
	if err != nil {
		log.Fatal("Couldn't encrypt symmetric key with public key: ", err)
		os.Exit(1)
	}

	// Generate a new client.
	admin.driveClient = driveapi.NewDriveClient("admin", admin.Token)

	// Get shared folder.
	folder := driveapi.GetFolder(admin.driveClient, admin.Username+"-shared")
	if folder == nil {
		log.Fatal("Couldn't find shared folder!")
		os.Exit(1)
	}

	// Create Keys folder.
	keysFolder, err := driveapi.CreateDir(admin.driveClient, "keys", folder.Id)
	if err != nil {
		log.Fatal("Couldn't create keys folder: ", err)
		os.Exit(1)
	}

	// Upload encrypted symmetric key.
	_, err = driveapi.UploadFile(admin.driveClient, email, keysFolder.Id, encryptedsymkey)
	if err != nil {
		log.Fatal("Couldn't upload public key for ", email)
		os.Exit(1)
	}

	err = driveapi.AddUser(admin.driveClient, admin.Username+"-shared", email)
	if err != nil {
		log.Fatal("Couldn't add user: ", err)
		os.Exit(1)
	}

	fmt.Println("An invite has been sent to: ", email)
}

/*
RemoveUser removes read access from shared Google Drive folder and removes encrypted
symmetric key for user from keys folder.
*/
func (admin *Admin) RemoveUser(email string) {
	// Generate a new client.
	admin.driveClient = driveapi.NewDriveClient("admin", admin.Token)

	// Get shared folder.
	folder := driveapi.GetFolder(admin.driveClient, admin.Username+"-shared")
	if folder == nil {
		log.Fatal("Couldn't find shared folder!")
		os.Exit(1)
	}

	// Remove user.
	err := driveapi.RemoveUser(admin.driveClient, folder, email)
	if err != nil {
		log.Fatal("Couldn't remove user: ", err)
		os.Exit(1)
	}

	// Remove user encrypted symmetric key.
	keysFile := driveapi.GetKeyFile(admin.driveClient, email, folder.Id)

	err = driveapi.DeleteFile(admin.driveClient, keysFile)
	if err != nil {
		log.Fatal("Couldn't delete users encrypted symmetric key file: ", err)
	}

	fmt.Println("Successfully removed user: ", email)
}

// ListUsers lists all of the users that the shared folder has been shared with.
func (admin *Admin) ListUsers() {
	//Generate a new client.
	admin.driveClient = driveapi.NewDriveClient("admin", admin.Token)

	users, err := driveapi.ListUsers(admin.driveClient, admin.Username+"-shared")
	if err != nil {
		log.Fatal("Couldn't get users list: ", err)
	}

	fmt.Println("----Users----")
	for _, user := range users {
		fmt.Println(user.EmailAddress)
	}
}

// UploadFile uploads file from given path.
func (admin *Admin) UploadFile(path string) {
	// Generate a new client.
	admin.driveClient = driveapi.NewDriveClient("admin", admin.Token)

	// Get shared folder.
	folder := driveapi.GetFolder(admin.driveClient, admin.Username+"-shared")
	if folder == nil {
		log.Fatal("Couldn't find shared folder!")
		os.Exit(1)
	}

	// Read file into memory.
	fmt.Println("Reading file to upload...")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("Couldn't read in file to upload: ", err)
	}

	// Encrypt data.
	fmt.Println("Encrypting file...")
	encrypted, err := symkey.EncryptData(data, admin.SymKey)
	if err != nil {
		log.Fatal("Error encrypting the file: ", err)
	}

	// Extract the file name from the path.
	filename := filepath.Base(path)

	// Upload the file with the name and .enc extension to Drive.
	fmt.Println("Uploading ", filename, "...")
	_, err = driveapi.UploadFile(admin.driveClient, filename, folder.Id, encrypted)
	if err != nil {
		log.Fatal("Couldn't upload encrypted file: ", err)
	}

	fmt.Println("File Uploaded!")
}

// DeleteFile deletes a file from Google Drive shared folder.
func (admin *Admin) DeleteFile(filename string) {
	// Generate a new client.
	admin.driveClient = driveapi.NewDriveClient("admin", admin.Token)

	fmt.Println("Deleting file...")

	// Get shared folder.
	sharedFolder := driveapi.GetFolder(admin.driveClient, admin.Username+"-shared")

	file := driveapi.FindFile(admin.driveClient, filename, sharedFolder.Id)

	err := driveapi.DeleteFile(admin.driveClient, file)
	if err != nil {
		log.Fatal("Couldn't delete file: ", err)
	}

	fmt.Println("Successfully deleted file: ", filename)
}
