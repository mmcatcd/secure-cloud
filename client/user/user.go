package user

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"../asymkey"
	"../driveapi"
	"../symkey"
	"golang.org/x/oauth2"
	drive "google.golang.org/api/drive/v3"
)

// User is a cacheable structure that stores information about a user.
type User struct {
	Username       string        `json:"username"`
	Token          *oauth2.Token `json:"token"`
	symkey         []byte        `json:"symkey"`
	SharedFolder   string        `json:"sharedFolder"`
	PrivateKeyPath string        `json:"privateKeyPath"`
	driveClient    *drive.Service
}

// UserFile is the default name for the file to store cached user information.
var UserFile = "user.json"

// New creates a new user, and stores the path to access the private asymmetric key.
func New(email string, privateKeyPath string) *User {
	user := &User{
		Username:       email,
		PrivateKeyPath: privateKeyPath,
	}

	return user
}

// Login gets a token for Google Drive and caches the user to json file.
func (user *User) Login() {
	// Remove user that may be logged in.
	os.Remove("./user.json")

	// Generate token for Google Drive if one doesn't already exist.
	if user.Token != nil {
		fmt.Println("Admin already logged in!")
		return
	}

	fmt.Println("Logging into Google Drive...")
	config := driveapi.GenerateConfig("user")
	token := driveapi.GetTokenFromWeb(config)
	user.Token = token

	// Save the current user.
	user.ToFile()

	fmt.Println("Logged in successfully!")
}

// GetSharedFolders returns a list of the folders with a '-shared' postfix.
func (user *User) GetSharedFolders() {
	// New Client.
	user.driveClient = driveapi.NewDriveClient("user", user.Token)

	// Get matching folders.
	sharedFolders := driveapi.GetFolders(user.driveClient, "-shared")
	if sharedFolders == nil {
		fmt.Println("No shared folders found!")
		return
	}

	fmt.Println("-----Shared Folders-----")
	for _, folder := range sharedFolders {
		fmt.Println(folder.Name)
	}
}

// SelectShared selects a folder you wish the user to download files from.
func (user *User) SelectShared(name string) {
	// New client.
	user.driveClient = driveapi.NewDriveClient("user", user.Token)

	// Get the folder ID.
	f := driveapi.GetFolder(user.driveClient, name)
	if f == nil {
		fmt.Println("Are you sure the folder is shared with you?")
	}

	user.SharedFolder = f.Id
	fmt.Println("Selected folder:", name, "with id", user.SharedFolder)

	// Get the symmetric key for the folder.
	encFile := driveapi.GetKeyFile(user.driveClient, user.Username, user.SharedFolder)
	fmt.Println("Encrypted File ID: ", encFile.Id)

	// Download the encrypted symmetric key.
	fmt.Println("Downloading encrypted symmetric key...")
	encKey, err := driveapi.DownloadFile(user.driveClient, encFile)
	if err != nil {
		fmt.Println("Couldn't download encrypted symmetric key file :(", err)
	}

	// Decrypt the encrypted key.
	decrKey, err := asymkey.DecryptFromPath(encKey, user.PrivateKeyPath)
	if err != nil {
		fmt.Println("Couldn't decrypt the key: ", err)
	}

	fmt.Println("Successfully decrypted the key: ", string(decrKey))
	user.symkey = decrKey

	// Save the user to a file.
	user.ToFile()
}

// Download finds and downloads a file from the currently selected folder.
func (user *User) Download(filename string) {
	// New client.
	user.driveClient = driveapi.NewDriveClient("user", user.Token)

	// Get current folder.
	if user.SharedFolder == "" {
		fmt.Println("Please select a shared folder first by: client select-shared")
	}

	// Get file.
	file := driveapi.FindFile(user.driveClient, filename+".enc", user.SharedFolder)
	if file == nil {
		log.Fatal("Couldn't find the file you wanted to download in: ", user.SharedFolder)
		return
	}

	encrData, err := driveapi.DownloadFile(user.driveClient, file)
	if err != nil {
		log.Fatal("Couldn't download the file: ", err)
		return
	}

	// Decrypt the data.
	decrData, err := symkey.DecryptData(encrData, user.symkey)
	if err != nil {
		log.Fatal("Couldn't decrypt the file: ", err)
		return
	}

	// Put decrypted data into a file and put it into downloads folder.
	os.MkdirAll("./downloads", os.ModePerm)
	err = ioutil.WriteFile("./downloads/"+filename, decrData, 0644)
	if err != nil {
		log.Fatal("Couldn't write decrypted data to file: ", err)
		return
	}

	fmt.Println("File downloaded to: ./downloads/" + filename)
}

// ToFile caches the user in the form of a json file.
func (user *User) ToFile() {
	f, err := os.OpenFile(UserFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache user: %v", err)
	}

	defer f.Close()
	json.NewEncoder(f).Encode(user)
}

// FromFile reads in a cached user from a json file.
func FromFile() (*User, error) {
	f, err := os.Open(UserFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	user := &User{}
	err = json.NewDecoder(f).Decode(user)

	return user, nil
}
