package driveapi

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
)

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config, userType string, token *oauth2.Token) *http.Client {
	return config.Client(context.Background(), token)
}

// GetTokenFromWeb requests a token from the web, then returns the retrieved token.
func GetTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	return tok
}

// CreateDir is a helper that creates a shared folder in the root directory.
func CreateDir(service *drive.Service, name string, parent string) (*drive.File, error) {
	// Check if the folder already exists.
	r, err := service.Files.List().Q("name='" + name + "' and mimeType='application/vnd.google-apps.folder' and trashed=false").Do()
	if err != nil {
		return nil, err
	}

	// Returns first found result if folder already exists.
	if len(r.Files) != 0 {
		return r.Files[0], err
	}

	// Create new directory if one doesn't already exist.
	f := &drive.File{
		MimeType: "application/vnd.google-apps.folder",
		Name:     name,
		Parents:  []string{parent},
	}

	file, err := service.Files.Create(f).Do()
	if err != nil {
		log.Println("Could not create dir: ", err)
		return nil, err
	}

	fmt.Println("Created shared directory for user called: ", name)
	return file, nil
}

// UploadFile is a helper that uploads data as a file to Google Drive.
func UploadFile(service *drive.Service, name string, parentID string, data []byte) (*drive.File, error) {
	// Create new file with .enc at the end for encrypted.
	f := &drive.File{
		MimeType: "text/plain",
		Name:     name + ".enc",
		Parents:  []string{parentID},
	}

	// Convert data into an io Reader for Google Drive API.
	r := bytes.NewReader(data)
	// Upload Google Drive file.
	file, err := service.Files.Create(f).Media(r).Do()
	if err != nil {
		return nil, err
	}

	fmt.Println("Uploaded encrypted file:", name+".enc")
	return file, nil
}

// AddUser adds the appropriate permission to give an email Google Drive read permissions.
func AddUser(service *drive.Service, folder string, email string) error {
	var err error
	// Check if the folder already exists.
	f := GetFolder(service, folder)

	// Create folder if it doesn't exist.
	if f == nil {
		f, err = CreateDir(service, folder, "root")
		if err != nil {
			return err
		}
	}

	// Add user to folder.
	userPermission := &drive.Permission{
		Type:         "user",
		Role:         "reader",
		EmailAddress: email,
	}
	_, err = service.Permissions.Create(f.Id, userPermission).Do()
	if err != nil {
		return err
	}

	return nil
}

// RemoveUser removes read permission for a given email address to a Google Drive folder.
func RemoveUser(service *drive.Service, folder *drive.File, email string) error {
	// Get list of permissions.
	permissions, err := ListUsers(service, folder.Name)
	if err != nil {
		return err
	}

	// Check if there is a permission for given email.
	permissionID := ""
	for _, v := range permissions {
		if v.EmailAddress == email {
			permissionID = v.Id
		}
	}

	// If there is no matching permission, handle.
	if permissionID == "" {
		return errors.New("couldn't remove because couldn't find user")
	}

	// Remove permission.
	fmt.Println("Removing user...")
	err = service.Permissions.Delete(folder.Id, permissionID).Do()

	return err
}

// DeleteFile removes a file from Google Drive.
func DeleteFile(service *drive.Service, file *drive.File) error {
	err := service.Files.Delete(file.Id).Do()
	return err
}

// ListUsers lists all permissions set for a given folder in Google Drive.
func ListUsers(service *drive.Service, folder string) ([]*drive.Permission, error) {
	// Check if the folder already exists.
	f := GetFolder(service, folder)
	if f == nil {
		return nil, nil
	}

	l, err := service.Permissions.List(f.Id).Fields("permissions(id, emailAddress)").Do()
	service.Permissions.List(f.Id).Fields("'emailAddress' and 'displayName'")
	if err != nil {
		return nil, err
	}

	return l.Permissions, nil
}

// GetFolder finds the corresponding file for a folder with a given name.
func GetFolder(service *drive.Service, name string) *drive.File {
	r, err := service.Files.List().Q("name='" + name + "' and mimeType='application/vnd.google-apps.folder' and trashed=false").Do()
	if err != nil {
		log.Fatal("Couldn't get Google Drive shared folder ID: ", err)
		return nil
	}

	if len(r.Files) == 0 {
		return nil
	}

	return r.Files[0]
}

// GetFileFromID takes a file ID and returns all of the file metadata.
func GetFileFromID(service *drive.Service, id string) *drive.File {
	f, err := service.Files.Get(id).Do()
	if err != nil {
		return nil
	}

	return f
}

// GetKeyFile gets the corresponding key file given a shared folder and the user email.
func GetKeyFile(service *drive.Service, name string, parent string) *drive.File {
	r, err := service.Files.List().Q("name='keys' and mimeType='application/vnd.google-apps.folder' and trashed=false and '" + parent + "' in parents").Do()
	if err != nil {
		log.Fatal("Couldn't find keys folder in shared folder!", err)
		return nil
	}

	if len(r.Files) == 0 {
		log.Fatal("Couldn't find keys folder in shared folder!")
		return nil
	}

	keys := r.Files[0]

	r, err = service.Files.List().Q("name='" + name + ".enc' and mimeType='text/plain' and trashed=false and '" + keys.Id + "' in parents").Do()
	if err != nil {
		log.Fatal("Couldn't find encrypted symmetric key in keys folder :(", err)
		return nil
	}

	if len(r.Files) == 0 {
		log.Fatal("Couldn't find encrypted symmetric key in keys folder :(")
		return nil
	}

	return r.Files[0]
}

/*
FindFile searches for a file of given name in a given parent folder and either returns
the file or nil if it couldn't find one.
*/
func FindFile(service *drive.Service, name string, parent string) *drive.File {
	r, err := service.Files.List().Q("name='" + name + "' and trashed=false and '" + parent + "' in parents").Do()
	if err != nil {
		return nil
	}

	if len(r.Files) == 0 {
		return nil
	}

	return r.Files[0]
}

// DownloadFile takes the data from a file and loads it into memory as a byte slice.
func DownloadFile(service *drive.Service, file *drive.File) ([]byte, error) {
	res, err := service.Files.Get(file.Id).Download()
	if err != nil {
		return nil, err
	}

	result, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetFolders returns all folders with '-shared' in the name in Google Drive root folder.
func GetFolders(service *drive.Service, name string) []*drive.File {
	r, err := service.Files.List().Q("name contains '-shared' and mimeType='application/vnd.google-apps.folder' and trashed=false").Do()
	if err != nil {
		log.Fatal("Couldn't find any shared folders: ", err)
		return nil
	}

	return r.Files
}

// GenerateConfig creates an OAuth config from the user credentials and.
func GenerateConfig(userType string) *oauth2.Config {
	// Read in client ID and secret.
	b, err := ioutil.ReadFile("credentials.json")
	if err != nil {
		log.Fatalf("Unable to read Google Drive client secret file: %v", err)
		return nil
	}

	// Setting necessary scope.
	var scope string
	if userType == "admin" {
		scope = drive.DriveScope
	} else {
		scope = drive.DriveReadonlyScope
	}

	config, err := google.ConfigFromJSON(b, scope)
	if err != nil {
		log.Fatalf("Unable to parse Google Drive client secret file to config: %v", err)
		return nil
	}

	return config
}

// NewDriveClient returns a client for interfacing with the Drive API.
func NewDriveClient(userType string, token *oauth2.Token) *drive.Service {
	config := GenerateConfig(userType)
	client := getClient(config, userType, token)
	srv, err := drive.New(client)
	if err != nil {
		log.Fatalf("Unable to retrieve Drive client: %v", err)
	}

	return srv
}
