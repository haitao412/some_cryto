package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

    // You neet to add with
    // go get github.com/nweaver/cs161-p2/userlib
    "github.com/nweaver/cs161-p2/userlib"

    // Life is much easier with json:  You are
    // going to want to use this so you can easily
    // turn complex structures into strings etc...
    "encoding/json"

    // Likewise useful for debugging etc
    "encoding/hex"

    // UUIDs are generated right based on the crypto RNG
    // so lets make life easier and use those too...
    //
    // You need to add with "go get github.com/google/uuid"
    "github.com/google/uuid"

    // Useful for debug messages, or string manipulation for datastore keys
    "strings"

    // Want to import errors
    "errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
    // Creates a random UUID
    f := uuid.New()
    userlib.DebugMsg("UUID as string:%v", f.String())

    // Example of writing over a byte of f
    f[0] = 10
    userlib.DebugMsg("UUID as string:%v", f.String())

    // takes a sequence of bytes and renders as hex
    h := hex.EncodeToString([]byte("fubar"))
    userlib.DebugMsg("The hex: %v", h)

    // Marshals data into a JSON representation
    // Will actually work with go structures as well
    d, _ := json.Marshal(f)
    userlib.DebugMsg("The json data: %v", string(d))
    var g uuid.UUID
    json.Unmarshal(d, &g)
    userlib.DebugMsg("Unmashaled data %v", g.String())

    // This creates an error type
    userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

    // And a random RSA key.  In this case, ignoring the error
    // return value
    var key *userlib.PrivateKey
    key, _ = userlib.GenerateRSAKey()
    userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
    for x := range ret {
        ret[x] = data[x]
    }
    return
}

// The structure definition for a user record
type User struct {
    /*
     username:        username of this user
     dataStoreKey:    key used for store file in datastore
     encryptionKey:   key user for encyption of content of file
     signedKey:       key used for cheking integrity and authentication
     fileContent:     the content of file we want to store
    */
    Username      string
    dataStoreKey  []byte 
    encryptionKey []byte 
    macKey        []byte
    signedKey     *rsa.PrivateKey
    fileListId    string
}


/*
With each file, we initialize one
FileKey struct to store encyption_key,
mac_key and file_begin.
encryption_key: used to encrypt the file
mac_key:        used to "mac" the file for integrity
file_begin:     to get the FileBeginNode of this file
                in dataStore
*/
type FileKey struct {

    encyption_key []byte
    mac_key       []byte
    file_begin    string
}

/*
This file contains information about
the file it is initialized for 
file_length:   length of this file in byte
node_nums:     num of nodes to store this byte
start_node:    to get the start node of the file
               (get at DataStore)
*/
type  FileBeginNode struct {
     
     file_length int 
     node_nums   int 
     start_node  string
}

/*
Keep small infor of the file 
content:    content of file at this place
next_node:  to get the next FileNode in DataStore
            (nil for the last node)
*/
type  FileNode struct {

    content   []byte
    next_node  string
}

/***************************************************************
                HELPER FUNCTION IN THIS AREA
***************************************************************/

/*
Generate a pair key include
a key to store userdata in datastore and 
a key to encrypt userdate
*/

func generate_user_key(username string, password string) ([]byte, []byte) {

    datastore_key := userlib.Argon2Key([]byte(username), []byte(password), len(username))
    encyption_key := userlib.Argon2Key([]byte(password), []byte(username), userlib.AESKeySize)

    return datastore_key, encyption_key
}

/*
Generate a mac key for user
with this username and password
*/
func generate_mac_key(username string, password string) ([]byte) {

    return userlib.Argon2Key([]byte(username), []byte(password), userlib.AESKeySize)
}

/*
Encrypt data with CFB block method
append iv as first of cipher text since it 
is not secret, just need to be random
*/

func encrypt_data(key []byte, data []byte) ([] byte) {

    ciphertext := make([]byte, userlib.BlockSize + len(data))
    iv := ciphertext[:userlib.BlockSize]
    copy(iv, randomBytes(userlib.BlockSize))
    mode := userlib.CFBEncrypter(key, iv)
    mode.XORKeyStream(ciphertext[aes.BlockSize:], data)
    return ciphertext
}

/*
Decrypt data with CFB block method
append iv as first of cipher text since it 
is not secret, just need to be random
*/

func decrypt_data(key []byte, data []byte) ([] byte){

    block := userlib.CFBDecrypter(key, data[:userlib.BlockSize])
    block.XORKeyStream(data[userlib.BlockSize:], data[userlib.BlockSize:])
    return data[userlib.BlockSize:]
}

/*
Store into DataStore the information
id and value as json but json is
encrypted and maced by 2 keys
*/

func DatastoreEncryptSet(encyption_key []byte, mac_key []byte, json []byte, id string) {

    ciphertext := encypt_and_mac(encyption_key, mac_key, json)
    userlib.DatastoreSet(id, ciphertext)
}


func DatastoreDecrytGet(encyption_key []byte, mac_key []byte, id string) (json []byte, err error){

    ciphertext, valid = userlib.DatastoreGet(id)
    if !valid {
        return nil, errors.New(strings.ToTitle("Can not get from Datastore !!!"))
    }

    json, err := decrypt_and_demac(encyption_key, mac_key, ciphertext)
    if err != nil {
        return nil, err
    }

    return json, nil

}

func GetFileList(encyption_key []byte, mac_key []byte, id string) (filelist map[string]FileKey, err error) {

    json_file_list, err1 := DatastoreDecrytGet(encyption_key, mac_key, id)

    if err1 != nil {
        return nil, err1
    }

    err2 := json.Unmarshal(json_file_list, &filelist)

    if err2 != nil {
        return nil, err2
    }

    return filelist, nil
}

func encypt_and_mac(encyption_key []byte, mac_key []byte, data []byte) {

    ciphertext := encrypt_data(encyption_key, data)
    mac = generate_hmac(mac_key, data)
    ciphertext.append(mac)
    return ciphertext
}

func decrypt_and_demac(encyption_key []byte, mac_key []byte, ciphertext []byte) ([]byte, error) {

    encypted_data := ciphertext[:len(ciphertext) - userlib.HashSize]
    hmac := ciphertext[len(ciphertext) - userlib.HashSize:]

    computed_mac := generate_hmac(mac_key, encypted_data)

    if !userlib.Equal(hmac, computed_mac) {

        return nil, errors.New(strings.ToTitle("Cipthertext is temperd !!!"))
    }

    return decrypt_data(encryption_key, encypted_data), nil
}

func generate_hmac(mac_key []byte, data []byte) []byte {

    mac := userlib.NewHMAC(mac_key)
    mac.Write(data)
    expectedMAC := mac.Sum(nil)
    return expectedMAC
}

func generate_encryption_key_for_file(file_name string, random_string string) []byte {

    return userlib.Argon2Key([]byte(random_string), []byte(file_name), userlib.AESKeySize)
}

func generate_hmac_key_for_file(file_name string, random_string string) []byte {

    return userlib.Argon2Key([]byte(random_string), []byte(file_name), userlib.AESKeySize)
}


func SplitAndStoreFile(data []byte, int node_size, encryption_key []byte, mac_key []byte) (num_of_node int,node_id string) {

    new_data := make([]byte, len(data))
    length := len(data)
    node_id := uuid.New().String()
    num_of_node := 0
    var thisNode FileNode

    if length < node_size {

        num_of_node = 1
        thisNode.content = new_data
        thisNode.next_node = uuid.New().String()

        var terminal_node FileNode
        terminal_node.content = nil

        terminal_node_json, _ := json.Marshal(terminal_node)
        DatastoreSet(encryption_key, mac_key, terminal_node_json, thisNode.next_node)

        thisNode_json, _ := json.Marshal(thisNode)
        DatastoreSet(encryption_key, mac_key, thisNode_json, node_id)

    }
    else {

        thisNode.content = new_data[:node_size]
        num_of_node, thisNode.next_node := SplitAndStoreFile(new_data[node_size:], node_size, encryption_key, mac_key)
        thisNode_json, _ := json.Marshal(thisNode)
        DatastoreSet(encryption_key, mac_key, thisNode_json, node_id)
        num_of_node = num_of_node + 1

        
    }

    return num_of_node, node_id

}





/***************************************************************
                END HELPER FUNCTION IN THIS AREA
***************************************************************/




// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {

    _, user_exist := userlib.KeystoreGet(username)

    if user_exist {
        return nil, errors.New(strings.ToTitle("User exist already !!!"))
    }

    var userdata User
    signed_key, _ := userlib.GenerateRSAKey()
    datastore_key, encyption_key := generate_user_key(username, password)
    userlib.KeystoreSet(username, signed_key.PublicKey)


    userdata.Username = username
    userdata.dataStoreKey = datastore_key
    userdata.signedKey = signed_key
    userdata.encryptionKey = encyption_key
    userdata.mac_key = generate_mac_key(username, password)
    userdata.fileListId = uuid.New().String()
    file_list := make(map[string]FileKey)
    file_list_json , _ := userlib.Marshal(file_list)
    DatastoreEncryptSet(userdata.encryptionKey, userdata.mac_key, file_list_json, userdata.fileListId)


    user_json, _ := json.Marshal(userdata)
    encypted_user_data := encrypt_data(encyption_key, user_json)

    signed_encypted_user_data := userlib.RSASign(signed_key, encypted_user_data)
    encypted_user_data_and_signature := [2][]byte{encypted_user_data, signed_encypted_user_data}
    encypted_user_data_and_signature_json, _ := json.Marshal(encypted_user_data_and_signature)
    userlib.DatastoreSet(string(datastore_key), encypted_user_data_and_signature_json)

    
    return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {

    publicKey, key_exist := userlib.KeystoreGet(username)
    if !key_exist {
        return nil, errors.New(strings.ToTitle("Not Found User !!!"))
    }

    var userdata User
    datastore_key, encyption_key := generate_user_key(username, password)
    user_data_json, key_exist := userlib.DatastoreGet(string(datastore_key))
    if !key_exist {
        return nil, errors.New(strings.ToTitle("Wrong user information !!!"))
    }

    var encypted_user_data_and_signature [2][]byte

    err := json.Unmashaled(user_data_json, &encypted_user_data_and_signature)
    if err != nil {
        return nil, errors.New(strings.ToTitle("Json of user data corrupted !!!"))
    }

    encypted_user_data := encypted_user_data_and_signature[0] 
    signed_encypted_user_data := encypted_user_data_and_signature[1]

    err := userlib.RSAVerify(&publicKey, encypted_user_data, signed_encypted_user_data)
    if err != nil {
        return nil, errors.New(strings.ToTitle("user data corrupted !!!"))
    }

    user_json := decrypt_data(encyption_key, encypted_user_data)
    err := json.Unmashaled(user_json, &userdata) 
    if err != nil {
        return nil, errors.New(strings.ToTitle("Json of user data corrupted !!!"))
    }
    return &userdata, err

}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

    var file_key FileKey
    file_key.encryption_key = generate_encryption_key_for_file(filename, uuid.New().String())
    file_key.mac_key = generate_hmac_key_for_file(filename, uuid.New().String())
    file_key.file_begin = uuid.New().String()

    var file_info FileBeginNode
    file_info.file_length = len(data)
    num_of_nodes, start_node := SplitAndStoreFile(data, node_size, file_key.encryption_key, file_key.mac_key)
    file_info.num_of_nodes = num_of_nodes
    file_info.start_node = start_node


    file_info_json, _ := json.Marshal(file_info)
    DatastoreEncryptSet(file_key.encryption_key, file_key.mac_key, file_info_json, file_key.file_begin)

    filelist := GetFileList(userdata.encryptionKey, userdata.macKey, userdata.fileListId)
    filelist[filename] = &file_key

    file_list_json , _ = json.Marshal(filelist)
    debugMsg("filelist %s", file_list_json)
    DatastoreEncryptSet(userdata.encryptionKey, userdata.macKey, file_list_json, userdata.fileListId)

    return nil


}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
    return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
    return
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
    msgid string, err error) {
    return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
    msgid string) error {
    return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
    return
}