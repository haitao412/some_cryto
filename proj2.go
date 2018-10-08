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

    _"crypto/aes"
    "crypto/rsa"
    // Want to import errors
    "errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
    //Creates a random UUID
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

    //userlib.DebugMsg("datastore is %v", userlib.datastore)
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
    DataStoreKey  []byte 
    EncryptionKey []byte 
    MacKey        []byte
    SignedKey     *rsa.PrivateKey
    FileListId    string
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

    Encyption_key []byte
    Mac_key       []byte
    File_begin    string
    Is_owner      bool
}

/*
This file contains information about
the file it is initialized for 
file_length:   length of this file in byte
node_nums:     num of nodes to store this byte
start_node:    to get the start node of the file
               (get at DataStore)
end_node:      track the very node of the file.
*/
type  FileBeginNode struct {
     
     File_length int 
     Node_nums   int 
     Start_node  string
     End_node string
}

/*
Keep small infor of the file 
content:    content of file at this place
next_node:  to get the next FileNode in DataStore
            (nil for the last node)
*/
type  FileNode struct {

    Content   []byte
    Next_node  string
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
    encyption_key := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.BlockSize))
    datastore_key := userlib.Argon2Key([]byte(username), []byte(password), uint32(len(username)))
    
    return datastore_key, encyption_key
}

/*
Generate a mac key for user
with this username and password
*/
func generate_mac_key(username string, password string) ([]byte) {

    return userlib.Argon2Key([]byte(username), []byte(password), uint32(userlib.AESKeySize))
}

/*
Encrypt data with CFB block method
append iv as first of cipher text since it 
is not secret, just need to be random
*/

func encrypt_data(key []byte, data []byte) ([] byte) {

    ciphertext := make([]byte, userlib.BlockSize + len(data))
    iv := ciphertext[:userlib.BlockSize]
    copy(iv, userlib.RandomBytes(userlib.BlockSize))
    mode := userlib.CFBEncrypter(key, iv)
    mode.XORKeyStream(ciphertext[userlib.BlockSize:], data)
    return ciphertext
}

/*
Decrypt data with CFB block method
append iv as first of cipher text since it 
is not secret, just need to be random
*/

func decrypt_data(key []byte, data []byte) ([]byte){

    block := userlib.CFBDecrypter(key, data[:userlib.BlockSize])
    block.XORKeyStream(data[userlib.BlockSize:], data[userlib.BlockSize:])
    result := make([]byte, len(data[userlib.AESKeySize:]))
    copy(result, data[userlib.AESKeySize:])
    return result
}


func generate_random_AES_key() ([]byte){

    return  userlib.RandomBytes(userlib.AESKeySize)
}


func DatastoreDecrytGet(encyption_key []byte, mac_key []byte, id string) ([]byte, error){
    var ciphertext []byte
    var valid bool

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
    //userlib.DebugMsg("file_list_json %v", json_file_list)

    if err1 != nil {
        return nil, err1
    }

    err2 := json.Unmarshal(json_file_list, &filelist)

    if err2 != nil {
        return nil, err2
    }

    return filelist, nil
}

/*
Store into DataStore the information
id and value as json but json is
encrypted and maced by 2 keys
*/
func encypt_and_mac(encyption_key []byte, mac_key []byte, data []byte) ([]byte){
    var mac []byte
    ciphertext := encrypt_data(encyption_key, data)
    //userlib.DebugMsg("encrypted_json %v", ciphertext)

    mac = generate_hmac(mac_key, ciphertext)
    aes_ciphertext := append(ciphertext, mac...)
    //userlib.DebugMsg("encrypted_json_anc_mac %v", aes_ciphertext)
    return aes_ciphertext
}

func DatastoreEncryptSet(encyption_key []byte, mac_key []byte, json []byte, id string) {

    ciphertext := encypt_and_mac(encyption_key, mac_key, json)

    // userlib.DebugMsg("id %v", id)
    // userlib.DebugMsg("encruyted file list %v", ciphertext)

    userlib.DatastoreSet(id, ciphertext)
}
func decrypt_and_demac(encyption_key []byte, mac_key []byte, ciphertext []byte) ([]byte, error) {

    encypted_data := ciphertext[:len(ciphertext) - userlib.HashSize]
    //userlib.DebugMsg("encrypted_json %v", encypted_data)
    //userlib.DebugMsg("encrypted_json_anc_mac %v", ciphertext)
    hmac := ciphertext[len(ciphertext) - userlib.HashSize:]

    computed_mac := generate_hmac(mac_key, encypted_data)

    if !userlib.Equal(hmac, computed_mac) {

        return nil, errors.New(strings.ToTitle("Cipthertext is temperd !!!"))
    }

    
    return decrypt_data(encyption_key, encypted_data), nil
}

func generate_hmac(mac_key []byte, data []byte) []byte {

    mac := userlib.NewHMAC(mac_key)
    mac.Write(data)
    expectedMAC := mac.Sum(nil)
    return expectedMAC
}

func generate_encryption_key_for_file(file_name string, random_string string) ([]byte) {

    return userlib.Argon2Key([]byte(random_string), []byte(file_name), uint32(userlib.AESKeySize))
}

func generate_hmac_key_for_file(file_name string, random_string string) ([]byte) {

    return userlib.Argon2Key([]byte(random_string), []byte(file_name), uint32(userlib.AESKeySize))
}


func SplitAndStoreFile(data []byte, node_size int, encryption_key []byte, mac_key []byte) (num_of_node int,node_id string) {

    new_data := make([]byte, len(data))
    copy(new_data, data)
    length := len(data)
    node_id = uuid.New().String()
    num_of_node = 0
    var thisNode FileNode

    if length < node_size {

        num_of_node = 1
        thisNode.Content = new_data
        thisNode.Next_node = uuid.New().String()

        var terminal_node FileNode
        terminal_node.Content = nil

        terminal_node_json, _ := json.Marshal(terminal_node)
        DatastoreEncryptSet(encryption_key, mac_key, terminal_node_json, thisNode.Next_node)

        thisNode_json, _ := json.Marshal(thisNode)
        DatastoreEncryptSet(encryption_key, mac_key, thisNode_json, node_id)

    } else {
        var thisNode_json []byte
        thisNode.Content = new_data[:node_size]
        num_of_node, thisNode.Next_node = SplitAndStoreFile(new_data[node_size:], node_size, encryption_key, mac_key)
        thisNode_json, _ = json.Marshal(thisNode)
        DatastoreEncryptSet(encryption_key, mac_key, thisNode_json, node_id)
        num_of_node = num_of_node + 1

        
    }

    return num_of_node, node_id

}

func get_file_node(filekey *FileKey) (file_begin *FileBeginNode, data []*FileNode, err error) {

    file_begin_node_json, err := DatastoreDecrytGet(filekey.Encyption_key, filekey.Mac_key, filekey.File_begin)

    if err != nil {
        return nil, nil, errors.New(strings.ToTitle("file not found !!!"))
    }

    err1 := json.Unmarshal(file_begin_node_json, &file_begin)

    if err1 != nil {

        return nil, nil, errors.New(strings.ToTitle("Json file corrupted !!!"))
    }

    data = make([]*FileNode, file_begin.Node_nums)
    node_data_json, err2 := DatastoreDecrytGet(filekey.Encyption_key, filekey.Mac_key, file_begin.Start_node)

    if err2 != nil {
        return nil, nil, errors.New(strings.ToTitle("file not found !!!"))
    }

    for i:= 0; i < file_begin.Node_nums; i++ {
        var node_data FileNode

        err3 := json.Unmarshal(node_data_json, &node_data)

        if err3 != nil {
            return nil, nil, errors.New(strings.ToTitle("Json file corrupted !!!"))
        }

        if node_data.Content == nil {
            break
        }
        data[i] = &node_data

        node_data_json, err2 = DatastoreDecrytGet(filekey.Encyption_key, filekey.Mac_key, node_data.Next_node)

        if err2 != nil {
            return nil, nil, errors.New(strings.ToTitle("Json file corrupted !!!"))
        }

    }

    return file_begin, data, err
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

    signed_key, _ := userlib.GenerateRSAKey()
    datastore_key, encyption_key := generate_user_key(username, password)
    userlib.KeystoreSet(username, signed_key.PublicKey)
    mac_key := generate_mac_key(username, password)
    fileListId := uuid.New().String()
    file_list := make(map[string]FileKey)
    file_list_json , _ := json.Marshal(file_list)

    userdata := User{
        Username      : username,
        DataStoreKey  : datastore_key,
        EncryptionKey : encyption_key,
        MacKey        : mac_key,
        SignedKey     : signed_key,
        FileListId    : fileListId,
    }
    DatastoreEncryptSet(userdata.EncryptionKey, userdata.MacKey, file_list_json, userdata.FileListId)

    user_json, _ := json.Marshal(userdata)
    encypted_user_data := encrypt_data(encyption_key, user_json)
    signed_encypted_user_data, _ := userlib.RSASign(signed_key, encypted_user_data)
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

    datastore_key, encyption_key := generate_user_key(username, password)
    user_data_json, key_exist := userlib.DatastoreGet(string(datastore_key))
    if  !key_exist {
        return nil, errors.New(strings.ToTitle("Wrong user information !!!"))
    }

    var encypted_user_data_and_signature [2][]byte

    err = json.Unmarshal(user_data_json, &encypted_user_data_and_signature)
    if err != nil {
        return nil, errors.New(strings.ToTitle("Json of user data corrupted !!!"))
    }

    encypted_user_data := encypted_user_data_and_signature[0] 
    signed_encypted_user_data := encypted_user_data_and_signature[1]

    err = userlib.RSAVerify(&publicKey, encypted_user_data, signed_encypted_user_data)
    if err != nil {
        return nil, errors.New(strings.ToTitle("user data corrupted !!!"))
    }

    user_json := decrypt_data(encyption_key, encypted_user_data)

    var userdata User
    err = json.Unmarshal(user_json, &userdata) 
    if err != nil {
        return nil, errors.New(strings.ToTitle("Json of user data corrupted !!!"))
    }
 
    return &userdata, nil


}

// This stores a file in the datastore.
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

    var file_key FileKey
    file_key.Encyption_key = generate_random_AES_key()
    file_key.Mac_key = generate_random_AES_key()
    file_key.File_begin = uuid.New().String()
    file_key.Is_owner = true

    var file_info FileBeginNode
    file_info.File_length = len(data)
    num_of_nodes, start_node := SplitAndStoreFile(data, userlib.AESKeySize * 5, file_key.Encyption_key, file_key.Mac_key)
    file_info.Node_nums  = num_of_nodes
    file_info.Start_node = start_node

    file_info_json, _ := json.Marshal(file_info)
    DatastoreEncryptSet(file_key.Encyption_key, file_key.Mac_key, file_info_json, file_key.File_begin)
    filelist, err := GetFileList(userdata.EncryptionKey, userdata.MacKey, userdata.FileListId)

    if err != nil {
        return errors.New(strings.ToTitle("file is temperd !!!"))
    }

    filelist[filename] = file_key

    //userlib.DebugMsg("I am fine !!!")
    var file_list_json []byte
    file_list_json , _ = json.Marshal(filelist)
    DatastoreEncryptSet(userdata.EncryptionKey, userdata.MacKey, file_list_json, userdata.FileListId)

    return nil
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {

    file_list, err := GetFileList(userdata.EncryptionKey, userdata.MacKey, userdata.FileListId)

    if err != nil {
        return  err
    }

    var file_key FileKey
    var exist bool
    file_key, exist = file_list[filename]

    if !exist {
        return  errors.New(strings.ToTitle("This file does not exist"))
    }
    var content []byte
    file_begin, files ,err := get_file_node(&file_key)
    var last_node *FileNode
    var last_node_index int
    last_node_index = len(files) - 1
    last_node = files[last_node_index]
    content = last_node.Content
    content = append(content, data...)

    num_of_nodes, last_node_id := SplitAndStoreFile(content, userlib.AESKeySize * 5, userdata.EncryptionKey, userdata.MacKey)
    file_begin.File_length = len(files)
    file_begin.Node_nums += (num_of_nodes - 1)
    last_node.Next_node = last_node_id

    file_begin_node_json, _ := json.Marshal(file_begin)
    DatastoreEncryptSet(file_key.Encyption_key, file_key.Mac_key, file_begin_node_json, file_key.File_begin)

    return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

    file_list, err := GetFileList(userdata.EncryptionKey, userdata.MacKey, userdata.FileListId)

    if err != nil {
        return nil, err
    }

    var file_key FileKey
    var exist bool 
    file_key, exist = file_list[filename]

    if !exist {
        return nil, errors.New(strings.ToTitle("This file does not exist"))
    }

    _, files ,err := get_file_node(&file_key)

    if err != nil {
        return nil, err
    }

    for i:=0; i < len(files); i++ {
        data = append(data, files[i].Content...)
    }

    return data, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {

    Signature      []byte
    Encrypted_file []byte
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
    var exist bool
    public_key_recipient, exist := userlib.KeystoreGet(recipient) 

    if !exist {
        return "", errors.New(strings.ToTitle("This recipient does not exist"))
    }

    file_list, err := GetFileList(userdata.EncryptionKey, userdata.MacKey, userdata.FileListId)

    if err != nil {
        return "", err
    }

    var file_key FileKey 
    file_key, exist = file_list[filename]

    if !exist {
        return "", errors.New(strings.ToTitle("This file does not exist"))
    }

    var a_file_key FileKey
    var file_key_recipient *FileKey 
    file_key_recipient = &a_file_key
    file_key_recipient.Encyption_key = file_key.Encyption_key
    file_key_recipient.Mac_key = file_key.Mac_key
    file_key_recipient.File_begin = file_key.File_begin
    file_key_recipient.Is_owner = false
    file_key_recipient_json, _ := json.Marshal(file_key_recipient)
    recipient_sharing_id := uuid.New().String()
    file_key_recipient_json_encrypted, err := userlib.RSAEncrypt(&public_key_recipient,
                            file_key_recipient_json, []byte(userdata.Username))

    signature, err := userlib.RSASign(userdata.SignedKey, file_key_recipient_json_encrypted)
    shared_record := sharingRecord{Signature:signature, Encrypted_file:file_key_recipient_json_encrypted}
    shared_record_json, _ := json.Marshal(shared_record)
    userlib.DatastoreSet(recipient_sharing_id, shared_record_json)

    return recipient_sharing_id, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
    msgid string) error {

    sender_public_key, valid := userlib.KeystoreGet(sender)

    if !valid {
        return errors.New(strings.ToTitle("This file does not exist"))
    }

    shared_record_json, valid := userlib.DatastoreGet(msgid)

    if !valid {
        return errors.New(strings.ToTitle("shared record does not exist"))
    }

    var sharingRecord sharingRecord
    err := json.Unmarshal(shared_record_json, &sharingRecord)

    if err != nil {
        return errors.New(strings.ToTitle("Json file is tampered !!!"))
    }

    err = userlib.RSAVerify(&sender_public_key, sharingRecord.Encrypted_file,
        sharingRecord.Signature)

    if err != nil {
        return errors.New(strings.ToTitle("RSA Verify fails!!!"))
    }

    file_key_recipient_json, err := userlib.RSADecrypt(userdata.SignedKey, 
                                    sharingRecord.Encrypted_file, []byte(sender))
    var file_key_recipient FileKey

    err = json.Unmarshal(file_key_recipient_json, &file_key_recipient)

    if err != nil {
        return errors.New(strings.ToTitle("Integrity Error!"))
    } 


    file_list_of_receiver, err := GetFileList(userdata.EncryptionKey, userdata.MacKey, userdata.FileListId)

    if err != nil {
        return err
    }

    file_list_of_receiver[filename] = file_key_recipient
    file_list_of_receiver_json , _ := json.Marshal(file_list_of_receiver)

    DatastoreEncryptSet(userdata.EncryptionKey, userdata.MacKey, file_list_of_receiver_json, userdata.FileListId)

    return err
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {


    file_list, err1 := GetFileList(userdata.EncryptionKey, userdata.MacKey, userdata.FileListId)

    if err1 != nil {
        return errors.New(strings.ToTitle("Can not get FileList!"))
    }

    file_key, exist := file_list[filename]

    if !exist {
        return errors.New(strings.ToTitle("Revoke unexist file!"))
    }


    if file_key.Is_owner {

        file_begin, array_of_file_node, _ := get_file_node(&file_key)

        file_key.Encyption_key = generate_random_AES_key()
        file_key.Mac_key = generate_random_AES_key()

        // Re Encrypt the file

        for i := 0; i < len(array_of_file_node); i++ {

            file_node_json, _ := json.Marshal(array_of_file_node[i])
            cipthertext_file_node_json := encypt_and_mac(file_key.Encyption_key, file_key.Mac_key, file_node_json)

            if i == 0 {
                userlib.DatastoreSet(file_begin.Start_node, cipthertext_file_node_json)
            } else {
                userlib.DatastoreSet(array_of_file_node[i-1].Next_node, cipthertext_file_node_json)
            }


        }

        file_begin_json, _ := json.Marshal(file_begin)
        DatastoreEncryptSet(file_key.Encyption_key, file_key.Mac_key, file_begin_json, file_key.File_begin)

        file_list_json, _ := json.Marshal(file_list)
        DatastoreEncryptSet(userdata.EncryptionKey, userdata.MacKey, file_list_json, userdata.FileListId)

    } else {
        return errors.New(strings.ToTitle("Not Owner of this file !!!"))
    }


    return nil
}